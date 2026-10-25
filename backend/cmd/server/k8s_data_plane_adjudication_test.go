package main

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/custodexa/backend/pkg/crypto"
)

// K8s 容器檔案進出的資料面裁決。
//
// 真 sqlite、真 AssetService／AuthService／AssetAuthorizationService／AccessPolicyService／
// DataTransferService、真 sshproxy.Handler（裁決器）與真 AssetHandler；只把 `kubectl cp`
// 那一步換成計數替身（嵌入真 AssetService，覆寫兩個複製方法），使「被拒的請求零命中
// 複製階段、零解封」可被機器斷言。
//
// 突變自檢：把 sshproxy.(*Handler).AuthorizeDataPlane 改成一律回 nil，
// 「只有管理能力時被拒」「帳號範圍」「存取政策」「停用資產」格全部轉紅。

type countingAssets struct {
	*asset.AssetService
	copies int
}

func (c *countingAssets) K8sCopyToPod(context.Context, uint, string, string, string, string) error {
	c.copies++
	return nil
}

func (c *countingAssets) K8sCopyFromPod(_ context.Context, _ uint, _, _, _, localPath string) error {
	c.copies++
	return writeStubFile(localPath)
}

// ListK8sPods 管理探測的替身：回純中繼資料（不打叢集）。
func (c *countingAssets) ListK8sPods(context.Context, uint) ([]k8sproxy.PodInfo, error) {
	return []k8sproxy.PodInfo{{Name: "web-0", Phase: "Running", Ready: "1/1", Node: "n1",
		Containers: []k8sproxy.ContainerInfo{{Name: "web", Image: "nginx"}}}}, nil
}

type k8sPlaneEnv struct {
	db       *gorm.DB
	assets   *countingAssets
	handler  *api.AssetHandler
	ssh      *sshproxy.Handler
	auth     *identity.AuthService
	authzSvc *authz.AssetAuthorizationService
	policies *policy.SecurityPolicyService
	// lastAuditDetails 最近一次請求結束時 gin context 內的 audit_details（中介層合併用）
	lastAuditDetails map[string]string
}

const (
	k8sPlaneAssetK8s      = uint(1)
	k8sPlaneAssetApproval = uint(2)
	k8sPlaneAssetDisabled = uint(3)
	k8sPlaneUserManager   = uint(1) // 自訂角色：全部資產管理權限，無連線授權
	k8sPlaneUserGranter   = uint(2) // 超管（替他人授權）
	k8sPlaneUserScoped    = uint(3) // 帳號範圍不含預設帳號
)

func newK8sPlaneEnv(t *testing.T, transferOff bool) *k8sPlaneEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{}, &model.AssetAccount{},
		&model.Credential{}, &model.CredentialSecretVersion{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.AccessRequest{}, &model.SecurityPolicy{}, &model.AuditLog{},
		&model.Session{}, &model.RolePermission{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatalf("migrate tail: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	// 角色：超管（內建）與「資產管理」自訂角色（全部資產管理權限點，含 asset:update、asset:test）
	admin := model.Role{Name: model.RoleAdmin}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	manager := model.Role{Name: "asset-manager-custom", DefinitionVersion: 1}
	if err := db.Create(&manager).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("UPDATE roles SET builtin_key = NULL WHERE id = ?", manager.ID).Error; err != nil {
		t.Fatal(err)
	}
	for _, p := range []authz.Permission{authz.PermAssetView, authz.PermAssetCreate, authz.PermAssetUpdate,
		authz.PermAssetDelete, authz.PermAssetTest, authz.PermAssetGroupManage} {
		if err := db.Create(&model.RolePermission{RoleID: manager.ID, PermissionKey: string(p)}).Error; err != nil {
			t.Fatal(err)
		}
	}
	users := []model.User{
		{Username: "k8s-manager", Email: emailOf("m@x"), Active: true, Kind: model.KindHuman},
		{Username: "k8s-granter", Email: emailOf("g@x"), Active: true, Kind: model.KindHuman},
		{Username: "k8s-scoped", Email: emailOf("s@x"), Active: true, Kind: model.KindHuman},
	}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, ur := range []model.UserRole{
		{UserID: k8sPlaneUserManager, RoleID: manager.ID, ScopeKind: model.ScopeKindGlobal},
		{UserID: k8sPlaneUserGranter, RoleID: admin.ID, ScopeKind: model.ScopeKindGlobal},
	} {
		if err := db.Create(&ur).Error; err != nil {
			t.Fatal(err)
		}
	}
	approval := model.AccessPolicyApproval
	assets := []model.Asset{
		{Name: "cluster", Protocol: model.ProtocolK8s, Host: "127.0.0.1", Port: 6443, CreatedBy: 2, Active: true, K8sNamespace: "default"},
		{Name: "cluster-approval", Protocol: model.ProtocolK8s, Host: "127.0.0.1", Port: 6443, CreatedBy: 2, Active: true, K8sNamespace: "default", AccessPolicy: &approval},
		{Name: "cluster-disabled", Protocol: model.ProtocolK8s, Host: "127.0.0.1", Port: 6443, CreatedBy: 2, Active: false, K8sNamespace: "default"},
	}
	for i := range assets {
		if err := db.Create(&assets[i]).Error; err != nil {
			t.Fatal(err)
		}
		// Active 帶 default:true：零值會被 GORM 以預設值寫入並回填結構，停用資產要另外明確更新
		if assets[i].Name == "cluster-disabled" {
			if err := db.Model(&model.Asset{}).Where("id = ?", assets[i].ID).Update("active", false).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := db.Create(&model.AssetAccount{AssetID: assets[i].ID, Username: "default", IsDefault: true}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if transferOff {
		for _, key := range []string{policy.PolicyFileUploadEnabled, policy.PolicyFileDownloadEnabled} {
			if err := db.Create(&model.SecurityPolicy{Key: key, Value: "false", UpdatedBy: "init", UpdatedAt: time.Now()}).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := db.Exec("DELETE FROM audit_logs").Error; err != nil {
		t.Fatal(err)
	}

	aes, err := crypto.NewAESCrypto(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	assetSvc, err := asset.NewAssetService(fieldCapTestCodec{c: aes}, "localhost", 4822, audit.NewTxSink())
	assetSvc.SetTopologyPermissionPort(noopTopologyPort{})
	if err != nil {
		t.Fatal(err)
	}
	authzSvc := authz.NewAssetAuthorizationService(db)
	authSvc := identity.NewAuthService("k8s-plane-secret", time.Hour)
	auditService := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false})
	ssh := sshproxy.NewHandler(assetSvc, authSvc, authzSvc, nil, nil, t.TempDir(), auditService)
	policies := policy.NewSecurityPolicyService(db)
	ssh.AccessPolicy = policy.NewAccessPolicyService(db, policies, authzSvc)
	ssh.TransmissionConsent = policy.NewTransmissionConsentService(db,
		policy.NewTransmissionPolicyService(policies, func() policy.LDAPRiskResult { return policy.LDAPRiskResult{} }))

	counting := &countingAssets{AssetService: assetSvc}
	handler := api.NewAssetHandler(counting, authzSvc, audit.NewDirectSink(db))
	handler.SetDataTransfer(policy.NewDataTransferService(policies))
	handler.SetDataPlaneAuthorizer(ssh)
	return &k8sPlaneEnv{db: db, assets: counting, handler: handler, ssh: ssh, auth: authSvc, authzSvc: authzSvc, policies: policies}
}

func emailOf(s string) *string { return &s }

// engine 與生產同形的路由鏈：登錄執行中介層 → handler；主體由 DB 現查（同 AuthMiddleware）。
func (e *k8sPlaneEnv) engine(t *testing.T, userID uint) *gin.Engine {
	t.Helper()
	p, err := e.auth.CurrentConnectPrincipal(userID)
	if err != nil {
		t.Fatalf("resolve principal: %v", err)
	}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("username", "k8s-plane")
		middleware.SetPrincipal(c, p)
		c.Next()
		e.lastAuditDetails = nil
		if v, ok := c.Get("audit_details"); ok {
			e.lastAuditDetails, _ = v.(map[string]string)
		}
	})
	g := r.Group("/api/v1")
	g.POST("/assets/:id/k8s/upload", middleware.EnforceRegistry(), e.handler.UploadK8sFile)
	g.GET("/assets/:id/k8s/download", middleware.EnforceRegistry(), e.handler.DownloadK8sFile)
	g.GET("/assets/:id/k8s/pods", middleware.EnforceRegistry(), e.handler.ListK8sPods)
	g.POST("/connect-tokens", middleware.EnforceRegistry(), e.ssh.HandleCreateConnectToken)
	return r
}

func (e *k8sPlaneEnv) upload(t *testing.T, userID, assetID uint) (int, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("pod", "web-0")
	_ = mw.WriteField("container", "web")
	f, _ := mw.CreateFormFile("file", "payload.txt")
	_, _ = f.Write([]byte("hello"))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assets/"+itoa(assetID)+"/k8s/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	e.engine(t, userID).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (e *k8sPlaneEnv) download(t *testing.T, userID, assetID uint) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets/"+itoa(assetID)+"/k8s/download?pod=web-0&container=web&path=/tmp/x", nil)
	w := httptest.NewRecorder()
	e.engine(t, userID).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (e *k8sPlaneEnv) issueToken(t *testing.T, userID, assetID uint) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/connect-tokens", strings.NewReader(`{"asset_id":`+itoa(assetID)+`}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.engine(t, userID).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (e *k8sPlaneEnv) grantConnect(t *testing.T, userID, assetID uint, accounts *[]string) uint {
	t.Helper()
	ctx := authz.ContextWithPrincipal(context.Background(), authz.NewPrincipal(k8sPlaneUserGranter, authz.TokenFacts{}, []authz.Assignment{{
		RoleName: model.RoleAdmin, BuiltinKey: model.BuiltinSuperAdmin, Via: authz.ViaDirect, Scope: model.ScopeKindGlobal,
	}}))
	auth, err := e.authzSvc.Grant(ctx, authz.GrantSpec{UserID: &userID, AssetID: &assetID,
		Permission: model.PermissionConnect, GrantedBy: k8sPlaneUserGranter, Accounts: accounts})
	if err != nil {
		t.Fatalf("grant connect: %v", err)
	}
	return auth.ID
}

func (e *k8sPlaneEnv) deniedAuditRows(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := e.db.Model(&model.AuditLog{}).Where("status = ? AND resource = ?", model.StatusDenied, model.ResourceFile).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func expectCode(t *testing.T, label string, gotStatus int, body string, wantStatus int, wantCode string) {
	t.Helper()
	if gotStatus != wantStatus || !strings.Contains(body, `"code":"`+wantCode+`"`) {
		t.Fatalf("%s：want %d %s，got %d %s", label, wantStatus, wantCode, gotStatus, body)
	}
}

func TestK8sDataPlaneAdjudication(t *testing.T) {
	t.Run("持全部資產管理權限而無連線授權：上傳、下載、連線簽發皆被拒且零複製", func(t *testing.T) {
		env := newK8sPlaneEnv(t, false)
		if !env.mustPrincipal(t, k8sPlaneUserManager).Has(authz.PermAssetUpdate) {
			t.Fatal("夾具：管理者應持 asset:update")
		}
		st, body := env.upload(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		expectCode(t, "upload", st, body, http.StatusForbidden, "AUTH_ASSET_CONNECT_DENIED")
		st, body = env.download(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		expectCode(t, "download", st, body, http.StatusForbidden, "AUTH_ASSET_CONNECT_DENIED")
		st, body = env.issueToken(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		if st == http.StatusOK || strings.Contains(body, "connect_token") {
			t.Fatalf("連線簽發應被拒: %d %s", st, body)
		}
		if env.assets.copies != 0 {
			t.Fatalf("被拒的請求不得走到 kubectl 複製階段: copies=%d", env.assets.copies)
		}
	})

	t.Run("同一主體由他人授予連線授權後上傳與下載通過", func(t *testing.T) {
		env := newK8sPlaneEnv(t, false)
		env.grantConnect(t, k8sPlaneUserManager, k8sPlaneAssetK8s, nil)
		st, body := env.upload(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		if st != http.StatusOK {
			t.Fatalf("upload 應通過: %d %s", st, body)
		}
		st, body = env.download(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		if st != http.StatusOK {
			t.Fatalf("download 應通過: %d %s", st, body)
		}
		if env.assets.copies != 2 {
			t.Fatalf("通過裁決後應各走到一次複製: copies=%d", env.assets.copies)
		}
	})

	t.Run("常設授權＋需核准段位：無時窗臨時授權以存取政策碼拒絕，加入時窗內核准後通過", func(t *testing.T) {
		env := newK8sPlaneEnv(t, false)
		env.grantConnect(t, k8sPlaneUserManager, k8sPlaneAssetApproval, nil)
		st, body := env.download(t, k8sPlaneUserManager, k8sPlaneAssetApproval)
		expectCode(t, "approval without ticket", st, body, http.StatusForbidden, "RULE_ACCESS_APPROVAL_REQUIRED")
		if env.assets.copies != 0 {
			t.Fatalf("copies=%d", env.assets.copies)
		}
		uid, aid := k8sPlaneUserManager, k8sPlaneAssetApproval
		start, end := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
		if err := env.db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect,
			GrantedBy: k8sPlaneUserGranter, Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &end}).Error; err != nil {
			t.Fatal(err)
		}
		st, body = env.download(t, k8sPlaneUserManager, k8sPlaneAssetApproval)
		if st != http.StatusOK {
			t.Fatalf("時窗內核准後應通過: %d %s", st, body)
		}
	})

	t.Run("帳號範圍閘與連線簽發同一判定：K8s 不受帳號範圍約束，兩處結論一致", func(t *testing.T) {
		// G-I10 經 AuthorizeConnectAccount 對 K8s 協定一律放行（固定單一預設帳號、不經
		// per-account 判定），連線簽發亦然。資料面重用同一道閘：帳號範圍收緊為 ["other"]
		// （不含預設帳號）時，簽發與檔案進出都照常通過，兩處結論相同。
		// 設計已明定 K8s 不受帳號範圍約束；日後若要改，須同時改簽發側判定與授權管理既有條文，
		// 不在資料面單方面加嚴。
		env := newK8sPlaneEnv(t, false)
		env.grantConnect(t, k8sPlaneUserScoped, k8sPlaneAssetK8s, &[]string{"other"})
		tokenStatus, tokenBody := env.issueToken(t, k8sPlaneUserScoped, k8sPlaneAssetK8s)
		st, body := env.upload(t, k8sPlaneUserScoped, k8sPlaneAssetK8s)
		if (tokenStatus == http.StatusOK) != (st == http.StatusOK) {
			t.Fatalf("帳號範圍收緊時簽發與資料面結論分歧: issue=%d %s / upload=%d %s", tokenStatus, tokenBody, st, body)
		}
		if st != http.StatusOK {
			t.Fatalf("K8s 不受帳號範圍約束，帳號範圍不含預設帳號時兩處都應通過: issue=%d %s / upload=%d %s", tokenStatus, tokenBody, st, body)
		}
	})

	t.Run("停用資產被拒", func(t *testing.T) {
		env := newK8sPlaneEnv(t, false)
		env.grantConnect(t, k8sPlaneUserManager, k8sPlaneAssetDisabled, nil)
		st, body := env.download(t, k8sPlaneUserManager, k8sPlaneAssetDisabled)
		expectCode(t, "disabled asset", st, body, http.StatusForbidden, "RULE_ASSET_DISABLED")
	})

	t.Run("來源限定：有連線授權但來源不在允許網段內，上傳、下載、連線簽發皆被拒且零複製", func(t *testing.T) {
		env := newK8sPlaneEnv(t, false)
		env.grantConnect(t, k8sPlaneUserManager, k8sPlaneAssetK8s, nil)
		// 測試請求的來源位址為 192.0.2.1（httptest 預設），不在 10.0.0.0/8 內
		if err := env.db.Model(&model.User{}).Where("id = ?", k8sPlaneUserManager).
			Update("allowed_cidrs", "10.0.0.0/8").Error; err != nil {
			t.Fatal(err)
		}
		st, body := env.upload(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		expectCode(t, "upload from outside", st, body, http.StatusForbidden, "AUTH_SOURCE_NOT_ALLOWED")
		st, body = env.download(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		expectCode(t, "download from outside", st, body, http.StatusForbidden, "AUTH_SOURCE_NOT_ALLOWED")
		st, body = env.issueToken(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		expectCode(t, "issue from outside", st, body, http.StatusForbidden, "AUTH_SOURCE_NOT_ALLOWED")
		if env.assets.copies != 0 {
			t.Fatalf("被拒的請求不得走到 kubectl 複製階段: copies=%d", env.assets.copies)
		}
	})

	t.Run("超管通過且審計帶 policy_exemption（需核准段位）", func(t *testing.T) {
		env := newK8sPlaneEnv(t, false)
		st, body := env.upload(t, k8sPlaneUserGranter, k8sPlaneAssetApproval)
		if st != http.StatusOK {
			t.Fatalf("超管應通過: %d %s", st, body)
		}
		if env.lastAuditDetails["policy_exemption"] != "admin" {
			t.Fatalf("超管豁免應合併 policy_exemption 審計標記: %+v", env.lastAuditDetails)
		}
	})

	t.Run("傳輸鍵關閉：無授權者回連線授權碼，有授權者回 RULE_TRANSFER_DENIED 並留 denied 審計", func(t *testing.T) {
		env := newK8sPlaneEnv(t, true)
		st, body := env.upload(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		expectCode(t, "no grant + transfer off", st, body, http.StatusForbidden, "AUTH_ASSET_CONNECT_DENIED")
		if env.deniedAuditRows(t) != 0 {
			t.Fatal("連線裁決拒絕不進傳輸控管，不得留 denied 檔案審計")
		}
		env.grantConnect(t, k8sPlaneUserManager, k8sPlaneAssetK8s, nil)
		st, body = env.upload(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		expectCode(t, "granted + transfer off", st, body, http.StatusForbidden, "RULE_TRANSFER_DENIED")
		if env.deniedAuditRows(t) != 1 {
			t.Fatalf("傳輸控管拒絕應留一列 denied 檔案審計: %d", env.deniedAuditRows(t))
		}
		if env.assets.copies != 0 {
			t.Fatalf("copies=%d", env.assets.copies)
		}
	})

	t.Run("未注入裁決器時請求被拒", func(t *testing.T) {
		env := newK8sPlaneEnv(t, false)
		env.grantConnect(t, k8sPlaneUserManager, k8sPlaneAssetK8s, nil)
		env.handler.SetDataPlaneAuthorizer(nil)
		st, _ := env.download(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		if st != http.StatusInternalServerError || env.assets.copies != 0 {
			t.Fatalf("未注入應 fail-close: status=%d copies=%d", st, env.assets.copies)
		}
	})

	t.Run("登錄：兩條檔案路由為已認證＋資料面類別且不帶管理權限點；探測路由維持管理權限", func(t *testing.T) {
		for _, k := range []struct{ method, path string }{
			{"POST", "/api/v1/assets/:id/k8s/upload"}, {"GET", "/api/v1/assets/:id/k8s/download"},
		} {
			e, ok := authz.LookupRoute(k.method, k.path)
			if !ok || e.Base != authz.BaseAuthenticated || !e.DataPlane || e.Perm != "" || len(e.Fields) != 0 {
				t.Errorf("%s %s 應登錄為已認證＋資料面且無任何管理權限點: %+v ok=%v", k.method, k.path, e, ok)
			}
			if allowed, registered := middleware.AgentRouteDecision(k.method, k.path); allowed || !registered {
				t.Errorf("%s %s 對 agent 應維持既有路由拒絕: allowed=%v registered=%v", k.method, k.path, allowed, registered)
			}
		}
		pods, _ := authz.LookupRoute("GET", "/api/v1/assets/:id/k8s/pods")
		test, _ := authz.LookupRoute("POST", "/api/v1/assets/:id/test-connection")
		if pods.Perm != authz.PermAssetView || test.Perm != authz.PermAssetTest {
			t.Errorf("管理探測應維持管理權限點: pods=%+v test=%+v", pods, test)
		}
	})

	t.Run("管理探測只回中繼資料，且探測成功不構成資料面放行", func(t *testing.T) {
		allowedPod := map[string]bool{"name": true, "phase": true, "ready": true, "restarts": true, "started_at": true,
			"node": true, "containers": true, "default_container": true}
		for _, f := range jsonFieldNames(reflect.TypeOf(k8sproxy.PodInfo{})) {
			if !allowedPod[f] {
				t.Errorf("PodInfo 含非中繼資料欄位 %q", f)
			}
		}
		allowedProbe := map[string]bool{"success": true, "message": true, "code": true, "latency_ms": true,
			"error_code": true, "protocol": true, "tested_at": true,
			"warning_code": true} // 探測本身的主機金鑰警示碼，不含資料面內容
		for _, f := range jsonFieldNames(reflect.TypeOf(asset.ConnectionTestResult{})) {
			if !allowedProbe[f] {
				t.Errorf("ConnectionTestResult 含非探測結果欄位 %q", f)
			}
		}
		env := newK8sPlaneEnv(t, false)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assets/1/k8s/pods", nil)
		w := httptest.NewRecorder()
		env.engine(t, k8sPlaneUserManager).ServeHTTP(w, req)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"web-0"`) {
			t.Fatalf("持 asset:view 的管理者列 pod 應成功: %d %s", w.Code, w.Body.String())
		}
		st, body := env.upload(t, k8sPlaneUserManager, k8sPlaneAssetK8s)
		expectCode(t, "upload after pods", st, body, http.StatusForbidden, "AUTH_ASSET_CONNECT_DENIED")
	})
}

func (e *k8sPlaneEnv) mustPrincipal(t *testing.T, userID uint) *authz.Principal {
	t.Helper()
	p, err := e.auth.CurrentConnectPrincipal(userID)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func jsonFieldNames(tp reflect.Type) []string {
	var out []string
	for i := 0; i < tp.NumField(); i++ {
		tag := tp.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		out = append(out, strings.Split(tag, ",")[0])
	}
	return out
}

// writeStubFile 下載替身：在本地產出一個檔，讓 handler 的「來源存在」判斷成立
func writeStubFile(path string) error { return os.WriteFile(path, []byte("stub"), 0o600) }
