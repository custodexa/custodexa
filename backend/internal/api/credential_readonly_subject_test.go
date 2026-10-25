package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
)

// 只具憑證檢視能力的主體：讀取在路由層與服務層都放行並留痕，寫入被拒且秘密不變。
//
// 兩層各自判定：路由登錄按語義能力（讀＝credential:view、寫＝credential:manage），
// 服務層再以動作的語義能力判（列表／詳情＝view、SetSecret＝set-secret）。只看一層的
// 版本擋不住「路由放行但服務漏判」或「服務已放寬但路由仍拒」——後者正是本測試要釘的
// 狀態：服務改驗 view 之後，路由若仍要求 manage，唯讀主體在第一道就 403。
//
// 服務層用生產同款的判定（自資料庫重新解析主體的 HasAllCapabilities），
// 不用讀 context 主體的替身：唯讀能力來自資料庫中的自訂角色指派。

// credReadonlyUserID 只持 credential:view＋asset:view 的帳號。
const credReadonlyUserID uint = 21

// credLegacyManageUserID 只持舊 credential:manage（加 view、asset:view）而無語義寫入能力的帳號。
const credLegacyManageUserID uint = 22

// resolverCredentialAuthorizer 與組裝根的轉接頭同一判定：以資料庫現況解析主體。
type resolverCredentialAuthorizer struct{ db *gorm.DB }

func (a resolverCredentialAuthorizer) AuthorizeCredentialManagement(_ context.Context, db *gorm.DB,
	actor asset.CredentialManagementActor, req asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	if db == nil {
		db = a.db
	}
	d, err := authz.NewResolver(a.db).HasAllCapabilities(db, actor.UserID, req.Capabilities)
	if err != nil {
		return asset.CredentialManagementDecision{}, err
	}
	return asset.CredentialManagementDecision{Allowed: d.Allowed, Missing: d.Missing, AuthzVersion: d.Version, Sources: d.Sources}, nil
}

// grantCustomCredentialRole 建一個自訂角色（定義版本 1）並以全域直接指派給帳號。
func grantCustomCredentialRole(t *testing.T, db *gorm.DB, userID uint, name string, perms ...authz.Permission) {
	t.Helper()
	role := &model.Role{Name: name, DefinitionVersion: 1}
	require.NoError(t, db.Create(role).Error)
	for _, p := range perms {
		require.NoError(t, db.Create(&model.RolePermission{RoleID: role.ID, PermissionKey: string(p)}).Error)
	}
	require.NoError(t, db.Create(&model.UserRole{UserID: userID, RoleID: role.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
}

func TestCredentialReadOnlySubject(t *testing.T) {
	t.Run("憑證路由的登錄能力與服務層判定一致", func(t *testing.T) {
		reads := []string{
			"GET /api/v1/credentials",
			"GET /api/v1/credentials/:id",
			"GET /api/v1/credentials/:id/rotations/:rid",
		}
		writes := []string{
			"POST /api/v1/credentials",
			"PUT /api/v1/credentials/:id",
			"DELETE /api/v1/credentials/:id",
			"POST /api/v1/credentials/:id/bindings",
			"DELETE /api/v1/credentials/:id/bindings/:accountId",
			"POST /api/v1/credentials/:id/bindings/:accountId/detach",
			"POST /api/v1/credentials/:id/scope",
			"POST /api/v1/credentials/:id/secret",
			"POST /api/v1/credentials/:id/impact-confirmations",
			"POST /api/v1/credentials/ownership",
			"POST /api/v1/credentials/:id/rotations",
			"POST /api/v1/credentials/:id/rotations/:rid/abandon",
			"POST /api/v1/credentials/:id/rotations/:rid/members/:mid/retry",
			"PUT /api/v1/assets/:id/accounts/:accountId/credential",
		}
		check := func(key string, want authz.Permission) {
			parts := strings.SplitN(key, " ", 2)
			e, ok := authz.LookupRoute(parts[0], parts[1])
			require.True(t, ok, "%s 未登錄", key)
			assert.Equal(t, authz.BasePerm, e.Base, key)
			assert.Equal(t, want, e.Perm, "%s 的登錄能力", key)
		}
		for _, k := range reads {
			check(k, authz.PermCredentialView)
		}
		for _, k := range writes {
			check(k, authz.PermCredentialManage)
		}
	})

	f := setupCredentialAPIEnv(t)
	require.NoError(t, f.db.AutoMigrate(&model.RolePermission{}, &model.AuthzState{}))
	require.NoError(t, f.db.Exec("INSERT OR IGNORE INTO authz_state (id, version) VALUES (1, 0)").Error)
	seedCredentialGateUsers(t, f.db, 1, 7, credReadonlyUserID, credLegacyManageUserID)
	ensureCredentialGateRole(t, f.db, 1, model.RoleAdmin)
	grantCustomCredentialRole(t, f.db, credReadonlyUserID, "cred-readonly",
		authz.PermCredentialView, authz.PermAssetView)
	grantCustomCredentialRole(t, f.db, credLegacyManageUserID, "cred-legacy-manage",
		authz.PermCredentialManage, authz.PermCredentialView, authz.PermAssetView)

	// 服務層換成生產同款判定；輪替服務沿用夾具（改密進度讀取不經判定器）
	creds := asset.NewCredentialService(f.assetSvc, aesColumnCodec(t, make([]byte, 32)), audit.NewTxSink()).WithOwnershipScope(globalOwnershipScopeForTest{}).
		WithManagementAuthorizer(resolverCredentialAuthorizer{db: f.db}).WithSystemAlertSink(recordingSystemAlerts{})
	handler := NewCredentialHandler(creds, f.rotations,
		asset.NewRotationReportBuilder(f.db, asset.NewChangeSecretPlanService(f.db), func() int { return 0 }))

	// 審計中介層是讀取留痕的來源，必須在鏈上；同步落庫才讀得到
	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(middleware.AuditLogMiddleware(auditSvc))
	authService := identity.NewAuthService("credential-api-test-secret", time.Minute)
	handler.RegisterRoutes(engine.Group("/api/v1"), authService)
	mgr := crypto.NewJWTManager("credential-api-test-secret", time.Minute)

	token := func(uid uint) string {
		tok, err := mgr.GenerateToken(uid, "subject", "s@example.com", model.RoleUser, crypto.AuthContext{})
		require.NoError(t, err)
		return tok
	}
	do := func(uid uint, method, path, body string) (int, string) {
		var req *http.Request
		if body == "" {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+token(uid))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	versions := func() int64 {
		var n int64
		require.NoError(t, f.db.Model(&model.CredentialSecretVersion{}).Count(&n).Error)
		return n
	}
	snapshot := func() model.Credential {
		var c model.Credential
		require.NoError(t, f.db.First(&c, f.sharedID).Error)
		return c
	}
	readRows := func(uid uint) []model.AuditLog {
		var rows []model.AuditLog
		require.NoError(t, f.db.Where("resource = ? AND method = ? AND user_id = ?",
			string(model.ResourceCredential), "GET", uid).Order("id ASC").Find(&rows).Error)
		return rows
	}
	detailPath := "/api/v1/credentials/" + uintToStr(f.sharedID)

	t.Run("沒有檢視能力的主體讀取被拒且不透露存在與否", func(t *testing.T) {
		for _, path := range []string{"/api/v1/credentials", detailPath, "/api/v1/credentials/999999"} {
			code, body := do(7, "GET", path, "")
			assert.Equal(t, http.StatusForbidden, code, path)
			assert.NotContains(t, body, "shareduser", path)
		}
	})

	t.Run("只持舊 credential:manage 的主體：路由放行但服務層以語義能力拒絕寫入", func(t *testing.T) {
		// 須在任何輪替發起之前：輪替進行中的拒絕（409）會蓋過能力判定
		before, beforeCred := versions(), snapshot()
		code, body := do(credLegacyManageUserID, "POST", detailPath+"/secret", `{"password":"Legacy-Override-1"}`)
		// 服務層無權沿既有端點的收斂拒絕形狀（與「憑證不存在」同回應），不是路由層的 403
		assert.Equal(t, http.StatusNotFound, code, body)
		assert.Contains(t, body, "NOTFOUND_CREDENTIAL", "拒絕來自服務層的收斂形狀")
		assert.NotContains(t, body, "AUTH_PERMISSION_DENIED", "拒絕來自服務層而非路由層")
		assert.Equal(t, before, versions(), "秘密版本數不變")
		assert.Equal(t, beforeCred.CurrentVersionID, snapshot().CurrentVersionID, "現行秘密版本不變")

		code, body = do(credLegacyManageUserID, "GET", detailPath, "")
		assert.Equal(t, http.StatusOK, code, "檢視能力照常生效：%s", body)
	})

	t.Run("唯讀主體：列表、詳情、改密進度成功並各留一筆讀取審計", func(t *testing.T) {
		code, body := do(credReadonlyUserID, "GET", "/api/v1/credentials?scope=shared", "")
		require.Equal(t, http.StatusOK, code, body)
		assert.Contains(t, body, "shareduser", "列表含共用憑證（否則讀取成功只證明空集合）")
		assert.NotContains(t, body, "shared-pw", "讀取不回秘密")

		code, body = do(credReadonlyUserID, "GET", detailPath, "")
		require.Equal(t, http.StatusOK, code, body)
		assert.Contains(t, body, "\"bindings\"", "詳情含掛載清單")
		assert.NotContains(t, body, "shared-pw", "讀取不回秘密")

		before, beforeCred := versions(), snapshot()
		for _, c := range []struct{ method, path, body string }{
			{"POST", detailPath + "/secret", `{"password":"Readonly-Override-1"}`},
			{"PUT", detailPath, `{"name":"renamed-by-readonly"}`},
			{"DELETE", detailPath, ""},
			{"POST", "/api/v1/credentials", `{"name":"x","username":"x","protocol_family":"ssh","password":"x-pw"}`},
			{"POST", detailPath + "/rotations", `{}`},
		} {
			code, body := do(credReadonlyUserID, c.method, c.path, c.body)
			assert.Equal(t, http.StatusForbidden, code, "%s %s 應被拒：%s", c.method, c.path, body)
			assert.NotContains(t, body, "shared-pw")
		}
		assert.Equal(t, before, versions(), "寫入被拒後秘密版本數不變")
		after := snapshot()
		assert.Equal(t, *beforeCred.Name, *after.Name, "中繼資料不變")
		assert.Equal(t, beforeCred.CurrentVersionID, after.CurrentVersionID, "現行秘密版本不變")

		// 改密進度也是讀取：由管理者發起一次輪替，唯讀主體讀它的進度
		rot, err := f.rotations.Start(credAdminCtx(), f.sharedID, asset.StartRotationRequest{})
		require.NoError(t, err)
		code, body = do(credReadonlyUserID, "GET", detailPath+"/rotations/"+uintToStr(rot.ID), "")
		require.Equal(t, http.StatusOK, code, body)

		rows := readRows(credReadonlyUserID)
		require.Len(t, rows, 3, "列表、詳情、改密進度各恰一筆讀取審計")
		for _, row := range rows {
			assert.Equal(t, "subject", row.Username)
			assert.NotEmpty(t, row.Details, "讀取列帶查詢摘要")
			assert.NotContains(t, row.Details, "shared-pw", "審計列不含秘密")
		}
	})

}
