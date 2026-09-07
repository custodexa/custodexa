package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
)

// 憑證庫 API 的接入層守衛。
//
// 本檔驗的是**接入層自己的責任**：路由集合、錯誤信封形狀、讀取留痕、
// 掛載類動作的資產主體鍵，以及非管理者投影的欄位邊界。
// 服務層的規則（掛載唯一性、範圍轉換、輪替狀態機）由 asset 模組的測試承擔，
// 此處不重測——重測會讓同一條規則有兩份會各自演化的期望。

type credentialAPIFixture struct {
	handler   *CredentialHandler
	accounts  *AssetAccountHandler
	db        *gorm.DB
	creds     *asset.CredentialService
	rotations *asset.CredentialRotationService
	assetSvc  *asset.AssetService
	assetIDs  []uint
	sharedID  uint
	accountID uint
}

func setupCredentialAPIEnv(t *testing.T) *credentialAPIFixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// sqlite `:memory:` 配連線池時每條連線是各自獨立的空 DB
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetAccount{},
		&model.Credential{}, &model.CredentialSecretVersion{},
		&model.CredentialRotation{}, &model.CredentialRotationMember{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{},
		&model.AssetHostKey{}, &model.ChangeSecretCandidate{}, &model.ChangeSecretRecord{},
		&model.ChangeSecretPlan{}))
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	codec := aesColumnCodec(t, make([]byte, 32))
	sink := audit.NewTxSink()
	assetSvc, err := asset.NewAssetService(codec, "localhost", 4822, sink)
	require.NoError(t, err)
	authorization := authz.NewAssetAuthorizationService(db)
	creds := asset.NewCredentialService(assetSvc, codec, sink).WithAuthorization(authorization)
	candidates, err := asset.NewChangeSecretCandidateService(db, codec, assetSvc, sink)
	require.NoError(t, err)
	rotations := asset.NewCredentialRotationService(db, assetSvc, candidates,
		asset.NewHostKeyService(db), codec, sink, authorization)

	f := &credentialAPIFixture{
		db: db, creds: creds, rotations: rotations, assetSvc: assetSvc,
		handler: NewCredentialHandler(creds, rotations,
			asset.NewRotationReportBuilder(db, asset.NewChangeSecretPlanService(db),
				func() int { return 0 })),
		accounts: NewAssetAccountHandler(
			asset.NewAssetAccountService(assetSvc, codec, sink).WithAuthorization(authorization),
			authorization),
	}

	// 兩台資產各帶一個專用憑證的預設掛載
	for _, spec := range []struct{ name, host string }{{"alpha", "10.9.0.1"}, {"beta", "10.9.0.2"}} {
		a, cerr := assetSvc.Create(&asset.CreateAssetRequest{
			Name: spec.name, Protocol: model.ProtocolSSH, Host: spec.host, Port: 22,
			Username: "ops", Password: "dedicated-pw", CreatedBy: 1,
		})
		require.NoError(t, cerr)
		f.assetIDs = append(f.assetIDs, a.ID)
	}

	// 一筆共用憑證，掛在第一台上（掛載類動作與可見性斷言的對象）
	shared, err := creds.Create(credAdminCtx(), &asset.CreateCredentialRequest{
		Name: "共用維運帳號", Username: "shareduser",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "shared-pw",
	})
	require.NoError(t, err)
	f.sharedID = shared.ID
	bound, err := creds.Bind(credAdminCtx(), shared.ID, &asset.BindCredentialRequest{AssetID: f.assetIDs[0]})
	require.NoError(t, err)
	f.accountID = bound.ID
	return f
}

// credAdminCtx 帶 admin 身分與角色的服務層 context（跨資產權限判定短路 admin）。
func credAdminCtx() context.Context {
	ctx := context.WithValue(context.Background(), "userID", uint(1)) //nolint:staticcheck // 沿用既有審計 context 慣例
	ctx = context.WithValue(ctx, "username", "admin")                 //nolint:staticcheck // 同上
	return context.WithValue(ctx, "role", model.RoleAdmin)            //nolint:staticcheck // 同上
}

// credentialTestRouter 以真實入口掛上憑證庫路由（AuthMiddleware → RequireRole →
// RequirePermission → handler），回傳引擎與可簽 token 的 JWT manager。
func credentialTestRouter(t *testing.T, f *credentialAPIFixture) (*gin.Engine, *crypto.JWTManager) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	// 世代閘現查 users：token 宣稱的兩個 ID 必須存在，否則整條鏈在認證就被擋下
	// 而本檔的斷言會落在 401 上假綠
	seedCredentialGateUsers(t, f.db, 1, 7)

	authService := identity.NewAuthService("credential-api-test-secret", time.Minute)
	r := gin.New()
	group := r.Group("/api/v1")
	f.handler.RegisterRoutes(group, authService)
	f.accounts.RegisterRoutes(group, authService, authz.NewAssetAuthorizationService(f.db))
	return r, crypto.NewJWTManager("credential-api-test-secret", time.Minute)
}

// seedCredentialGateUsers 在**同一個** DB 上補齊世代閘要查的使用者列。
// 不重用 installEpochGateDB：那支會另建一個 DB 並蓋掉 database.DB，
// 本檔的資料就此從服務層的視野裡消失（而斷言會在空集合上假綠）。
func seedCredentialGateUsers(t *testing.T, db *gorm.DB, ids ...uint) {
	t.Helper()
	for i, id := range ids {
		var exists int64
		require.NoError(t, db.Model(&model.User{}).Where("id = ?", id).Count(&exists).Error)
		if exists > 0 {
			continue
		}
		u := &model.User{Username: "gate-" + string(rune('a'+i)), Password: "x", Active: true}
		u.ID = id
		require.NoError(t, db.Create(u).Error)
	}
}

// TestCredentialHandlerRoutesAndErrorEnvelope 路由集合與錯誤信封。
//
// 路由集合逐支比對而非數個數：少掛一支的症狀是「那個按鈕按下去 404」，
// 而數量斷言在「刪一支、加一支」時仍然綠。
func TestCredentialHandlerRoutesAndErrorEnvelope(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	r, mgr := credentialTestRouter(t, f)

	want := []string{
		"DELETE /api/v1/credentials/:id",
		"DELETE /api/v1/credentials/:id/bindings/:accountId",
		"GET /api/v1/credentials",
		"GET /api/v1/credentials/:id",
		"GET /api/v1/credentials/:id/rotations/:rid",
		"POST /api/v1/credentials",
		"POST /api/v1/credentials/:id/bindings",
		"POST /api/v1/credentials/:id/bindings/:accountId/detach",
		"POST /api/v1/credentials/:id/rotations",
		"POST /api/v1/credentials/:id/rotations/:rid/abandon",
		"POST /api/v1/credentials/:id/rotations/:rid/members/:mid/retry",
		"POST /api/v1/credentials/:id/scope",
		"POST /api/v1/credentials/:id/secret",
		"PUT /api/v1/assets/:id/accounts/:accountId/credential",
		"PUT /api/v1/credentials/:id",
	}
	var got []string
	for _, route := range r.Routes() {
		if strings.Contains(route.Path, "credential") {
			got = append(got, route.Method+" "+route.Path)
		}
	}
	sort.Strings(got)
	assert.Equal(t, want, got, "憑證庫路由集合")

	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)

	// 錯誤信封：與既有端點同形（只有 code，成因不出站）
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/credentials/999999", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	assert.Equal(t, "NOTFOUND_CREDENTIAL", envelope["code"], "機器碼")
	assert.NotEmpty(t, envelope["error"], "信封帶 wire fallback 訊息（與既有端點同形）")
	assert.Len(t, envelope, 2, "信封只有 code 與 error 兩鍵：成因不出站")
	// 「不存在」不得洩漏任何自由字串：回應裡不出現請求方送進來的識別以外的東西
	assert.NotContains(t, w.Body.String(), "shareduser")
	assert.NotContains(t, w.Body.String(), "共用維運帳號")
}

// TestCredentialCreateRejectsInvalidAuthMethodAs400 `auth_method` 值域是 sql｜domain
// （資料庫協定族的認證類型），送 secret_type 的值（password）屬請求錯誤：
// 必須以既有帳號碼回 400，不得漏到 500。
func TestCredentialCreateRejectsInvalidAuthMethodAs400(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	r, mgr := credentialTestRouter(t, f)
	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)

	cases := []struct {
		authMethod string
		wantCode   string
	}{
		{authMethod: "password", wantCode: "VALIDATION_ACCOUNT_AUTH_METHOD"},
		{authMethod: "domain", wantCode: "VALIDATION_ACCOUNT_AUTH_METHOD_UNSUPPORTED"},
	}
	for _, tc := range cases {
		body := fmt.Sprintf(`{"name":"ops-%s","username":"ops","protocol_family":"ssh","auth_method":%q,"password":"p@ss"}`,
			tc.authMethod, tc.authMethod)
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/credentials", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code, "auth_method=%s 應為請求錯誤：%s", tc.authMethod, w.Body.String())
		var envelope map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
		assert.Equal(t, tc.wantCode, envelope["code"], "auth_method=%s", tc.authMethod)
	}
}

// TestCredentialReadAuditTrail 三支讀取端點各留一筆帶查詢條件摘要的審計列。
//
// 讀取留痕不因其為 GET 而豁免：共用關係本身即敏感資訊，
// 「誰看過哪些憑證的分布」是可課責事實。
func TestCredentialReadAuditTrail(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	seedCredentialGateUsers(t, f.db, 1)

	// 審計中介層是留痕的來源，必須掛在鏈上（否則本測試在零列上假綠）；
	// 同步模式落庫，測試才讀得到那幾列
	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(middleware.AuditLogMiddleware(auditSvc))
	authService := identity.NewAuthService("credential-api-test-secret", time.Minute)
	f.handler.RegisterRoutes(engine.Group("/api/v1"), authService)

	mgr := crypto.NewJWTManager("credential-api-test-secret", time.Minute)
	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)

	// 改密進度也是一支讀取端點：它回答的是「那組秘密此刻換到哪台了」，
	// 與列表、詳情同屬可課責的閱覽
	rot, err := f.rotations.Start(credAdminCtx(), f.sharedID, asset.StartRotationRequest{})
	require.NoError(t, err)
	require.NotZero(t, rot.ID)

	for _, path := range []string{
		"/api/v1/credentials?scope=shared",
		"/api/v1/credentials/" + uintToStr(f.sharedID),
		"/api/v1/credentials/" + uintToStr(f.sharedID) + "/rotations/" + uintToStr(rot.ID),
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		engine.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, path)
	}

	var rows []model.AuditLog
	require.NoError(t, f.db.Where("resource = ?", string(model.ResourceCredential)).
		Order("id ASC").Find(&rows).Error)

	reads := 0
	paths := make([]string, 0, 3)
	for _, row := range rows {
		if row.Method != "GET" {
			continue
		}
		reads++
		paths = append(paths, row.Path)
		assert.Equal(t, string(model.ResourceCredential), string(row.Resource),
			"讀取列的分類為憑證自身，不得落入資產分類")
		assert.NotEmpty(t, row.Details, "讀取列須帶查詢條件摘要")
		assert.NotContains(t, row.Details, "shared-pw", "審計列不得含秘密材料")
	}
	// 精確等於 3：「至少 N 筆」既擋不住漏記（少掉的那一支被別支補足），
	// 也擋不住重複記（同一次閱覽落兩列會讓稽核以為看過兩次）
	assert.Equal(t, 3, reads, "列表、詳情、改密進度各恰一筆讀取列（實際：%v）", paths)
}

// TestCredentialBindAuditCarriesAsset 掛載與卸載的審計列帶受影響資產識別。
//
// 掛載改變的是「秘密在哪些主機上生效」；只掛在憑證下的話，
// 「這台機器的登入身分被誰換掉」在資產樞紐上查不出來。
func TestCredentialBindAuditCarriesAsset(t *testing.T) {
	f := setupCredentialAPIEnv(t)

	// 掛到第二台
	bound, err := f.creds.Bind(credAdminCtx(), f.sharedID,
		&asset.BindCredentialRequest{AssetID: f.assetIDs[1]})
	require.NoError(t, err)

	var bindRows []model.AuditLog
	require.NoError(t, f.db.Where("resource = ? AND asset_id = ?",
		string(model.ResourceCredential), f.assetIDs[1]).Find(&bindRows).Error)
	require.NotEmpty(t, bindRows, "掛載列須帶受影響資產識別")
	assert.NotContains(t, bindRows[0].Details, "shared-pw")

	// 卸載同理（卸載後掛載列已不存在，主體鍵只能在動作當下取得）
	require.NoError(t, f.creds.Unbind(credAdminCtx(), f.sharedID, bound.ID))
	var afterRows []model.AuditLog
	require.NoError(t, f.db.Where("resource = ? AND asset_id = ?",
		string(model.ResourceCredential), f.assetIDs[1]).Find(&afterRows).Error)
	assert.Greater(t, len(afterRows), len(bindRows), "卸載另留一列，且同樣帶資產識別")
}

// TestNonAdminDTOOmitsCredentialFields 守衛 3：非管理者的帳號投影不含任何憑證欄位。
//
// **走真實入口**（路由 → AuthMiddleware → RequirePermission → RequireAssetVisible
// → handler）：只呼叫 handler 方法的版本證明不了「這條路由上的投影是精簡版」，
// 而投影的選擇正是在請求上下文裡做的。
func TestNonAdminDTOOmitsCredentialFields(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	r, mgr := credentialTestRouter(t, f)

	// 讓 user 7 對第一台資產有連線權（否則列表被範圍過濾成空而假綠）
	uid, aid := uint(7), f.assetIDs[0]
	require.NoError(t, f.db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
		Accounts: model.AccountScope{model.AccountScopeAll},
	}).Error)

	forbidden := []string{"credential_id", "credential_name", "credential_scope",
		"shared_credential", "effective_version_no", "binding_count"}
	path := "/api/v1/assets/" + uintToStr(f.assetIDs[0]) + "/accounts"

	// 先確認完整版**真的帶著**那些鍵：不然「非 admin 沒有」只證明欄位根本不存在
	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)
	adminBody := credentialGet(t, r, path, adminToken)
	for _, key := range []string{"credential_id", "credential_name", "credential_scope", "shared_credential"} {
		assert.Contains(t, adminBody, key, "管理視圖應帶憑證欄位（否則本守衛在空集合上假綠）")
	}
	assert.Contains(t, adminBody, "shareduser", "前置條件：清單非空")

	for _, role := range []string{model.RoleUser, model.RoleAuditor} {
		token, terr := mgr.GenerateToken(7, "normaluser", "u@example.com", role, crypto.AuthContext{})
		require.NoError(t, terr)
		body := credentialGet(t, r, path, token)
		require.Contains(t, body, "\"username\"", role+" 應讀得到帳號選單（前置條件）")
		for _, key := range forbidden {
			assert.NotContains(t, body, key, role+" 的回應不得含 "+key)
		}
	}
}

// credentialGet 以指定 token 打一支 GET 並回傳回應體（狀態碼非 2xx 即失敗）。
func credentialGet(t *testing.T, r *gin.Engine, path, token string) string {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "%s 應為 200（實得 %d：%s）", path, w.Code, w.Body.String())
	return w.Body.String()
}

// TestAssetAccountCreateAcceptsEitherCredentialSource 建號的憑證來源二擇一。
func TestAssetAccountCreateAcceptsEitherCredentialSource(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	accounts := f.accounts

	// (1) 掛既有共用憑證：不建立任何新密文版本
	var before int64
	require.NoError(t, f.db.Model(&model.CredentialSecretVersion{}).Count(&before).Error)
	w := credentialCall(t, accounts.Create, "POST",
		"/assets/"+uintToStr(f.assetIDs[1])+"/accounts",
		`{"credential_id":`+uintToStr(f.sharedID)+`}`, f.assetIDs[1], 0)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var after int64
	require.NoError(t, f.db.Model(&model.CredentialSecretVersion{}).Count(&after).Error)
	assert.Equal(t, before, after, "掛既有共用憑證不得複製密文")

	// (2) 這台專用：同一交易建憑證與 v1 版本
	w = credentialCall(t, accounts.Create, "POST",
		"/assets/"+uintToStr(f.assetIDs[1])+"/accounts",
		`{"credential":{"username":"solo","password":"solo-pw"}}`, f.assetIDs[1], 0)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// (3) 兩者同時給：拒絕，不靜默擇一
	w = credentialCall(t, accounts.Create, "POST",
		"/assets/"+uintToStr(f.assetIDs[1])+"/accounts",
		`{"credential_id":`+uintToStr(f.sharedID)+`,"credential":{"username":"x","password":"y"}}`,
		f.assetIDs[1], 0)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VALIDATION_CREDENTIAL_SOURCE_AMBIGUOUS")
}

// TestAssetAccountCreateRejectsCopyFromParam 已退場的複製參數帶值即回機器碼。
//
// 靜默忽略會讓舊呼叫端以為複製成立，實際建出來的是一筆沒有秘密的掛載——
// 那台機器連不上，且畫面上看不出原因。
func TestAssetAccountCreateRejectsCopyFromParam(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	w := credentialCall(t, f.accounts.Create, "POST",
		"/assets/"+uintToStr(f.assetIDs[1])+"/accounts",
		`{"copy_from_account_id":`+uintToStr(f.accountID)+`,"username":"copied"}`,
		f.assetIDs[1], 0)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VALIDATION_ACCOUNT_COPY_FROM_REMOVED")

	var created int64
	require.NoError(t, f.db.Model(&model.AssetAccount{}).
		Where("asset_id = ? AND username = ?", f.assetIDs[1], "copied").Count(&created).Error)
	assert.Zero(t, created, "被拒的請求不得留下半成品掛載")
}

// TestAssetUpdateRejectsSharedCredentialSecretWrite 對掛在共用憑證上的帳號
// 走既有 per-account 寫密端點一律拒絕。
//
// 那組秘密同時是其他主機的登入身分；由單台入口改寫會讓其餘掛載當場失去登入身分，
// 而操作者在那個畫面上看得見的只有這一台。
func TestAssetUpdateRejectsSharedCredentialSecretWrite(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	newPw := "typed-in-single-host-form"
	w := credentialCall(t, f.accounts.Update, "PUT",
		"/assets/"+uintToStr(f.assetIDs[0])+"/accounts/"+uintToStr(f.accountID),
		`{"password":"`+newPw+`"}`, f.assetIDs[0], f.accountID)
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "RULE_ACCOUNT_SHARED_CREDENTIAL_SECRET")

	// 共用憑證不得被追加版本（拒絕必須發生在寫入之前）
	var versions int64
	require.NoError(t, f.db.Model(&model.CredentialSecretVersion{}).
		Where("credential_id = ?", f.sharedID).Count(&versions).Error)
	assert.EqualValues(t, 1, versions)

	// 專用憑證維持既有行為
	var dedicated model.AssetAccount
	require.NoError(t, f.db.Where("asset_id = ? AND username = ?", f.assetIDs[1], "ops").
		First(&dedicated).Error)
	w = credentialCall(t, f.accounts.Update, "PUT",
		"/assets/"+uintToStr(f.assetIDs[1])+"/accounts/"+uintToStr(dedicated.ID),
		`{"password":"dedicated-rotated"}`, f.assetIDs[1], dedicated.ID)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// credentialCall 直呼 handler 方法並帶妥路徑參數與 admin 身分。
func credentialCall(t *testing.T, h gin.HandlerFunc, method, path, body string,
	assetID, accountID uint) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	route := "/assets/:id/accounts"
	if accountID != 0 {
		route += "/:accountId"
	}
	r.Handle(method, route, func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "admin")
		c.Set("role", model.RoleAdmin)
		h(c)
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

// TestAccountUpdateResponseCarriesAuthMethod 更新帳號的回應須帶回未更動的欄位。
//
// 回應是呼叫端回填表單與列的資料來源：投影漏帶一欄時 DB 是對的、畫面是空的，
// 而下一次送出就把那個空值寫回去——症狀出現在別的地方、別的時間。
func TestAccountUpdateResponseCarriesAuthMethod(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	r, mgr := credentialTestRouter(t, f)
	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)

	// 第一台的專用掛載（共用憑證那一筆另有其 id）
	var account model.AssetAccount
	require.NoError(t, f.db.Where("asset_id = ? AND id <> ?", f.assetIDs[0], f.accountID).
		Order("id ASC").First(&account).Error)
	require.NotEmpty(t, account.AuthMethod,
		"前置條件：認證方式已落庫，否則本斷言在空值上兩邊都對")

	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT",
		"/api/v1/assets/"+uintToStr(f.assetIDs[0])+"/accounts/"+uintToStr(account.ID),
		strings.NewReader(`{"note":"改個備註"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, account.AuthMethod, body["auth_method"], "未更動的認證方式原樣回填")
	assert.Equal(t, "改個備註", body["note"], "本次更動的欄位帶新值")
	assert.Equal(t, account.Username, body["username"], "未更動的帳號名原樣回填")

	var after model.AssetAccount
	require.NoError(t, f.db.First(&after, account.ID).Error)
	assert.Equal(t, account.AuthMethod, after.AuthMethod, "回應的值即資料的值")
}

// credentialListResult 列表回應的解析結果。
type credentialListResult struct {
	Data  []map[string]any `json:"data"`
	Total int              `json:"total"`
}

// getCredentialList 以 admin 打列表端點並解析回應；code 非 200 時直接讓測試失敗。
func getCredentialList(t *testing.T, r *gin.Engine, token, query string) credentialListResult {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/credentials"+query, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, query+" → "+w.Body.String())
	var out credentialListResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	return out
}

// credentialListNames 列表回應中每一筆的顯示名。
func credentialListNames(t *testing.T, r *gin.Engine, token, query string) []string {
	t.Helper()
	res := getCredentialList(t, r, token, query)
	out := make([]string, 0, len(res.Data))
	for _, item := range res.Data {
		name, _ := item["name"].(string)
		out = append(out, name)
	}
	return out
}

// getCredentialListCode 只取回應的狀態碼與機器碼（拒絕面用）。
func getCredentialListCode(t *testing.T, r *gin.Engine, token, query string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/credentials"+query, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	code, _ := body["code"].(string)
	return w.Code, code
}

// credentialListErrorField 取拒絕回應中 params.field 的值。
//
// 只驗狀態碼會漏掉「回了 400 但指不出是哪個參數」——那正是泛用碼未登記欄位時的形態。
func credentialListErrorField(t *testing.T, r *gin.Engine, token, query string) string {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/credentials"+query, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	var body struct {
		Params map[string]any `json:"params"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	field, _ := body.Params["field"].(string)
	return field
}

// TestCredentialListSearchMatchesDisplayName 搜尋比對的是畫面上看得到的那個名字。
//
// 專用憑證的顯示名是「資產名 / 帳號名」的計算值，名稱欄本身是空的：只比對名稱欄
// 會讓每一筆專用憑證都搜不到，而搜不到不會有任何錯誤——使用者只會以為它不存在。
func TestCredentialListSearchMatchesDisplayName(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	r, mgr := credentialTestRouter(t, f)
	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)

	// 前置條件：專用憑證的名稱欄確實不落庫，否則本測試會在「剛好有落庫」上假綠
	var dedicated model.Credential
	require.NoError(t, f.db.Where("scope = ?", model.CredentialScopeDedicated).
		Order("id ASC").First(&dedicated).Error)
	require.Nil(t, dedicated.Name, "前置條件：專用憑證的名稱欄不落庫")
	assert.Contains(t, credentialListNames(t, r, adminToken, ""), "alpha / ops",
		"前置條件：專用憑證的顯示名為「資產名 / 帳號名」")

	byAsset := credentialListNames(t, r, adminToken, "?search=alpha")
	assert.Contains(t, byAsset, "alpha / ops", "搜資產名要找得到掛在那台上的專用憑證")
	assert.NotContains(t, byAsset, "beta / ops", "別台的專用憑證不該被搜到")
	assert.NotContains(t, byAsset, "共用維運帳號",
		"共用憑證的顯示名是它自己的名稱，不隨掛載到哪台而改變")

	byDedicatedUser := credentialListNames(t, r, adminToken, "?search=ops")
	assert.Contains(t, byDedicatedUser, "alpha / ops", "搜帳號名要找得到專用憑證")
	assert.Contains(t, byDedicatedUser, "beta / ops")

	bySharedUser := credentialListNames(t, r, adminToken, "?search=shareduser")
	assert.Contains(t, bySharedUser, "共用維運帳號", "搜帳號名要找得到共用憑證")

	bySharedName := credentialListNames(t, r, adminToken, "?search=共用維運")
	assert.Contains(t, bySharedName, "共用維運帳號", "搜共用憑證的名稱")
}

// TestCredentialListPaginationAndFilters 選用分頁與三個篩選條件。
//
// 分頁是選用的：不帶 page 即回全部，既有呼叫端的行為不變。
// total 恆為套用全部篩選後的筆數而非本頁筆數，否則畫面算不出有幾頁。
func TestCredentialListPaginationAndFilters(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	r, mgr := credentialTestRouter(t, f)
	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)

	all := getCredentialList(t, r, adminToken, "")
	require.GreaterOrEqual(t, len(all.Data), 3, "前置條件：至少三筆憑證，分頁斷言才有意義")
	assert.Equal(t, len(all.Data), all.Total, "不帶分頁參數＝回全部")

	page1 := getCredentialList(t, r, adminToken, "?page=1&page_size=2")
	assert.Len(t, page1.Data, 2, "帶了分頁就切頁")
	assert.Equal(t, all.Total, page1.Total, "total 是全部筆數，不是本頁筆數")
	page2 := getCredentialList(t, r, adminToken, "?page=2&page_size=2")
	require.NotEmpty(t, page2.Data)
	assert.NotEqual(t, page1.Data[0]["id"], page2.Data[0]["id"], "第二頁是不同的資料")

	over := getCredentialList(t, r, adminToken, "?page=99&page_size=2")
	assert.Empty(t, over.Data, "翻到沒有資料的那一頁回空片")
	assert.Equal(t, all.Total, over.Total, "翻過頭不影響總數")

	code, machine := getCredentialListCode(t, r, adminToken, "?page=0")
	assert.Equal(t, http.StatusBadRequest, code, "頁碼自 1 起算")
	assert.Equal(t, "VALIDATION_INVALID_QUERY_PARAM", machine)
	assert.Equal(t, "page", credentialListErrorField(t, r, adminToken, "?page=0"),
		"錯誤要指得出是哪個參數")
	code, _ = getCredentialListCode(t, r, adminToken, "?page_size=abc")
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "page_size", credentialListErrorField(t, r, adminToken, "?page_size=abc"))

	// scope：兩個值域各自成立，且加總回全部
	shared := getCredentialList(t, r, adminToken, "?scope=shared")
	dedicated := getCredentialList(t, r, adminToken, "?scope=dedicated")
	assert.Equal(t, 1, shared.Total, "本環境一筆共用憑證")
	assert.Equal(t, all.Total, shared.Total+dedicated.Total, "兩個範圍加總即全部")

	// secret_type：本環境全為密碼型，金鑰型應為零筆（證明條件真的有作用）
	password := getCredentialList(t, r, adminToken, "?secret_type=password")
	sshKey := getCredentialList(t, r, adminToken, "?secret_type=ssh_key")
	assert.Equal(t, all.Total, password.Total)
	assert.Equal(t, 0, sshKey.Total, "篩選確實有作用，不是原樣回全部")
	code, machine = getCredentialListCode(t, r, adminToken, "?secret_type=bogus")
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "VALIDATION_CREDENTIAL_SECRET_TYPE_INVALID", machine)

	// rotation_state：六個桶互斥且窮盡（每筆憑證的狀態＝其掛載的狀態桶取最嚴）
	buckets := []string{asset.BucketOverdue, asset.BucketDueSoon, asset.BucketUnverified,
		asset.BucketNoRecord, asset.BucketNoPolicy, asset.BucketCompliant}
	sum, nonEmpty, empty := 0, 0, 0
	for _, bucket := range buckets {
		got := getCredentialList(t, r, adminToken, "?rotation_state="+bucket)
		assert.Len(t, got.Data, got.Total, bucket+"：未分頁時 data 與 total 一致")
		sum += got.Total
		if got.Total > 0 {
			nonEmpty++
		} else {
			empty++
		}
	}
	assert.Equal(t, all.Total, sum, "六個桶互斥且窮盡：加總即全部")
	assert.Greater(t, nonEmpty, 0, "至少一個桶有資料，否則篩選斷言在空集合上假綠")
	assert.Greater(t, empty, 0, "至少一個桶為空，證明條件真的有作用")

	code, _ = getCredentialListCode(t, r, adminToken, "?rotation_state=bogus")
	assert.Equal(t, http.StatusBadRequest, code, "值域外的狀態桶回錯而非靜默不篩")
	assert.Equal(t, "rotation_state",
		credentialListErrorField(t, r, adminToken, "?rotation_state=bogus"))
}

// TestRotationRequestBindsPasswordPolicy 送出的密碼策略要真的成為那一輪的策略。
//
// 請求體裡的兩個布林是底線命名，Go 欄位名是駝峰——沒有 tag 時它們靜默讀成 false
// （不含符號、不排除易混淆字元），而畫面上勾了與沒勾生出同一種密碼，沒有任何
// 錯誤看得見。長度只差大小寫而剛好對得上，故三欄一起驗：只驗長度會在兩個布林
// 失效時照樣綠。
//
// 鏈路走完整條：請求體 → 接入層的請求結構 → 服務層 → 落庫的那一列。
func TestRotationRequestBindsPasswordPolicy(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	gin.SetMode(gin.TestMode)

	// (1) 接入層的請求結構以真實綁定路徑解出
	var body startRotationBody
	r := gin.New()
	r.POST("/rotations", func(c *gin.Context) {
		require.NoError(t, c.ShouldBindJSON(&body))
		c.Status(http.StatusAccepted)
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/rotations", strings.NewReader(
		`{"mode":"group","policy":{"length":20,"include_symbol":true,"exclude_ambiguous":true}}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())

	assert.Equal(t, model.CredentialRotationModeGroup, body.Mode)
	assert.Equal(t, 20, body.Policy.Length, "長度")
	assert.True(t, body.Policy.IncludeSymbol, "include_symbol 送 true 就要是 true")
	assert.True(t, body.Policy.ExcludeAmbiguous, "exclude_ambiguous 送 true 就要是 true")

	// (2) 服務層收到的即落庫的那一列（策略三欄隨輪替持久保存）
	rot, err := f.rotations.Start(credAdminCtx(), f.sharedID,
		asset.StartRotationRequest{Policy: body.Policy})
	require.NoError(t, err)
	var row model.CredentialRotation
	require.NoError(t, f.db.First(&row, rot.ID).Error)
	assert.Equal(t, 20, row.PasswordLength)
	assert.True(t, row.PasswordIncludeSymbol, "落庫的策略不得是被靜默丟掉的預設值")
	assert.True(t, row.PasswordExcludeAmbiguous)

	// (3) 送 false 就是 false：兩個方向都要跟著請求走，否則「恆為 true」也會綠
	var offBody startRotationBody
	require.NoError(t, json.Unmarshal([]byte(
		`{"policy":{"length":16,"include_symbol":false,"exclude_ambiguous":false}}`), &offBody))
	assert.False(t, offBody.Policy.IncludeSymbol)
	assert.False(t, offBody.Policy.ExcludeAmbiguous)

	// (4) 單台脫離是另一個請求結構、共用同一個策略型別
	var detach asset.DetachCredentialRequest
	require.NoError(t, json.Unmarshal([]byte(
		`{"source":"random","policy":{"length":24,"include_symbol":true,"exclude_ambiguous":true}}`),
		&detach))
	assert.Equal(t, 24, detach.Policy.Length)
	assert.True(t, detach.Policy.IncludeSymbol, "脫離端點同樣不得靜默丟掉開關")
	assert.True(t, detach.Policy.ExcludeAmbiguous)
}

// TestCredentialDTOCarriesActiveRotationID 列表與詳情都帶進行中那一輪的識別。
//
// 進度端點以輪替識別定址。少了這一欄，逐台進度就只有「發起那一次操作」的呼叫端
// 看得到——重新整理或換一台電腦打開，同一筆憑證只剩「輪替中」與被擋住的動作。
func TestCredentialDTOCarriesActiveRotationID(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	r, mgr := credentialTestRouter(t, f)
	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)

	// 前置條件：沒有輪替時為 0。少了這一段，「有值」證明不了那是本輪的識別
	before := credentialDetailBody(t, r, adminToken, f.sharedID)
	require.EqualValues(t, 0, before["active_rotation_id"], "無輪替時為 0")
	require.Equal(t, false, before["rotation_active"], "前置條件：此刻沒有進行中的輪替")

	rot, err := f.rotations.Start(credAdminCtx(), f.sharedID, asset.StartRotationRequest{})
	require.NoError(t, err)
	require.NotZero(t, rot.ID)

	detail := credentialDetailBody(t, r, adminToken, f.sharedID)
	assert.EqualValues(t, rot.ID, detail["active_rotation_id"], "詳情帶本輪識別")
	assert.Equal(t, true, detail["rotation_active"])

	var listed map[string]any
	for _, item := range getCredentialList(t, r, adminToken, "?scope=shared").Data {
		if uint(item["id"].(float64)) == f.sharedID {
			listed = item
		}
	}
	require.NotNil(t, listed, "前置條件：列表找得到那筆共用憑證")
	assert.EqualValues(t, rot.ID, listed["active_rotation_id"], "列表也帶本輪識別")

	// 其餘憑證不得跟著沾上別人的輪替識別
	for _, item := range getCredentialList(t, r, adminToken, "?scope=dedicated").Data {
		assert.EqualValues(t, 0, item["active_rotation_id"],
			"沒有輪替的憑證為 0，不是抄鄰居的值")
	}
}

// credentialDetailBody 取詳情端點回應中的 data 物件。
func credentialDetailBody(t *testing.T, r *gin.Engine, token string, id uint) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/credentials/"+uintToStr(id), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body.Data
}

// TestCredentialListFiltersByProtocolCompatibility 依資產協定與 Windows OpenSSH 開關
// 篩出掛得上去的憑證。
//
// 族別由後端以協定與改密通道共同推導，畫面上不複製那份判準：複製的那一份會在
// 通道規則改變時開始說謊，而說謊的方向正好是「挑得到的憑證其實掛不上去」。
func TestCredentialListFiltersByProtocolCompatibility(t *testing.T) {
	f := setupCredentialAPIEnv(t)

	// 另建一筆 Windows 族的共用憑證：沒有它，「ssh 只回 ssh 族」在單一族別上假綠
	winCred, err := f.creds.Create(credAdminCtx(), &asset.CreateCredentialRequest{
		Name: "Windows 維運帳號", Username: "winops",
		ProtocolFamily: model.ProtocolFamilyWindows, Password: "win-pw",
	})
	require.NoError(t, err)

	r, mgr := credentialTestRouter(t, f)
	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)

	all := getCredentialList(t, r, adminToken, "")
	require.GreaterOrEqual(t, all.Total, 4, "前置條件：兩族各有憑證，篩選斷言才有意義")

	// ssh：只回 ssh 族（Windows 開關缺席＝關）
	ssh := getCredentialList(t, r, adminToken, "?protocol=ssh")
	require.NotEmpty(t, ssh.Data, "ssh 族非空，否則以下斷言在空集合上假綠")
	for _, item := range ssh.Data {
		assert.Equal(t, model.ProtocolFamilySSH, item["protocol_family"])
	}
	assert.Less(t, ssh.Total, all.Total, "篩選確實有作用，不是原樣回全部")

	// ssh ＋ Windows OpenSSH：同一個協定改推導出 windows 族
	win := getCredentialList(t, r, adminToken, "?protocol=ssh&windows_openssh=true")
	require.Len(t, win.Data, 1, "本環境一筆 Windows 族憑證")
	assert.EqualValues(t, winCred.ID, win.Data[0]["id"])
	assert.Equal(t, model.ProtocolFamilyWindows, win.Data[0]["protocol_family"])

	// 開關明寫 false 等同缺席
	off := getCredentialList(t, r, adminToken, "?protocol=ssh&windows_openssh=false")
	assert.Equal(t, ssh.Total, off.Total, "開關關閉＝與不帶開關同義")

	// rdp 本來就是 windows 族（不必帶開關）
	rdp := getCredentialList(t, r, adminToken, "?protocol=rdp")
	assert.Equal(t, win.Total, rdp.Total)

	// 只帶開關而沒有協定：不構成篩選條件，回全部
	lone := getCredentialList(t, r, adminToken, "?windows_openssh=true")
	assert.Equal(t, all.Total, lone.Total, "兩參數缺一不擋")

	// 資料庫協定推導出 database 族：本環境無此族憑證，回零筆而非全部
	db := getCredentialList(t, r, adminToken, "?protocol=mysql")
	assert.Equal(t, 0, db.Total, "沒有相容憑證時回空，不是靜默不篩")

	// 值域外一律回錯，且指得出是哪個參數
	code, machine := getCredentialListCode(t, r, adminToken, "?protocol=telnet")
	assert.Equal(t, http.StatusBadRequest, code, "協定值域外回錯而非靜默不篩")
	assert.Equal(t, "VALIDATION_INVALID_QUERY_PARAM", machine)
	assert.Equal(t, "protocol", credentialListErrorField(t, r, adminToken, "?protocol=telnet"))

	code, _ = getCredentialListCode(t, r, adminToken, "?protocol=ssh&windows_openssh=maybe")
	assert.Equal(t, http.StatusBadRequest, code, "開關不是布林即回錯")
	assert.Equal(t, "windows_openssh",
		credentialListErrorField(t, r, adminToken, "?protocol=ssh&windows_openssh=maybe"))

	// 開關與協定不相容：描述的是本系統建不出來的資產，回錯而非回一份族別不對的清單
	code, _ = getCredentialListCode(t, r, adminToken, "?protocol=mysql&windows_openssh=true")
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "windows_openssh",
		credentialListErrorField(t, r, adminToken, "?protocol=mysql&windows_openssh=true"))
}


// TestCredentialLibraryDeniesNonAdmin 憑證庫的讀取面對非管理者一律 403。
//
// 憑證庫回答的是「哪一組秘密掛在哪些主機上」，那本身即敏感——
// 稽核角色讀得到操作紀錄，不代表讀得到身分本體的分布。
// **存在與不存在必須同形**：兩者回應不同就等於開出一支存在性探測器，
// 讓沒有權限的人逐號問出憑證庫有幾筆、識別落在哪一段。
func TestCredentialLibraryDeniesNonAdmin(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	r, mgr := credentialTestRouter(t, f)

	// 使用者 7 由 credentialTestRouter 一併備妥（世代閘現查 users，
	// token 宣稱的 ID 不存在時整條鏈在認證就被擋下，403 的斷言會落在 401 上假綠）
	const missingID = "999999"
	for _, role := range []string{model.RoleUser, model.RoleAuditor} {
		token, err := mgr.GenerateToken(7, "non-admin", "n@example.com", role, crypto.AuthContext{})
		require.NoError(t, err)

		bodies := make(map[string]string, 3)
		for _, path := range []string{
			"/api/v1/credentials",
			"/api/v1/credentials/" + uintToStr(f.sharedID),
			"/api/v1/credentials/" + missingID,
		} {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			r.ServeHTTP(w, req)

			require.Equal(t, http.StatusForbidden, w.Code,
				"role=%s path=%s 應為 403：%s", role, path, w.Body.String())

			var envelope map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
			assert.NotEmpty(t, envelope["code"], "role=%s path=%s 須帶機器碼", role, path)
			assert.NotEmpty(t, envelope["error"], "role=%s path=%s 須帶 wire fallback 訊息", role, path)
			// 角色閘的信封是 code＋error＋params（params 是訊息代入值，
			// 此處恆為 {"role":"admin"}）。逐鍵列舉而非只數個數：多出來的那一鍵
			// 若哪天改成帶請求上下文，就是把成因送出站了
			for key := range envelope {
				assert.Contains(t, []string{"code", "error", "params"}, key,
					"role=%s path=%s 信封多出 %q 鍵：成因不得出站", role, path, key)
			}
			assert.Equal(t, map[string]any{"role": "admin"}, envelope["params"],
				"role=%s path=%s params 只帶所需角色，不帶任何請求上下文", role, path)
			assert.NotContains(t, w.Body.String(), "共用維運帳號", "被拒的回應不得洩漏憑證顯示名")
			assert.NotContains(t, w.Body.String(), "shareduser", "被拒的回應不得洩漏帳號名")
			bodies[path] = w.Body.String()
		}
		assert.Equal(t,
			bodies["/api/v1/credentials/"+uintToStr(f.sharedID)],
			bodies["/api/v1/credentials/"+missingID],
			"role=%s：存在與不存在的憑證回應必須逐字相同，否則即為存在性探測器", role)
	}
}
