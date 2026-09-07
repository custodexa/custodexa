package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
)

// 改密計劃與批次端點的**錯誤映射**守衛。
//
// 驗的是「服務層已經表達出來的可預期錯誤，接入層有沒有把它翻成契約上的
// 狀態碼與機器碼」。這幾條全部漏到 500 過：呼叫端因而看到一個內部錯誤，
// 既無從判斷是自己送錯還是伺服器壞了，也無從對使用者說出可行動的話。
//
// 每一列一個案例，斷言 HTTP 狀態與機器碼兩者——只斷言狀態碼會讓
// 「碼換成另一支同狀態的碼」靜默通過，而前端是靠碼決定文案的。

type planErrorFixture struct {
	handler        *ChangeSecretHandler
	db             *gorm.DB
	sharedAssetID  uint // 該資產的預設帳號掛在共用憑證上
	plainAssetID   uint // 專用憑證的資產（不觸發共用擋阻）
	sharedCredName string
}

func setupPlanErrorEnv(t *testing.T) *planErrorFixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// sqlite `:memory:` 配連線池時每條連線是各自獨立的空 DB
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Asset{}, &model.AssetAccount{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetHostKey{},
		&model.Credential{}, &model.CredentialSecretVersion{},
		&model.CredentialRotation{}, &model.CredentialRotationMember{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{},
		&model.ChangeSecretPlan{}, &model.ChangeSecretRecord{},
		&model.ChangeSecretCandidate{}, &model.ChangeSecretBatch{}))
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
	hostKeys := asset.NewHostKeyService(db)
	planSvc := asset.NewChangeSecretPlanService(db)
	runner := asset.NewChangeSecretRunner(db, assetSvc, candidates, hostKeys, nil)
	retry := asset.NewChangeSecretRetryRunner(db, candidates, assetSvc, hostKeys, nil)
	reports := asset.NewRotationReportBuilder(db, planSvc, func() int { return 0 })
	batches := asset.NewChangeSecretBatchService(db, reports)

	f := &planErrorFixture{
		db:             db,
		sharedCredName: "共用維運帳號",
		handler: NewChangeSecretHandler(planSvc, runner, candidates, retry,
			batches, nil),
	}

	for _, spec := range []struct {
		name, host string
		into       *uint
	}{
		{"shared-host", "10.8.0.1", &f.sharedAssetID},
		{"plain-host", "10.8.0.2", &f.plainAssetID},
	} {
		a, cerr := assetSvc.Create(&asset.CreateAssetRequest{
			Name: spec.name, Protocol: model.ProtocolSSH, Host: spec.host, Port: 22,
			Username: "ops", Password: "dedicated-pw", CreatedBy: 1,
		})
		require.NoError(t, cerr)
		*spec.into = a.ID
	}

	// 一筆共用憑證，掛在第一台上：以帳號為目標的計劃命中它即應被擋下
	shared, err := creds.Create(credAdminCtx(), &asset.CreateCredentialRequest{
		Name: f.sharedCredName, Username: "shareduser",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "shared-pw",
	})
	require.NoError(t, err)
	_, err = creds.Bind(credAdminCtx(), shared.ID,
		&asset.BindCredentialRequest{AssetID: f.sharedAssetID})
	require.NoError(t, err)
	return f
}

// planErrorRouter 以真實註冊器掛路由（AuthMiddleware → RequireRole → handler）。
func planErrorRouter(t *testing.T, f *planErrorFixture) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	// 世代閘現查 users：token 宣稱的 ID 不存在時整條鏈在認證即被擋下，
	// 本檔的狀態碼斷言會落在 401 上假綠
	seedCredentialGateUsers(t, f.db, 1)

	authService := identity.NewAuthService("change-secret-error-map-secret", time.Minute)
	r := gin.New()
	group := r.Group("/api/v1")
	f.handler.RegisterRoutes(group, authService)

	mgr := crypto.NewJWTManager("change-secret-error-map-secret", time.Minute)
	token, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)
	return r, token
}

// postChangeSecretJSON 打一次端點並回傳狀態碼與機器碼（信封只有 code 與 error 兩鍵）。
func postChangeSecretJSON(t *testing.T, r *gin.Engine, token, path, body string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope),
		"回應不是 JSON 信封：%s", w.Body.String())
	code, _ := envelope["code"].(string)
	return w.Code, code
}

// TestPlanTargetErrorsMapToContract 計劃端點的目標相關錯誤映射。
//
// 這四條在服務層都有專屬 sentinel、在 apierror 都有已註冊的碼，
// 但接入層沒有對應 case 時一律落到 default 的 500——對呼叫端而言
// 「送錯目標種類」與「資料庫掛了」變成同一個回應。
func TestPlanTargetErrorsMapToContract(t *testing.T) {
	f := setupPlanErrorEnv(t)
	r, token := planErrorRouter(t, f)

	cases := []struct {
		name     string
		body     string
		wantHTTP int
		wantCode string
	}{
		{
			name: "目標種類不在值域",
			body: fmt.Sprintf(`{"name":"p1","asset_ids":[%d],"target_kind":"bogus"}`,
				f.plainAssetID),
			wantHTTP: http.StatusBadRequest,
			wantCode: "VALIDATION_PLAN_TARGET_KIND",
		},
		{
			name: "以憑證為目標卻未指定憑證",
			body: fmt.Sprintf(`{"name":"p2","asset_ids":[%d],"target_kind":"credential"}`,
				f.plainAssetID),
			wantHTTP: http.StatusBadRequest,
			wantCode: "VALIDATION_PLAN_TARGET_CREDENTIAL_REQUIRED",
		},
		{
			// 與憑證庫端點同碼：「不存在／不可見」在憑證這個資源上是同一個出口，
			// 分流即製造存在性探測器
			name: "指定的目標憑證不存在",
			body: fmt.Sprintf(`{"name":"p3","asset_ids":[%d],"target_kind":"credential","target_credential_id":999999}`,
				f.plainAssetID),
			wantHTTP: http.StatusNotFound,
			wantCode: "NOTFOUND_CREDENTIAL",
		},
		{
			name: "以帳號為目標卻命中共用憑證的成員",
			body: fmt.Sprintf(`{"name":"p4","asset_ids":[%d]}`, f.sharedAssetID),
			wantHTTP: http.StatusBadRequest,
			wantCode: "VALIDATION_PLAN_SHARED_CREDENTIAL_TARGET",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, code := postChangeSecretJSON(t, r, token, "/api/v1/change-secret-plans", tc.body)
			assert.Equal(t, tc.wantHTTP, status, "HTTP 狀態")
			assert.Equal(t, tc.wantCode, code, "機器碼")
		})
	}
}

// TestBatchSharedCredentialNameErrorsMapToContract 批次「整批同一組」模式的
// 名稱檢核映射。名稱在送出前就擋，四條都是請求方可修正的輸入問題。
func TestBatchSharedCredentialNameErrorsMapToContract(t *testing.T) {
	f := setupPlanErrorEnv(t)
	r, token := planErrorRouter(t, f)

	// 129 個字元：長度上限是 128
	tooLong := strings.Repeat("n", 129)

	cases := []struct {
		name     string
		body     string
		wantHTTP int
		wantCode string
	}{
		{
			name:     "整批同一組未給名稱",
			body:     `{"username":"ops","all":true,"password_mode":"shared"}`,
			wantHTTP: http.StatusBadRequest,
			wantCode: "VALIDATION_BATCH_CREDENTIAL_NAME_REQUIRED",
		},
		{
			name:     "名稱超過長度上限",
			body:     fmt.Sprintf(`{"username":"ops","all":true,"password_mode":"shared","credential_name":%q}`, tooLong),
			wantHTTP: http.StatusBadRequest,
			wantCode: "VALIDATION_CREDENTIAL_NAME_TOO_LONG",
		},
		{
			name:     "名稱含控制字元",
			body:     `{"username":"ops","all":true,"password_mode":"shared","credential_name":"ops\nadmin"}`,
			wantHTTP: http.StatusBadRequest,
			wantCode: "VALIDATION_CREDENTIAL_NAME_INVALID",
		},
		{
			name: "名稱與既有共用憑證撞名",
			body: fmt.Sprintf(`{"username":"ops","all":true,"password_mode":"shared","credential_name":%q}`,
				f.sharedCredName),
			wantHTTP: http.StatusConflict,
			wantCode: "CONFLICT_CREDENTIAL_NAME",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, code := postChangeSecretJSON(t, r, token, "/api/v1/change-secret-batches", tc.body)
			assert.Equal(t, tc.wantHTTP, status, "HTTP 狀態")
			assert.Equal(t, tc.wantCode, code, "機器碼")
		})
	}
}
