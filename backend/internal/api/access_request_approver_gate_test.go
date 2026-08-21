package api

import (
	"bytes"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// D-12 審核者資格收斂（modular-architecture W7b）的**路由級**驗證：經完整
// `RegisterRoutes`（真 AuthMiddleware＋真 JWT＋真 sqlite＋真守衛），確認
//   - 8.6 僅具 admin 者對審核端點一律 403，有效審核者放行
//   - 8.7 兼具 admin 的有效審核者其核准以「非 admin」身分進 service
//     （＝計一票、走範圍與 quorum；admin 單票繞過門檻的路徑自 API 層消失）
//   - 8.8 撤銷端點分離後，admin 無 approver 角色仍可撤銷
//   - 8.9 破窗補審對「僅具 admin」者 403
//
// 為何測在路由層而非只測 middleware：死鎖與否、以及 handler 是否仍把 admin 身分
// 遞給 service，取決於「守衛＋handler＋service 呼叫參數」三者的組合，單測任一層
// 都可能漏掉組合處的退化。

const approverGateSecret = "approver-gate-secret"

type approverGateEnv struct {
	r        *gin.Engine
	mgr      *crypto.JWTManager
	db       *gorm.DB
	reqSvc   *MockAccessRequestService
	scopeSvc *MockApproverScopeService
}

// setupApproverGateEnv 造出四類身分：
// 1 admin（僅 admin 角色）／2 approver（approver 角色＋範圍蓋 asset 1）／
// 3 adminApprover（admin＋approver，範圍蓋 asset 1）／4 plain（純 user）
func setupApproverGateEnv(t *testing.T) approverGateEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(
		&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{},
		&model.ApproverScope{}, &model.AuditLog{},
	))

	// AuthMiddleware 的憑證世代閘走 database.DB（fail-close：未注入即一律拒）
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	roleIDs := map[string]uint{}
	for _, name := range []string{model.RoleAdmin, model.RoleApprover, model.RoleUser} {
		r := model.Role{Name: name}
		assert.NoError(t, db.Create(&r).Error)
		roleIDs[name] = r.ID
	}
	mk := func(id uint, name string, roles ...string) {
		u := &model.User{Username: name, Password: "x", Email: emailPtr(name + "@t.local"), Active: true}
		u.ID = id
		assert.NoError(t, db.Create(u).Error)
		for _, rn := range roles {
			assert.NoError(t, db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", id, roleIDs[rn]).Error)
		}
	}
	mk(1, "gate-admin", model.RoleAdmin)
	mk(2, "gate-approver", model.RoleApprover)
	mk(3, "gate-admin-approver", model.RoleAdmin, model.RoleApprover)
	mk(4, "gate-plain", model.RoleUser)

	assert.NoError(t, db.Create(&model.Asset{Name: "srv", Protocol: model.ProtocolSSH, Host: "h", Port: 22}).Error)
	aid := uint(1)
	for _, approverID := range []uint{2, 3} {
		id := approverID
		assert.NoError(t, db.Create(&model.ApproverScope{ApproverID: &id, AssetID: &aid, GrantedBy: 1}).Error)
	}

	reqSvc := new(MockAccessRequestService)
	scopeSvc := new(MockApproverScopeService)
	h := NewAccessRequestHandler(reqSvc, scopeSvc, db)
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"), identity.NewAuthService(approverGateSecret, time.Minute))

	return approverGateEnv{r: r, mgr: crypto.NewJWTManager(approverGateSecret, time.Minute),
		db: db, reqSvc: reqSvc, scopeSvc: scopeSvc}
}

func (e approverGateEnv) token(t *testing.T, id uint, name, role string) string {
	t.Helper()
	tok, err := e.mgr.GenerateToken(id, name, name+"@t.local", role, crypto.AuthContext{})
	assert.NoError(t, err)
	return tok
}

func (e approverGateEnv) call(t *testing.T, method, path, token string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

// TestApproverRouteGate_AdminOnlyDenied （8.6／8.9）D-12 行為變更：僅具 admin
// 角色者對審核類端點一律 403，且**不得抵達 service**（抵達即代表資格判定被繞過）
func TestApproverRouteGate_AdminOnlyDenied(t *testing.T) {
	e := setupApproverGateEnv(t)
	adminToken := e.token(t, 1, "gate-admin", model.RoleAdmin)

	gets := []string{
		"/api/v1/access-requests/pending",
		"/api/v1/access-requests/pending/count",
		"/api/v1/access-requests/history",
		"/api/v1/access-requests/tickets",
		"/api/v1/access-requests/reviews/pending",
	}
	for _, p := range gets {
		w := e.call(t, http.MethodGet, p, adminToken, nil)
		assert.Equal(t, http.StatusForbidden, w.Code, "僅具 admin 者對 %s 應 403（D-12）", p)
	}
	posts := []string{
		"/api/v1/access-requests/1/approve",
		"/api/v1/access-requests/1/reject",
		"/api/v1/access-requests/1/review", // 8.9 破窗補審
	}
	for _, p := range posts {
		w := e.call(t, http.MethodPost, p, adminToken, map[string]string{"note": "x", "disposition": "confirmed"})
		assert.Equal(t, http.StatusForbidden, w.Code, "僅具 admin 者對 %s 應 403（D-12）", p)
	}

	// 守衛必須在抵達 service 之前擋下。
	// 刻意不用 `AssertNotCalled(t, m)`——testify 的零引數形式是**恆真斷言**：
	// 它以 `Arguments(expected).Diff(call.Arguments)` 比對，空 expected 對任何帶參數的
	// 呼叫都會產生 differences 而判為不匹配，故永遠不會失敗（2026-08-10 W7b 獨立驗收發現）。
	// 直接查呼叫記錄則與參數個數無關，改動 service 簽名也不會讓它靜默失效。
	for _, m := range []string{"ListPending", "PendingCount", "ListHistory", "ActiveTickets",
		"ListPendingReview", "Approve", "Reject", "Review"} {
		for _, c := range e.reqSvc.Calls {
			assert.NotEqual(t, m, c.Method,
				"僅具 admin 者應被守衛擋下，但 service.%s 仍被呼叫（D-12）", m)
		}
	}
}

// TestApproverRouteGate_EffectiveApproverAllowed （8.6）兼具資格者正常放行，
// 且 handler 以「非 admin」身分呼叫 service（範圍過濾一律依審核範圍）
func TestApproverRouteGate_EffectiveApproverAllowed(t *testing.T) {
	e := setupApproverGateEnv(t)
	approverToken := e.token(t, 2, "gate-approver", model.RoleUser)

	e.reqSvc.On("ListPending", uint(2), false, mock.Anything).Return([]*model.AccessRequest{}, nil)
	w := e.call(t, http.MethodGet, "/api/v1/access-requests/pending", approverToken, nil)
	assert.Equal(t, http.StatusOK, w.Code, "有效審核者應放行")
	e.reqSvc.AssertCalled(t, "ListPending", uint(2), false, mock.Anything)

	e.reqSvc.On("Approve", uint(2), false, uint(7), mock.Anything).
		Return(&model.AccessRequest{ID: 7, Status: model.AccessRequestApproved}, nil)
	w = e.call(t, http.MethodPost, "/api/v1/access-requests/7/approve", approverToken, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	e.reqSvc.AssertCalled(t, "Approve", uint(2), false, uint(7), mock.Anything)
}

// TestApproverRouteGate_AdminApproverCountsAsOneVote （8.7）兼具 admin 身分的
// 有效審核者：放行，但以 `isAdmin=false` 進 service——故其核准與一般審核者同樣
// 逐票計入、受 quorum 門檻約束，**不存在單票繞過門檻的 admin 短路**
// （service 端「一票不轉態」的計票語義見 authz `TestAccessRequest_Quorum`）
func TestApproverRouteGate_AdminApproverCountsAsOneVote(t *testing.T) {
	e := setupApproverGateEnv(t)
	token := e.token(t, 3, "gate-admin-approver", model.RoleAdmin)

	e.reqSvc.On("Approve", uint(3), false, uint(7), mock.Anything).
		Return(&model.AccessRequest{ID: 7, Status: model.AccessRequestPending,
			ApprovalsReceived: 1, ApprovalsRequired: 2}, nil)
	w := e.call(t, http.MethodPost, "/api/v1/access-requests/7/approve", token, nil)
	assert.Equal(t, http.StatusOK, w.Code, "admin＋approver 應放行")
	e.reqSvc.AssertCalled(t, "Approve", uint(3), false, uint(7), mock.Anything)
	e.reqSvc.AssertNotCalled(t, "Approve", uint(3), true, uint(7), mock.Anything)
}

// TestRevokeRouteGate_AdminStillAllowed （8.8）撤銷端點分離：admin 無 approver
// 角色仍可撤銷，且 admin 身分照舊遞給 service（`eligibleToRevoke` 的 admin 分支
// 是既有 spec 契約；一併收斂會造成 admin 無法撤銷已核票證的安全倒退）
func TestRevokeRouteGate_AdminStillAllowed(t *testing.T) {
	e := setupApproverGateEnv(t)
	adminToken := e.token(t, 1, "gate-admin", model.RoleAdmin)

	e.reqSvc.On("Revoke", uint(1), true, "gate-admin", uint(7), "遏制").
		Return(&model.AccessRequest{ID: 7}, nil)
	w := e.call(t, http.MethodPost, "/api/v1/access-requests/7/revoke", adminToken,
		map[string]string{"note": "遏制"})
	assert.Equal(t, http.StatusOK, w.Code, "僅具 admin 者仍須能撤銷")
	e.reqSvc.AssertCalled(t, "Revoke", uint(1), true, "gate-admin", uint(7), "遏制")

	// 有效審核者：放行且以非 admin 身分（細緻資格由 service 裁決）
	approverToken := e.token(t, 2, "gate-approver", model.RoleUser)
	e.reqSvc.On("Revoke", uint(2), false, "gate-approver", uint(8), "遏制").
		Return(&model.AccessRequest{ID: 8}, nil)
	w = e.call(t, http.MethodPost, "/api/v1/access-requests/8/revoke", approverToken,
		map[string]string{"note": "遏制"})
	assert.Equal(t, http.StatusOK, w.Code)

	// 既無 admin 亦無審核資格者：擋在守衛
	plainToken := e.token(t, 4, "gate-plain", model.RoleUser)
	w = e.call(t, http.MethodPost, "/api/v1/access-requests/9/revoke", plainToken,
		map[string]string{"note": "遏制"})
	assert.Equal(t, http.StatusForbidden, w.Code, "無資格者撤銷應 403")
}

// TestApproverRouteGate_EscapeHatchNotGuarded （8.5 的結構前提）審核範圍管理端點
// **不得**掛上審核類守衛——它是 admin 的脫困路徑，若被 `RequireApproverRole` 罩住，
// 零有效審核者時系統將永久死鎖（無人能核准，也無人能指派審核者）。
// 端到端實跑證據見 round-log W7b 的脫困路徑一節
func TestApproverRouteGate_EscapeHatchNotGuarded(t *testing.T) {
	e := setupApproverGateEnv(t)
	adminToken := e.token(t, 1, "gate-admin", model.RoleAdmin)

	e.scopeSvc.On("List").Return([]*model.ApproverScope{}, nil)

	// 僅具 admin 者（＝非有效審核者）仍可讀寫審核範圍
	w := e.call(t, http.MethodGet, "/api/v1/approver-scopes", adminToken, nil)
	assert.Equal(t, http.StatusOK, w.Code,
		"審核範圍管理不得被審核資格守衛罩住（admin 脫困路徑）")

	// 非 admin 的有效審核者不得管理範圍（脫困路徑限 admin，未因收斂而放寬）
	approverToken := e.token(t, 2, "gate-approver", model.RoleUser)
	w = e.call(t, http.MethodGet, "/api/v1/approver-scopes", approverToken, nil)
	assert.Equal(t, http.StatusForbidden, w.Code, "範圍管理仍為 admin only")
}
