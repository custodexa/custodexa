package api

import (
	"bytes"
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
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
)

// 待審清單與項目核決的路由級驗證：真的路由（含認證與審核資格守門）、真的 handler、
// 真的服務與 sqlite。假服務只能證明序列化，證明不了服務實際把哪些欄位投影進回應，
// 也證明不了直接呼叫端點時範圍、本人與狀態的檢查仍在。

const pendingRouteSecret = "pending-route-secret"

type pendingRouteEnv struct {
	t      *testing.T
	db     *gorm.DB
	r      *gin.Engine
	jwt    *crypto.JWTManager
	ids    map[string]uint
	assets map[string]uint
	now    time.Time
}

func setupPendingRouteEnv(t *testing.T) *pendingRouteEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	// 具名的共用記憶體庫：同一測試內的每條連線看到同一份資料，避免連線池開出未遷移的空庫
	dsn := fmt.Sprintf("file:pending_route_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, migrateWithAuthz(db, &model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.AccessRequest{}, &model.AccessRequestItem{}, &model.AgentVisibilityExposure{},
		&model.AccessRequestApproval{}, &model.ApproverScope{}, &model.SecurityPolicy{}, &model.SecurityPolicyHistory{}, &model.AuditLog{},
		&model.NotificationChannel{}, &model.RolePermission{},
		&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	policies := policy.NewSecurityPolicyService(db)
	accessPolicy := policy.NewAccessPolicyService(db, policies, authz.NewAssetAuthorizationService(db))
	svc := authz.NewAccessRequestService(db, policies, accessPolicy, nil, nil)
	h := NewAccessRequestHandler(svc, new(MockApproverScopeService), db)
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"), identity.NewAuthService(pendingRouteSecret, time.Minute))
	e := &pendingRouteEnv{t: t, db: db, r: r, jwt: crypto.NewJWTManager(pendingRouteSecret, time.Minute),
		ids: map[string]uint{}, assets: map[string]uint{}, now: time.Now()}

	approval := model.AccessPolicyApproval
	for _, name := range []string{"in-scope", "out-of-scope", "removed", "other"} {
		a := model.Asset{Name: "host-" + name, Protocol: model.ProtocolSSH, Host: "addr-" + name + ".internal", Port: 22, CreatedBy: 1, AccessPolicy: &approval}
		require.NoError(t, db.Create(&a).Error)
		e.assets[name] = a.ID
	}
	e.user("admin", model.RoleAdmin)
	e.user("requester", model.RoleApprover)
	e.user("requester2")
	e.user("reviewer", model.RoleApprover)
	e.user("outsider", model.RoleApprover)
	// reviewer 的範圍只涵蓋 in-scope；outsider 的範圍只涵蓋 other。
	// requester 本人也是 in-scope 的審核者，用來證明擋下本人的是本人檢查而不是範圍。
	e.scope("reviewer", "in-scope")
	e.scope("outsider", "other")
	e.scope("requester", "in-scope")
	return e
}

func (e *pendingRouteEnv) user(name string, roles ...string) {
	e.t.Helper()
	u := &model.User{Username: name, Password: "x", Email: emailPtr(name + "@t.local"), Active: true, Kind: model.KindHuman}
	require.NoError(e.t, e.db.Create(u).Error)
	for _, role := range roles {
		grantLegacyRole(e.t, e.db, u.ID, role)
	}
	e.ids[name] = u.ID
}

func (e *pendingRouteEnv) scope(approver, asset string) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.ApproverScope{ApproverID: uptr(e.ids[approver]), AssetID: uptr(e.assets[asset]), GrantedBy: e.ids["admin"]}).Error)
}

// request 直接寫一張待審申請；項目依 assets 的順序建立，回傳申請與各項的編號。
func (e *pendingRouteEnv) request(requester string, assets ...string) (uint, []uint) {
	e.t.Helper()
	req := model.AccessRequest{RequesterID: e.ids[requester], AssetID: e.assets[assets[0]], Reason: "maintenance",
		RequestedDurationMinutes: 60, Status: model.AccessRequestPending, Kind: model.AccessRequestKindNormal,
		PendingExpiresAt: e.now.Add(24 * time.Hour)}
	require.NoError(e.t, e.db.Create(&req).Error)
	items := make([]uint, 0, len(assets))
	for _, a := range assets {
		item := model.AccessRequestItem{RequestID: req.ID, RequesterID: req.RequesterID, AssetID: e.assets[a], Status: model.AccessRequestPending, PolicySnapshot: "{}"}
		require.NoError(e.t, e.db.Create(&item).Error)
		items = append(items, item.ID)
	}
	return req.ID, items
}

func (e *pendingRouteEnv) do(method, path, as string, payload any) *httptest.ResponseRecorder {
	e.t.Helper()
	var body *bytes.Buffer
	if payload != nil {
		b, err := json.Marshal(payload)
		require.NoError(e.t, err)
		body = bytes.NewBuffer(b)
	} else {
		body = bytes.NewBuffer(nil)
	}
	tok, err := e.jwt.GenerateToken(e.ids[as], as, as+"@t.local", "user", crypto.AuthContext{})
	require.NoError(e.t, err)
	req := httptest.NewRequest(method, "/api/v1"+path, body)
	req.Header.Set("Authorization", "Bearer "+tok)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

func (e *pendingRouteEnv) item(id uint) model.AccessRequestItem {
	e.t.Helper()
	var item model.AccessRequestItem
	require.NoError(e.t, e.db.First(&item, id).Error)
	return item
}

func (e *pendingRouteEnv) votes(requestID uint) int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.AccessRequestApproval{}).Where("request_id = ?", requestID).Count(&n).Error)
	return n
}

func requireErrorCode(t *testing.T, w *httptest.ResponseRecorder, status int, code apierror.ErrCode) {
	t.Helper()
	require.Equal(t, status, w.Code, w.Body.String())
	var body struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), w.Body.String())
	require.Equal(t, string(code), body.Code, w.Body.String())
}

// 待審清單的每一個項目都要帶資產名稱：審核人要知道自己在決定哪一台。
// 涵蓋第二項起、審核人對該資產沒有任何授權也不在範圍內、資產已軟刪除三種情況；
// 名稱只以字串投影，項目不夾帶資產物件或主機位址。
func TestPendingRouteEveryItemCarriesAssetName(t *testing.T) {
	e := setupPendingRouteEnv(t)
	// 三項申請：第一項在審核人範圍內，第二、三項不在；第三台已軟刪除。
	first, _ := e.request("requester2", "in-scope", "out-of-scope", "removed")
	// 第二張申請的範圍內項目排在第二位。
	second, _ := e.request("requester", "other", "in-scope")
	require.NoError(t, e.db.Delete(&model.Asset{}, e.assets["removed"]).Error)
	var grants int64
	require.NoError(t, e.db.Model(&model.AssetAuthorization{}).Where("user_id = ?", e.ids["reviewer"]).Count(&grants).Error)
	require.Zero(t, grants, "前提：審核人對這些資產沒有任何授權")

	w := e.do(http.MethodGet, "/access-requests/pending", "reviewer", nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		Data []struct {
			ID    uint             `json:"id"`
			Items []map[string]any `json:"items"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	byID := map[uint][]map[string]any{}
	for _, r := range body.Data {
		byID[r.ID] = r.Items
	}
	require.Len(t, byID, 2, "兩張申請都在審核人的待審清單內")

	want := map[uint][]struct {
		name    string
		deleted bool
	}{
		first:  {{"host-in-scope", false}, {"host-out-of-scope", false}, {"host-removed", true}},
		second: {{"host-other", false}, {"host-in-scope", false}},
	}
	// 項目的欄位集合固定：資產名稱與軟刪除標示是唯二的資產相關投影。
	wantKeys := []string{"accounts", "approvals_received", "approvals_required", "asset_deleted", "asset_id", "asset_name",
		"created_at", "decision_bounds", "id", "policy_snapshot", "request_id", "requested_accounts", "requester_id", "status", "updated_at"}
	for reqID, expected := range want {
		items := byID[reqID]
		require.Len(t, items, len(expected), "申請 %d 的項目數", reqID)
		for i, exp := range expected {
			item := items[i]
			require.Equal(t, exp.name, item["asset_name"], "申請 %d 第 %d 項的資產名稱", reqID, i+1)
			require.Equal(t, exp.deleted, item["asset_deleted"], "申請 %d 第 %d 項的軟刪除標示", reqID, i+1)
			keys := make([]string, 0, len(item))
			for k := range item {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			require.Equal(t, wantKeys, keys, "申請 %d 第 %d 項的欄位集合", reqID, i+1)
			raw, err := json.Marshal(item)
			require.NoError(t, err)
			require.False(t, strings.Contains(string(raw), ".internal"), "項目不得帶出主機位址：%s", raw)
		}
	}
}

// 範圍外的審核者直接送「移除這一項」被拒，該項與票數不變；
// 範圍內的審核者送同一請求，該項變為已拒絕、記下決定者、不寫核准票，其他項不受影響。
func TestRemoveItemRouteOutOfScopeRejected(t *testing.T) {
	e := setupPendingRouteEnv(t)
	reqID, items := e.request("requester2", "in-scope", "other")
	path := fmt.Sprintf("/access-requests/%d/approve", reqID)
	payload := map[string]any{"item_id": items[0], "remove": true}

	w := e.do(http.MethodPost, path, "outsider", payload)
	requireErrorCode(t, w, http.StatusForbidden, apierror.CodeNotEligibleApprover)
	got := e.item(items[0])
	require.Equal(t, model.AccessRequestPending, got.Status, "範圍外的移除不得改變該項")
	require.Nil(t, got.DecidedBy)
	require.Zero(t, e.votes(reqID))

	w = e.do(http.MethodPost, path, "reviewer", payload)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	got = e.item(items[0])
	require.Equal(t, model.AccessRequestRejected, got.Status)
	require.NotNil(t, got.DecidedBy)
	require.Equal(t, e.ids["reviewer"], *got.DecidedBy)
	require.Zero(t, e.votes(reqID), "移除不寫核准票")
	require.Equal(t, model.AccessRequestPending, e.item(items[1]).Status, "其他項不受影響")
}

// 申請人本人即使在該資產的審核範圍內，也不能移除或核准自己申請的項目。
func TestRemoveItemRouteSelfRejected(t *testing.T) {
	e := setupPendingRouteEnv(t)
	reqID, items := e.request("requester", "in-scope", "out-of-scope")
	path := fmt.Sprintf("/access-requests/%d/approve", reqID)

	w := e.do(http.MethodPost, path, "requester", map[string]any{"item_id": items[0], "remove": true})
	requireErrorCode(t, w, http.StatusForbidden, apierror.CodeAccessRequestSelfApproval)
	// 以 items 明列全部待決項核准自己的申請，同樣被拒。
	w = e.do(http.MethodPost, path, "requester", map[string]any{"items": []map[string]any{{"item_id": items[0]}, {"item_id": items[1]}}})
	requireErrorCode(t, w, http.StatusForbidden, apierror.CodeAccessRequestSelfApproval)

	for _, id := range items {
		got := e.item(id)
		require.Equal(t, model.AccessRequestPending, got.Status)
		require.Nil(t, got.DecidedBy)
	}
	require.Zero(t, e.votes(reqID))
}

// 已是終態的項不能再移除：單項請求回 409；以 items 明列時只要有一項已非待審，
// 整張回 409，同一請求中排在前面、已在交易內移除的待審項也一併不生效。
func TestRemoveItemRouteTerminalItemConflict(t *testing.T) {
	e := setupPendingRouteEnv(t)
	reqID, items := e.request("requester2", "in-scope", "in-scope")
	// 第二項先以既有路徑移除，成為終態。
	path := fmt.Sprintf("/access-requests/%d/approve", reqID)
	w := e.do(http.MethodPost, path, "reviewer", map[string]any{"item_id": items[1], "remove": true})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	terminal := e.item(items[1])
	require.Equal(t, model.AccessRequestRejected, terminal.Status)

	w = e.do(http.MethodPost, path, "reviewer", map[string]any{"item_id": items[1], "remove": true})
	requireErrorCode(t, w, http.StatusConflict, apierror.CodeAccessRequestStateChanged)

	w = e.do(http.MethodPost, path, "reviewer", map[string]any{"items": []map[string]any{
		{"item_id": items[0], "remove": true}, {"item_id": items[1], "remove": true}}})
	requireErrorCode(t, w, http.StatusConflict, apierror.CodeAccessRequestStateChanged)

	got := e.item(items[0])
	require.Equal(t, model.AccessRequestPending, got.Status, "整張回 409 時其他項不變")
	require.Nil(t, got.DecidedBy)
	after := e.item(items[1])
	require.Equal(t, terminal.Status, after.Status)
	require.Equal(t, terminal.DecidedAt.UnixNano(), after.DecidedAt.UnixNano(), "終態項的決定時間不被覆寫")
	require.Zero(t, e.votes(reqID))
}
