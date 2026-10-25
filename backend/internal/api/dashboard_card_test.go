package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
)

// cardCalls 所有來源 stub 共用的呼叫計數：被拒的請求在拒絕前不得讀任何資料來源。
type cardCalls struct{ n atomic.Int32 }

func (c *cardCalls) hit() { c.n.Add(1) }

// cardStub 十二張卡的固定來源：值各不相同，才分得出一次請求是否帶出了別張卡的資料。
type cardStub struct{ calls *cardCalls }

func (s cardStub) CountAssets(_ context.Context, _ *authz.Principal, _ uint) (int64, error) {
	s.calls.hit()
	return 42, nil
}

func (s cardStub) List(f *session.SessionFilter) (*session.SessionListResponse, error) {
	s.calls.hit()
	switch {
	case f.Status == model.SessionStatusActive:
		return &session.SessionListResponse{Total: 7}, nil
	case f.StartTime != nil:
		return &session.SessionListResponse{Total: 3}, nil
	}
	return &session.SessionListResponse{Total: 11}, nil
}

func (s cardStub) GetActiveSessions() ([]model.Session, error) {
	s.calls.hit()
	return []model.Session{{RecordingError: "disk full"}, {}, {RecordingError: "io"}, {}, {}}, nil
}

func (s cardStub) ListMyConnections(userID uint, _, _ int) (*session.MyConnectionListResponse, error) {
	s.calls.hit()
	return &session.MyConnectionListResponse{Total: int64(100 + userID)}, nil
}

// 告警與其他共用方法名的介面分開，避免與 session 的 List 衝突。
type cardAlertStub struct{ calls *cardCalls }

func (s cardAlertStub) List(f *audit.CommandAlertFilter) (*audit.CommandAlertListResponse, error) {
	s.calls.hit()
	if f.Unreviewed {
		return &audit.CommandAlertListResponse{Total: 5}, nil
	}
	return &audit.CommandAlertListResponse{Total: 2}, nil
}

type cardRecordingStub struct{ calls *cardCalls }

func (s cardRecordingStub) GetRecordingStats() (*session.RecordingStats, error) {
	s.calls.hit()
	return &session.RecordingStats{TotalSize: 1048576}, nil
}

type cardReviewStub struct{ calls *cardCalls }

func (s cardReviewStub) LastReviewDaysAgo() (int, error) {
	s.calls.hit()
	return 200, nil
}

// cardRequestStub 本人申請依呼叫者回不同結果，驗證只讀本人。
type cardRequestStub struct{ calls *cardCalls }

func (s cardRequestStub) CountMinePending(requesterID uint) (int64, error) {
	s.calls.hit()
	return int64(requesterID), nil
}

func (s cardRequestStub) PendingCount(_ uint, isAdmin bool, _ time.Time) (int64, error) {
	s.calls.hit()
	if isAdmin {
		return 999, nil
	}
	return 4, nil
}

func (s cardRequestStub) PendingReviewCount(_ uint, isAdmin bool) (int64, error) {
	s.calls.hit()
	if isAdmin {
		return 999, nil
	}
	return 2, nil
}

type cardEnv struct {
	r     *gin.Engine
	db    *gorm.DB
	mgr   *crypto.JWTManager
	calls *cardCalls
	// audit 最近一次請求結束時，審計中介層會讀到的分類覆寫（resource／resource_id）
	auditResource   model.AuditResource
	auditResourceID uint
	// denial 最近一次請求經能力拒絕寫出函式存下的依據（未經它拒絕時 hasDenial 為 false）
	denial    middleware.CapabilityDenial
	hasDenial bool
}

func newCardEnv(t *testing.T) *cardEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, migrateWithAuthz(db,
		&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}, &model.UserRole{},
		&model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}, &model.AuthzState{},
		&model.RolePermission{}))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	calls := &cardCalls{}
	h, err := NewDashboardCardHandler(DashboardCardDeps{
		Assets: cardStub{calls}, Sessions: cardStub{calls}, MyConnections: cardStub{calls}, Alerts: cardAlertStub{calls},
		Recordings: cardRecordingStub{calls}, Reviews: cardReviewStub{calls}, Requests: cardRequestStub{calls}, DB: db,
	})
	require.NoError(t, err)
	secret := "dashboard-card-secret"
	env := &cardEnv{db: db, mgr: crypto.NewJWTManager(secret, time.Minute), calls: calls}
	r := gin.New()
	// 模擬審計中介層的讀取點：請求結束後讀 handler 設定的分類覆寫
	r.Use(func(c *gin.Context) {
		c.Next()
		env.auditResource, env.auditResourceID = "", 0
		if v, ok := c.Get("audit_resource"); ok {
			env.auditResource, _ = v.(model.AuditResource)
		}
		if v, ok := c.Get("audit_resource_id"); ok {
			env.auditResourceID, _ = v.(uint)
		}
		env.denial, env.hasDenial = middleware.CapabilityDenialFrom(c)
	})
	h.RegisterRoutes(r.Group("/api/v1"), identity.NewAuthService(secret, time.Minute))
	env.r = r
	return env
}

// user 建帳號；perms 非空時給一個自訂角色（名稱與任何內建角色無關），只含這些能力。
func (e *cardEnv) user(t *testing.T, name string, legacyRole string, perms ...authz.Permission) (*model.User, string) {
	t.Helper()
	u := &model.User{Username: name, Password: "x", Active: true, Email: emailPtr(name + "@x")}
	require.NoError(t, e.db.Create(u).Error)
	if legacyRole != "" {
		grantLegacyRole(t, e.db, u.ID, legacyRole)
	}
	if len(perms) > 0 {
		grantCustomCredentialRole(t, e.db, u.ID, "custom-"+name, perms...)
	}
	tok, err := e.mgr.GenerateToken(u.ID, u.Username, u.EmailString(), "user", crypto.AuthContext{})
	require.NoError(t, err)
	return u, tok
}

func (e *cardEnv) get(key, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/cards/"+key, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

// getNoRead 送出一個應被拒絕的請求，並斷言拒絕前沒有讀任何資料來源（呼叫次數為 0）。
func (e *cardEnv) getNoRead(t *testing.T, key, token string) *httptest.ResponseRecorder {
	t.Helper()
	e.calls.n.Store(0)
	w := e.get(key, token)
	assert.Zero(t, e.calls.n.Load(), "%s 被拒絕前不得讀資料來源", key)
	return w
}

// assertCapabilityDenied 能力拒絕的單一形狀：本文只有 code、error 兩鍵、碼為權限不足、不含所需鍵；
// 依據只在請求脈絡。
func (e *cardEnv) assertCapabilityDenied(t *testing.T, w *httptest.ResponseRecorder, key string,
	basis authz.DenialBasis, required string) {
	t.Helper()
	assert.Equal(t, []string{"code", "error"}, cardBodyKeys(t, w), key)
	assert.Contains(t, w.Body.String(), `"code":"AUTH_PERMISSION_DENIED"`, key)
	assert.NotContains(t, w.Body.String(), required, key)
	require.True(t, e.hasDenial, "%s：拒絕依據未存入脈絡", key)
	assert.Equal(t, basis, e.denial.Basis, key)
	assert.Equal(t, []string{required}, e.denial.Required, key)
}

func cardBodyKeys(t *testing.T, w *httptest.ResponseRecorder) []string {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func cardValue(t *testing.T, w *httptest.ResponseRecorder) (string, int64, string) {
	t.Helper()
	var r struct {
		Key   string `json:"key"`
		Value int64  `json:"value"`
		Unit  string `json:"unit"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &r))
	return r.Key, r.Value, r.Unit
}

// TestDashboardCardAuthorization 逐卡授權：每張卡各一個有權取得值、一個缺少必要判準被拒的案例。
func TestDashboardCardAuthorization(t *testing.T) {
	// 十二張卡：必要能力（空＝本人／審核資格）、預期值、單位。
	type cardCase struct {
		key   string
		perm  authz.Permission
		value int64
		unit  string
	}
	permCards := []cardCase{
		{"assets", authz.PermAssetView, 42, "count"},
		{"active-sessions", authz.PermSessionView, 7, "count"},
		{"today-sessions", authz.PermSessionView, 3, "count"},
		{"total-sessions", authz.PermSessionView, 11, "count"},
		{"today-alerts", authz.PermAuditView, 2, "count"},
		{"recording-storage", authz.PermAuditView, 1048576, "bytes"},
		{"unreviewed-alerts", authz.PermAuditView, 5, "count"},
		{"recording-failures", authz.PermSessionView, 2, "count"},
		{"last-access-review", authz.PermAuditView, 200, "days"},
	}

	t.Run("能力卡", func(t *testing.T) {
		env := newCardEnv(t)
		// 一個無關能力的帳號：對每張能力卡都被拒
		_, other := env.user(t, "cap-other", "", authz.PermAlertManage)
		for _, c := range permCards {
			// 自訂角色只含該卡的必要能力：取得值
			_, ok := env.user(t, "cap-ok-"+c.key, "", c.perm)
			w := env.get(c.key, ok)
			require.Equal(t, http.StatusOK, w.Code, "%s 有權: %s", c.key, w.Body.String())
			k, v, u := cardValue(t, w)
			assert.Equal(t, c.key, k)
			assert.Equal(t, c.value, v, c.key)
			assert.Equal(t, c.unit, u, c.key)

			// 缺少必要能力：單一形狀拒絕、回應不帶所需能力，依據（脈絡）指向該卡的必要能力，不帶任何卡值
			w = env.getNoRead(t, c.key, other)
			require.Equal(t, http.StatusForbidden, w.Code, "%s 缺能力", c.key)
			env.assertCapabilityDenied(t, w, c.key, authz.DenialAllOf, string(c.perm))
			assert.NotContains(t, w.Body.String(), `"value"`, c.key)
		}
	})

	t.Run("recording-failures以session:view裁決", func(t *testing.T) {
		env := newCardEnv(t)
		_, auditOnly := env.user(t, "rf-audit", "", authz.PermAuditView)
		w := env.getNoRead(t, "recording-failures", auditOnly)
		require.Equal(t, http.StatusForbidden, w.Code)
		env.assertCapabilityDenied(t, w, "recording-failures", authz.DenialAllOf, string(authz.PermSessionView))

		_, sessOnly := env.user(t, "rf-session", "", authz.PermSessionView)
		w = env.get("recording-failures", sessOnly)
		require.Equal(t, http.StatusOK, w.Code)
		_, v, _ := cardValue(t, w)
		assert.EqualValues(t, 2, v, "只計錄影失敗的進行中連線")
	})

	t.Run("self卡", func(t *testing.T) {
		env := newCardEnv(t)
		a, tokA := env.user(t, "self-a", "")
		b, tokB := env.user(t, "self-b", "")
		for _, key := range []string{"my-connections", "my-pending-requests"} {
			// 未登入拒絕
			assert.Equal(t, http.StatusUnauthorized, env.getNoRead(t, key, "").Code, key)
		}
		// 不需任何管理能力；只讀本人（來源以呼叫者為參數）
		w := env.get("my-connections", tokA)
		require.Equal(t, http.StatusOK, w.Code)
		_, v, _ := cardValue(t, w)
		assert.EqualValues(t, 100+a.ID, v)
		w = env.get("my-connections", tokB)
		_, v, _ = cardValue(t, w)
		assert.EqualValues(t, 100+b.ID, v)

		w = env.get("my-pending-requests", tokA)
		require.Equal(t, http.StatusOK, w.Code)
		_, v, _ = cardValue(t, w)
		assert.EqualValues(t, a.ID, v, "只計本人 pending")
		// 帶他人 ID 的查詢參數無效
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/dashboard/cards/my-pending-requests?user_id=%d&owner=%d", b.ID, b.ID), nil)
		req.Header.Set("Authorization", "Bearer "+tokA)
		rec := httptest.NewRecorder()
		env.r.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		_, v, _ = cardValue(t, rec)
		assert.EqualValues(t, a.ID, v, "查詢字串不能改變範圍")
	})

	t.Run("待審卡看實際審核資格", func(t *testing.T) {
		env := newCardEnv(t)
		assert.Equal(t, http.StatusUnauthorized, env.getNoRead(t, "pending-approvals", "").Code)

		_, approver := env.user(t, "pa-approver", model.RoleApprover)
		w := env.get("pending-approvals", approver)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		_, v, _ := cardValue(t, w)
		assert.EqualValues(t, 6, v, "件數＝待審 4＋待補審 2")
		assert.Contains(t, w.Body.String(), `"count":4`)
		assert.Contains(t, w.Body.String(), `"review_count":2`)

		// 審核方群組成員同樣有資格（不靠角色名稱）
		g := &model.UserGroup{Name: "approver-grp"}
		require.NoError(t, env.db.Create(g).Error)
		gm, gmTok := env.user(t, "pa-group-member", "")
		require.NoError(t, env.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: gm.ID}).Error)
		subject := gm.ID
		require.NoError(t, env.db.Create(&model.ApproverScope{ApproverGroupID: &g.ID, SubjectUserID: &subject}).Error)
		assert.Equal(t, http.StatusOK, env.get("pending-approvals", gmTok).Code)

		// admin 不兜底、無資格者與持有其他能力者都拒絕
		_, admin := env.user(t, "pa-admin", model.RoleAdmin)
		w = env.getNoRead(t, "pending-approvals", admin)
		assert.Equal(t, http.StatusForbidden, w.Code)
		env.assertCapabilityDenied(t, w, "pending-approvals", authz.DenialReserved, authz.ReservedApproverEligibility)
		assert.NotContains(t, w.Body.String(), `"value"`)
		_, plain := env.user(t, "pa-plain", model.RoleUser)
		assert.Equal(t, http.StatusForbidden, env.getNoRead(t, "pending-approvals", plain).Code)
		_, audit := env.user(t, "pa-audit", "", authz.PermAuditView, authz.PermSessionView, authz.PermAssetView)
		assert.Equal(t, http.StatusForbidden, env.getNoRead(t, "pending-approvals", audit).Code)
	})

	t.Run("有效自訂能力不依角色名稱", func(t *testing.T) {
		env := newCardEnv(t)
		// 內建角色名稱但不含該能力的帳號：不因名稱得到卡片
		_, plainUser := env.user(t, "cn-user", model.RoleUser)
		assert.Equal(t, http.StatusForbidden, env.getNoRead(t, "recording-storage", plainUser).Code)
		// 角色名稱隨意、只含 audit:view：取得稽核卡
		role := &model.Role{Name: "totally-unrelated-name", DefinitionVersion: 1}
		require.NoError(t, env.db.Create(role).Error)
		require.NoError(t, env.db.Create(&model.RolePermission{RoleID: role.ID, PermissionKey: string(authz.PermAuditView)}).Error)
		u := &model.User{Username: "cn-custom", Password: "x", Active: true, Email: emailPtr("cn-custom@x")}
		require.NoError(t, env.db.Create(u).Error)
		require.NoError(t, env.db.Create(&model.UserRole{UserID: u.ID, RoleID: role.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		tok, err := env.mgr.GenerateToken(u.ID, u.Username, u.EmailString(), "user", crypto.AuthContext{})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, env.get("recording-storage", tok).Code)
		assert.Equal(t, http.StatusForbidden, env.getNoRead(t, "active-sessions", tok).Code, "audit:view 不帶出連線卡")
	})

	t.Run("未知key拒絕", func(t *testing.T) {
		env := newCardEnv(t)
		_, all := env.user(t, "uk-all", "", authz.PermAssetView, authz.PermSessionView, authz.PermAuditView)
		_, admin := env.user(t, "uk-admin", model.RoleAdmin)
		for _, key := range []string{"nope", "ASSETS", "assets%20", "dashboard", "daily-review", "0", "pending_approvals"} {
			for name, tok := range map[string]string{"全能力": all, "admin": admin} {
				w := env.getNoRead(t, key, tok)
				assert.Equal(t, http.StatusBadRequest, w.Code, "%s/%s", name, key)
				assert.Contains(t, w.Body.String(), "VALIDATION_BAD_PARAMS", key)
				assert.NotContains(t, w.Body.String(), `"value"`, key)
			}
		}
		// 未登入先於 key 驗證被擋
		assert.Equal(t, http.StatusUnauthorized, env.getNoRead(t, "nope", "").Code)
	})

	t.Run("單一能力不帶出其他卡", func(t *testing.T) {
		env := newCardEnv(t)
		bundles := map[authz.Permission][]string{
			authz.PermAssetView:   {"assets"},
			authz.PermSessionView: {"active-sessions", "today-sessions", "total-sessions", "recording-failures"},
			authz.PermAuditView:   {"today-alerts", "recording-storage", "unreviewed-alerts", "last-access-review"},
		}
		all := map[string]bool{}
		for _, c := range permCards {
			all[c.key] = true
		}
		for perm, allowed := range bundles {
			_, tok := env.user(t, "iso-"+string(perm), "", perm)
			allowedSet := map[string]bool{}
			for _, k := range allowed {
				allowedSet[k] = true
			}
			for k := range all {
				var w *httptest.ResponseRecorder
				if allowedSet[k] {
					w = env.get(k, tok)
				} else {
					w = env.getNoRead(t, k, tok)
				}
				if allowedSet[k] {
					assert.Equal(t, http.StatusOK, w.Code, "%s 應可取 %s", perm, k)
					want := []string{"filters", "key", "unit", "value"}
					if k == "last-access-review" {
						want = []string{"filters", "key", "overdue", "review_period_days", "unit", "value"}
					}
					assert.Equal(t, want, cardBodyKeys(t, w), "回應只含這張卡的欄位")
				} else {
					assert.Equal(t, http.StatusForbidden, w.Code, "%s 不可取 %s", perm, k)
				}
			}
			// 本人卡不因持有管理能力而改變，也不因缺少而被拒
			assert.Equal(t, http.StatusOK, env.get("my-connections", tok).Code)
			// 待審卡不由任何管理能力代授
			assert.Equal(t, http.StatusForbidden, env.getNoRead(t, "pending-approvals", tok).Code)
		}
	})

	t.Run("agent主體拒絕", func(t *testing.T) {
		env := newCardEnv(t)
		agentTok := identity.AgentTokenPrefix + "0123456789abcdef"
		for _, key := range []string{"assets", "my-connections", "pending-approvals", "nope"} {
			w := env.getNoRead(t, key, agentTok)
			assert.Equal(t, http.StatusForbidden, w.Code, key)
			assert.NotContains(t, w.Body.String(), `"value"`, key)
		}
		allowed, registered := middleware.AgentRouteDecision(http.MethodGet, "/api/v1/dashboard/cards/:key")
		assert.False(t, allowed)
		assert.True(t, registered)
	})

	t.Run("審計分類逐卡覆寫", func(t *testing.T) {
		env := newCardEnv(t)
		u, tok := env.user(t, "audit-all", "", authz.PermAssetView, authz.PermSessionView, authz.PermAuditView)
		wantResource := map[string]model.AuditResource{
			"assets": model.ResourceAsset, "my-connections": model.ResourceUser, "my-pending-requests": model.ResourceUser,
			"active-sessions": model.ResourceSession, "today-sessions": model.ResourceSession, "total-sessions": model.ResourceSession,
			"recording-failures": model.ResourceSession, "today-alerts": model.ResourceCommandAlert,
			"unreviewed-alerts": model.ResourceCommandAlert, "recording-storage": model.ResourceRecording,
			"last-access-review": model.ResourceAccessReview,
		}
		for key, want := range wantResource {
			require.Equal(t, http.StatusOK, env.get(key, tok).Code, key)
			assert.Equal(t, want, env.auditResource, key)
			if want == model.ResourceUser {
				assert.Equal(t, u.ID, env.auditResourceID, "%s 本人卡的 resource_id 是本人", key)
			} else {
				assert.Zero(t, env.auditResourceID, "%s 非本人卡不帶 resource_id", key)
			}
		}
		// 被拒的請求同樣記在它想讀的資料類別上；未知 key 不覆寫（落路由層預設）
		_, none := env.user(t, "audit-none", "", authz.PermAlertManage)
		require.Equal(t, http.StatusForbidden, env.get("today-alerts", none).Code)
		assert.Equal(t, model.ResourceCommandAlert, env.auditResource)
		require.Equal(t, http.StatusForbidden, env.get("pending-approvals", none).Code)
		assert.Equal(t, model.ResourceAccessRequest, env.auditResource)
		require.Equal(t, http.StatusBadRequest, env.get("nope", tok).Code)
		assert.Empty(t, env.auditResource)
		// 他人看不到的規則：本人卡的 resource_id 永遠是呼叫者，不隨查詢字串改變
		other, otherTok := env.user(t, "audit-other", "")
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/dashboard/cards/my-connections?user_id=%d", u.ID), nil)
		req.Header.Set("Authorization", "Bearer "+otherTok)
		env.r.ServeHTTP(httptest.NewRecorder(), req)
		assert.Equal(t, other.ID, env.auditResourceID)
	})

	t.Run("登錄完整", func(t *testing.T) {
		defs := dashboardCardDefs()
		require.Len(t, defs, 12)
		seen := map[string]bool{}
		for _, d := range defs {
			assert.False(t, seen[d.Key], "key 重複: %s", d.Key)
			seen[d.Key] = true
			assert.NotEmpty(t, d.Unit, d.Key)
			assert.NotEmpty(t, d.ErrCode, d.Key)
			assert.NotEmpty(t, d.Resource, "%s 缺審計分類", d.Key)
			if d.Criterion == criterionPerm {
				_, ok := authz.LookupPermission(d.Perm)
				assert.True(t, ok, "%s 的能力不在目錄內", d.Key)
			}
		}
		e, ok := authz.LookupRoute(http.MethodGet, "/api/v1/dashboard/cards/:key")
		require.True(t, ok)
		assert.Equal(t, authz.BaseAuthenticated, e.Base)
	})

	t.Run("來源缺少即建構失敗", func(t *testing.T) {
		_, err := NewDashboardCardHandler(DashboardCardDeps{})
		assert.Error(t, err)
	})
}
