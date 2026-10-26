package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 使用者權限一覽兩條唯讀路由：登錄裁決、agent 拒絕、錯誤形狀、同形 404 與讀取不寫入。
// 經正式 handler、登錄閘與真服務（in-memory SQLite）；映射規則與政策段位以替身提供。

const (
	poOverviewPath = "/api/v1/users/:id/permission-overview"
	poAssetPath    = "/api/v1/users/:id/permission-overview/assets/:asset_id"
)

type poNoMappings struct{}

func (poNoMappings) RoleMappingRules(*gorm.DB, uint) (map[uint][]authz.OverviewRuleRef, error) {
	return map[uint][]authz.OverviewRuleRef{}, nil
}

func (poNoMappings) GroupMappingRules(*gorm.DB, uint) (map[uint][]authz.OverviewRuleRef, error) {
	return map[uint][]authz.OverviewRuleRef{}, nil
}

type poOpenPolicies struct{}

func (poOpenPolicies) ResolveSegments(in []*string) []string {
	out := make([]string, len(in))
	for i := range in {
		out[i] = model.AccessPolicyOpen
	}
	return out
}

type poFailingReader struct{}

func (poFailingReader) Overview(context.Context, uint) (*authz.PermissionOverview, error) {
	return nil, errors.New("internal-secret-detail-xyz")
}

func (poFailingReader) ProbeAsset(context.Context, uint, uint) (*authz.OverviewAssetProbe, error) {
	return nil, errors.New("internal-secret-detail-xyz")
}

type poEnv struct {
	db      *gorm.DB
	handler *api.PermissionOverviewHandler
	ids     map[string]uint
	assets  map[string]uint
}

func newPOEnv(t *testing.T) *poEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.RolePermission{}, &model.UserGroup{}, &model.AssetGroup{},
		&model.Asset{}, &model.AssetNode{}, &model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{},
		&model.AuthzState{}, &model.SystemAlertDetail{}, &model.SystemAlertOutbox{}))
	require.NoError(t, db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}))
	require.NoError(t, db.Create(&model.AuthzState{ID: 1}).Error)

	e := &poEnv{db: db, ids: map[string]uint{}, assets: map[string]uint{}}
	role := func(name, builtin string, perms ...authz.Permission) uint {
		r := model.Role{Name: name}
		if builtin != "" {
			r.BuiltinKey = &builtin
		} else {
			r.DefinitionVersion = 1
		}
		require.NoError(t, db.Create(&r).Error)
		for _, p := range perms {
			require.NoError(t, db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(p)}).Error)
		}
		return r.ID
	}
	superRole := role("super", model.BuiltinSuperAdmin)
	idRole := role("idadmin", model.BuiltinIdentityAdmin)
	assetRole := role("asset-only", "", authz.PermAssetView, authz.PermAssetUpdate)
	authzRole := role("authz-only", "", authz.PermAuthorizationManage)
	auditRole := role("audit-only", "", authz.PermAuditView, authz.PermAlertView)
	mkUser := func(name string, kind string, roleID uint, scope string, nodes ...uint) {
		u := model.User{Username: name, Password: "x", Active: true, Kind: kind}
		require.NoError(t, db.Create(&u).Error)
		e.ids[name] = u.ID
		if roleID == 0 {
			return
		}
		require.NoError(t, db.Create(&model.UserRole{UserID: u.ID, RoleID: roleID, Source: model.RoleSourceManual, ScopeKind: scope}).Error)
		for _, n := range nodes {
			require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: u.ID, RoleID: roleID, NodeID: n}).Error)
		}
	}
	node := model.AssetGroup{Name: "po-node"}
	require.NoError(t, db.Create(&node).Error)
	for _, name := range []string{"po-visible", "po-hidden-secret-name"} {
		a := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: "h", Port: 22}
		require.NoError(t, db.Create(&a).Error)
		e.assets[name] = a.ID
	}
	require.NoError(t, db.Create(&model.AssetNode{AssetID: e.assets["po-visible"], NodeID: node.ID}).Error)
	mkUser("root", model.KindHuman, superRole, model.ScopeKindGlobal)
	mkUser("idadmin", model.KindHuman, idRole, model.ScopeKindGlobal)
	mkUser("nodeid", model.KindHuman, idRole, model.ScopeKindNodes, node.ID)
	mkUser("assetonly", model.KindHuman, assetRole, model.ScopeKindGlobal)
	mkUser("authzonly", model.KindHuman, authzRole, model.ScopeKindGlobal)
	mkUser("auditonly", model.KindHuman, auditRole, model.ScopeKindGlobal)
	mkUser("subject", model.KindHuman, 0, "")
	// 身分管理員兼具範圍限定的資產檢視：看不到範圍外資產（用於同形 404）
	mkUser("scopedmgr", model.KindHuman, idRole, model.ScopeKindGlobal)
	viewRole := role("asset-view-scoped", "", authz.PermAssetView)
	require.NoError(t, db.Create(&model.UserRole{UserID: e.ids["scopedmgr"], RoleID: viewRole, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: e.ids["scopedmgr"], RoleID: viewRole, NodeID: node.ID}).Error)
	mkUser("agent", model.KindAgent, 0, "")

	topo := asset.NewScopeTopologyReader()
	ev := authz.NewScopeEvaluator(authz.ProductCatalogue(), topo, authz.ProductScopeResolvers()...)
	svc := authz.NewPermissionOverviewService(db, ev, authz.NewEffectiveAccessResolver(db).WithScope(ev),
		authz.NewAssetAuthorizationService(db), poNoMappings{}, poOpenPolicies{})
	e.handler = api.NewPermissionOverviewHandler(svc)
	return e
}

func (e *poEnv) router(h *api.PermissionOverviewHandler, actor string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if uid, ok := e.ids[actor]; ok {
			var u model.User
			if err := e.db.First(&u, uid).Error; err == nil {
				if p, err := authz.ResolveUserOn(e.db, uid, authz.TokenFacts{SubjectKind: u.Kind}); err == nil {
					middleware.SetPrincipal(c, p)
					c.Set("userID", uid)
				}
			}
		}
		c.Next()
	})
	r.GET(poOverviewPath, middleware.EnforceRegistry(), h.Get)
	r.GET(poAssetPath, middleware.EnforceRegistry(), h.GetAsset)
	return r
}

func (e *poEnv) get(actor, url string) (int, string) {
	w := httptest.NewRecorder()
	e.router(e.handler, actor).ServeHTTP(w, httptest.NewRequest("GET", url, nil))
	return w.Code, w.Body.String()
}

func (e *poEnv) url(user string) string {
	return fmt.Sprintf("/api/v1/users/%d/permission-overview", e.ids[user])
}

// stateHash 權限相關表的列內容雜湊（依主鍵排序）、權限版本、審計列與 outbox 列數。
func (e *poEnv) stateHash(t *testing.T) string {
	t.Helper()
	h := sha256.New()
	for _, tbl := range []string{"users", "roles", "role_permissions", "user_roles", "user_groups", "user_group_members",
		"user_group_roles", "role_binding_nodes", "asset_authorizations", "approver_scopes", "authz_state", "audit_logs",
		"system_alert_outbox", "system_alert_details"} {
		var rows []map[string]any
		require.NoError(t, e.db.Raw("SELECT * FROM "+tbl+" ORDER BY 1, 2").Scan(&rows).Error, tbl)
		b, err := json.Marshal(rows)
		require.NoError(t, err)
		h.Write([]byte(tbl))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestPermissionOverviewAccess(t *testing.T) {
	t.Run("兩條路由登錄為使用者檢視能力，且在路由清冊與 agent 拒絕表內", func(t *testing.T) {
		for _, key := range []string{"GET " + poOverviewPath, "GET " + poAssetPath} {
			parts := strings.SplitN(key, " ", 2)
			entry, ok := authz.LookupRoute(parts[0], parts[1])
			require.True(t, ok, key)
			assert.Equal(t, authz.BasePerm, entry.Base, key)
			assert.Equal(t, authz.PermUserManage, entry.Perm, key)
			allowed, registered := middleware.AgentRouteDecision(parts[0], parts[1])
			assert.True(t, registered, "agent 路由登錄表有此項 %s", key)
			assert.False(t, allowed, "agent 一律被拒 %s", key)
		}
		routes, _ := buildRouter(t, gin.ReleaseMode, true)
		for _, p := range []string{poOverviewPath, poAssetPath} {
			_, ok := routes[[2]string{"GET", p}]
			assert.True(t, ok, "路由清冊含 GET %s", p)
		}
	})

	t.Run("超管與身分管理員可讀", func(t *testing.T) {
		e := newPOEnv(t)
		for _, actor := range []string{"root", "idadmin"} {
			code, body := e.get(actor, e.url("subject"))
			assert.Equal(t, http.StatusOK, code, actor+" "+body)
			assert.Contains(t, body, `"management"`)
		}
		code, _ := e.get("idadmin", fmt.Sprintf("%s/assets/%d", e.url("subject"), e.assets["po-visible"]))
		assert.NotEqual(t, http.StatusForbidden, code)
	})

	t.Run("其他能力者回單一 forbidden 形狀，附任意查詢參數時與不附時逐位元組相同", func(t *testing.T) {
		e := newPOEnv(t)
		// 存在的權限變化告警：只帶識別碼，不改變裁決
		require.NoError(t, e.db.Create(&model.SystemAlertDetail{AlertType: "self_privilege_increased", TargetKind: "user"}).Error)
		for _, actor := range []string{"assetonly", "authzonly", "auditonly", "nodeid"} {
			code, base := e.get(actor, e.url("subject"))
			assert.Equal(t, http.StatusForbidden, code, actor)
			assert.NotContains(t, base, "management")
			for _, q := range []string{"?alert_id=1", "?alert_id=1&user_id=1&scope=all", "?force=true"} {
				c2, b2 := e.get(actor, e.url("subject")+q)
				assert.Equal(t, code, c2, actor+q)
				assert.Equal(t, base, b2, actor+" "+q)
			}
			codeA, bodyA := e.get(actor, fmt.Sprintf("%s/assets/%d?alert_id=1", e.url("subject"), e.assets["po-visible"]))
			assert.Equal(t, http.StatusForbidden, codeA)
			assert.Equal(t, base, bodyA, "兩條路由的拒絕本文相同")
		}
	})

	t.Run("agent 主體與無主體被拒", func(t *testing.T) {
		e := newPOEnv(t)
		code, _ := e.get("agent", e.url("subject"))
		assert.NotEqual(t, http.StatusOK, code)
		code, _ = e.get("nobody", e.url("subject"))
		assert.NotEqual(t, http.StatusOK, code)
	})

	t.Run("使用者不存在、路徑參數不合法與解析失敗的錯誤碼", func(t *testing.T) {
		e := newPOEnv(t)
		code, body := e.get("root", "/api/v1/users/987654/permission-overview")
		assert.Equal(t, http.StatusNotFound, code)
		assert.Contains(t, body, "AUTH_USER_NOT_FOUND")
		code, body = e.get("root", "/api/v1/users/abc/permission-overview")
		assert.Equal(t, http.StatusBadRequest, code)
		assert.Contains(t, body, "VALIDATION_INVALID_ID")
		code, body = e.get("root", fmt.Sprintf("%s/assets/xyz", e.url("subject")))
		assert.Equal(t, http.StatusBadRequest, code)
		assert.Contains(t, body, "VALIDATION_INVALID_ID")

		failing := api.NewPermissionOverviewHandler(poFailingReader{})
		for _, url := range []string{e.url("subject"), fmt.Sprintf("%s/assets/%d", e.url("subject"), e.assets["po-visible"])} {
			w := httptest.NewRecorder()
			e.router(failing, "root").ServeHTTP(w, httptest.NewRequest("GET", url, nil))
			assert.Equal(t, http.StatusInternalServerError, w.Code)
			assert.Contains(t, w.Body.String(), "INTERNAL_PERMISSION_OVERVIEW")
			assert.NotContains(t, w.Body.String(), "internal-secret-detail-xyz")
		}
		// 組裝缺依賴：端點回內部錯誤，不回空集合
		w := httptest.NewRecorder()
		e.router(api.NewPermissionOverviewHandler(nil), "root").ServeHTTP(w, httptest.NewRequest("GET", e.url("subject"), nil))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "INTERNAL_PERMISSION_OVERVIEW")
	})

	t.Run("看不到的資產與不存在的資產回應逐位元組相同", func(t *testing.T) {
		e := newPOEnv(t)
		// 檢視者是範圍限定的資產檢視者時，看不到範圍外的資產：與不存在的 ID 逐位元組相同
		code1, body1 := e.get("scopedmgr", fmt.Sprintf("%s/assets/%d", e.url("subject"), e.assets["po-hidden-secret-name"]))
		code2, body2 := e.get("scopedmgr", fmt.Sprintf("%s/assets/%d", e.url("subject"), 987655))
		assert.Equal(t, http.StatusNotFound, code1)
		assert.Equal(t, code1, code2)
		assert.Equal(t, body1, body2)
		assert.Contains(t, body1, "NOTFOUND_ASSET")
		assert.NotContains(t, body1, "po-hidden-secret-name")
		code3, _ := e.get("scopedmgr", fmt.Sprintf("%s/assets/%d", e.url("subject"), e.assets["po-visible"]))
		assert.Equal(t, http.StatusOK, code3, "範圍內的資產照常回答")
	})

	t.Run("兩條路由呼叫前後權限相關狀態不變", func(t *testing.T) {
		e := newPOEnv(t)
		before := e.stateHash(t)
		for _, url := range []string{e.url("subject"), e.url("root"), e.url("agent"),
			fmt.Sprintf("%s/assets/%d", e.url("subject"), e.assets["po-visible"]),
			fmt.Sprintf("%s/assets/%d", e.url("subject"), e.assets["po-hidden-secret-name"])} {
			code, body := e.get("root", url)
			require.Equal(t, http.StatusOK, code, body)
		}
		assert.Equal(t, before, e.stateHash(t), "指派、群組、映射、角色、權限版本、審計列與 outbox 皆不變")
	})
}
