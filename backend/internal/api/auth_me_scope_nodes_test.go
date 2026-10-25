package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// scopeNodesEnv 經完整 RegisterRoutes（真 AuthMiddleware＋真解析）的 /auth/me 環境；
// wired 注入正式的拓撲讀取器，unwired 未注入節點路徑來源。
type scopeNodesEnv struct {
	wired, unwired *gin.Engine
	db             *gorm.DB
	jwt            *crypto.JWTManager
	seq            int
}

func setupScopeNodesEnv(t *testing.T) *scopeNodesEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&model.User{}, &model.Role{}, &model.UserGroup{}, &model.UserGroupMember{}, &model.Asset{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}, &model.UserRole{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}, &model.RolePermission{}, &model.AuthzState{},
		&model.AssetGroup{}))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	secret := "me-scope-nodes-secret"
	auth := identity.NewAuthService(secret, time.Minute)
	build := func(reader scopeNodePathReader) *gin.Engine {
		r := gin.New()
		h := NewAuthHandler(auth, nil)
		h.SetSourcePolicyReader(unrestrictedSourcePolicy())
		if reader != nil {
			h.SetScopeNodePathReader(reader)
		}
		h.RegisterRoutes(r.Group("/api/v1"), auth)
		return r
	}
	return &scopeNodesEnv{
		wired: build(asset.NewScopeTopologyReader()), unwired: build(nil),
		db: db, jwt: crypto.NewJWTManager(secret, time.Minute),
	}
}

func (e *scopeNodesEnv) node(t *testing.T, name string, parent *model.AssetGroup) *model.AssetGroup {
	t.Helper()
	n := &model.AssetGroup{Name: name}
	if parent != nil {
		n.ParentID = &parent.ID
	}
	require.NoError(t, e.db.Create(n).Error)
	return n
}

func (e *scopeNodesEnv) builtinRole(t *testing.T, key string) *model.Role {
	t.Helper()
	var role model.Role
	if err := e.db.Where("builtin_key = ?", key).First(&role).Error; err == nil {
		return &role
	}
	k := key
	role = model.Role{Name: "builtin-" + key, BuiltinKey: &k, DefinitionVersion: 1}
	require.NoError(t, e.db.Create(&role).Error)
	return &role
}

func (e *scopeNodesEnv) customRole(t *testing.T, name string, perms ...authz.Permission) *model.Role {
	t.Helper()
	role := &model.Role{Name: name, DefinitionVersion: 1}
	require.NoError(t, e.db.Create(role).Error)
	for _, p := range perms {
		require.NoError(t, e.db.Create(&model.RolePermission{RoleID: role.ID, PermissionKey: string(p)}).Error)
	}
	return role
}

func (e *scopeNodesEnv) user(t *testing.T, name string) (*model.User, string) {
	t.Helper()
	u := &model.User{Username: name, FullName: name, Email: emailPtr(name + "@x"), Active: true}
	require.NoError(t, e.db.Create(u).Error)
	tok, err := e.jwt.GenerateToken(u.ID, u.Username, name+"@x", "user", crypto.AuthContext{})
	require.NoError(t, err)
	return u, tok
}

func scopeOf(nodes []*model.AssetGroup) string {
	if len(nodes) == 0 {
		return model.ScopeKindGlobal
	}
	return model.ScopeKindNodes
}

func (e *scopeNodesEnv) assignDirect(t *testing.T, u *model.User, role *model.Role, nodes ...*model.AssetGroup) {
	t.Helper()
	require.NoError(t, e.db.Create(&model.UserRole{UserID: u.ID, RoleID: role.ID,
		Source: model.RoleSourceManual, ScopeKind: scopeOf(nodes)}).Error)
	for _, n := range nodes {
		require.NoError(t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
			SubjectID: u.ID, RoleID: role.ID, NodeID: n.ID}).Error)
	}
}

func (e *scopeNodesEnv) assignViaGroup(t *testing.T, u *model.User, role *model.Role, nodes ...*model.AssetGroup) {
	t.Helper()
	e.seq++
	g := &model.UserGroup{Name: fmt.Sprintf("group-%d", e.seq)}
	require.NoError(t, e.db.Create(g).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: u.ID, Manual: true}).Error)
	require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: role.ID,
		ScopeKind: scopeOf(nodes), CreatedAt: time.Now()}).Error)
	for _, n := range nodes {
		require.NoError(t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUserGroup,
			SubjectID: g.ID, RoleID: role.ID, NodeID: n.ID}).Error)
	}
}

func (e *scopeNodesEnv) call(r *gin.Engine, method, body, token string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, "/api/v1/auth/me", nil)
	} else {
		req = httptest.NewRequest(method, "/api/v1/auth/me", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

type scopeNodesView struct {
	Permissions  []string                  `json:"permissions"`
	ScopeSummary []authz.ScopeSummaryEntry `json:"scope_summary"`
}

func (v scopeNodesView) entries(perm string) []authz.ScopeSummaryEntry {
	var out []authz.ScopeSummaryEntry
	for _, e := range v.ScopeSummary {
		if e.Permission == perm {
			out = append(out, e)
		}
	}
	return out
}

// me 以正式 GET 與 PATCH 兩條處理路徑各取一次，兩者的兩欄須相同；回 GET 的解碼結果與原始回應。
func (e *scopeNodesEnv) me(t *testing.T, token string) (scopeNodesView, string) {
	t.Helper()
	get := e.call(e.wired, http.MethodGet, "", token)
	require.Equal(t, http.StatusOK, get.Code, get.Body.String())
	e.seq++
	patch := e.call(e.wired, http.MethodPatch, fmt.Sprintf(`{"local_display_name":"name-%d"}`, e.seq), token)
	require.Equal(t, http.StatusOK, patch.Code, patch.Body.String())
	var g, p scopeNodesView
	require.NoError(t, json.Unmarshal(get.Body.Bytes(), &g))
	require.NoError(t, json.Unmarshal(patch.Body.Bytes(), &p))
	assert.Equal(t, g, p, "GET 與 PATCH 的兩欄相同")
	return g, get.Body.String() + patch.Body.String()
}

func assertGlobalOnly(t *testing.T, v scopeNodesView, perm, msg string) {
	t.Helper()
	assert.Contains(t, v.Permissions, perm, msg)
	es := v.entries(perm)
	require.Len(t, es, 1, msg+": "+perm)
	assert.Equal(t, authz.BindingScopeGlobal, es[0].BindingScope, msg+": "+perm)
	assert.Empty(t, es[0].Nodes, msg+": "+perm)
}

// TestCurrentUserScopeSummaryNodes 擋：全域條目只認舊主角色範本（漏列或誤標）、節點條目缺漏或洩漏
// 範圍外與已刪除節點名稱、GET 與 PATCH 結果分歧、未注入路徑來源時以全域兜底。
func TestCurrentUserScopeSummaryNodes(t *testing.T) {
	env := setupScopeNodesEnv(t)
	rootA := env.node(t, "Alpha 機房", nil)
	nodeA := env.node(t, "核心 A", rootA)
	env.node(t, "核心 A 之下子節點", nodeA)
	rootB := env.node(t, "Beta 機房", nil)
	nodeB := env.node(t, "邊緣 B", rootB)
	env.node(t, "範圍外 X", nil)
	deleted := env.node(t, "已刪節點 D", rootA)
	require.NoError(t, env.db.Delete(deleted).Error)
	leaked := []string{"核心 A 之下子節點", "範圍外 X", "已刪節點 D"}
	pathA := []string{"Alpha 機房", "核心 A"}
	pathB := []string{"Beta 機房", "邊緣 B"}

	t.Run("只經全域指派持自訂角色：經該指派取得的點皆為一筆 global", func(t *testing.T) {
		perms := []authz.Permission{authz.PermAssetView, authz.PermAssetUpdate, authz.PermCredentialView}
		role := env.customRole(t, "global-custom", perms...)
		u, tok := env.user(t, "s-custom-global")
		env.assignDirect(t, u, role)
		v, _ := env.me(t, tok)
		for _, p := range perms {
			assertGlobalOnly(t, v, string(p), "全域自訂角色")
		}
	})

	t.Run("只經群組全域指派持鎖定範本：經該指派取得的點皆為一筆 global", func(t *testing.T) {
		u, tok := env.user(t, "s-template-group")
		env.assignViaGroup(t, u, env.builtinRole(t, model.BuiltinAssetAdmin))
		v, _ := env.me(t, tok)
		perms := authz.TemplatePermissions(model.BuiltinAssetAdmin)
		require.NotEmpty(t, perms)
		for _, p := range perms {
			assertGlobalOnly(t, v, string(p), "群組全域鎖定範本")
		}
	})

	t.Run("直接指派 A、群組指派 B：兩節點、路徑由根開始、不洩漏子節點／範圍外／已刪節點", func(t *testing.T) {
		role := env.customRole(t, "node-custom", authz.PermAssetView, authz.PermAssetUpdate)
		u, tok := env.user(t, "s-two-nodes")
		env.assignDirect(t, u, role, nodeA, deleted)
		env.assignViaGroup(t, u, role, nodeB)
		v, raw := env.me(t, tok)
		for _, p := range []string{string(authz.PermAssetView), string(authz.PermAssetUpdate)} {
			assert.Contains(t, v.Permissions, p)
			es := v.entries(p)
			require.Len(t, es, 1, p)
			assert.Equal(t, authz.BindingScopeNodes, es[0].BindingScope, p)
			assert.Equal(t, []authz.ScopeSummaryNode{{ID: nodeA.ID, Path: pathA}, {ID: nodeB.ID, Path: pathB}},
				es[0].Nodes, p)
		}
		for _, name := range leaked {
			assert.NotContains(t, raw, name)
		}
	})

	t.Run("同一點另有全域指派時只有一筆 global", func(t *testing.T) {
		nodeRole := env.customRole(t, "node-custom-2", authz.PermAssetView, authz.PermAssetUpdate)
		globalRole := env.customRole(t, "global-update", authz.PermAssetView, authz.PermAssetUpdate)
		u, tok := env.user(t, "s-mixed")
		env.assignDirect(t, u, nodeRole, nodeA)
		env.assignViaGroup(t, u, globalRole)
		v, _ := env.me(t, tok)
		assertGlobalOnly(t, v, string(authz.PermAssetUpdate), "另有全域")
		assertGlobalOnly(t, v, string(authz.PermAssetView), "另有全域")
	})

	t.Run("全域一般使用者＋節點範圍自訂角色：只經節點取得者為 nodes，無任何 global", func(t *testing.T) {
		nodePerms := []authz.Permission{authz.PermAssetView, authz.PermAssetUpdate, authz.PermCredentialView}
		role := env.customRole(t, "node-credential", nodePerms...)
		u, tok := env.user(t, "s-user-plus-node")
		env.assignDirect(t, u, env.builtinRole(t, model.BuiltinUser))
		env.assignDirect(t, u, role, nodeA)
		v, raw := env.me(t, tok)
		assertGlobalOnly(t, v, string(authz.PermAssetView), "一般使用者範本")
		for _, p := range []string{string(authz.PermAssetUpdate), string(authz.PermCredentialView)} {
			assert.Contains(t, v.Permissions, p)
			es := v.entries(p)
			require.Len(t, es, 1, p)
			assert.Equal(t, authz.BindingScopeNodes, es[0].BindingScope, p+": 不得標成全域")
			assert.Equal(t, []authz.ScopeSummaryNode{{ID: nodeA.ID, Path: pathA}}, es[0].Nodes, p)
		}
		for _, name := range leaked {
			assert.NotContains(t, raw, name)
		}
	})

	t.Run("範圍節點全刪的指派：該點不在兩欄", func(t *testing.T) {
		role := env.customRole(t, "deleted-only", authz.PermAssetView, authz.PermAssetUpdate)
		u, tok := env.user(t, "s-all-deleted")
		env.assignDirect(t, u, role, deleted)
		v, raw := env.me(t, tok)
		for _, p := range []string{string(authz.PermAssetView), string(authz.PermAssetUpdate)} {
			assert.NotContains(t, v.Permissions, p)
			assert.Empty(t, v.entries(p), p)
		}
		assert.NotContains(t, raw, "已刪節點 D")
	})

	t.Run("拓撲介面未注入：回解析失敗的既有形狀，不以 global 兜底", func(t *testing.T) {
		role := env.customRole(t, "node-unwired", authz.PermAssetView, authz.PermAssetUpdate)
		u, tok := env.user(t, "s-unwired")
		env.assignDirect(t, u, role, nodeA)
		w := env.call(env.unwired, http.MethodGet, "", tok)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		body := decodeMap(t, w.Body.Bytes())
		assert.NotContains(t, body, "permissions")
		assert.NotContains(t, body, "scope_summary")
		w = env.call(env.unwired, http.MethodPatch, `{"local_display_name":"不應寫入"}`, tok)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.NotContains(t, decodeMap(t, w.Body.Bytes()), "scope_summary")
		var got model.User
		require.NoError(t, env.db.First(&got, u.ID).Error)
		assert.Nil(t, got.LocalDisplayName, "失敗時尚未寫入")
	})
}
