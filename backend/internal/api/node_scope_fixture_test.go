package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
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
)

// 節點範圍化動作與樹讀取的 HTTP 夾具：正式接線的節點樹服務與範圍化讀取、直接寫表建立的指派。
// 樹形：prod、prod/db、prod/db/a、prod/db/b、prod/web、sit、sit/web。

type nodeScopeEnv struct {
	t     *testing.T
	db    *gorm.DB
	cat   authz.Catalogue
	eval  *authz.ScopeEvaluator
	svc   *asset.AssetGroupService
	h     *AssetGroupHandler
	plain *AssetGroupHandler // 同一服務、未注入範圍化讀取（現行讀取路徑的對照）
	pre   []gin.HandlerFunc  // 掛在主體解析之前的中介層（如審計）
	nodes map[string]uint    // 路徑 → 節點識別碼
	seq   int
}

// newNodeScopeEnv extraScoped：測試目錄中另改為 scoped-enforced 的鍵（資產與憑證權限點仍為保留時用）。
func newNodeScopeEnv(t *testing.T, extraScoped ...authz.Permission) *nodeScopeEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1) // :memory: 每條連線各自一個庫
	return newNodeScopeEnvOn(t, db, extraScoped...)
}

// newNodeScopeEnvOn 同 newNodeScopeEnv，但用呼叫端提供的資料庫（PostgreSQL 子案例用）。
func newNodeScopeEnvOn(t *testing.T, db *gorm.DB, extraScoped ...authz.Permission) *nodeScopeEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	var err error
	require.NoError(t, migrateWithAuthz(db,
		&model.AssetGroup{}, &model.AssetNode{}, &model.Asset{}, &model.AuditLog{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.User{}, &model.Role{},
		&model.RolePermission{}, &model.AuthzState{}, &model.PermissionStateEvent{},
		&model.UserGroup{}, &model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{},
		&model.Credential{})) // 節點刪除承接歸屬該節點的共用憑證
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)

	cat := authz.ProductCatalogue()
	if len(extraScoped) > 0 {
		cat, err = authz.CatalogueWithScopedEnforcedForTest(extraScoped...)
		require.NoError(t, err)
	}
	topo := asset.NewScopeTopologyReader()
	eval := authz.NewScopeEvaluator(cat, topo)
	authzSvc := authz.NewAssetAuthorizationService(db)
	svc := asset.NewAssetGroupService(db, audit.NewTxSink(), authzSvc)
	svc.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	svc.SetNodeWriteScopePort(authz.NewNodeWriteScope(eval))
	svc.SetNodeScopeReferencePort(authz.NewNodeScopeReferenceReader())
	svc.SetCoverageSnapshotPort(authz.NewTopologyCoverageReader(topo))
	h := NewAssetGroupHandler(svc, authzSvc, authzSvc)
	h.SetNodeTreeScope(authz.NewNodeTreeScopeReader(eval, db))
	plain := NewAssetGroupHandler(svc, authzSvc, authzSvc)

	e := &nodeScopeEnv{t: t, db: db, cat: cat, eval: eval, svc: svc, h: h, plain: plain, nodes: map[string]uint{}}
	for _, p := range [][2]string{{"prod", ""}, {"prod/db", "prod"}, {"prod/db/a", "prod/db"}, {"prod/db/b", "prod/db"},
		{"prod/web", "prod"}, {"sit", ""}, {"sit/web", "sit"}} {
		e.node(p[0], p[1])
	}
	return e
}

// node 直接寫表建節點（路徑最後一段為名稱）。
func (e *nodeScopeEnv) node(path, parent string) uint {
	e.t.Helper()
	g := model.AssetGroup{Name: path[lastSlash(path)+1:]}
	if parent != "" {
		pid := e.nodes[parent]
		g.ParentID = &pid
	}
	require.NoError(e.t, e.db.Create(&g).Error)
	e.nodes[path] = g.ID
	return g.ID
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

func (e *nodeScopeEnv) user(name string) uint {
	e.t.Helper()
	u := model.User{Username: name, Password: "x", Active: true}
	require.NoError(e.t, e.db.Create(&u).Error)
	return u.ID
}

// role 自訂角色（定義版本 1）。
func (e *nodeScopeEnv) role(perms ...authz.Permission) uint {
	e.t.Helper()
	e.seq++
	r := model.Role{Name: fmt.Sprintf("node-scope-role-%d", e.seq), DefinitionVersion: 1}
	require.NoError(e.t, e.db.Create(&r).Error)
	for _, p := range perms {
		require.NoError(e.t, e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(p)}).Error)
	}
	return r.ID
}

// grantNodes 使用者直接的節點範圍指派。
func (e *nodeScopeEnv) grantNodes(userID, roleID uint, paths ...string) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	for _, p := range paths {
		require.NoError(e.t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
			SubjectID: userID, RoleID: roleID, NodeID: e.nodes[p]}).Error)
	}
}

// grantGlobal 使用者直接的全域指派。
func (e *nodeScopeEnv) grantGlobal(userID, roleID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
}

// groupNodes 建群組（members 為成員）並以節點範圍指派角色；回群組識別碼。
func (e *nodeScopeEnv) groupNodes(name string, roleID uint, members []uint, paths ...string) uint {
	e.t.Helper()
	g := model.UserGroup{Name: name}
	require.NoError(e.t, e.db.Create(&g).Error)
	for _, m := range members {
		require.NoError(e.t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: m, Manual: true}).Error)
	}
	require.NoError(e.t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: roleID,
		ScopeKind: model.ScopeKindNodes, CreatedAt: time.Now()}).Error)
	for _, p := range paths {
		require.NoError(e.t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUserGroup,
			SubjectID: g.ID, RoleID: roleID, NodeID: e.nodes[p]}).Error)
	}
	return g.ID
}

// superAdmin 建超級管理者。
func (e *nodeScopeEnv) superAdmin() uint {
	e.t.Helper()
	id := e.user(fmt.Sprintf("super-%d", e.seq))
	grantLegacyRole(e.t, e.db, id, model.RoleAdmin)
	return id
}

// router 以 userID 為操作者（每請求自資料庫以測試目錄解析主體）的路由。
func (e *nodeScopeEnv) router(userID uint) *gin.Engine { return e.routerFor(e.h, userID) }

// routerFor 以指定 handler 掛路由（e.pre 先於主體解析）。
func (e *nodeScopeEnv) routerFor(h *AssetGroupHandler, userID uint) *gin.Engine {
	r := gin.New()
	r.Use(e.pre...)
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, userID, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", userID)
		c.Set("username", fmt.Sprintf("u%d", userID))
		c.Next()
	})
	g := r.Group("/asset-groups")
	g.GET("", h.List)
	g.GET("/tree", h.Tree)
	g.POST("", h.Create)
	g.PUT("/:id", h.Update)
	g.PUT("/:id/move", h.Move)
	g.DELETE("/:id", h.Delete)
	return r
}

// do 送出請求，回狀態碼與原始 body。
func (e *nodeScopeEnv) do(userID uint, method, path string, body any) (int, []byte) {
	e.t.Helper()
	return e.doWith(e.h, userID, method, path, body)
}

// doWith 以指定 handler 送出請求。
func (e *nodeScopeEnv) doWith(h *AssetGroupHandler, userID uint, method, path string, body any) (int, []byte) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(e.t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.routerFor(h, userID).ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

func (e *nodeScopeEnv) id(path string) uint { return e.nodes[path] }

func (e *nodeScopeEnv) idStr(path string) string { return fmt.Sprint(e.nodes[path]) }

// parentOf 節點目前的父節點（nil＝根層）。
func (e *nodeScopeEnv) parentOf(path string) *uint {
	e.t.Helper()
	var g model.AssetGroup
	require.NoError(e.t, e.db.Unscoped().First(&g, e.nodes[path]).Error)
	return g.ParentID
}

// serviceAudits 節點的服務審計列（成功列）。
func (e *nodeScopeEnv) serviceAudits() []model.AuditLog {
	e.t.Helper()
	var rows []model.AuditLog
	require.NoError(e.t, e.db.Order("id").Find(&rows).Error)
	return rows
}

// asset 直接寫表建資產並掛到 paths 各節點；回資產識別碼。
func (e *nodeScopeEnv) asset(name string, paths ...string) uint {
	e.t.Helper()
	a := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22}
	require.NoError(e.t, e.db.Create(&a).Error)
	for _, p := range paths {
		require.NoError(e.t, e.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: e.nodes[p]}).Error)
	}
	return a.ID
}

// connect 使用者對資產的直接連線授權（連線可視來源）。
func (e *nodeScopeEnv) connect(userID, assetID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.AssetAuthorization{UserID: &userID, AssetID: &assetID,
		Permission: model.PermissionConnect, Source: "manual", GrantedBy: 1}).Error)
}

// withAudit 在主體解析之前掛同步寫入的審計中介層（寫入本環境的資料庫）。
func (e *nodeScopeEnv) withAudit() {
	e.t.Helper()
	old := database.DB
	database.DB = e.db
	e.t.Cleanup(func() { database.DB = old })
	svc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})
	e.pre = append(e.pre, middleware.AuditLogMiddleware(svc))
}

// lastAudit 最新一筆審計列。
func (e *nodeScopeEnv) lastAudit() model.AuditLog {
	e.t.Helper()
	var row model.AuditLog
	require.NoError(e.t, e.db.Unscoped().Order("id desc").First(&row).Error)
	return row
}
