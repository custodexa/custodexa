package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// 審核範圍路由以正式組裝跑端到端（SQLite；設 TEST_PG_DSN 時改在 PostgreSQL）：產品目錄、正式判定器（newScopeEvaluator）、與 buildRouteDeps 同一組
// 服務注入，路由掛登錄閘＋handler。主體每個請求以產品目錄自資料庫重解；指派直接寫表。
//
// 證明申請人型審核範圍只由全域指派涵蓋：
//   - 只在節點範圍指派、角色同時帶審核範圍管理與申請人型管理者：列表看不到申請人型列、建立回 403
//     單一形狀、移除回與不存在相同的 NOTFOUND_APPROVER_SCOPE；
//   - 全域指派同一組權限點者（對照組）：三者皆成功；
//   - 只持申請人型管理、不持審核範圍管理者：五條路由皆 403（登錄閘）。

type asmEnv struct {
	t     *testing.T
	db    *gorm.DB
	h     *api.AccessRequestHandler
	nodes map[string]uint
	super uint
	seq   int
}

// newASMEnv TEST_PG_DSN 有值（或要求整合測試）時在獨立 schema 的 PostgreSQL 上跑，否則 SQLite。
func newASMEnv(t *testing.T) *asmEnv {
	t.Helper()
	var db *gorm.DB
	if os.Getenv(testgate.EnvPGDSN) != "" || testgate.RequireIntegration() {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		schema := fmt.Sprintf("asm_scope_%d", time.Now().UnixNano())
		admin := pwloOpen(t, dsn)
		require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
		t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE") })
		db = pwloOpen(t, dsn+" search_path="+schema)
		require.Equal(t, "postgres", db.Dialector.Name(), "PG 子案例的實際 dialector 必須是 postgres")
		fmt.Println("EVIDENCE dialect=postgres")
	} else {
		var err error
		db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		sqlDB.SetMaxOpenConns(1)
	}
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.RolePermission{}, &model.UserGroup{},
		&model.AuthzState{}, &model.AssetGroup{}, &model.Asset{}, &model.AssetNode{}, &model.AssetAuthorization{},
		&model.ApproverScope{}, &model.AuditLog{}, &model.PermissionStateEvent{}))
	require.NoError(t, db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	old := database.DB
	database.DB = db // 審計中介層寫入本測試庫
	t.Cleanup(func() { database.DB = old })
	// 與 buildRouteDeps 同一組注入
	eval := newScopeEvaluator()
	svc := authz.NewApproverScopeService(db)
	svc.SetWriteScope(authz.NewApproverScopeWriteScope(eval), eval)
	svc.SetPolicies(asmPolicies{})
	require.NoError(t, svc.RequireWriteScope())
	e := &asmEnv{t: t, db: db, h: api.NewAccessRequestHandler(nil, svc, db), nodes: map[string]uint{}}
	e.super = e.user("zz-asm-super")
	e.builtin(e.super, model.RoleAdmin)
	return e
}

func (e *asmEnv) node(name, parent string) {
	e.t.Helper()
	g := model.AssetGroup{Name: name}
	if parent != "" {
		pid := e.nodes[parent]
		g.ParentID = &pid
	}
	require.NoError(e.t, e.db.Create(&g).Error)
	e.nodes[name] = g.ID
}

func (e *asmEnv) user(name string) uint {
	e.t.Helper()
	u := model.User{Username: name, Password: "x", Active: true}
	require.NoError(e.t, e.db.Create(&u).Error)
	return u.ID
}

func (e *asmEnv) role(perms ...authz.Permission) uint {
	e.t.Helper()
	e.seq++
	r := model.Role{Name: fmt.Sprintf("zz-asm-role-%d", e.seq), DefinitionVersion: 1}
	require.NoError(e.t, e.db.Create(&r).Error)
	for _, p := range perms {
		require.NoError(e.t, e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(p)}).Error)
	}
	return r.ID
}

func (e *asmEnv) builtin(userID uint, name string) {
	e.t.Helper()
	var r model.Role
	if err := e.db.Where("name = ?", name).First(&r).Error; err != nil {
		r = model.Role{Name: name}
		require.NoError(e.t, e.db.Create(&r).Error)
	}
	e.grantGlobal(userID, r.ID)
}

func (e *asmEnv) grantGlobal(userID, roleID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
}

func (e *asmEnv) grantNodes(userID, roleID uint, nodes ...string) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	for _, n := range nodes {
		require.NoError(e.t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
			SubjectID: userID, RoleID: roleID, NodeID: e.nodes[n]}).Error)
	}
}

type asmPolicies struct{}

func (asmPolicies) GetInt(string) int { return 1 }

func (e *asmEnv) send(uid uint, method, path, body string) (int, string) {
	e.t.Helper()
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOn(e.db, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	g := r.Group("/api/v1/approver-scopes", middleware.EnforceRegistry())
	g.GET("", e.h.ListScopes)
	g.POST("", e.h.CreateScope)
	g.DELETE("/:id", e.h.DeleteScope)
	g.GET("/approver-options", e.h.ApproverOptions)
	g.GET("/target-options", e.h.TargetOptions)
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func asmKeys(t *testing.T, raw string) []string {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(raw), &m), raw)
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestApproverScopeAssembledScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := newASMEnv(t)
	def, ok := authz.ProductCatalogue().Lookup(authz.PermApproverScopeManage)
	require.True(t, ok)
	require.Equal(t, authz.ScopeEnforced, def.Scope, "產品目錄的審核範圍管理須為範圍生效")
	e.node("zz-asm-prod", "")
	e.node("zz-asm-db", "zz-asm-prod")
	e.node("zz-asm-sit", "")
	ap := e.user("zz-asm-approver")
	e.builtin(ap, model.RoleApprover)
	subject := e.user("zz-asm-subject")
	subject2 := e.user("zz-asm-subject-2")
	dbNode := e.nodes["zz-asm-db"]
	nodeRow := model.ApproverScope{ApproverID: &ap, AssetGroupID: &dbNode, GrantedBy: e.super}
	require.NoError(t, e.db.Create(&nodeRow).Error)
	newApplicantRow := func() uint {
		row := model.ApproverScope{ApproverID: &ap, SubjectUserID: &subject, GrantedBy: e.super}
		require.NoError(t, e.db.Create(&row).Error)
		return row.ID
	}
	applicantRow := newApplicantRow()
	both := e.role(authz.PermApproverScopeManage, authz.PermApproverScopeApplicantManage)
	nodeBoth := e.user("zz-asm-node-both")
	e.grantNodes(nodeBoth, both, "zz-asm-prod")
	globalBoth := e.user("zz-asm-global-both")
	e.grantGlobal(globalBoth, both)
	kaOnly := e.user("zz-asm-ka-only")
	e.grantGlobal(kaOnly, e.role(authz.PermApproverScopeApplicantManage))
	rowExists := func(id uint) bool {
		var n int64
		require.NoError(t, e.db.Model(&model.ApproverScope{}).Where("id = ?", id).Count(&n).Error)
		return n == 1
	}
	applicantBody := func(s uint) string { return fmt.Sprintf(`{"approver_id":%d,"subject_user_id":%d}`, ap, s) }
	listIDs := func(raw string) map[uint]bool {
		var out struct {
			Data []model.ApproverScope `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
		ids := map[uint]bool{}
		for _, r := range out.Data {
			ids[r.ID] = true
		}
		return ids
	}

	t.Run("node_scoped_both_keys", func(t *testing.T) {
		code, raw := e.send(nodeBoth, "GET", "/api/v1/approver-scopes", "")
		require.Equal(t, http.StatusOK, code, raw)
		ids := listIDs(raw)
		assert.True(t, ids[nodeRow.ID], "範圍內節點型列可見")
		assert.False(t, ids[applicantRow], "申請人型列不可見")
		assert.NotContains(t, raw, `"subject_user_id":`+fmt.Sprint(subject))
		assert.Contains(t, raw, `"applicant_manageable":false`)

		code, raw = e.send(nodeBoth, "POST", "/api/v1/approver-scopes", applicantBody(subject2))
		assert.Equal(t, http.StatusForbidden, code, raw)
		assert.Equal(t, []string{"code", "error"}, asmKeys(t, raw))
		assert.Contains(t, raw, `"AUTH_PERMISSION_DENIED"`)

		code, raw = e.send(nodeBoth, "DELETE", fmt.Sprintf("/api/v1/approver-scopes/%d", applicantRow), "")
		mCode, mRaw := e.send(nodeBoth, "DELETE", "/api/v1/approver-scopes/999931", "")
		assert.Equal(t, http.StatusNotFound, code, raw)
		assert.Contains(t, raw, `"NOTFOUND_APPROVER_SCOPE"`)
		assert.Equal(t, mCode, code)
		assert.Equal(t, mRaw, raw, "申請人型列與不存在逐位元相同")
		assert.True(t, rowExists(applicantRow))
	})

	t.Run("global_both_keys_control", func(t *testing.T) {
		code, raw := e.send(globalBoth, "GET", "/api/v1/approver-scopes", "")
		require.Equal(t, http.StatusOK, code, raw)
		assert.True(t, listIDs(raw)[applicantRow], "全域兩鍵持有者看得到申請人型列")
		assert.Contains(t, raw, `"applicant_manageable":true`)
		code, raw = e.send(globalBoth, "POST", "/api/v1/approver-scopes", applicantBody(subject2))
		assert.Equal(t, http.StatusCreated, code, raw)
		code, raw = e.send(globalBoth, "DELETE", fmt.Sprintf("/api/v1/approver-scopes/%d", applicantRow), "")
		assert.Equal(t, http.StatusOK, code, raw)
		assert.False(t, rowExists(applicantRow))
	})

	t.Run("applicant_key_without_manage_key", func(t *testing.T) {
		row := newApplicantRow()
		for _, c := range []struct{ method, path, body string }{
			{"GET", "/api/v1/approver-scopes", ""},
			{"POST", "/api/v1/approver-scopes", applicantBody(subject2)},
			{"DELETE", fmt.Sprintf("/api/v1/approver-scopes/%d", row), ""},
			{"GET", "/api/v1/approver-scopes/approver-options", ""},
			{"GET", "/api/v1/approver-scopes/target-options?kind=node", ""},
		} {
			code, raw := e.send(kaOnly, c.method, c.path, c.body)
			assert.Equal(t, http.StatusForbidden, code, "%s %s：%s", c.method, c.path, raw)
			assert.Equal(t, []string{"code", "error"}, asmKeys(t, raw), "%s %s", c.method, c.path)
			assert.Contains(t, raw, `"AUTH_PERMISSION_DENIED"`)
		}
		assert.True(t, rowExists(row))
	})
}
