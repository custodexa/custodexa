package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// 審核範圍範圍化的 HTTP 夾具：節點樹沿用 nodeScopeEnv（prod、prod/db、prod/db/a、prod/db/b、prod/web、
// sit、sit/web），測試目錄把審核範圍管理標為範圍生效；服務與正式組裝同形注入交易內範圍判定與判定器。
// 指派直接寫表。每個請求自資料庫以測試目錄重解主體。

const apsMissing = 999907 // 不存在的資產、節點、審核範圍 ID

type apsEnv struct {
	*nodeScopeEnv
	aeval *authz.ScopeEvaluator
	svc   *authz.ApproverScopeService // 正式組裝（範圍判定已注入）
	plain *authz.ApproverScopeService // 現行路徑（未注入），供超級管理者逐欄比對
	// failNames 為真時，審核範圍列寫入之後的顯示名稱查詢一律失敗（注入預載失敗）
	failNames atomic.Bool
	armed     atomic.Bool
	super     uint
	obs       *gorm.DB // PostgreSQL 觀測連線（SQLite 為 nil）
}

type fixedMinApprovals int

func (f fixedMinApprovals) GetInt(string) int { return int(f) }

// newAPSEnv db 為 nil 時用 SQLite :memory:。
func newAPSEnv(t *testing.T, db *gorm.DB, obs *gorm.DB) *apsEnv {
	t.Helper()
	var base *nodeScopeEnv
	if db == nil {
		base = newNodeScopeEnv(t, authz.PermApproverScopeManage)
	} else {
		base = newNodeScopeEnvOn(t, db, authz.PermApproverScopeManage)
	}
	aeval := authz.NewAuthorizationScopeEvaluator(base.cat, asset.NewScopeTopologyReader())
	svc := authz.NewApproverScopeService(base.db)
	svc.SetWriteScope(authz.NewApproverScopeWriteScope(aeval), aeval)
	svc.SetPolicies(fixedMinApprovals(2))
	require.NoError(t, svc.RequireWriteScope())
	e := &apsEnv{nodeScopeEnv: base, aeval: aeval, svc: svc, plain: authz.NewApproverScopeService(base.db), obs: obs}
	e.super = e.superAdmin()
	e.withAudit()
	e.installNameFailure()
	return e
}

// installNameFailure 審核範圍列寫入後才武裝，之後對使用者、群組、資產、節點的查詢注入錯誤
// （交易內的主體重解與判定都在寫入之前，不受影響）。
func (e *apsEnv) installNameFailure() {
	cb := e.db.Callback()
	require.NoError(e.t, cb.Create().After("gorm:create").Register("aps:arm", func(d *gorm.DB) {
		if e.failNames.Load() && d.Statement.Table == "approver_scopes" {
			e.armed.Store(true)
		}
	}))
	require.NoError(e.t, cb.Query().Before("gorm:query").Register("aps:fail-names", func(d *gorm.DB) {
		if !e.armed.Load() {
			return
		}
		switch d.Statement.Table {
		case "users", "user_groups", "assets", "asset_groups":
			_ = d.AddError(fmt.Errorf("injected display name failure"))
		}
	}))
}

// router 掛審核範圍五條路由（登錄閘＋handler，與正式組裝同形）。scoped=false 為現行路徑的對照。
func (e *apsEnv) router(uid uint, scoped bool) *gin.Engine {
	r := gin.New()
	r.Use(e.pre...)
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	var svc ApproverScopeServiceInterface = e.svc
	if !scoped {
		svc = e.plain
	}
	h := NewAccessRequestHandler(nil, svc, e.db)
	g := r.Group("/api/v1/approver-scopes", middleware.EnforceRegistry())
	g.GET("", h.ListScopes)
	g.POST("", h.CreateScope)
	g.DELETE("/:id", h.DeleteScope)
	g.GET("/approver-options", h.ApproverOptions)
	g.GET("/target-options", h.TargetOptions)
	return r
}

type apsResp struct {
	code int
	raw  string
}

func (e *apsEnv) call(uid uint, scoped bool, method, path string, body any) apsResp {
	e.t.Helper()
	var rd *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(e.t, err)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.router(uid, scoped).ServeHTTP(w, req)
	return apsResp{code: w.Code, raw: w.Body.String()}
}

func (e *apsEnv) do(uid uint, method, path string, body any) apsResp {
	e.t.Helper()
	return e.call(uid, true, method, path, body)
}

// approver 具全域 approver 角色的使用者（帶 email，供序列化零命中檢查）。
func (e *apsEnv) approver(name string) uint {
	e.t.Helper()
	id := e.user(name)
	email := name + "@aps-fixture.test"
	require.NoError(e.t, e.db.Model(&model.User{}).Where("id = ?", id).Update("email", email).Error)
	grantLegacyRole(e.t, e.db, id, model.RoleApprover)
	return id
}

// hostAsset 直接寫表建資產（位址可辨識）並掛到節點。
func (e *apsEnv) hostAsset(name, host string, paths ...string) uint {
	e.t.Helper()
	a := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: host, Port: 22}
	require.NoError(e.t, e.db.Create(&a).Error)
	for _, p := range paths {
		require.NoError(e.t, e.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: e.nodes[p]}).Error)
	}
	return a.ID
}

// seedScope 直接寫表建審核範圍列（granted_by＝超級管理者）。
func (e *apsEnv) seedScope(s model.ApproverScope) uint {
	e.t.Helper()
	s.GrantedBy = e.super
	require.NoError(e.t, e.db.Create(&s).Error)
	return s.ID
}

func (e *apsEnv) scopeCount() int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.ApproverScope{}).Count(&n).Error)
	return n
}

func (e *apsEnv) scopeExists(id uint) bool {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.ApproverScope{}).Where("id = ?", id).Count(&n).Error)
	return n == 1
}

func ptrU(v uint) *uint { return &v }

func apsPath(id uint) string { return fmt.Sprintf("/api/v1/approver-scopes/%d", id) }

// keysOf JSON 物件的鍵集（排序）。
func keysOf(t *testing.T, raw string) []string {
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

// apsPG 開一個獨立 schema 的 PostgreSQL 連線與同 schema 的觀測連線（不得回退 SQLite）。
func apsPG(t *testing.T, prefix string) (*gorm.DB, *gorm.DB) {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	schema := fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	open := func() *gorm.DB {
		db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		t.Cleanup(func() {
			if s, err := db.DB(); err == nil {
				_ = s.Close()
			}
		})
		return db
	}
	db, obs := open(), open()
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	require.Equal(t, "postgres", db.Dialector.Name(), "PG 子案例的實際 dialector 必須是 postgres")
	fmt.Println("EVIDENCE dialect=postgres")
	return db, obs
}

// apsEnvFor 依 TEST_PG_DSN 選資料庫：有值走 PostgreSQL，否則 SQLite。
func apsEnvFor(t *testing.T, prefix string) *apsEnv {
	t.Helper()
	if os.Getenv(testgate.EnvPGDSN) == "" && !testgate.RequireIntegration() {
		return newAPSEnv(t, nil, nil)
	}
	db, obs := apsPG(t, prefix)
	return newAPSEnv(t, db, obs)
}

// bodyOnlyCodeError 403 本文只有 code 與 error 兩鍵。
func bodyOnlyCodeError(t *testing.T, r apsResp) {
	t.Helper()
	require.Equal(t, http.StatusForbidden, r.code, r.raw)
	require.Equal(t, []string{"code", "error"}, keysOf(t, r.raw), r.raw)
	require.Contains(t, r.raw, `"AUTH_PERMISSION_DENIED"`)
}
