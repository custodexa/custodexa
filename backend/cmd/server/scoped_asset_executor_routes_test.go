package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 堡壘機專用帳號四條路由：無權單一形狀、憑證語義能力、範圍外與不存在同形、公鑰匯出標頭。
// 組裝與正式同形：登錄閘（能力）→ 逐資產可視守門 → 服務層範圍判定（asset:executor-manage）。

// executorRouter 專用帳號路由。
func (e *saEnv) executorRouter(uid uint) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		e.current = p
		c.Next()
	})
	accounts := asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
		WithManagementAuthorizer(fieldCapManagementAuthorizer{env: e.fieldCapEnv}).WithSystemAlertSink(noopAlertSink{}).
		WithAccountWriteScope(authz.NewAssetWriteScope(e.eval))
	svc := asset.NewAssetExecutorService(accounts, authz.NewAssetWriteScope(e.eval)).
		WithCredentialVisibility(authz.NewCredentialScopeReader(e.eval, e.db))
	gate := middleware.NewScopeGate(e.db, e.eval, authz.RouteScopeDeclarations())
	h := api.NewAssetExecutorHandler(svc, gate)
	src := authz.NewAssetScopeReader(e.eval, e.db)
	h.SetAssetManagementVisibility(src)
	h.SetAccountRowProjector(authz.NewCredentialScopeReader(e.eval, e.db))
	visible := middleware.RequireAssetVisibleOrManaged(e.authzSvc, src)
	g := r.Group("/api/v1/assets/:id/executor")
	g.GET("", middleware.EnforceRegistry(gate), visible, h.Get)
	g.PUT("", middleware.EnforceRegistry(gate), visible, h.Set)
	g.DELETE("", middleware.EnforceRegistry(gate), visible, h.Clear)
	g.GET("/public-key", middleware.EnforceRegistry(gate), visible, h.ExportPublicKey)
	return r
}

type executorResp struct {
	code   int
	body   string
	header http.Header
}

func (e *saEnv) doExecutor(uid uint, method, path, body string) executorResp {
	e.t.Helper()
	defer func() { e.current = nil }()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	e.executorRouter(uid).ServeHTTP(w, req)
	return executorResp{code: w.Code, body: w.Body.String(), header: w.Header()}
}

const executorGenerateBody = `{"source":"generate","username":"cx-exec","expected_account_id":0}`

// executorRoutes 四條路由（方法、路徑後綴、本文）。
var executorRoutes = []struct {
	name, method, suffix, body string
}{
	{"get", "GET", "/executor", ""},
	{"put", "PUT", "/executor", executorGenerateBody},
	{"delete", "DELETE", "/executor", ""},
	{"public_key", "GET", "/executor/public-key", ""},
}

func TestAssetExecutorRoutes(t *testing.T) {
	env := newSAEnv(t)
	cat, err := authz.CatalogueWithScopedEnforcedForTest(append(saPerms, authz.PermAssetExecutorManage)...)
	require.NoError(t, err)
	env.cat = cat
	env.eval = authz.NewScopeEvaluator(cat, asset.NewScopeTopologyReader())
	env.assets.SetAssetWriteScopePort(authz.NewAssetWriteScope(env.eval))

	env.node("zz-sa-exec-in", "")
	env.node("zz-sa-exec-out", "")
	inScope := env.asset("zz-sa-exec-a", "zz-sa-exec-in")
	outScope := env.asset("zz-sa-exec-b", "zz-sa-exec-out")
	credCaps := []authz.Permission{authz.PermCredentialView, authz.PermCredentialCreate, authz.PermCredentialBind,
		authz.PermCredentialUpdate, authz.PermCredentialDelete}

	t.Run("no_new_key_single_forbidden_shape", func(t *testing.T) {
		u := env.user("zz-sa-exec-nokey")
		env.grantGlobal(u, env.role(append([]authz.Permission{authz.PermAssetView, authz.PermAssetUpdate}, credCaps...)...))
		var first string
		for _, rt := range executorRoutes {
			res := env.doExecutor(u, rt.method, idPath(inScope)+rt.suffix, rt.body)
			require.Equal(t, http.StatusForbidden, res.code, "%s: %s", rt.name, res.body)
			if first == "" {
				first = res.body
			}
			assert.Equal(t, first, res.body, "%s 與其他路由同一形狀", rt.name)
		}
	})

	t.Run("compat_manage_without_create_same_as_missing", func(t *testing.T) {
		compat := env.user("zz-sa-exec-compat")
		env.grantNodes(compat, env.role(authz.PermAssetView, authz.PermAssetExecutorManage, authz.PermCredentialManage), "zz-sa-exec-in")
		bare := env.user("zz-sa-exec-bare")
		env.grantNodes(bare, env.role(authz.PermAssetView, authz.PermAssetExecutorManage), "zz-sa-exec-in")
		a := env.doExecutor(compat, "PUT", idPath(inScope)+"/executor", executorGenerateBody)
		b := env.doExecutor(bare, "PUT", idPath(inScope)+"/executor", executorGenerateBody)
		require.Equal(t, http.StatusForbidden, a.code, a.body)
		assert.Equal(t, b.code, a.code)
		assert.Equal(t, b.body, a.body, "只持相容鍵與完全缺能力回應相同")
		var execs int64
		require.NoError(t, env.db.Model(&model.AssetAccount{}).Where("asset_id = ? AND purpose = ?", inScope,
			model.AccountPurposeExecutor).Count(&execs).Error)
		assert.Zero(t, execs)
	})

	// 範圍化主體：兩個節點都可看資產（逐資產可視守門放行），專用帳號管理只在 in 節點——範圍外只剩服務層判定擋
	scoped := env.user("zz-sa-exec-scoped")
	env.grantNodes(scoped, env.role(authz.PermAssetView), "zz-sa-exec-in", "zz-sa-exec-out")
	env.grantNodes(scoped, env.role(append([]authz.Permission{authz.PermAssetView, authz.PermAssetExecutorManage}, credCaps...)...),
		"zz-sa-exec-in")

	t.Run("in_scope_generate_and_export", func(t *testing.T) {
		res := env.doExecutor(scoped, "PUT", idPath(inScope)+"/executor", executorGenerateBody)
		require.Equal(t, http.StatusOK, res.code, res.body)
		pk := env.doExecutor(scoped, "GET", idPath(inScope)+"/executor/public-key", "")
		require.Equal(t, http.StatusOK, pk.code, pk.body)
		assert.True(t, strings.HasPrefix(pk.header.Get("Content-Type"), "text/plain"), pk.header.Get("Content-Type"))
		assert.True(t, strings.HasPrefix(pk.header.Get("Content-Disposition"), "attachment"), pk.header.Get("Content-Disposition"))
		assert.True(t, strings.HasPrefix(pk.body, "ssh-ed25519 "))
	})

	t.Run("out_of_scope_same_as_missing", func(t *testing.T) {
		for _, rt := range executorRoutes {
			out := env.doExecutor(scoped, rt.method, idPath(outScope)+rt.suffix, rt.body)
			missing := env.doExecutor(scoped, rt.method, "/api/v1/assets/"+saMissing+rt.suffix, rt.body)
			assert.Equal(t, missing.code, out.code, rt.name)
			assert.Equal(t, missing.body, out.body, "%s：範圍外與不存在逐位元相同", rt.name)
			assert.Equal(t, http.StatusNotFound, out.code, "%s: %s", rt.name, out.body)
		}
		var execs int64
		require.NoError(t, env.db.Model(&model.AssetAccount{}).Where("asset_id = ? AND purpose = ?", outScope,
			model.AccountPurposeExecutor).Count(&execs).Error)
		assert.Zero(t, execs)
	})
}
