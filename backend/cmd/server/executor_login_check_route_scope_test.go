package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 專用帳號測試登入兩條路由的授權射程：只有 asset:executor-manage 通過登錄閘；
// 持有資產檢視、連線測試、帳號盤點三者之一都不夠；範圍外與不存在同形 404；
// 資產沒有專用帳號回 404（以服務層的哨兵錯誤代替，不撥號）。被拒的請求不得到達服務，
// 也就沒有任何撥號與測試登入審計。

// execCheckScopeSvc 測試登入服務替身：只記呼叫次數，成功回最小形狀。
type execCheckScopeSvc struct {
	runs, states int
	err          error
}

func (s *execCheckScopeSvc) Run(_ context.Context, assetID uint, _ asset.InventoryActor) (*asset.ExecutorLoginCheckResult, error) {
	s.runs++
	if s.err != nil {
		return nil, s.err
	}
	return &asset.ExecutorLoginCheckResult{Success: true, Method: "executor_root", InventoryRead: "not_needed",
		AccountUsername: "cx-exec", CheckedAt: time.Unix(1700000000, 0).UTC()}, nil
}

func (s *execCheckScopeSvc) State(uint) (*asset.ExecutorLoginCheckState, error) {
	s.states++
	if s.err != nil {
		return nil, s.err
	}
	return &asset.ExecutorLoginCheckState{}, nil
}

func (s *execCheckScopeSvc) calls() int { return s.runs + s.states }

// execCheckRouter 以正式宣告表的登錄閘掛兩條測試登入路由；每個請求自資料庫重解主體。
func execCheckRouter(e *saEnv, uid uint, svc *execCheckScopeSvc) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	gate := middleware.NewScopeGate(e.db, e.eval, authz.RouteScopeDeclarations())
	h := api.NewExecutorLoginCheckHandler(svc, gate)
	reg := middleware.EnforceRegistry(gate)
	g := r.Group("/api/v1/assets/:id/executor/login-check")
	g.POST("", reg, h.Run)
	g.GET("", reg, h.Get)
	return r
}

func execCheckDo(e *saEnv, uid uint, svc *execCheckScopeSvc, method, path string) (int, string) {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(""))
	w := httptest.NewRecorder()
	execCheckRouter(e, uid, svc).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func TestExecutorLoginCheckRouteScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := newSAEnv(t)
	var err error
	e.cat, err = authz.CatalogueWithScopedEnforcedForTest(append(append([]authz.Permission{}, saPerms...), authz.PermAssetExecutorManage)...)
	require.NoError(t, err)
	e.eval = authz.NewScopeEvaluator(e.cat, asset.NewScopeTopologyReader())

	e.node("zz-sa-chk-in", "")
	e.node("zz-sa-chk-out", "")
	aIn := e.asset("zz-sa-chk-a-in", "zz-sa-chk-in")
	aOut := e.asset("zz-sa-chk-a-out", "zz-sa-chk-out")

	nobody := e.user("zz-sa-chk-nobody")
	e.grantGlobal(nobody, e.role())
	viewOnly := e.user("zz-sa-chk-view")
	e.grantGlobal(viewOnly, e.role(authz.PermAssetView))
	testOnly := e.user("zz-sa-chk-test")
	e.grantGlobal(testOnly, e.role(authz.PermAssetTest))
	discoverOnly := e.user("zz-sa-chk-discover")
	e.grantGlobal(discoverOnly, e.role(authz.PermAccountDiscover))
	manager := e.user("zz-sa-chk-manager")
	e.grantNodes(manager, e.role(authz.PermAssetExecutorManage), "zz-sa-chk-in")

	path := func(id uint) string { return fmt.Sprintf("/api/v1/assets/%d/executor/login-check", id) }
	methods := []string{"POST", "GET"}

	// 能力不足：一律 403，不到達服務
	for _, c := range []struct {
		name string
		uid  uint
	}{
		{"no_permission", nobody}, {"asset_view_only", viewOnly}, {"asset_test_only", testOnly}, {"account_discover_only", discoverOnly},
	} {
		for _, m := range methods {
			t.Run(c.name+"_"+strings.ToLower(m)+"_403", func(t *testing.T) {
				svc := &execCheckScopeSvc{}
				code, raw := execCheckDo(e, c.uid, svc, m, path(aIn))
				assert.Equal(t, http.StatusForbidden, code, raw)
				assert.Zero(t, svc.calls(), "被拒的請求不得到達服務（零撥號、零測試登入審計）")
			})
		}
	}

	// 範圍外與不存在同形 404，且不到達服務
	for _, m := range methods {
		t.Run("scoped_manager_out_of_scope_"+strings.ToLower(m)+"_404_like_missing", func(t *testing.T) {
			svcOut, svcMissing := &execCheckScopeSvc{}, &execCheckScopeSvc{}
			codeOut, rawOut := execCheckDo(e, manager, svcOut, m, path(aOut))
			codeMissing, rawMissing := execCheckDo(e, manager, svcMissing, m,
				strings.Replace(path(aOut), fmt.Sprintf("/%d/", aOut), "/"+saMissing+"/", 1))
			assert.Equal(t, http.StatusNotFound, codeOut, rawOut)
			assert.Equal(t, codeMissing, codeOut)
			assert.JSONEq(t, rawMissing, rawOut, "範圍外與不存在必須同形")
			assert.Zero(t, svcOut.calls()+svcMissing.calls())
		})
	}

	// 範圍內：放行並到達服務
	t.Run("scoped_manager_in_scope_post_200", func(t *testing.T) {
		svc := &execCheckScopeSvc{}
		code, raw := execCheckDo(e, manager, svc, "POST", path(aIn))
		assert.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, 1, svc.runs)
	})
	t.Run("scoped_manager_in_scope_get_200", func(t *testing.T) {
		svc := &execCheckScopeSvc{}
		code, raw := execCheckDo(e, manager, svc, "GET", path(aIn))
		assert.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, 1, svc.states)
	})

	// 範圍內但資產沒有專用帳號：服務回哨兵錯誤，兩條路由都是 404 NOTFOUND_ASSET_EXECUTOR
	for _, m := range methods {
		t.Run("asset_without_executor_"+strings.ToLower(m)+"_404", func(t *testing.T) {
			svc := &execCheckScopeSvc{err: asset.ErrAssetExecutorNotFound}
			code, raw := execCheckDo(e, manager, svc, m, path(aIn))
			assert.Equal(t, http.StatusNotFound, code, raw)
			assert.Contains(t, raw, "NOTFOUND_ASSET_EXECUTOR")
			assert.Equal(t, 1, svc.calls())
		})
	}
}
