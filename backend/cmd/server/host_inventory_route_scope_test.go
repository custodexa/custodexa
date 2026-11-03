package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// invScopeSvc 盤點服務替身：只記呼叫與全域清單收到的範圍，成功回最小形狀。
type invScopeSvc struct {
	calls   int
	allowed []uint
	gotNil  bool
	all     []uint // 全域清單「不限範圍」時回的資產集合
}

func (s *invScopeSvc) Initiate(id uint, _ asset.InventoryActor) (*model.HostAccountScan, error) {
	s.calls++
	return &model.HostAccountScan{AssetID: id}, nil
}

func (s *invScopeSvc) GetAssetInventory(uint, asset.InventoryFindingQuery) (*asset.AssetInventoryView, error) {
	s.calls++
	return &asset.AssetInventoryView{}, nil
}

func (s *invScopeSvc) ListGlobalFindings(q asset.InventoryGlobalQuery) (*asset.InventoryGlobalView, error) {
	s.calls++
	s.gotNil = q.AllowedAssetIDs == nil
	s.allowed = append([]uint(nil), q.AllowedAssetIDs...)
	ids := q.AllowedAssetIDs
	if ids == nil {
		ids = s.all
	}
	out := &asset.InventoryGlobalView{Findings: []asset.InventoryFindingView{}}
	for _, id := range ids {
		f := asset.InventoryFindingView{}
		f.AssetID = id
		out.Findings = append(out.Findings, f)
	}
	out.Total = int64(len(out.Findings))
	return out, nil
}

func (s *invScopeSvc) IgnoreFinding(id, fid uint, _ string, _ asset.InventoryActor) (*model.HostAccountFinding, error) {
	s.calls++
	return &model.HostAccountFinding{ID: fid, AssetID: id}, nil
}

func (s *invScopeSvc) ReopenFinding(id, fid uint, _ asset.InventoryActor) (*model.HostAccountFinding, error) {
	s.calls++
	return &model.HostAccountFinding{ID: fid, AssetID: id}, nil
}

// invRouter 以正式宣告表的登錄閘掛五條盤點路由；每個請求自資料庫重解主體。
func invRouter(e *saEnv, uid uint, svc *invScopeSvc) *gin.Engine {
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
	h := api.NewHostInventoryHandler(svc, e.authzSvc, authz.NewAssetScopeReader(e.eval, e.db), gate)
	h.MountRoutes(r.Group("/api/v1"))
	return r
}

func invDo(e *saEnv, uid uint, svc *invScopeSvc, method, path string) (int, string) {
	e.t.Helper()
	var req *http.Request
	if method == http.MethodPost {
		req = httptest.NewRequest(method, path, strings.NewReader(`{"reason":"service account"}`))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	invRouter(e, uid, svc).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// invGlobalAssets 全域清單回應中出現的資產集合（排序）。
func invGlobalAssets(t *testing.T, raw string) []uint {
	t.Helper()
	var v struct {
		Findings []struct {
			AssetID uint `json:"asset_id"`
		} `json:"findings"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &v), raw)
	out := []uint{}
	for _, f := range v.Findings {
		out = append(out, f.AssetID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// TestHostAccountInventoryRouteScope 盤點五條路由的授權射程：讀取跟隨資產檢視權，
// 寫入要盤點權限點；節點範圍外的資產與不存在同形回 404 且不到達服務；全域清單依檢視範圍投影。
func TestHostAccountInventoryRouteScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := newSAEnv(t)
	var err error
	e.cat, err = authz.CatalogueWithScopedEnforcedForTest(append(append([]authz.Permission{}, saPerms...), authz.PermAccountDiscover)...)
	require.NoError(t, err)
	e.eval = authz.NewScopeEvaluator(e.cat, asset.NewScopeTopologyReader())

	e.node("zz-sa-inv-in", "")
	e.node("zz-sa-inv-out", "")
	aIn := e.asset("zz-sa-inv-a-in", "zz-sa-inv-in")
	aOut := e.asset("zz-sa-inv-a-out", "zz-sa-inv-out")
	all := []uint{aIn, aOut}

	viewer := e.user("zz-sa-inv-viewer")
	e.grantGlobal(viewer, e.role(authz.PermAssetView))
	disc := e.user("zz-sa-inv-disc")
	e.grantNodes(disc, e.role(authz.PermAssetView, authz.PermAccountDiscover), "zz-sa-inv-in")
	nodeViewer := e.user("zz-sa-inv-nodeviewer")
	e.grantNodes(nodeViewer, e.role(authz.PermAssetView), "zz-sa-inv-in")
	nobody := e.user("zz-sa-inv-nobody")
	e.grantGlobal(nobody, e.role())

	inv := func(id uint) string { return fmt.Sprintf("/api/v1/assets/%d/account-inventory", id) }
	scans := func(id uint) string { return inv(id) + "/scans" }
	ignore := func(id uint) string { return inv(id) + "/findings/9/ignore" }
	reopen := func(id uint) string { return inv(id) + "/findings/9/reopen" }
	const global = "/api/v1/account-inventory/findings"

	expect := func(name string, uid uint, method, path string, want int, reach bool) {
		t.Run(name, func(t *testing.T) {
			svc := &invScopeSvc{all: all}
			code, raw := invDo(e, uid, svc, method, path)
			assert.Equal(t, want, code, raw)
			if reach {
				assert.Equal(t, 1, svc.calls, "應到達服務")
			} else {
				assert.Zero(t, svc.calls, "被拒的請求不得到達服務")
			}
		})
	}

	// 只持全域資產檢視權：全域資產檢視不構成管理可視（與資產詳情相同），單資產讀取與不存在同形 404、
	// 全域清單為空；三條寫入能力不足
	t.Run("view_only_get_asset_404_like_missing", func(t *testing.T) {
		svcIn, svcMissing := &invScopeSvc{all: all}, &invScopeSvc{all: all}
		codeIn, rawIn := invDo(e, viewer, svcIn, "GET", inv(aIn))
		codeMissing, rawMissing := invDo(e, viewer, svcMissing, "GET", "/api/v1/assets/"+saMissing+"/account-inventory")
		assert.Equal(t, http.StatusNotFound, codeIn, rawIn)
		assert.Equal(t, codeMissing, codeIn)
		assert.JSONEq(t, rawMissing, rawIn, "看不到的資產與不存在必須同形")
		assert.Zero(t, svcIn.calls+svcMissing.calls)
	})
	expect("view_only_initiate_403", viewer, "POST", scans(aIn), http.StatusForbidden, false)
	expect("view_only_ignore_403", viewer, "POST", ignore(aIn), http.StatusForbidden, false)
	expect("view_only_reopen_403", viewer, "POST", reopen(aIn), http.StatusForbidden, false)
	t.Run("view_only_global_empty", func(t *testing.T) {
		svc := &invScopeSvc{all: all}
		code, raw := invDo(e, viewer, svc, "GET", global)
		require.Equal(t, http.StatusOK, code, raw)
		assert.False(t, svc.gotNil, "全域資產檢視不得被當成不限範圍")
		assert.Empty(t, svc.allowed)
		assert.Empty(t, invGlobalAssets(t, raw))
	})

	// 節點範圍持有盤點權：範圍內放行
	expect("scoped_discover_initiate_in_202", disc, "POST", scans(aIn), http.StatusAccepted, true)
	expect("scoped_discover_get_in_200", disc, "GET", inv(aIn), http.StatusOK, true)
	expect("scoped_discover_ignore_in_200", disc, "POST", ignore(aIn), http.StatusOK, true)
	expect("scoped_discover_reopen_in_200", disc, "POST", reopen(aIn), http.StatusOK, true)

	// 範圍外：與不存在的資產同形 404，且不到達服務
	for _, rc := range []struct {
		name, method string
		path         func(uint) string
	}{
		{"get", "GET", inv}, {"initiate", "POST", scans}, {"ignore", "POST", ignore}, {"reopen", "POST", reopen},
	} {
		t.Run("scoped_discover_out_"+rc.name+"_404_like_missing", func(t *testing.T) {
			svcOut, svcMissing := &invScopeSvc{all: all}, &invScopeSvc{all: all}
			codeOut, rawOut := invDo(e, disc, svcOut, rc.method, rc.path(aOut))
			codeMissing, rawMissing := invDo(e, disc, svcMissing, rc.method, strings.Replace(rc.path(aOut), fmt.Sprintf("/%d/", aOut), "/"+saMissing+"/", 1))
			assert.Equal(t, http.StatusNotFound, codeOut, rawOut)
			assert.Equal(t, codeMissing, codeOut)
			assert.JSONEq(t, rawMissing, rawOut, "範圍外與不存在必須同形")
			assert.Zero(t, svcOut.calls+svcMissing.calls)
		})
	}
	t.Run("scoped_discover_global_in_scope_only", func(t *testing.T) {
		svc := &invScopeSvc{all: all}
		code, raw := invDo(e, disc, svc, "GET", global)
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, []uint{aIn}, invGlobalAssets(t, raw))
	})

	// 只經節點範圍持有資產檢視權：全域清單只含範圍內資產
	t.Run("scoped_view_global_in_scope_only", func(t *testing.T) {
		svc := &invScopeSvc{all: all}
		code, raw := invDo(e, nodeViewer, svc, "GET", global)
		require.Equal(t, http.StatusOK, code, raw)
		assert.False(t, svc.gotNil, "節點範圍檢視者不得被當成不限範圍")
		assert.Equal(t, []uint{aIn}, svc.allowed)
		assert.Equal(t, []uint{aIn}, invGlobalAssets(t, raw))
	})
	expect("scoped_view_initiate_in_403", nodeViewer, "POST", scans(aIn), http.StatusForbidden, false)

	// 無任何檢視權：兩條讀取皆 403
	expect("no_view_get_asset_403", nobody, "GET", inv(aIn), http.StatusForbidden, false)
	expect("no_view_global_403", nobody, "GET", global, http.StatusForbidden, false)
}
