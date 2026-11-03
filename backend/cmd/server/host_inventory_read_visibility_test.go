package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
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

// 盤點讀取的可視範圍必須與資產詳情、資產列表一致：同一個帳號、同一台資產，盤點與詳情同時 200 或同時 404
// （404 本文相同）；全域清單的資產集合等於該帳號資產列表的可見集合。

// invVisSvc 盤點服務替身：單資產讀取對不存在的資產回不存在；全域清單回收到的範圍（不限時回全部資產）。
type invVisSvc struct {
	db *invVisDB
}

type invVisDB struct {
	exists func(uint) bool
	all    func() []uint
}

func (s invVisSvc) Initiate(id uint, _ asset.InventoryActor) (*model.HostAccountScan, error) {
	return &model.HostAccountScan{AssetID: id}, nil
}

func (s invVisSvc) GetAssetInventory(id uint, _ asset.InventoryFindingQuery) (*asset.AssetInventoryView, error) {
	if !s.db.exists(id) {
		return nil, asset.ErrInventoryAssetNotFound
	}
	return &asset.AssetInventoryView{}, nil
}

func (s invVisSvc) ListGlobalFindings(q asset.InventoryGlobalQuery) (*asset.InventoryGlobalView, error) {
	ids := q.AllowedAssetIDs
	if ids == nil {
		ids = s.db.all()
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

func (s invVisSvc) IgnoreFinding(id, fid uint, _ string, _ asset.InventoryActor) (*model.HostAccountFinding, error) {
	return &model.HostAccountFinding{ID: fid, AssetID: id}, nil
}

func (s invVisSvc) ReopenFinding(id, fid uint, _ asset.InventoryActor) (*model.HostAccountFinding, error) {
	return &model.HostAccountFinding{ID: fid, AssetID: id}, nil
}

// invVisRouter 以正式組裝的掛載方式掛盤點路由（登錄閘＋逐資產可視守門＋handler）。
func invVisRouter(e *saEnv, uid uint, svc invVisSvc) *gin.Engine {
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

func invVisDo(e *saEnv, uid uint, svc invVisSvc, path string) (int, string) {
	e.t.Helper()
	w := httptest.NewRecorder()
	invVisRouter(e, uid, svc).ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w.Code, w.Body.String()
}

func sortedIDs(m map[uint]bool) []uint {
	out := make([]uint, 0, len(m))
	for id, ok := range m {
		if ok {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func TestHostAccountInventoryReadMatchesAssetDetail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := newSAEnv(t)
	var err error
	e.cat, err = authz.CatalogueWithScopedEnforcedForTest(append(append([]authz.Permission{}, saPerms...), authz.PermAccountDiscover)...)
	require.NoError(t, err)
	e.eval = authz.NewScopeEvaluator(e.cat, asset.NewScopeTopologyReader())

	e.node("zz-iv-in", "")
	e.node("zz-iv-out", "")
	aIn := e.asset("zz-iv-a-in", "zz-iv-in")
	aOut := e.asset("zz-iv-a-out", "zz-iv-out")
	aConn := e.asset("zz-iv-a-conn", "zz-iv-out")
	var missing uint = 999917

	db := &invVisDB{
		exists: func(id uint) bool {
			var n int64
			require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", id).Count(&n).Error)
			return n > 0
		},
		all: func() []uint {
			var ids []uint
			require.NoError(t, e.db.Model(&model.Asset{}).Order("id").Pluck("id", &ids).Error)
			return ids
		},
	}
	svc := invVisSvc{db: db}

	// 零指派：自動套一般使用者範本（全域資產檢視）
	zero := e.user("zz-iv-zero")
	// 內建 user，另有一台資產的連線授權
	conn := e.user("zz-iv-conn")
	e.builtin(conn, model.RoleUser)
	e.connGrant(conn, aConn)
	// 只有全域資產檢視的自訂角色
	globalView := e.user("zz-iv-globalview")
	e.grantGlobal(globalView, e.role(authz.PermAssetView))
	// 節點範圍的資產檢視
	nodeViewer := e.user("zz-iv-nodeviewer")
	e.grantNodes(nodeViewer, e.role(authz.PermAssetView), "zz-iv-in")
	// 檢視捷徑主體
	auditor := e.user("zz-iv-auditor")
	e.builtin(auditor, model.RoleAuditor)

	type want map[uint]int
	cases := []struct {
		name string
		uid  uint
		want want
	}{
		{"zero_assignment", zero, want{aIn: 404, aOut: 404, aConn: 404, missing: 404}},
		{"builtin_user_with_connect", conn, want{aIn: 404, aOut: 404, aConn: 200, missing: 404}},
		{"global_asset_view_only", globalView, want{aIn: 404, aOut: 404, aConn: 404, missing: 404}},
		{"node_scoped_viewer", nodeViewer, want{aIn: 200, aOut: 404, aConn: 404, missing: 404}},
		{"view_shortcut_auditor", auditor, want{aIn: 200, aOut: 200, aConn: 200, missing: 404}},
		{"view_shortcut_admin", e.super, want{aIn: 200, aOut: 200, aConn: 200, missing: 404}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, id := range []uint{aIn, aOut, aConn, missing} {
				detailCode, detailRaw := e.do(tc.uid, true, http.MethodGet, idPath(id), "")
				invCode, invRaw := invVisDo(e, tc.uid, svc, fmt.Sprintf("/api/v1/assets/%d/account-inventory", id))
				assert.Equal(t, tc.want[id], detailCode, "asset %d detail: %s", id, detailRaw)
				assert.Equal(t, detailCode, invCode, "asset %d: inventory must match detail (%s)", id, invRaw)
				if detailCode == http.StatusNotFound && invCode == http.StatusNotFound {
					assert.JSONEq(t, detailRaw, invRaw, "asset %d: 404 body must match detail", id)
				}
			}

			listed := e.list(tc.uid, "").ids()
			code, raw := invVisDo(e, tc.uid, svc, "/api/v1/account-inventory/findings")
			require.Equal(t, http.StatusOK, code, raw)
			assert.Equal(t, sortedIDs(listed), invGlobalAssets(t, raw), "global findings must cover exactly the asset list's visible set")
		})
	}
}
