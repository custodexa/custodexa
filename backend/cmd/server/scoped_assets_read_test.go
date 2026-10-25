package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// saTree 讀取測試的共用樹：zz-sa-a（含子節點 zz-sa-a1）、zz-sa-b、zz-sa-c、兩個遠端節點 zz-sa-far-1／-2。
func saTree(e *saEnv) {
	e.node("zz-sa-a", "")
	e.node("zz-sa-a1", "zz-sa-a")
	e.node("zz-sa-b", "")
	e.node("zz-sa-c", "")
	e.node("zz-sa-far-1", "")
	e.node("zz-sa-far-2", "")
}

// saManagedCount 列表中經管理可視的列數（這些列一律帶範圍外計數鍵）。
func saManagedCount(l saList) int {
	n := 0
	for _, r := range l.Data {
		if _, ok := r["out_of_scope_node_count"]; ok {
			n++
		}
	}
	return n
}

// saPreviewCount 預覽入口以同一組指派算出的管理可視台數。
func saPreviewCount(t *testing.T, e *saEnv, uid uint) int64 {
	t.Helper()
	m, err := e.eval.ManagementVisibleScopeForAssignments(e.db, e.assignments(uid))
	require.NoError(t, err)
	n, err := e.eval.CountManagementVisible(e.db, m)
	require.NoError(t, err)
	return n
}

// saCardValue 經正式逐卡端點（GET /dashboard/cards/assets）取資產卡數值；其餘卡的來源用替身。
func saCardValue(t *testing.T, e *saEnv, uid uint) int64 {
	t.Helper()
	hits := 0
	src := cardSourceStub{hits: &hits}
	counter, err := api.NewDashboardAssetCounter(e.assets, e.authzSvc, authz.NewAssetScopeReader(e.eval, e.db))
	require.NoError(t, err)
	cards, err := api.NewDashboardCardHandler(api.DashboardCardDeps{
		Assets: counter, Sessions: src, MyConnections: src, Alerts: cardAlertSourceStub{hits: &hits},
		Recordings: src, Reviews: src, Requests: src, DB: e.db,
	})
	require.NoError(t, err)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Next()
	})
	r.GET("/api/v1/dashboard/cards/:key", middleware.EnforceRegistry(), cards.GetCard)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/dashboard/cards/assets", nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		Key   string `json:"key"`
		Value int64  `json:"value"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, "assets", body.Key)
	return body.Value
}

func sameResponse(t *testing.T, name string, e *saEnv, uid uint, a, b string) {
	t.Helper()
	ca, ra := e.do(uid, true, "GET", a, "")
	cb, rb := e.do(uid, true, "GET", b, "")
	assert.Equal(t, cb, ca, "%s：狀態", name)
	assert.JSONEq(t, rb, ra, "%s：本文", name)
}

func TestScopedAssetListProjection(t *testing.T) {
	t.Run("union_with_connection_fields_only_on_connection_rows", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		u := e.user("zz-sa-u1")
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a")
		x := e.asset("zz-sa-x", "zz-sa-b")
		y := e.asset("zz-sa-y", "zz-sa-a1")
		z := e.asset("zz-sa-z", "zz-sa-c")
		e.connGrant(u, x)
		l := e.list(u, "")
		assert.Equal(t, map[uint]bool{x: true, y: true}, l.ids())
		assert.False(t, l.ids()[z])
		assert.Equal(t, int64(len(l.Data)), l.Total)
		_, hasPerm := l.row(y)["permission"]
		_, hasState := l.row(y)["access_state"]
		assert.False(t, hasPerm || hasState, "只經管理可視的列不帶連線欄")
		_, xPerm := l.row(x)["permission"]
		assert.True(t, xPerm, "連線可視列保留連線欄")
		assert.Equal(t, int64(saManagedCount(l)), saPreviewCount(t, e, u))
	})

	t.Run("authorized_only_returns_connection_rows_only", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		u := e.user("zz-sa-conn-only")
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a")
		x := e.asset("zz-sa-x", "zz-sa-b")
		y := e.asset("zz-sa-y", "zz-sa-a1")
		e.connGrant(u, x)
		union := e.list(u, "")
		require.True(t, union.ids()[y], "不帶參數時聯集含只經管理可視的列")
		l := e.list(u, "authorized_only=true")
		assert.Equal(t, map[uint]bool{x: true}, l.ids())
		assert.NotContains(t, l.raw, "zz-sa-y")
		assert.NotContains(t, l.raw, fmt.Sprintf(`"id":%d,`, y))
		assert.Equal(t, int64(1), l.Total)
		_, hasPerm := l.row(x)["permission"]
		assert.True(t, hasPerm, "連線可視列保留連線欄")
		assert.Equal(t, union.row(x), l.row(x), "同一台資產帶與不帶參數逐欄相同（含 actions）")
		assert.NotNil(t, l.ManagementScope, "management_scope 照附")

		m := e.user("zz-sa-mgmt-only-subject")
		e.grantNodes(m, e.role(authz.PermAssetView), "zz-sa-a")
		ml := e.list(m, "authorized_only=true")
		assert.Empty(t, ml.Data)
		assert.Equal(t, int64(0), ml.Total)
		assert.NotContains(t, ml.raw, "zz-sa-y")
	})

	t.Run("search_and_total_before_paging", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		u := e.user("zz-sa-u2")
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a")
		for i := 1; i <= 3; i++ {
			e.asset(fmt.Sprintf("zz-sa-find-%d", i), "zz-sa-a")
		}
		e.asset("zz-sa-other", "zz-sa-a")
		e.asset("zz-sa-find-outside", "zz-sa-c")
		// 聯集的連線來源：B 下一台經連線授權可見、名稱同樣符合搜尋
		e.connGrant(u, e.asset("zz-sa-find-conn", "zz-sa-b"))
		code, raw := e.do(u, true, "GET", "/api/v1/assets?search=zz-sa-find&page=1&page_size=2", "")
		require.Equal(t, http.StatusOK, code, raw)
		var l saList
		require.NoError(t, json.Unmarshal([]byte(raw), &l))
		assert.Equal(t, int64(4), l.Total, "total 只計聯集內符合者（管理三台＋連線一台）")
		assert.Len(t, l.Data, 2)
		assert.NotContains(t, raw, "zz-sa-find-outside")
		for _, r := range l.Data {
			name, _ := r["name"].(string)
			assert.True(t, strings.HasPrefix(name, "zz-sa-find-") && name != "zz-sa-find-outside", "第一頁只含聯集內符合者：%s", name)
		}
		all := e.list(u, "search=zz-sa-find")
		assert.Equal(t, int64(len(all.Data)), all.Total, "total 等於實際筆數")
		assert.Equal(t, l.Total, all.Total, "切頁前計 total")
		assert.Equal(t, int64(saManagedCount(e.list(u, ""))), saPreviewCount(t, e, u))
	})

	t.Run("node_filter_source_matrix", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		u := e.user("zz-sa-u3")
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a")
		e.asset("zz-sa-c-only", "zz-sa-c")
		cID := e.nodes["zz-sa-c"]
		empty := e.list(u, fmt.Sprintf("node_id=%d", cID))
		missing := e.list(u, "node_id="+saMissing)
		assert.Empty(t, empty.Data)
		assert.Equal(t, int64(0), empty.Total)
		assert.Equal(t, missing.Total, empty.Total)
		assert.Equal(t, len(missing.Data), len(empty.Data))

		w := e.asset("zz-sa-w", "zz-sa-c")
		e.connGrant(u, w)
		dual := e.asset("zz-sa-dual", "zz-sa-a", "zz-sa-c")
		e.connGrant(u, dual)
		got := e.list(u, fmt.Sprintf("node_id=%d", cID))
		assert.Equal(t, map[uint]bool{w: true}, got.ids(), "範圍外節點篩選只命中只經連線可視的列")
		assert.Equal(t, int64(saManagedCount(e.list(u, ""))), saPreviewCount(t, e, u))
	})

	t.Run("dropping_node_assignment_restores_current_branch", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		u := e.user("zz-sa-u4")
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a")
		x := e.asset("zz-sa-x", "zz-sa-b")
		e.asset("zz-sa-y", "zz-sa-a")
		e.connGrant(u, x)
		e.dropNodeAssignments(u)
		e.builtin(u, model.RoleUser)
		_, scoped := e.do(u, true, "GET", "/api/v1/assets?page_size=500", "")
		_, plain := e.do(u, false, "GET", "/api/v1/assets?page_size=500", "")
		assert.JSONEq(t, plain, scoped)
		assert.Equal(t, int64(saManagedCount(e.list(u, ""))), saPreviewCount(t, e, u))
	})

	t.Run("global_view_plus_node_scope_does_not_expand", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		m := e.user("zz-sa-mixed")
		e.builtin(m, model.RoleUser)
		e.grantNodes(m, e.role(authz.PermAssetView), "zz-sa-a")
		y := e.asset("zz-sa-y", "zz-sa-a")
		z := e.asset("zz-sa-z", "zz-sa-c")
		l := e.list(m, "")
		assert.True(t, l.ids()[y])
		assert.False(t, l.ids()[z], "全域資產檢視不構成管理可視")
		require.NotNil(t, l.ManagementScope)
		var ids []uint
		for _, n := range l.ManagementScope.Nodes {
			ids = append(ids, n.ID)
		}
		assert.Contains(t, ids, e.nodes["zz-sa-a"])
		assert.Equal(t, int64(saManagedCount(l)), saPreviewCount(t, e, m))
	})

	t.Run("management_scope_shape_with_deleted_node", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		e.node("zz-sa-gone", "")
		u := e.user("zz-sa-u5")
		// 指派含子節點 a1（非根）：path 須由根起
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a1", "zz-sa-b", "zz-sa-gone")
		require.NoError(t, e.db.Delete(&model.AssetGroup{}, e.nodes["zz-sa-gone"]).Error)
		a := e.asset("zz-sa-in-a", "zz-sa-a1")
		l := e.list(u, "")
		require.NotNil(t, l.ManagementScope)
		ms := l.ManagementScope
		assert.Equal(t, 2, ms.EffectiveNodeCount)
		assert.Equal(t, 1, ms.InactiveNodeCount)
		assert.Len(t, ms.Nodes, ms.EffectiveNodeCount)
		got := map[uint]string{}
		for _, n := range ms.Nodes {
			got[n.ID] = n.Path
		}
		assert.Equal(t, map[uint]bool{e.nodes["zz-sa-a1"]: true, e.nodes["zz-sa-b"]: true},
			map[uint]bool{saKeys(got)[0]: true, saKeys(got)[1]: true})
		assert.Equal(t, "zz-sa-a / zz-sa-a1", got[e.nodes["zz-sa-a1"]], "path 由根起")
		assert.Equal(t, "zz-sa-b", got[e.nodes["zz-sa-b"]])
		paths, _ := l.row(a)["node_paths"].([]any)
		require.Len(t, paths, 1)
		assert.Equal(t, paths[0], got[e.nodes["zz-sa-a1"]], "管理範圍路徑與歸屬路徑同格式")
		assert.NotContains(t, l.raw, "zz-sa-gone")
		assert.Equal(t, int64(saManagedCount(l)), saPreviewCount(t, e, u))
	})

	t.Run("global_only_keyset_unchanged", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		g := e.user("zz-sa-global")
		e.grantGlobal(g, e.role(authz.PermAssetView, authz.PermAssetUpdate))
		x := e.asset("zz-sa-x", "zz-sa-b")
		e.connGrant(g, x)
		_, scoped := e.do(g, true, "GET", "/api/v1/assets?page_size=500", "")
		_, plain := e.do(g, false, "GET", "/api/v1/assets?page_size=500", "")
		assert.JSONEq(t, plain, scoped)
		assert.NotContains(t, scoped, "management_scope")
		assert.Equal(t, int64(saManagedCount(e.list(g, ""))), saPreviewCount(t, e, g))
	})

	t.Run("dashboard_card_matches_list_total", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		u := e.user("zz-sa-u6")
		// 一般使用者範本（全域資產檢視）：列表路由的登錄閘要求持有資產檢視；節點指派全數失效時仍須看得到連線資產
		e.builtin(u, model.RoleUser)
		e.node("zz-sa-gone2", "")
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-gone2")
		require.NoError(t, e.db.Delete(&model.AssetGroup{}, e.nodes["zz-sa-gone2"]).Error)
		x := e.asset("zz-sa-x", "zz-sa-b")
		e.asset("zz-sa-z", "zz-sa-c")
		e.connGrant(u, x)
		counter, err := api.NewDashboardAssetCounter(e.assets, e.authzSvc, authz.NewAssetScopeReader(e.eval, e.db))
		require.NoError(t, err)
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, u, authz.TokenFacts{})
		require.NoError(t, err)
		n, err := counter.CountAssets(context.Background(), p, u)
		require.NoError(t, err)
		l := e.list(u, "")
		assert.Equal(t, l.Total, n)
		card := saCardValue(t, e, u)
		assert.Equal(t, l.Total, card, "卡片端點取值等於同主體列表 total")
		assert.Equal(t, int64(1), card, "有效管理節點 0 且有連線資產時不為 0")
		assert.NotEqual(t, saAssetCount(t, e), card, "也不等於全表數")
		assert.Equal(t, int64(saManagedCount(l)), saPreviewCount(t, e, u))
	})

	t.Run("per_asset_reads", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		viewer := e.user("zz-sa-viewer")
		e.grantNodes(viewer, e.role(authz.PermAssetView), "zz-sa-a")
		tester := e.user("zz-sa-tester")
		e.grantNodes(tester, e.role(authz.PermAssetView, authz.PermAssetTest), "zz-sa-a")
		mixed := e.user("zz-sa-mixed")
		e.builtin(mixed, model.RoleUser)
		e.grantNodes(mixed, e.role(authz.PermAssetView, authz.PermAssetTest), "zz-sa-a")
		y := e.asset("zz-sa-y", "zz-sa-a")
		yNoKey := e.asset("zz-sa-y-nokey", "zz-sa-a")
		z := e.asset("zz-sa-z", "zz-sa-c")
		x := e.asset("zz-sa-x", "zz-sa-b")
		e.connGrant(viewer, x)
		e.hostKeys.recs[y] = &model.AssetHostKey{AssetID: y, Algorithm: "ssh-ed25519", Fingerprint: "SHA256:zz"}

		code, raw := e.do(viewer, true, "GET", idPath(y), "")
		assert.Equal(t, http.StatusOK, code, raw)
		code, raw = e.do(viewer, true, "GET", idPath(y)+"/host-key", "")
		assert.Equal(t, http.StatusOK, code, raw)
		// 未種記錄：與連線可視者對同一狀態的回應相同
		cNo, rNo := e.do(viewer, true, "GET", idPath(yNoKey)+"/host-key", "")
		cConn, rConn := e.do(viewer, true, "GET", idPath(x)+"/host-key", "")
		assert.Equal(t, cConn, cNo)
		assert.JSONEq(t, rConn, rNo)

		e.podCalls = 0
		code, raw = e.do(tester, true, "GET", idPath(y)+"/k8s/pods", "")
		assert.Equal(t, http.StatusOK, code, raw)
		code, raw = e.do(viewer, true, "GET", idPath(y)+"/k8s/pods", "")
		assert.Equal(t, http.StatusForbidden, code, raw)
		assert.Equal(t, 1, e.podCalls, "只持檢視者不得打到 pod 清單")

		for _, who := range []uint{viewer, mixed} {
			for _, suffix := range []string{"", "/host-key", "/k8s/pods"} {
				sameResponse(t, "範圍外對不存在"+suffix, e, who, idPath(z)+suffix, "/api/v1/assets/"+saMissing+suffix)
			}
		}
		// 只經連線可視：與現行路徑相同
		_, scoped := e.do(viewer, true, "GET", idPath(x), "")
		_, plain := e.do(viewer, false, "GET", idPath(x), "")
		var sm, pm map[string]any
		require.NoError(t, json.Unmarshal([]byte(scoped), &sm))
		require.NoError(t, json.Unmarshal([]byte(plain), &pm))
		delete(sm, "actions")
		assert.Equal(t, pm, sm)

		for _, req := range [][2]string{{"DELETE", idPath(y) + "/host-key"}, {"POST", idPath(y) + "/host-key/adopt"}} {
			body := ""
			if req[0] == "POST" {
				body = `{"fingerprint":"SHA256:other"}`
			}
			code, _ := e.do(tester, true, req[0], req[1], body)
			assert.GreaterOrEqual(t, code, 400, "%s %s 須被拒", req[0], req[1])
		}
		assert.Equal(t, "SHA256:zz", e.hostKeys.recs[y].Fingerprint, "主機金鑰記錄不變")
	})
}

func saKeys(m map[uint]string) []uint {
	out := make([]uint, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	for len(out) < 2 {
		out = append(out, 0)
	}
	return out
}

// saFailingSource 投影查詢失敗的來源替身。
type saFailingSource struct{ api.AssetScopeSource }

var errSAProjection = errors.New("projection failed")

func (s saFailingSource) ManagementVisibleIDs(*authz.AssetScopeView) ([]uint, error) {
	return nil, errSAProjection
}

func (s saFailingSource) ManagementVisibleAsset(context.Context, uint) (bool, *authz.AssetScopeView, error) {
	return false, nil, errSAProjection
}

func TestScopedAssetOutOfScopeAttribution(t *testing.T) {
	setup := func(t *testing.T) (*saEnv, uint, uint, uint) {
		e := newSAEnv(t)
		saTree(e)
		u := e.user("zz-sa-attr")
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a")
		p := e.asset("zz-sa-p", "zz-sa-a1", "zz-sa-far-1", "zz-sa-far-2")
		x := e.asset("zz-sa-x", "zz-sa-b")
		e.connGrant(u, x)
		return e, u, p, x
	}
	checkMasked := func(t *testing.T, e *saEnv, row map[string]any, raw string) {
		t.Helper()
		require.NotNil(t, row)
		assert.Equal(t, []uint{e.nodes["zz-sa-a1"]}, uintsOf(row["node_ids"]))
		paths, _ := row["node_paths"].([]any)
		require.Len(t, paths, 1)
		assert.Equal(t, "zz-sa-a / zz-sa-a1", paths[0], "範圍內路徑保留定位祖先名稱（逐段比對，不以子字串）")
		assert.EqualValues(t, 2, row["out_of_scope_node_count"])
		assert.NotContains(t, raw, "zz-sa-far")
	}

	t.Run("list_and_detail_mask_out_of_scope_nodes", func(t *testing.T) {
		e, u, p, _ := setup(t)
		l := e.list(u, "")
		checkMasked(t, e, l.row(p), l.raw)
		code, raw := e.do(u, true, "GET", idPath(p), "")
		require.Equal(t, http.StatusOK, code, raw)
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &d))
		checkMasked(t, e, d, raw)
	})

	t.Run("authorized_only_keeps_mask", func(t *testing.T) {
		e, u, p, _ := setup(t)
		e.connGrant(u, p)
		e.asset("zz-sa-mgmt-only", "zz-sa-a1")
		l := e.list(u, "authorized_only=true")
		checkMasked(t, e, l.row(p), l.raw)
		assert.NotContains(t, l.raw, "zz-sa-mgmt-only")
		far := e.list(u, fmt.Sprintf("authorized_only=true&node_id=%d", e.nodes["zz-sa-far-1"]))
		assert.Nil(t, far.row(p), "以範圍外節點篩選不命中被遮蔽的列")
		assert.NotContains(t, far.raw, "zz-sa-far")
	})

	t.Run("connection_grant_still_masked", func(t *testing.T) {
		e, u, p, _ := setup(t)
		e.connGrant(u, p)
		l := e.list(u, "")
		checkMasked(t, e, l.row(p), l.raw)
	})

	t.Run("connection_only_row_unchanged", func(t *testing.T) {
		e, u, _, x := setup(t)
		row := e.list(u, "").row(x)
		require.NotNil(t, row)
		delete(row, "actions")
		g := e.user("zz-sa-plain")
		e.builtin(g, model.RoleUser)
		e.connGrant(g, x)
		_, plainRaw := e.do(g, false, "GET", "/api/v1/assets?page_size=500", "")
		var plain saList
		require.NoError(t, json.Unmarshal([]byte(plainRaw), &plain))
		want := plain.row(x)
		require.NotNil(t, want)
		assert.Equal(t, want["node_ids"], row["node_ids"])
		assert.Equal(t, want["node_paths"], row["node_paths"])
		assert.Equal(t, want, row, "只經連線可視的列除 actions 外與現行逐欄相同")
		_, has := row["out_of_scope_node_count"]
		assert.False(t, has)
	})

	t.Run("projection_failure_returns_error", func(t *testing.T) {
		e, u, p, _ := setup(t)
		e.source = saFailingSource{AssetScopeSource: authz.NewAssetScopeReader(e.eval, e.db)}
		code, raw := e.do(u, true, "GET", "/api/v1/assets?page_size=500", "")
		assert.Equal(t, http.StatusInternalServerError, code)
		assert.NotContains(t, raw, "zz-sa-")
		code, raw = e.do(u, true, "GET", idPath(p), "")
		assert.Equal(t, http.StatusInternalServerError, code)
		assert.NotContains(t, raw, "zz-sa-")
	})

	t.Run("global_principal_has_no_count_key", func(t *testing.T) {
		e, _, _, _ := setup(t)
		code, raw := e.do(e.super, true, "GET", "/api/v1/assets?page_size=500", "")
		require.Equal(t, http.StatusOK, code)
		assert.NotContains(t, raw, "out_of_scope_node_count")
	})
}

func saActions(t *testing.T, row map[string]any) map[string]map[string]any {
	t.Helper()
	require.NotNil(t, row)
	raw, ok := row["actions"].(map[string]any)
	require.True(t, ok, "列須帶 actions")
	out := map[string]map[string]any{}
	for k, v := range raw {
		m, _ := v.(map[string]any)
		out[k] = m
	}
	return out
}

func TestScopedAssetRowActions(t *testing.T) {
	e := newSAEnv(t)
	saTree(e)
	e.node("zz-sa-b2", "")
	e.node("zz-sa-c2", "")
	full := e.user("zz-sa-full")
	e.grantNodes(full, e.role(authz.PermAssetView, authz.PermAssetUpdate, authz.PermAssetDelete, authz.PermAssetTest), "zz-sa-a")
	p := e.asset("zz-sa-p", "zz-sa-a1", "zz-sa-far-1")
	x := e.asset("zz-sa-x", "zz-sa-b")
	e.connGrant(full, x)

	t.Run("in_scope_with_out_of_scope_attribution", func(t *testing.T) {
		a := saActions(t, e.list(full, "").row(p))
		assert.Equal(t, true, a["edit"]["allowed"])
		assert.Equal(t, true, a["test_connection"]["allowed"])
		for _, k := range []string{"delete", "disable"} {
			assert.Equal(t, false, a[k]["allowed"], k)
			assert.Equal(t, "out_of_scope_nodes", a[k]["reason"], k)
			assert.EqualValues(t, 1, a[k]["count"], k)
		}
	})

	t.Run("connection_only_row_out_of_scope", func(t *testing.T) {
		a := saActions(t, e.list(full, "").row(x))
		for _, k := range []string{"edit", "disable", "delete", "test_connection", "manage_accounts"} {
			assert.Equal(t, "out_of_scope", a[k]["reason"], k)
		}
	})

	t.Run("global_update_plus_node_delete", func(t *testing.T) {
		u := e.user("zz-sa-mix-ud")
		// 一般使用者範本（全域資產檢視）：列表路由的登錄閘要求持有資產檢視
		e.builtin(u, model.RoleUser)
		e.grantGlobal(u, e.role(authz.PermAssetUpdate))
		e.grantNodes(u, e.role(authz.PermAssetDelete), "zz-sa-a")
		e.connGrant(u, x)
		a := saActions(t, e.list(u, "").row(x))
		assert.Equal(t, true, a["edit"]["allowed"])
		assert.Equal(t, "out_of_scope", a["delete"]["reason"])
	})

	t.Run("missing_capability", func(t *testing.T) {
		u := e.user("zz-sa-viewonly")
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a")
		a := saActions(t, e.list(u, "").row(p))
		assert.Equal(t, "no_capability", a["delete"]["reason"])
	})

	t.Run("ungrouped_global_holder_allowed", func(t *testing.T) {
		u := e.user("zz-sa-global-del")
		e.grantGlobal(u, e.role(authz.PermAssetView, authz.PermAssetDelete))
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a")
		ung := e.asset("zz-sa-ungrouped")
		e.connGrant(u, ung)
		a := saActions(t, e.list(u, "").row(ung))
		// 未分組資產：持全域指派者照現行可刪停，不再回限超管的原因碼
		assert.Equal(t, true, a["delete"]["allowed"])
		assert.Nil(t, a["delete"]["reason"])

		// 只持節點範圍刪除能力者：未分組資產（只經連線可視）旗標為範圍外，送刪除與不存在同形
		n := e.user("zz-sa-node-del")
		e.grantNodes(n, e.role(authz.PermAssetView, authz.PermAssetDelete), "zz-sa-a")
		e.connGrant(n, ung)
		na := saActions(t, e.list(n, "").row(ung))
		assert.Equal(t, false, na["delete"]["allowed"])
		assert.Equal(t, "out_of_scope", na["delete"]["reason"])
		cU, rU := e.do(n, true, "DELETE", idPath(ung), "")
		cM, rM := e.do(n, true, "DELETE", "/api/v1/assets/"+saMissing, "")
		assert.Equal(t, http.StatusNotFound, cU, rU)
		assert.Equal(t, cM, cU)
		assert.JSONEq(t, rM, rU)
		var left int64
		require.NoError(t, database.DB.Model(&model.Asset{}).Where("id = ?", ung).Count(&left).Error)
		assert.Equal(t, int64(1), left, "未分組資產仍在")
	})

	t.Run("three_counts_per_permission", func(t *testing.T) {
		u := e.user("zz-sa-split")
		e.grantNodes(u, e.role(authz.PermAssetView), "zz-sa-a")
		e.grantNodes(u, e.role(authz.PermAssetDelete), "zz-sa-a", "zz-sa-b2")
		q := e.asset("zz-sa-q", "zz-sa-a", "zz-sa-b2", "zz-sa-c2")
		row := e.list(u, "").row(q)
		assert.EqualValues(t, 2, row["out_of_scope_node_count"])
		a := saActions(t, row)
		assert.EqualValues(t, 1, a["delete"]["count"])
		code, raw := e.do(u, true, "DELETE", idPath(q), "")
		assert.Equal(t, http.StatusConflict, code, raw)
		var body map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &body))
		assert.Equal(t, "RULE_ASSET_HAS_OUT_OF_SCOPE_NODES", body["code"])
		params, _ := body["params"].(map[string]any)
		assert.EqualValues(t, 1, params["count"])

		enc, err := json.Marshal(row["actions"])
		require.NoError(t, err)
		assert.NotContains(t, string(enc), "zz-sa")
		for _, n := range []string{"zz-sa-b2", "zz-sa-c2"} {
			assert.NotRegexp(t, regexp.MustCompile(fmt.Sprintf(`\b%d\b`, e.nodes[n])), string(enc), "旗標不含 %s 的識別碼", n)
		}
		for _, v := range a {
			for k := range v {
				assert.Contains(t, []string{"allowed", "reason", "count"}, k, "旗標只含受控鍵")
			}
		}
	})

	t.Run("server_rejects_flagged_delete", func(t *testing.T) {
		code, _ := e.do(full, true, "DELETE", idPath(p), "")
		assert.GreaterOrEqual(t, code, 400)
		var n int64
		require.NoError(t, database.DB.Model(&model.Asset{}).Where("id = ?", p).Count(&n).Error)
		assert.Equal(t, int64(1), n, "資產仍在")
	})

	t.Run("global_principal_has_no_actions", func(t *testing.T) {
		code, raw := e.do(e.super, true, "GET", "/api/v1/assets?page_size=500", "")
		require.Equal(t, http.StatusOK, code)
		assert.False(t, strings.Contains(raw, `"actions"`))
	})
}
