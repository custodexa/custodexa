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
	"github.com/custodexa/backend/internal/modules/authz"
)

// 單台覆寫清單（GET /api/v1/assets/access-policy-overrides）的範圍投影，經正式 handler、登錄閘與真判定器。
// 範圍只依存取政策權限點的有效指派；連線授權與其他權限點的節點範圍不擴大、不改變結果。

// apDefaultReason 全域預設讀取面替身：存取政策預設為 reason。
type apDefaultReason struct{}

func (apDefaultReason) Get(string) string { return model.AccessPolicyReason }

type apOverrideList struct {
	Data  []map[string]any `json:"data"`
	Total int64            `json:"total"`
	Meta  struct {
		GlobalDefault string `json:"global_default"`
		Scoped        bool   `json:"scoped"`
	} `json:"meta"`
	raw string
}

func (l apOverrideList) names() []string {
	out := []string{}
	for _, r := range l.Data {
		out = append(out, fmt.Sprint(r["name"]))
	}
	sort.Strings(out)
	return out
}

func (l apOverrideList) row(name string) map[string]any {
	for _, r := range l.Data {
		if r["name"] == name {
			return r
		}
	}
	return nil
}

// apListRaw 以使用者 uid 查詢覆寫清單，回狀態與本文。
func apListRaw(t *testing.T, e *saEnv, uid uint, query string) (int, string) {
	t.Helper()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Next()
	})
	h := api.NewAssetHandler(e.assets, e.authzSvc, nil)
	r.GET("/api/v1/assets/access-policy-overrides", middleware.EnforceRegistry(), h.ListAccessPolicyOverrides)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/assets/access-policy-overrides?"+query, nil))
	return w.Code, w.Body.String()
}

func apList(t *testing.T, e *saEnv, uid uint, query string) apOverrideList {
	t.Helper()
	code, raw := apListRaw(t, e, uid, query)
	require.Equal(t, http.StatusOK, code, raw)
	var out apOverrideList
	require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
	out.raw = raw
	return out
}

// apOverridden 建一台掛在 nodes 的已覆寫資產。
func apOverridden(t *testing.T, e *saEnv, name, policy string, nodes ...string) uint {
	t.Helper()
	id := e.asset(name, nodes...)
	apSetPolicy(t, e, id, policy)
	return id
}

func TestAccessPolicyOverrideListProjection(t *testing.T) {
	seed := func(t *testing.T) (*saEnv, uint) {
		e, _ := newAPEnv(t)
		e.assets.SetAccessPolicyDefaultReader(apDefaultReason{})
		holder := e.user("zz-sa-ap-holder")
		e.grantNodes(holder, e.role(authz.PermAccessPolicyManage, authz.PermAssetView), "zz-sa-a")
		apOverridden(t, e, "zz-sa-ap-in-1", model.AccessPolicyApproval, "zz-sa-a")
		apOverridden(t, e, "zz-sa-ap-in-2", model.AccessPolicyOpen, "zz-sa-a1")
		apOverridden(t, e, "zz-sa-ap-in-3", model.AccessPolicyReason, "zz-sa-a", "zz-sa-far-1", "zz-sa-far-2")
		for i := 1; i <= 5; i++ {
			apOverridden(t, e, fmt.Sprintf("zz-sa-ap-out-%d", i), model.AccessPolicyApproval, "zz-sa-b")
		}
		e.asset("zz-sa-ap-plain-in", "zz-sa-a")
		e.asset("zz-sa-ap-plain-out", "zz-sa-c")
		return e, holder
	}

	t.Run("scoped_holder_sees_in_scope_only", func(t *testing.T) {
		e, holder := seed(t)
		l := apList(t, e, holder, "")
		assert.Equal(t, []string{"zz-sa-ap-in-1", "zz-sa-ap-in-2", "zz-sa-ap-in-3"}, l.names())
		assert.EqualValues(t, 3, l.Total)
		assert.True(t, l.Meta.Scoped, "範圍化持有者 meta.scoped=true")
		multi := l.row("zz-sa-ap-in-3")
		require.NotNil(t, multi)
		assert.EqualValues(t, 2, multi["out_of_scope_node_count"], "掛 A 內 1、範圍外 2：計數 2")
		assert.Equal(t, []any{"zz-sa-a"}, multi["node_paths"], "只含範圍內節點路徑")
		assert.Len(t, uintsOf(multi["node_ids"]), 1)
		for _, n := range []string{"zz-sa-far-1", "zz-sa-far-2", "zz-sa-b"} {
			assert.NotContains(t, l.raw, n, "回應不含範圍外節點名稱或路徑 %s", n)
		}
		for _, r := range l.Data {
			for _, v := range uintsOf(r["node_ids"]) {
				for _, n := range []string{"zz-sa-far-1", "zz-sa-far-2", "zz-sa-b"} {
					assert.NotEqual(t, e.nodes[n], v, "範圍外節點 ID 不出 %s", n)
				}
			}
		}
		assert.Contains(t, l.raw, `"out_of_scope_node_count":0`, "範圍化檢視者每列都帶計數鍵（含 0）")
		t.Logf("EVIDENCE ap-list-scoped total=%d names=%v body=%s", l.Total, l.names(), l.raw)
	})

	t.Run("connect_grant_does_not_widen", func(t *testing.T) {
		e, holder := seed(t)
		y := apOverridden(t, e, "zz-sa-ap-granted-y", model.AccessPolicyApproval, "zz-sa-c")
		e.connGrant(holder, y)
		l := apList(t, e, holder, "")
		assert.Nil(t, l.row("zz-sa-ap-granted-y"), "覆寫清單不含經授權可連線的範圍外資產")
		apSetPolicy(t, e, y, "")
		s := apList(t, e, holder, "overridden=false&search=zz-sa-ap")
		assert.Nil(t, s.row("zz-sa-ap-granted-y"), "加入覆寫的搜尋不含範圍外資產")
		assert.Equal(t, []string{"zz-sa-ap-plain-in"}, s.names(), "搜尋只回範圍內未覆寫資產")
		assert.EqualValues(t, 1, s.Total)
		e2 := apList(t, e, holder, "overridden=false")
		assert.Empty(t, e2.Data, "未帶搜尋的候選查詢回空集合")
		assert.EqualValues(t, 0, e2.Total)
	})

	t.Run("other_permission_scope_does_not_change_result", func(t *testing.T) {
		e, _ := seed(t)
		mixed := e.user("zz-sa-ap-global")
		e.grantGlobal(mixed, e.role(authz.PermAccessPolicyManage))
		e.grantNodes(mixed, e.role(authz.PermAssetView), "zz-sa-a")
		l := apList(t, e, mixed, "")
		assert.EqualValues(t, 8, l.Total, "全域持存取政策：全部已覆寫資產")
		assert.False(t, l.Meta.Scoped, "另經節點範圍持資產檢視不使其成為範圍化檢視者")
		multi := l.row("zz-sa-ap-in-3")
		require.NotNil(t, multi)
		assert.Len(t, uintsOf(multi["node_ids"]), 3, "節點歸屬完整")
		_, has := multi["out_of_scope_node_count"]
		assert.False(t, has, "非範圍化檢視者不帶計數鍵")
	})

	t.Run("meta_global_default", func(t *testing.T) {
		e, holder := seed(t)
		l := apList(t, e, holder, "")
		assert.Equal(t, model.AccessPolicyReason, l.Meta.GlobalDefault)
	})

	t.Run("asset_view_only_rejected", func(t *testing.T) {
		e, _ := seed(t)
		viewer := e.user("zz-sa-ap-viewer")
		e.grantGlobal(viewer, e.role(authz.PermAssetView))
		code, raw := apListRaw(t, e, viewer, "")
		assert.Equal(t, http.StatusForbidden, code, raw)
		assert.Equal(t, "AUTH_PERMISSION_DENIED", saErrorCode(t, raw))
		assert.False(t, strings.Contains(raw, "zz-sa-ap"), "拒絕回應不含資產")
	})

	t.Run("super_admin_sees_all", func(t *testing.T) {
		e, _ := seed(t)
		l := apList(t, e, e.super, "")
		assert.EqualValues(t, 8, l.Total)
		assert.False(t, l.Meta.Scoped)
		assert.NotContains(t, l.raw, "out_of_scope_node_count", "超管無範圍外計數鍵")
		multi := l.row("zz-sa-ap-in-3")
		require.NotNil(t, multi)
		assert.Len(t, uintsOf(multi["node_ids"]), 3)
		t.Logf("EVIDENCE ap-list-super total=%d scoped=%v", l.Total, l.Meta.Scoped)
	})

	t.Run("paging_and_bad_params", func(t *testing.T) {
		e, holder := seed(t)
		l := apList(t, e, holder, "page=2&page_size=2")
		assert.EqualValues(t, 3, l.Total, "total 為分頁前筆數")
		assert.Equal(t, []string{"zz-sa-ap-in-3"}, l.names())
		code, raw := apListRaw(t, e, holder, "overridden=maybe")
		assert.Equal(t, http.StatusBadRequest, code, raw)
	})
}
