package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 授權列表與兩個有效權限視角的範圍化讀取夾具。
// 拓撲：p（定位祖先）→ a（範圍根）→ b；c（範圍外）→ d。名稱以 zz-ev- 起頭。
//   - x 掛 b（範圍內）、y 掛 d（範圍外）、m 同時掛 b 與 d（範圍內，另有一個範圍外歸屬）。
type evEnv struct {
	*awEnv
	nodeRule map[string]uint
	op       uint
	sub      uint
	x, y, m  uint
	rX, rY   uint // 直授資產的規則
	rM       uint
}

func (e *evEnv) seedNodeRule(subject uint, node string) uint {
	e.t.Helper()
	nodeID := e.nodes[node]
	a := model.AssetAuthorization{UserID: &subject, AssetGroupID: &nodeID, Permission: model.PermissionView,
		GrantedBy: e.super, Accounts: model.AccountScope{model.AccountScopeAll}}
	require.NoError(e.t, e.db.Create(&a).Error)
	e.nodeRule[node] = a.ID
	return a.ID
}

// newEVEnv 的 extra 見 newAWEnv。
func newEVEnv(t *testing.T, extra ...authz.Permission) *evEnv {
	t.Helper()
	e := &evEnv{awEnv: newAWEnv(t, extra...), nodeRule: map[string]uint{}}
	e.node("zz-ev-p", "")
	e.node("zz-ev-a", "zz-ev-p")
	e.node("zz-ev-b", "zz-ev-a")
	e.node("zz-ev-c", "")
	e.node("zz-ev-d", "zz-ev-c")
	e.x = e.asset("zz-ev-x", "zz-ev-b")
	e.y = e.asset("zz-ev-y", "zz-ev-d")
	e.m = e.asset("zz-ev-m", "zz-ev-b", "zz-ev-d")
	e.op = e.user("zz-ev-op")
	e.grantNodes(e.op, e.role(authz.PermAuthorizationManage), "zz-ev-a")
	e.sub = e.user("zz-ev-sub")
	e.rX = e.seedRule(e.sub, e.x)
	e.rY = e.seedRule(e.sub, e.y)
	e.rM = e.seedRule(e.sub, e.m)
	for _, n := range []string{"zz-ev-p", "zz-ev-a", "zz-ev-c", "zz-ev-d"} {
		e.seedNodeRule(e.sub, n)
	}
	return e
}

func (e *evEnv) get(uid uint, path string) (int, string) {
	e.t.Helper()
	return e.do2(uid, "GET", path, "")
}

type evList struct {
	Data []struct {
		ID uint `json:"id"`
	} `json:"data"`
	Total int64 `json:"total"`
}

func (e *evEnv) listIDs(uid uint, query string) (map[uint]bool, int64, string) {
	e.t.Helper()
	code, body := e.get(uid, "/api/v1/authorizations?page_size=100"+query)
	require.Equal(e.t, http.StatusOK, code, body)
	var l evList
	require.NoError(e.t, json.Unmarshal([]byte(body), &l), body)
	ids := map[uint]bool{}
	for _, d := range l.Data {
		ids[d.ID] = true
	}
	return ids, l.Total, body
}

// 規則客體在範圍內的集合：x、m（資產），a（範圍根）。
func (e *evEnv) inScopeRules() []uint {
	return []uint{e.rX, e.rM, e.nodeRule["zz-ev-a"]}
}

func (e *evEnv) outOfScopeRules() []uint {
	return []uint{e.rY, e.nodeRule["zz-ev-p"], e.nodeRule["zz-ev-c"], e.nodeRule["zz-ev-d"]}
}

// TestScopedAuthorizationListProjection 範圍化檢視者的授權列表：客體在範圍內的規則才進入結果，
// 計數與分頁同源；範圍外的資產或節點篩選與不存在同形；全域檢視者不受影響。
func TestScopedAuthorizationListProjection(t *testing.T) {
	e := newEVEnv(t)
	const missing = 999911

	t.Run("scoped viewer sees only rules whose object is in scope", func(t *testing.T) {
		ids, total, body := e.listIDs(e.op, "")
		for _, id := range e.inScopeRules() {
			require.True(t, ids[id], "範圍內規則缺席 %d: %s", id, body)
		}
		for _, id := range e.outOfScopeRules() {
			require.False(t, ids[id], "範圍外規則出現 %d", id)
		}
		require.EqualValues(t, len(e.inScopeRules()), total)
		require.Len(t, ids, len(e.inScopeRules()))
	})
	t.Run("count and paging come from the scoped set", func(t *testing.T) {
		code, body := e.get(e.op, "/api/v1/authorizations?page=2&page_size=2")
		require.Equal(t, http.StatusOK, code, body)
		var l evList
		require.NoError(t, json.Unmarshal([]byte(body), &l))
		require.EqualValues(t, len(e.inScopeRules()), l.Total)
		require.Len(t, l.Data, len(e.inScopeRules())-2)
	})
	t.Run("out of scope asset filter equals nonexistent", func(t *testing.T) {
		c1, b1 := e.get(e.op, fmt.Sprintf("/api/v1/authorizations?asset_id=%d", e.y))
		c2, b2 := e.get(e.op, fmt.Sprintf("/api/v1/authorizations?asset_id=%d", missing))
		require.Equal(t, http.StatusOK, c1, b1)
		require.Equal(t, c2, c1)
		require.Equal(t, b2, b1)
	})
	t.Run("out of scope node filter equals nonexistent", func(t *testing.T) {
		// d 節點下的資產 m 也掛在範圍內：以 d 篩選不得因多歸屬橋接而洩漏範圍內規則
		for _, n := range []string{"zz-ev-c", "zz-ev-d"} {
			c1, b1 := e.get(e.op, fmt.Sprintf("/api/v1/authorizations?node_id=%d", e.nodes[n]))
			c2, b2 := e.get(e.op, fmt.Sprintf("/api/v1/authorizations?node_id=%d", missing))
			require.Equal(t, http.StatusOK, c1, b1)
			require.Equal(t, c2, c1)
			require.Equal(t, b2, b1, n)
		}
	})
	t.Run("zero node filter equals nonexistent", func(t *testing.T) {
		c0, b0 := e.get(e.op, "/api/v1/authorizations?node_id=0")
		cm, bm := e.get(e.op, fmt.Sprintf("/api/v1/authorizations?node_id=%d", missing))
		require.Equal(t, http.StatusOK, c0, b0)
		require.Equal(t, cm, c0)
		require.Equal(t, bm, b0)
		// 全域檢視者的既有回應不變：空結果
		ids, total, body := e.listIDs(e.super, "&node_id=0")
		require.Empty(t, ids, body)
		require.EqualValues(t, 0, total)
	})
	t.Run("node filter in scope is intersected with scope", func(t *testing.T) {
		ids, _, body := e.listIDs(e.op, fmt.Sprintf("&node_id=%d", e.nodes["zz-ev-b"]))
		require.True(t, ids[e.rX], body)
		for _, id := range e.outOfScopeRules() {
			require.False(t, ids[id], "範圍外規則經涵蓋盤點洩漏 %d", id)
		}
	})
	t.Run("subject filters stay as is", func(t *testing.T) {
		ids, total, _ := e.listIDs(e.op, fmt.Sprintf("&user_id=%d", e.sub))
		require.EqualValues(t, len(e.inScopeRules()), total)
		require.False(t, ids[e.rY])
	})
	t.Run("global viewer is unchanged", func(t *testing.T) {
		ids, total, _ := e.listIDs(e.super, "")
		require.EqualValues(t, len(e.inScopeRules())+len(e.outOfScopeRules()), total)
		for _, id := range append(e.inScopeRules(), e.outOfScopeRules()...) {
			require.True(t, ids[id])
		}
	})
	t.Run("viewer without a scoped binding gets an empty page", func(t *testing.T) {
		nobody := e.user("zz-ev-nobody")
		ids, total, _ := e.listIDs(nobody, "")
		require.Empty(t, ids)
		require.EqualValues(t, 0, total)
	})
}

type evPath struct {
	Kind            string `json:"kind"`
	AuthorizationID *uint  `json:"authorization_id"`
	ViaNodeID       *uint  `json:"via_node_id"`
	ViaNodePath     string `json:"via_node_path"`
}

type evEntry struct {
	AssetID   uint     `json:"asset_id"`
	UserID    uint     `json:"user_id"`
	Paths     []evPath `json:"paths"`
	NodeCount *int     `json:"out_of_scope_node_count"`
}

func (e *evEnv) assetsView(uid uint) ([]evEntry, string) {
	e.t.Helper()
	code, body := e.get(uid, fmt.Sprintf("/api/v1/authorizations/effective-assets?user_id=%d", e.sub))
	require.Equal(e.t, http.StatusOK, code, body)
	var r struct {
		Assets []evEntry `json:"assets"`
	}
	require.NoError(e.t, json.Unmarshal([]byte(body), &r), body)
	return r.Assets, body
}

func (e *evEnv) usersView(uid, assetID uint) (int, []evEntry, string) {
	e.t.Helper()
	code, body := e.get(uid, fmt.Sprintf("/api/v1/authorizations/effective-users?asset_id=%d", assetID))
	var r struct {
		Users []evEntry `json:"users"`
	}
	if code == http.StatusOK {
		require.NoError(e.t, json.Unmarshal([]byte(body), &r), body)
	}
	return code, r.Users, body
}

func evFind(entries []evEntry, assetID uint) *evEntry {
	for i := range entries {
		if entries[i].AssetID == assetID {
			return &entries[i]
		}
	}
	return nil
}

// TestScopedEffectiveViews 兩個有效權限視角：主體視角資產與檢視者範圍取交集；客體視角範圍外與不存在同為 404；
// 溯因不帶範圍外節點的名稱與識別，範圍外歸屬節點數以匿名計數呈現。
func TestScopedEffectiveViews(t *testing.T) {
	e := newEVEnv(t)
	const missing = 999913

	t.Run("subject view keeps only in scope assets and gives no count for the rest", func(t *testing.T) {
		assets, body := e.assetsView(e.op)
		require.NotNil(t, evFind(assets, e.x), body)
		require.NotNil(t, evFind(assets, e.m), body)
		require.Nil(t, evFind(assets, e.y), body)
		require.NotContains(t, body, "zz-ev-y")
		require.NotContains(t, body, "zz-ev-c")
	})
	t.Run("subject view masks rule id and node outside the visible nodes", func(t *testing.T) {
		assets, body := e.assetsView(e.op)
		x := evFind(assets, e.x)
		require.NotNil(t, x, body)
		var sawVisibleRule, sawLocatorMaskedRule bool
		for _, p := range x.Paths {
			if p.AuthorizationID != nil && *p.AuthorizationID == e.rX {
				sawVisibleRule = true
			}
			// 定位祖先 p 的規則客體在範圍外：規則識別碼省略，但節點屬可見節點而保留
			if p.ViaNodeID != nil && *p.ViaNodeID == e.nodes["zz-ev-p"] {
				require.Nil(t, p.AuthorizationID, body)
				sawLocatorMaskedRule = true
			}
		}
		require.True(t, sawVisibleRule, body)
		require.True(t, sawLocatorMaskedRule, body)
		require.Nil(t, x.NodeCount, "只遮蔽規則識別碼時不需計數")

		m := evFind(assets, e.m)
		require.NotNil(t, m, body)
		for _, p := range m.Paths {
			if p.Kind == authz.PathAssetNode && p.ViaNodeID == nil {
				require.Empty(t, p.ViaNodePath)
				require.Nil(t, p.AuthorizationID)
			}
			if p.ViaNodeID != nil {
				require.NotEqual(t, e.nodes["zz-ev-d"], *p.ViaNodeID)
				require.NotEqual(t, e.nodes["zz-ev-c"], *p.ViaNodeID)
			}
		}
		require.NotNil(t, m.NodeCount, body)
		require.Equal(t, 1, *m.NodeCount, "m 的範圍外歸屬只有 d 一個")
	})
	t.Run("global viewer gets the unmasked response", func(t *testing.T) {
		assets, body := e.assetsView(e.super)
		require.NotNil(t, evFind(assets, e.y), body)
		require.NotContains(t, body, "out_of_scope_node_count")
		for _, a := range assets {
			for _, p := range a.Paths {
				require.NotNil(t, p.AuthorizationID, body)
			}
		}
	})
	t.Run("object view out of scope equals nonexistent", func(t *testing.T) {
		c1, _, b1 := e.usersView(e.op, e.y)
		c2, _, b2 := e.usersView(e.op, missing)
		require.Equal(t, http.StatusNotFound, c1, b1)
		require.Equal(t, c2, c1)
		require.Equal(t, b2, b1)
		require.NotContains(t, b1, "zz-ev-")
	})
	t.Run("object view lists users truthfully and masks provenance", func(t *testing.T) {
		code, users, body := e.usersView(e.op, e.m)
		require.Equal(t, http.StatusOK, code, body)
		require.Len(t, users, 1, body)
		u := users[0]
		require.Equal(t, e.sub, u.UserID)
		// 經範圍外節點 d 的規則仍列為可及路徑，但不帶節點名稱與識別
		require.NotContains(t, body, "zz-ev-d")
		require.NotContains(t, body, "zz-ev-c")
		require.NotNil(t, u.NodeCount, body)
		require.Equal(t, 1, *u.NodeCount)
		masked := false
		for _, p := range u.Paths {
			if p.Kind == authz.PathAssetNode && p.ViaNodeID == nil {
				masked = true
				require.Nil(t, p.AuthorizationID)
			}
		}
		require.True(t, masked, body)
	})
	t.Run("object view in scope without masked nodes carries no count", func(t *testing.T) {
		code, users, body := e.usersView(e.op, e.x)
		require.Equal(t, http.StatusOK, code, body)
		require.Len(t, users, 1)
		require.Nil(t, users[0].NodeCount, body)
	})
	t.Run("viewer without a scoped binding sees nothing", func(t *testing.T) {
		nobody := e.user("zz-ev-nobody2")
		code, _, body := e.usersView(nobody, e.x)
		require.Equal(t, http.StatusNotFound, code, body)
		c2, _, b2 := e.usersView(nobody, missing)
		require.Equal(t, c2, code)
		require.Equal(t, b2, body)
		assets, abody := e.assetsView(nobody)
		require.Empty(t, assets, abody)
	})
	t.Run("only the authorization capability projects the views", func(t *testing.T) {
		// 另一份夾具：資產檢視也標為範圍生效，使 B 上的資產檢視指派確實被物化
		f := newEVEnv(t, authz.PermAssetView)
		f.node("zz-ev-bv", "")
		f.node("zz-ev-cc", "")
		bv := f.asset("zz-ev-bv-asset", "zz-ev-bv")
		cc := f.asset("zz-ev-cc-asset", "zz-ev-cc")
		f.seedRule(f.sub, bv)
		f.seedRule(f.sub, cc)
		mixed := f.user("zz-ev-mixed")
		f.grantNodes(mixed, f.role(authz.PermAuthorizationManage), "zz-ev-a")
		f.grantNodes(mixed, f.role(authz.PermAssetView), "zz-ev-bv")
		f.seedRule(mixed, cc) // 可連線 C 下的資產
		p, err := authz.ResolveUserOnWithCatalogue(f.db, f.cat, mixed, authz.TokenFacts{})
		require.NoError(t, err)
		require.True(t, p.Has(authz.PermAssetView), "B 上的資產檢視指派須已物化")
		require.True(t, p.Has(authz.PermAuthorizationManage))

		assets, body := f.assetsView(mixed)
		got := map[uint]bool{}
		for _, a := range assets {
			got[a.AssetID] = true
		}
		require.Equal(t, map[uint]bool{f.x: true, f.m: true}, got, body)
		require.NotContains(t, body, "zz-ev-bv")
		require.NotContains(t, body, "zz-ev-cc")
		for _, a := range assets {
			for _, pth := range a.Paths {
				if pth.ViaNodeID != nil {
					require.NotEqual(t, f.nodes["zz-ev-bv"], *pth.ViaNodeID)
					require.NotEqual(t, f.nodes["zz-ev-cc"], *pth.ViaNodeID)
				}
			}
		}
		cm, _, bm := f.usersView(mixed, missing)
		require.Equal(t, http.StatusNotFound, cm, bm)
		for _, id := range []uint{bv, cc} {
			c1, _, b1 := f.usersView(mixed, id)
			require.Equal(t, cm, c1)
			require.Equal(t, bm, b1)
		}
		code, users, ubody := f.usersView(mixed, f.x)
		require.Equal(t, http.StatusOK, code, ubody)
		require.Len(t, users, 1, ubody)
	})
}
