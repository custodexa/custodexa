package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 樹端點與平面節點列表的範圍化投影、用途參數與列級旗標。

type nodeRow = map[string]any

var nodeRowFlagKeys = []string{"manageable", "locator_only", "scope_root", "can_create_child", "can_rename", "can_move", "can_delete"}

// treeFixture 每個節點各掛一台資產（prod 另有一台直掛）。
type treeFixture struct {
	*nodeScopeEnv
	assets map[string]uint // 資產名 → 識別碼
}

func newTreeFixture(t *testing.T) *treeFixture {
	t.Helper()
	e := newNodeScopeEnv(t, authz.PermAssetView, authz.PermAssetUpdate, authz.PermAssetCreate,
		authz.PermCredentialCreate, authz.PermCredentialUpdate, authz.PermCredentialConvertScope)
	f := &treeFixture{nodeScopeEnv: e, assets: map[string]uint{}}
	for _, a := range [][2]string{{"a-prod", "prod"}, {"a-db", "prod/db"}, {"a-db-a", "prod/db/a"}, {"a-db-b", "prod/db/b"},
		{"a-web", "prod/web"}, {"a-sit-web", "sit/web"}} {
		f.assets[a[0]] = e.asset(a[0], a[1])
	}
	return f
}

func (e *nodeScopeEnv) pathOf(id uint) string {
	for p, v := range e.nodes {
		if v == id {
			return p
		}
	}
	return fmt.Sprintf("#%d", id)
}

func rowID(r nodeRow) uint { return uint(r["id"].(float64)) }

// treeAll 以惰性子層逐層展開樹端點：回 節點識別碼→列、根層回應、各層原始 body 依序串接。
func (e *nodeScopeEnv) treeAll(h *AssetGroupHandler, uid uint) (map[uint]nodeRow, map[string]any, string) {
	e.t.Helper()
	rows := map[uint]nodeRow{}
	var root map[string]any
	var raw strings.Builder
	queue := []string{"/asset-groups/tree"}
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		code, body := e.doWith(h, uid, http.MethodGet, path, nil)
		require.Equal(e.t, http.StatusOK, code, string(body))
		raw.Write(body)
		raw.WriteByte('\n')
		var resp map[string]any
		require.NoError(e.t, json.Unmarshal(body, &resp))
		if root == nil {
			root = resp
		}
		data, _ := resp["data"].([]any)
		for _, d := range data {
			r := d.(map[string]any)
			rows[rowID(r)] = r
			if r["has_children"] == true {
				queue = append(queue, fmt.Sprintf("/asset-groups/tree?parent_id=%d", rowID(r)))
			}
		}
	}
	return rows, root, raw.String()
}

// listNodes 平面節點列表：回 節點識別碼→列、整體回應、原始 body。
func (e *nodeScopeEnv) listNodes(h *AssetGroupHandler, uid uint, query string) (map[uint]nodeRow, map[string]any, string) {
	e.t.Helper()
	path := "/asset-groups"
	if query != "" {
		path += "?" + query
	}
	code, body := e.doWith(h, uid, http.MethodGet, path, nil)
	require.Equal(e.t, http.StatusOK, code, string(body))
	var resp map[string]any
	require.NoError(e.t, json.Unmarshal(body, &resp))
	rows := map[uint]nodeRow{}
	data, _ := resp["data"].([]any)
	for _, d := range data {
		r := d.(map[string]any)
		rows[rowID(r)] = r
	}
	return rows, resp, string(body)
}

func (e *nodeScopeEnv) pathSet(rows map[uint]nodeRow) []string {
	out := make([]string, 0, len(rows))
	for id := range rows {
		out = append(out, e.pathOf(id))
	}
	sort.Strings(out)
	return out
}

func (e *nodeScopeEnv) row(rows map[uint]nodeRow, path string) nodeRow {
	e.t.Helper()
	r, ok := rows[e.id(path)]
	require.True(e.t, ok, "回應含 %s", path)
	return r
}

func sortedStrings(s ...string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// rowAssetIDs 平面列表一列的資產識別碼。
func rowAssetIDs(r nodeRow) []uint {
	var out []uint
	list, _ := r["assets"].([]any)
	for _, a := range list {
		out = append(out, uint(a.(map[string]any)["id"].(float64)))
	}
	return out
}

// assertFlagBools 每列七個旗標鍵皆存在且為布林。
func assertFlagBools(t *testing.T, rows map[uint]nodeRow) {
	t.Helper()
	for id, r := range rows {
		for _, k := range nodeRowFlagKeys {
			_, isBool := r[k].(bool)
			assert.True(t, isBool, "節點 %d 的 %s 為明確布林", id, k)
		}
	}
}

func assertNoFlagKeys(t *testing.T, rows map[uint]nodeRow) {
	t.Helper()
	for id, r := range rows {
		for _, k := range append([]string{"selectable"}, nodeRowFlagKeys...) {
			_, has := r[k]
			assert.False(t, has, "節點 %d 不帶 %s", id, k)
		}
	}
}

// assertSelectableBools 每列 selectable 與頂層 selectable_all 皆為明確布林（不以缺欄或 null 表示全量或空）。
func assertSelectableBools(t *testing.T, resp map[string]any, rows map[uint]nodeRow) {
	t.Helper()
	_, isBool := resp["selectable_all"].(bool)
	assert.True(t, isBool, "selectable_all 為明確布林")
	for id, r := range rows {
		_, isBool := r["selectable"].(bool)
		assert.True(t, isBool, "節點 %d 的 selectable 為明確布林", id)
	}
}

func (e *nodeScopeEnv) principal(uid uint) *authz.Principal {
	e.t.Helper()
	p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
	require.NoError(e.t, err)
	return p
}

func (e *nodeScopeEnv) deletedNode(path, parent string) {
	e.t.Helper()
	id := e.node(path, parent)
	require.NoError(e.t, e.db.Delete(&model.AssetGroup{}, id).Error)
}

func TestNodeTreeScopeProjection(t *testing.T) {
	scopeSubtree := sortedStrings("prod", "prod/db", "prod/db/a", "prod/db/b")

	t.Run("node_scope_viewer_sees_scope_subtree_and_locator", func(t *testing.T) {
		f := newTreeFixture(t)
		u := f.user("viewer")
		f.grantNodes(u, f.role(authz.PermAssetView), "prod/db")

		tree, _, _ := f.treeAll(f.h, u)
		assert.Equal(t, scopeSubtree, f.pathSet(tree), "樹：prod 只作定位、prod/db 子樹，不含 prod/web")
		prod := f.row(tree, "prod")
		assert.Equal(t, false, prod["manageable"])
		assert.Equal(t, true, prod["locator_only"])
		for _, k := range []string{"can_create_child", "can_rename", "can_move", "can_delete"} {
			assert.Equal(t, false, prod[k], "prod 不可操作：%s", k)
		}
		assert.Equal(t, float64(3), prod["subtree_asset_count"], "prod 子樹計數只計可視資產")
		assert.Equal(t, f.row(tree, "prod/db")["subtree_asset_count"], prod["subtree_asset_count"], "等於 prod/db 子樹可視資產數")
		assertFlagBools(t, tree)

		list, _, _ := f.listNodes(f.h, u, "")
		assert.Equal(t, scopeSubtree, f.pathSet(list), "平面列表同一組節點")
		visible := map[uint]bool{f.assets["a-db"]: true, f.assets["a-db-a"]: true, f.assets["a-db-b"]: true}
		for id, r := range list {
			for _, a := range rowAssetIDs(r) {
				assert.True(t, visible[a], "節點 %s 的資產陣列只含可視資產（得 %d）", f.pathOf(id), a)
			}
		}
		assert.Empty(t, rowAssetIDs(f.row(list, "prod")), "prod 直掛資產不可視")
	})

	t.Run("union_with_connection_visibility", func(t *testing.T) {
		f := newTreeFixture(t)
		u := f.user("viewer")
		f.grantNodes(u, f.role(authz.PermAssetView), "prod/db")
		f.connect(u, f.assets["a-sit-web"])

		want := sortedStrings(append(append([]string(nil), scopeSubtree...), "sit", "sit/web")...)
		tree, _, _ := f.treeAll(f.h, u)
		assert.Equal(t, want, f.pathSet(tree))
		list, _, _ := f.listNodes(f.h, u, "")
		assert.Equal(t, want, f.pathSet(list))
	})

	t.Run("multi_mounted_manage_asset_does_not_expose_outside_node", func(t *testing.T) {
		f := newTreeFixture(t)
		multi := f.asset("a-multi", "prod/db/b", "sit/web") // 範圍內與範圍外各掛一處
		u := f.user("viewer")
		f.grantNodes(u, f.role(authz.PermAssetView), "prod/db")

		tree, _, _ := f.treeAll(f.h, u)
		assert.Equal(t, scopeSubtree, f.pathSet(tree), "樹端點不含 sit、sit/web")
		list, _, _ := f.listNodes(f.h, u, "")
		assert.Equal(t, scopeSubtree, f.pathSet(list), "平面列表不因管理可視資產另掛範圍外而列出 sit、sit/web")
		assert.Contains(t, rowAssetIDs(f.row(list, "prod/db/b")), multi, "範圍內掛載處仍列出該資產")

		// 範圍外節點經連線授權本來可視時照常列出，且不是只作定位
		f.connect(u, f.assets["a-sit-web"])
		want := sortedStrings(append(append([]string(nil), scopeSubtree...), "sit", "sit/web")...)
		list, _, _ = f.listNodes(f.h, u, "")
		assert.Equal(t, want, f.pathSet(list))
		assert.Equal(t, false, f.row(list, "sit/web")["locator_only"])
		assert.Equal(t, true, f.row(list, "sit")["locator_only"])
	})

	t.Run("deleted_scope_node_does_not_change_result", func(t *testing.T) {
		f := newTreeFixture(t)
		f.deletedNode("sit/old", "sit")
		plainScope := f.user("viewer-a")
		f.grantNodes(plainScope, f.role(authz.PermAssetView), "prod/db")
		withDeleted := f.user("viewer-b")
		f.grantNodes(withDeleted, f.role(authz.PermAssetView), "prod/db", "sit/old")

		_, _, treeA := f.treeAll(f.h, plainScope)
		_, _, treeB := f.treeAll(f.h, withDeleted)
		assert.Equal(t, treeA, treeB, "範圍含已刪節點時樹與不含時相同")
		_, _, listA := f.listNodes(f.h, plainScope, "")
		_, _, listB := f.listNodes(f.h, withDeleted, "")
		assert.Equal(t, listA, listB, "平面列表相同")
	})

	t.Run("all_scope_nodes_deleted_yields_empty", func(t *testing.T) {
		f := newTreeFixture(t)
		f.deletedNode("sit/old", "sit")
		u := f.user("viewer")
		f.grantNodes(u, f.role(authz.PermAssetView), "sit/old")

		tree, _, _ := f.treeAll(f.h, u)
		assert.Empty(t, tree, "樹不回退全量")
		list, resp, _ := f.listNodes(f.h, u, "")
		assert.Empty(t, list)
		assert.Equal(t, float64(0), resp["total"])
	})

	t.Run("global_only_holder_response_unchanged", func(t *testing.T) {
		f := newTreeFixture(t)
		g := f.user("global-viewer")
		f.grantGlobal(g, f.role(authz.PermAssetView))
		f.connect(g, f.assets["a-web"])

		tree, _, rawTree := f.treeAll(f.h, g)
		_, _, rawTreePlain := f.treeAll(f.plain, g)
		assert.Equal(t, rawTreePlain, rawTree, "樹端點與現行讀取路徑逐位元組相同")
		assert.Equal(t, sortedStrings("prod", "prod/web"), f.pathSet(tree), "仍為連線可視")
		assertNoFlagKeys(t, tree)
		list, resp, rawList := f.listNodes(f.h, g, "")
		_, _, rawListPlain := f.listNodes(f.plain, g, "")
		assert.Equal(t, rawListPlain, rawList, "平面列表與現行讀取路徑逐位元組相同")
		assertNoFlagKeys(t, list)
		_, has := resp["selectable_all"]
		assert.False(t, has)
	})

	t.Run("mixed_global_view_does_not_expand_tree", func(t *testing.T) {
		f := newTreeFixture(t)
		m := f.user("mixed-viewer")
		grantLegacyRole(t, f.db, m, model.RoleUser) // 內建一般使用者範本（全域 asset:view）
		f.grantNodes(m, f.role(authz.PermAssetView), "prod/db")

		tree, _, _ := f.treeAll(f.h, m)
		assert.Equal(t, scopeSubtree, f.pathSet(tree), "樹端點不含 prod/web 與 sit 子樹")
		assert.Equal(t, true, f.row(tree, "prod")["locator_only"], "prod 只作定位")
		list, _, _ := f.listNodes(f.h, m, "")
		assert.Equal(t, scopeSubtree, f.pathSet(list), "平面列表不含 prod/web 與 sit 子樹")
		assert.Equal(t, true, f.row(list, "prod")["locator_only"])
	})

	t.Run("node_scope_projection_by_permission", func(t *testing.T) {
		f := newTreeFixture(t)
		scoped := f.user("updater")
		f.grantNodes(scoped, f.role(authz.PermAssetUpdate), "prod/db")
		global := f.user("global-updater")
		f.grantGlobal(global, f.role(authz.PermAssetUpdate))

		proj, err := f.eval.NodeScopeProjection(f.db, f.principal(scoped), authz.PermAssetUpdate)
		require.NoError(t, err)
		assert.Equal(t, authz.ScopeSetConditional, proj.State)
		assert.Equal(t, map[uint]bool{f.id("prod/db"): true, f.id("prod/db/a"): true, f.id("prod/db/b"): true}, proj.Selectable)
		assert.Equal(t, map[uint]bool{f.id("prod"): true}, proj.Locators)

		proj, err = f.eval.NodeScopeProjection(f.db, f.principal(global), authz.PermAssetUpdate)
		require.NoError(t, err)
		assert.Equal(t, authz.ScopeSetUnlimited, proj.State, "全域持有者回全量型別")
	})

	t.Run("purpose_marks_selectable_nodes", func(t *testing.T) {
		f := newTreeFixture(t)
		p := f.user("updater")
		f.grantNodes(p, f.role(authz.PermAssetUpdate), "prod/db")
		f.connect(p, f.assets["a-sit-web"])

		rows, resp, raw := f.listNodes(f.h, p, "purpose=asset_update")
		for _, path := range []string{"prod/db", "prod/db/a", "prod/db/b"} {
			r := f.row(rows, path)
			assert.Equal(t, true, r["selectable"], "%s 可選", path)
			assert.Empty(t, rowAssetIDs(r), "%s 的資產不含不可視者", path)
		}
		assert.Equal(t, false, f.row(rows, "prod")["selectable"], "prod 列出但不可選")
		assert.Equal(t, false, f.row(rows, "sit/web")["selectable"])
		assert.Equal(t, false, resp["selectable_all"], raw)
		assertSelectableBools(t, resp, rows)

		rows, resp, raw = f.listNodes(f.h, p, "purpose=asset_create")
		require.NotEmpty(t, rows)
		for id, r := range rows {
			assert.Equal(t, false, r["selectable"], "沒有建立權限點時每個節點不可選：%s", f.pathOf(id))
		}
		assert.Equal(t, false, resp["selectable_all"], raw)
		assertSelectableBools(t, resp, rows)
	})

	t.Run("purpose_global_holder_selects_all", func(t *testing.T) {
		f := newTreeFixture(t)
		m := f.user("mixed-updater")
		f.grantGlobal(m, f.role(authz.PermAssetUpdate))
		f.grantNodes(m, f.role(authz.PermAssetView), "prod/db")

		rows, resp, raw := f.listNodes(f.h, m, "purpose=asset_update")
		require.NotEmpty(t, rows)
		assert.Equal(t, true, resp["selectable_all"], raw)
		for id, r := range rows {
			assert.Equal(t, true, r["selectable"], f.pathOf(id))
		}
		assertSelectableBools(t, resp, rows)
	})

	t.Run("purpose_ignored_for_global_only_subject", func(t *testing.T) {
		f := newTreeFixture(t)
		g := f.user("global-updater")
		f.grantGlobal(g, f.role(authz.PermAssetUpdate, authz.PermAssetView))
		f.connect(g, f.assets["a-web"])

		_, _, with := f.listNodes(f.h, g, "purpose=asset_update")
		_, _, without := f.listNodes(f.h, g, "")
		assert.Equal(t, without, with, "帶與不帶用途參數逐位元組相同")
	})

	t.Run("purpose_for_non_viewer_node_scope_holder", func(t *testing.T) {
		f := newTreeFixture(t)
		c := f.user("converter")
		f.grantNodes(c, f.role(authz.PermCredentialConvertScope), "prod/db")

		rows, resp, _ := f.listNodes(f.h, c, "purpose=credential_convert_scope")
		assert.Equal(t, scopeSubtree, f.pathSet(rows), "範圍節點、子樹與祖先列出")
		for _, path := range []string{"prod/db", "prod/db/a", "prod/db/b"} {
			assert.Equal(t, true, f.row(rows, path)["selectable"], path)
		}
		assert.Equal(t, false, f.row(rows, "prod")["selectable"], "祖先不可選")
		assertSelectableBools(t, resp, rows)

		_, _, without := f.listNodes(f.h, c, "")
		_, _, plain := f.listNodes(f.plain, c, "")
		assert.Equal(t, plain, without, "不帶參數時與現行讀取路徑相同")
	})

	t.Run("purpose_whitelist_matches_projection", func(t *testing.T) {
		for value, perm := range nodePurposePerms {
			t.Run(value, func(t *testing.T) {
				f := newTreeFixture(t)
				s := f.user("holder")
				f.grantNodes(s, f.role(perm), "prod/db/a")
				f.connect(s, f.assets["a-sit-web"])

				proj, err := f.eval.NodeScopeProjection(f.db, f.principal(s), perm)
				require.NoError(t, err)
				rows, resp, raw := f.listNodes(f.h, s, "purpose="+value)
				assert.Equal(t, proj.State == authz.ScopeSetUnlimited, resp["selectable_all"], raw)
				for id := range proj.Selectable {
					_, listed := rows[id]
					assert.True(t, listed, "可選節點 %s 列出", f.pathOf(id))
				}
				for id, r := range rows {
					want := proj.State == authz.ScopeSetUnlimited || proj.Selectable[id]
					assert.Equal(t, want, r["selectable"], "%s：%s", value, f.pathOf(id))
				}
			})
		}
	})

	t.Run("purpose_invalid_values_rejected", func(t *testing.T) {
		f := newTreeFixture(t)
		p := f.user("updater")
		f.grantNodes(p, f.role(authz.PermAssetUpdate), "prod/db")
		for _, q := range []string{"purpose=", "purpose=ASSET_UPDATE", "purpose=asset:update", "purpose=credential_bind",
			"purpose=asset_update&purpose=asset_create"} {
			code, body := f.do(p, http.MethodGet, "/asset-groups?"+q, nil)
			assert.Equal(t, http.StatusBadRequest, code, q)
			var resp map[string]any
			require.NoError(t, json.Unmarshal(body, &resp))
			assert.Equal(t, string(apierror.CodeBadParams), resp["code"], q)
		}
	})

	t.Run("row_flags_follow_write_rules", func(t *testing.T) {
		// 範圍化管理者：prod/db 的節點管理權限點；prod/db/c/x 是他人的範圍節點（亦即被引用）
		setup := func(t *testing.T) (*treeFixture, uint) {
			f := newTreeFixture(t)
			f.node("prod/db/c", "prod/db")
			f.node("prod/db/c/x", "prod/db/c")
			mgr := f.user("mgr")
			f.grantNodes(mgr, f.role(authz.PermAssetGroupManage), "prod/db")
			other := f.user("other")
			f.grantNodes(other, f.role(authz.PermAssetView), "prod/db/c/x")
			return f, mgr
		}
		f, mgr := setup(t)
		tree, root, _ := f.treeAll(f.h, mgr)
		assert.Equal(t, false, root["can_create_root"], "節點範圍者不可在根層建立")
		assertFlagBools(t, tree)

		self := f.row(tree, "prod/db")
		assert.Equal(t, true, self["scope_root"])
		assert.Equal(t, true, self["can_create_child"])
		for _, k := range []string{"can_rename", "can_move", "can_delete"} {
			assert.Equal(t, false, self[k], "自身範圍節點 %s", k)
		}
		for _, path := range []string{"prod/db/a", "prod/db/b"} {
			r := f.row(tree, path)
			for _, k := range []string{"can_create_child", "can_rename", "can_move", "can_delete"} {
				assert.Equal(t, true, r[k], "嚴格子孫 %s 的 %s（惰性子層同樣帶旗標）", path, k)
			}
		}
		assert.Equal(t, false, f.row(tree, "prod/db/c")["can_move"], "子樹含他人範圍節點不可搬")
		assert.Equal(t, true, f.row(tree, "prod/db/c/x")["can_delete"], "被引用的嚴格子孫 can_delete 仍為 true")

		scopeNodes := []string{"prod/db", "prod/db/a", "prod/db/b", "prod/db/c", "prod/db/c/x"}
		for id := range tree {
			path := f.pathOf(id)
			assertFlagsMatchWrites(t, f.row(tree, path), path, scopeNodes, func(t *testing.T) (*nodeScopeEnv, uint) {
				g, actor := setup(t)
				return g.nodeScopeEnv, actor
			})
		}
	})

	t.Run("mixed_global_manager_flags", func(t *testing.T) {
		setup := func(t *testing.T) (*treeFixture, uint) {
			f := newTreeFixture(t)
			m := f.user("mixed-manager")
			f.grantGlobal(m, f.role(authz.PermAssetGroupManage))
			f.grantNodes(m, f.role(authz.PermAssetView), "prod/db")
			f.connect(m, f.assets["a-sit-web"])
			return f, m
		}
		f, m := setup(t)
		tree, root, _ := f.treeAll(f.h, m)
		assert.Equal(t, true, root["can_create_root"], "全域持有節點管理權限點者可在根層建立")
		sitWeb := f.row(tree, "sit/web")
		assert.Equal(t, false, sitWeb["manageable"])
		assert.Equal(t, false, sitWeb["locator_only"])
		for _, k := range []string{"can_create_child", "can_rename", "can_move", "can_delete"} {
			assert.Equal(t, true, sitWeb[k], "sit/web 的 %s", k)
		}
		sit := f.row(tree, "sit")
		assert.Equal(t, true, sit["locator_only"])
		assert.Equal(t, true, sit["can_rename"])

		want := sortedStrings(append(append([]string(nil), scopeSubtree...), "sit", "sit/web")...)
		assert.Equal(t, want, f.pathSet(tree), "樹端點不含 prod/web")
		list, _, _ := f.listNodes(f.h, m, "")
		assert.Equal(t, want, f.pathSet(list), "平面列表不含 prod/web")

		all := []string{"prod/db/a", "prod/db/b", "prod/db", "prod", "sit", "sit/web", "prod/web"}
		assertFlagsMatchWrites(t, sitWeb, "sit/web", all, func(t *testing.T) (*nodeScopeEnv, uint) {
			g, actor := setup(t)
			return g.nodeScopeEnv, actor
		})
	})
}

// isSubtreeOf path 是否為 root 本身或其子孫（依路徑字串）。
func isSubtreeOf(path, root string) bool { return path == root || strings.HasPrefix(path, root+"/") }

func parentPath(path string) string {
	if i := lastSlash(path); i >= 0 {
		return path[:i]
	}
	return ""
}

// moveTarget 搬移的目的：先取 candidates 中不在自身子樹、且不是現有父節點者；沒有時退而取範圍外的同條件節點。
func moveTarget(path string, candidates []string) string {
	for _, c := range append(append([]string(nil), candidates...), "sit/web", "sit", "prod/web") {
		if !isSubtreeOf(c, path) && c != parentPath(path) {
			return c
		}
	}
	return ""
}

// assertFlagsMatchWrites 逐項以全新的同一夾具呼叫對應寫入 API：旗標 false 必為授權拒絕
// （與不存在同形的 404 或 403），旗標 true 必不是授權拒絕（業務拒絕如 409、400 允許）。
func assertFlagsMatchWrites(t *testing.T, row nodeRow, path string, candidates []string, setup func(*testing.T) (*nodeScopeEnv, uint)) {
	t.Helper()
	type probe struct {
		flag   string
		method string
		url    func(e *nodeScopeEnv, id string) string
		body   func(e *nodeScopeEnv) any
	}
	dest := moveTarget(path, candidates)
	probes := []probe{
		{"can_create_child", http.MethodPost, func(*nodeScopeEnv, string) string { return "/asset-groups" },
			nil},
		{"can_rename", http.MethodPut, func(_ *nodeScopeEnv, id string) string { return "/asset-groups/" + id },
			func(*nodeScopeEnv) any { return map[string]any{"name": path[lastSlash(path)+1:] + "-renamed"} }},
		{"can_move", http.MethodPut, func(_ *nodeScopeEnv, id string) string { return "/asset-groups/" + id + "/move" },
			func(e *nodeScopeEnv) any { return map[string]any{"parent_id": e.id(dest)} }},
		{"can_delete", http.MethodDelete, func(_ *nodeScopeEnv, id string) string { return "/asset-groups/" + id },
			func(*nodeScopeEnv) any { return nil }},
	}
	for _, p := range probes {
		want, ok := row[p.flag].(bool)
		require.True(t, ok, "%s 帶 %s", path, p.flag)
		e, actor := setup(t)
		target, missing := e.idStr(path), "999999"
		var body, missingBody any
		if p.flag == "can_create_child" {
			body = map[string]any{"name": "probe-child", "parent_id": e.id(path)}
			missingBody = map[string]any{"name": "probe-child", "parent_id": 999999}
		} else {
			body, missingBody = p.body(e), p.body(e)
		}
		_, notFound := e.do(actor, p.method, p.url(e, missing), missingBody)
		code, resp := e.do(actor, p.method, p.url(e, target), body)
		denied := code == http.StatusForbidden || (code == http.StatusNotFound && string(resp) == string(notFound))
		if want {
			assert.False(t, denied, "%s 的 %s 為 true，寫入不得是授權拒絕：%d %s", path, p.flag, code, resp)
		} else {
			assert.True(t, denied, "%s 的 %s 為 false，寫入須是授權拒絕：%d %s", path, p.flag, code, resp)
		}
	}
}
