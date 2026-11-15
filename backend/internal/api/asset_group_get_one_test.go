package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 節點單筆讀取：同一個請求主體，單筆回應等於它在未帶用途參數的平面列表中看到的那一筆（去掉直掛資產清單）；
// 列表看不到的節點，單筆回應與不存在的節點逐位元組相同。

const nodeGetOneMissingID = 999999

// nodeSingleFromList 列表中那一列去掉直掛資產清單後的樣子（單筆讀取的預期回應）。
func nodeSingleFromList(r nodeRow) map[string]any {
	out := map[string]any{}
	for k, v := range r {
		if k == "assets" {
			continue
		}
		out[k] = v
	}
	return out
}

// getOneNode 單筆讀取：回狀態碼、解析後的本文與原始本文。
func (e *nodeScopeEnv) getOneNode(uid uint, id uint, query string) (int, map[string]any, []byte) {
	e.t.Helper()
	path := fmt.Sprintf("/asset-groups/%d", id)
	if query != "" {
		path += "?" + query
	}
	code, body := e.do(uid, http.MethodGet, path, nil)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return code, out, body
}

// assertNodeSingleMatchesList 對全部節點（含已刪除與不存在的識別）逐一比對：列表有者單筆逐欄相同，
// 列表沒有者單筆與不存在的節點同一回應。回列表看得到的節點路徑。
func (e *nodeScopeEnv) assertNodeSingleMatchesList(t *testing.T, uid uint, extraIDs ...uint) []string {
	t.Helper()
	list, _, _ := e.listNodes(e.h, uid, "")
	missCode, _, missBody := e.getOneNode(uid, nodeGetOneMissingID, "")
	require.Equal(t, http.StatusNotFound, missCode, string(missBody))

	ids := append([]uint{}, extraIDs...)
	for _, id := range e.nodes {
		ids = append(ids, id)
	}
	for _, id := range ids {
		code, got, raw := e.getOneNode(uid, id, "")
		if row, ok := list[id]; ok {
			require.Equal(t, http.StatusOK, code, "節點 %s：%s", e.pathOf(id), raw)
			assert.Equal(t, nodeSingleFromList(row), got, "節點 %s：單筆與列表中那一筆逐欄相同", e.pathOf(id))
			_, hasAssets := got["assets"]
			assert.False(t, hasAssets, "節點 %s：單筆不帶直掛資產清單", e.pathOf(id))
			_, hasSel := got["selectable"]
			assert.False(t, hasSel, "節點 %s：單筆不帶用途旗標", e.pathOf(id))
			continue
		}
		assert.Equal(t, missCode, code, "節點 %s：列表看不到時與不存在同狀態碼", e.pathOf(id))
		assert.Equal(t, string(missBody), string(raw), "節點 %s：列表看不到時與不存在同本文", e.pathOf(id))
	}
	return e.pathSet(list)
}

func TestAssetGroupHandler_GetOne(t *testing.T) {
	scopeSubtree := sortedStrings("prod", "prod/db", "prod/db/a", "prod/db/b")

	t.Run("super_admin_sees_every_node_as_listed", func(t *testing.T) {
		f := newTreeFixture(t)
		f.deletedNode("sit/old", "sit")
		admin := f.superAdmin()
		seen := f.assertNodeSingleMatchesList(t, admin)
		assert.Len(t, seen, 7, "超級管理者看得到全部未刪除節點")
		code, got, _ := f.getOneNode(admin, f.id("prod/db"), "")
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, "prod / db", got["path"], "回應帶完整路徑（與列表同一個路徑字串）")
		assert.EqualValues(t, f.id("prod"), got["parent_id"])
		for _, k := range nodeRowFlagKeys {
			_, has := got[k]
			assert.False(t, has, "非範圍化檢視者不帶列級旗標 %s", k)
		}
	})

	t.Run("auditor_sees_every_node_as_listed", func(t *testing.T) {
		f := newTreeFixture(t)
		aud := f.user("auditor")
		grantLegacyRole(t, f.db, aud, model.RoleAuditor)
		seen := f.assertNodeSingleMatchesList(t, aud)
		assert.Len(t, seen, 7)
	})

	t.Run("node_scope_manager_sees_scope_subtree_and_locator_with_flags", func(t *testing.T) {
		f := newTreeFixture(t)
		mgr := f.user("node-manager")
		f.grantNodes(mgr, f.role(authz.PermAssetView, authz.PermAssetGroupManage), "prod/db")
		seen := f.assertNodeSingleMatchesList(t, mgr)
		assert.Equal(t, scopeSubtree, seen)

		code, got, _ := f.getOneNode(mgr, f.id("prod"), "")
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, true, got["locator_only"], "定位祖先帶列級旗標且只作定位")
		code, got, _ = f.getOneNode(mgr, f.id("prod/db"), "")
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, true, got["manageable"], "範圍根可管理")
		for _, k := range nodeRowFlagKeys {
			_, isBool := got[k].(bool)
			assert.True(t, isBool, "列級旗標 %s 為明確布林", k)
		}
	})

	t.Run("purpose_parameter_does_not_change_single_read", func(t *testing.T) {
		f := newTreeFixture(t)
		creator := f.user("creator")
		f.grantNodes(creator, f.role(authz.PermAssetCreate), "sit")
		// 用途參數會讓列表擴入範圍內但原不可視的節點；單筆讀取以未帶用途的列表為準
		withPurpose, _, _ := f.listNodes(f.h, creator, "purpose=asset_create")
		plain, _, _ := f.listNodes(f.h, creator, "")
		for _, id := range f.nodes {
			c1, _, raw1 := f.getOneNode(creator, id, "")
			c2, _, raw2 := f.getOneNode(creator, id, "purpose=asset_create")
			assert.Equal(t, c1, c2, "節點 %s：帶不帶用途參數狀態碼相同", f.pathOf(id))
			assert.Equal(t, string(raw1), string(raw2), "節點 %s：帶不帶用途參數本文相同", f.pathOf(id))
			_, inPlain := plain[id]
			assert.Equal(t, inPlain, c1 == http.StatusOK, "節點 %s：可否讀到只跟未帶用途的列表走", f.pathOf(id))
		}
		assert.Greater(t, len(withPurpose), len(plain), "前提：用途參數確實讓列表多出節點")
		f.assertNodeSingleMatchesList(t, creator)
	})

	t.Run("ordinary_user_sees_connected_node_and_locator_ancestors_only", func(t *testing.T) {
		f := newTreeFixture(t)
		u := f.user("ordinary")
		grantLegacyRole(t, f.db, u, model.RoleUser)
		f.connect(u, f.assets["a-db-a"])
		seen := f.assertNodeSingleMatchesList(t, u)
		assert.Equal(t, sortedStrings("prod", "prod/db", "prod/db/a"), seen,
			"連線可視的直掛節點與其祖先；兄弟節點與其他子樹不可見")
		code, got, _ := f.getOneNode(u, f.id("prod"), "")
		require.Equal(t, http.StatusOK, code, "只作定位的祖先也讀得到")
		assert.Equal(t, "prod", got["name"])
		code, _, _ = f.getOneNode(u, f.id("prod/web"), "")
		assert.Equal(t, http.StatusNotFound, code)
	})

	t.Run("all_assigned_scope_nodes_deleted_reads_nothing", func(t *testing.T) {
		f := newTreeFixture(t)
		f.deletedNode("sit/old", "sit")
		u := f.user("viewer")
		f.grantNodes(u, f.role(authz.PermAssetView, authz.PermAssetGroupManage), "sit/old")
		seen := f.assertNodeSingleMatchesList(t, u, f.id("sit/old"))
		assert.Empty(t, seen, "指派的範圍節點已全數刪除時不回退全量")
	})

	t.Run("deleted_node_answers_like_missing", func(t *testing.T) {
		f := newTreeFixture(t)
		f.deletedNode("sit/old", "sit")
		admin := f.superAdmin()
		code, _, raw := f.getOneNode(admin, f.id("sit/old"), "")
		_, _, missRaw := f.getOneNode(admin, nodeGetOneMissingID, "")
		assert.Equal(t, http.StatusNotFound, code)
		assert.Equal(t, string(missRaw), string(raw), "已刪除節點與不存在節點同本文")
	})

	t.Run("invalid_id_is_bad_request", func(t *testing.T) {
		f := newTreeFixture(t)
		admin := f.superAdmin()
		code, body := f.do(admin, http.MethodGet, "/asset-groups/abc", nil)
		assert.Equal(t, http.StatusBadRequest, code, string(body))
	})

	t.Run("id_boundaries_depend_only_on_input", func(t *testing.T) {
		f := newTreeFixture(t)
		f.deletedNode("sit/old", "sit")
		admin := f.superAdmin()
		u := f.user("ordinary")
		grantLegacyRole(t, f.db, u, model.RoleUser)
		f.connect(u, f.assets["a-db-a"])
		getAs := func(uid uint) func(string) (int, []byte) {
			return func(raw string) (int, []byte) { return f.do(uid, http.MethodGet, "/asset-groups/"+raw, nil) }
		}
		// 超級管理者：看不到的只有已刪除節點；一般使用者：兄弟節點看不到
		assertIDBoundaries(t, getAs(admin), f.id("prod/db"), f.id("sit/old"), false)
		assertIDBoundaries(t, getAs(u), f.id("prod"), f.id("prod/web"), false)
	})
}
