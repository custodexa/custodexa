package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 節點列表的名稱精確查找：先算出完整的可見節點集合（含定位用的祖先與列級旗標），再只留名稱完全相同者；
// 不另帶不相符的祖先列。名稱只在同一層唯一，同名節點全部回傳，各帶自己的上層節點識別。

// assertNodeExactName 帶 name 的結果＝同一主體不帶 name 的列表中名稱完全相同的列（逐欄相同），回其路徑。
func (e *nodeScopeEnv) assertNodeExactName(t *testing.T, uid uint, query url.Values, name string) []string {
	t.Helper()
	all, _, _ := e.listNodes(e.h, uid, query.Encode())
	q := url.Values{}
	for k, v := range query {
		q[k] = v
	}
	q.Set("name", name)
	got, resp, raw := e.listNodes(e.h, uid, q.Encode())
	want := map[uint]nodeRow{}
	for id, r := range all {
		if r["name"] == name {
			want[id] = r
		}
	}
	assert.Equal(t, want, got, "name=%q：等於不帶 name 的列表中名稱相同的列：%s", name, raw)
	assert.EqualValues(t, len(want), resp["total"])
	return e.pathSet(got)
}

func TestAssetGroupHandler_ExactName(t *testing.T) {
	t.Run("same_name_under_different_parents_all_returned", func(t *testing.T) {
		f := newTreeFixture(t)
		admin := f.superAdmin()
		got := f.assertNodeExactName(t, admin, nil, "web")
		assert.Equal(t, sortedStrings("prod/web", "sit/web"), got, "兩個上層之下的同名節點都回傳，不帶祖先列")
		rows, _, _ := f.listNodes(f.h, admin, "name=web")
		assert.EqualValues(t, f.id("prod"), f.row(rows, "prod/web")["parent_id"])
		assert.EqualValues(t, f.id("sit"), f.row(rows, "sit/web")["parent_id"])
	})

	t.Run("partial_case_and_whitespace_variants_do_not_match", func(t *testing.T) {
		f := newTreeFixture(t)
		admin := f.superAdmin()
		f.node("prod/Web", "prod") // 同一層只差大小寫：節點建立時以原樣字串判重，兩者並存
		for _, n := range []string{"we", "WEB", " web", "web "} {
			assert.Empty(t, f.assertNodeExactName(t, admin, nil, n), "%q 不命中", n)
		}
		assert.Equal(t, []string{"prod/Web"}, f.assertNodeExactName(t, admin, nil, "Web"))
	})

	t.Run("scoped_viewer_finds_scope_and_locator_but_not_outside", func(t *testing.T) {
		f := newTreeFixture(t)
		mgr := f.user("node-manager")
		f.grantNodes(mgr, f.role(authz.PermAssetView, authz.PermAssetGroupManage), "prod/db")
		assert.Equal(t, []string{"prod/db"}, f.assertNodeExactName(t, mgr, nil, "db"))
		got := f.assertNodeExactName(t, mgr, nil, "prod")
		assert.Equal(t, []string{"prod"}, got, "定位祖先在列表中看得到，查找回同一列（含列級旗標）")
		rows, _, _ := f.listNodes(f.h, mgr, "name=prod")
		assert.Equal(t, true, f.row(rows, "prod")["locator_only"])

		_, _, missing := f.listNodes(f.h, mgr, "name=no-such-node")
		for _, n := range []string{"web", "sit"} {
			_, _, raw := f.listNodes(f.h, mgr, "name="+n)
			assert.Equal(t, missing, raw, "範圍外的 %q 與不存在同本文", n)
		}
	})

	t.Run("ordinary_user_sees_only_listed_nodes", func(t *testing.T) {
		f := newTreeFixture(t)
		u := f.user("plain")
		f.connect(u, f.assets["a-sit-web"])
		assert.Equal(t, []string{"sit/web"}, f.assertNodeExactName(t, u, nil, "web"), "只回看得到的同名節點")
		assert.Equal(t, []string{"sit"}, f.assertNodeExactName(t, u, nil, "sit"))
		_, _, missing := f.listNodes(f.h, u, "name=no-such-node")
		_, _, raw := f.listNodes(f.h, u, "name=prod")
		assert.Equal(t, missing, raw, "看不到的節點與不存在同本文")
	})

	t.Run("purpose_parameter_combines", func(t *testing.T) {
		f := newTreeFixture(t)
		creator := f.user("creator")
		f.grantNodes(creator, f.role(authz.PermAssetCreate), "sit")
		// 用途參數擴入範圍內但原不可視的節點；名稱查找在擴入後的集合上篩選，用途旗標照列表
		q := url.Values{"purpose": {"asset_create"}}
		assert.Equal(t, []string{"sit/web"}, f.assertNodeExactName(t, creator, q, "web"))
		assert.Empty(t, f.assertNodeExactName(t, creator, nil, "web"), "未帶用途時看不到")
	})

	t.Run("deleted_node_not_found", func(t *testing.T) {
		f := newTreeFixture(t)
		f.deletedNode("sit/old", "sit")
		admin := f.superAdmin()
		assert.Empty(t, f.assertNodeExactName(t, admin, nil, "old"))
	})

	t.Run("empty_value_is_bad_request", func(t *testing.T) {
		f := newTreeFixture(t)
		admin := f.superAdmin()
		u := f.user("plain")
		grantLegacyRole(t, f.db, f.user("aud"), model.RoleAuditor)
		var first string
		for _, uid := range []uint{admin, u} {
			code, body := f.do(uid, http.MethodGet, "/asset-groups?name=", nil)
			require.Equal(t, http.StatusBadRequest, code, string(body))
			var resp map[string]any
			require.NoError(t, json.Unmarshal(body, &resp))
			assert.Equal(t, "VALIDATION_INVALID_QUERY_PARAM", resp["code"])
			assert.Equal(t, map[string]any{"field": "name"}, resp["params"])
			if first == "" {
				first = string(body)
			}
			assert.Equal(t, first, string(body))
		}
	})
}
