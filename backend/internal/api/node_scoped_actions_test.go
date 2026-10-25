package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// lastMoveDetails 最後一筆服務審計列的 details（JSON 物件）。
func (e *nodeScopeEnv) lastDetails() map[string]any {
	e.t.Helper()
	rows := e.serviceAudits()
	require.NotEmpty(e.t, rows)
	var m map[string]any
	require.NoError(e.t, json.Unmarshal([]byte(rows[len(rows)-1].Details), &m))
	return m
}

func is2xx(code int) bool { return code >= 200 && code < 300 }

func TestNodeScopedActions(t *testing.T) {
	// 範圍化管理者：prod/db 的節點管理權限點（直接指派）
	setup := func(t *testing.T) (*nodeScopeEnv, uint, uint) {
		e := newNodeScopeEnv(t)
		mgr := e.user("mgr")
		e.grantNodes(mgr, e.role(authz.PermAssetGroupManage), "prod/db")
		global := e.user("global")
		e.grantGlobal(global, e.role(authz.PermAssetGroupManage))
		return e, mgr, global
	}

	t.Run("create", func(t *testing.T) {
		e, mgr, global := setup(t)
		for _, parent := range []string{"prod/db", "prod/db/a"} {
			before := len(e.serviceAudits())
			code, body := e.do(mgr, http.MethodPost, "/asset-groups", map[string]any{"name": "new-" + parent[len(parent)-1:], "parent_id": e.id(parent)})
			require.Equal(t, http.StatusCreated, code, string(body))
			assert.Equal(t, before+1, len(e.serviceAudits()), "建立在 %s 下有一筆同交易審計", parent)
		}
		codeOut, bodyOut := e.do(mgr, http.MethodPost, "/asset-groups", map[string]any{"name": "x", "parent_id": e.id("prod/web")})
		codeMissing, bodyMissing := e.do(mgr, http.MethodPost, "/asset-groups", map[string]any{"name": "x", "parent_id": 999999})
		assert.Equal(t, http.StatusNotFound, codeOut)
		assert.Equal(t, codeOut, codeMissing)
		assert.Equal(t, string(bodyMissing), string(bodyOut), "範圍外與不存在的父節點同形")
		assert.NotContains(t, string(bodyOut), "web")

		code, _ := e.do(mgr, http.MethodPost, "/asset-groups", map[string]any{"name": "root-by-mgr"})
		assert.Equal(t, http.StatusForbidden, code, "節點範圍者根層建立被拒")
		code, _ = e.do(global, http.MethodPost, "/asset-groups", map[string]any{"name": "root-by-global"})
		assert.Equal(t, http.StatusCreated, code, "全域持有者根層建立成功")

		code, body := e.do(mgr, http.MethodPost, "/asset-groups", map[string]any{"name": "a", "parent_id": e.id("prod/db")})
		assert.Equal(t, http.StatusConflict, code, "範圍內兄弟同名回既有 409：%s", body)
	})

	t.Run("rename_and_describe", func(t *testing.T) {
		e, mgr, _ := setup(t)
		other := e.user("other")
		e.grantNodes(other, e.role(authz.PermAssetGroupManage), "prod/db/a")
		for _, req := range []map[string]any{{"name": "db-renamed"}, {"name": "db", "description": "changed"}} {
			code, body := e.do(mgr, http.MethodPut, "/asset-groups/"+e.idStr("prod/db"), req)
			assert.Equal(t, http.StatusForbidden, code, "自身範圍節點改名／改描述回 403")
			assert.NotContains(t, string(body), string(authz.PermAssetGroupManage))
			assert.NotContains(t, string(body), "node-scope-role")
		}
		var name string
		require.NoError(t, e.db.Raw("SELECT name FROM asset_groups WHERE id = ?", e.id("prod/db")).Scan(&name).Error)
		assert.Equal(t, "db", name, "節點不變")

		code, _ := e.do(mgr, http.MethodPut, "/asset-groups/"+e.idStr("prod/db/a"), map[string]any{"name": "a2"})
		assert.Equal(t, http.StatusOK, code, "範圍內他人的範圍節點可改名")
		code, _ = e.do(mgr, http.MethodPut, "/asset-groups/"+e.idStr("prod/web"), map[string]any{"name": "w2"})
		codeMissing, _ := e.do(mgr, http.MethodPut, "/asset-groups/999999", map[string]any{"name": "w2"})
		assert.Equal(t, http.StatusNotFound, code)
		assert.Equal(t, codeMissing, code)

		code, body := e.do(mgr, http.MethodDelete, "/asset-groups/"+e.idStr("prod/db"), nil)
		assert.Equal(t, http.StatusForbidden, code, "刪除自身範圍節點回 403（先於引用）：%s", body)

		super := e.superAdmin()
		code, _ = e.do(super, http.MethodPut, "/asset-groups/"+e.idStr("prod/db"), map[string]any{"name": "db-by-super"})
		assert.Equal(t, http.StatusOK, code, "超管改名成功")
		code, _ = e.do(super, http.MethodPut, "/asset-groups/"+e.idStr("prod/db"), map[string]any{"name": "db-by-super", "description": "by-super"})
		assert.Equal(t, http.StatusOK, code, "超管改描述成功")
		var desc string
		require.NoError(t, e.db.Raw("SELECT description FROM asset_groups WHERE id = ?", e.id("prod/db")).Scan(&desc).Error)
		assert.Equal(t, "by-super", desc)
	})

	t.Run("denial_audit_markers", func(t *testing.T) {
		e, mgr, global := setup(t)
		e.withAudit()
		details := func(row model.AuditLog) map[string]any {
			m := map[string]any{}
			if row.Details != "" {
				require.NoError(t, json.Unmarshal([]byte(row.Details), &m), row.Details)
			}
			return m
		}

		code, body := e.do(mgr, http.MethodPost, "/asset-groups", map[string]any{"name": "x", "parent_id": e.id("prod/web")})
		require.Equal(t, http.StatusNotFound, code, string(body))
		row := e.lastAudit()
		assert.Equal(t, model.StatusDenied, row.Status, "範圍外父節點的拒絕審計")
		assert.Equal(t, "scope", details(row)["denial"], "範圍外父節點的拒絕審計帶範圍拒絕標記：%s", row.Details)

		code, body = e.do(global, http.MethodPost, "/asset-groups", map[string]any{"name": "x", "parent_id": 999999})
		require.Equal(t, http.StatusNotFound, code, string(body))
		row = e.lastAudit()
		_, marked := details(row)["denial"]
		assert.False(t, marked, "全域主體打不存在父節點的審計不帶範圍拒絕標記：%s", row.Details)

		code, body = e.do(mgr, http.MethodPost, "/asset-groups", map[string]any{"name": "a", "parent_id": e.id("prod/db")})
		require.Equal(t, http.StatusConflict, code, string(body))
		row = e.lastAudit()
		_, marked = details(row)["denial"]
		assert.False(t, marked, "範圍內兄弟同名的 409 審計不帶範圍拒絕標記：%s", row.Details)
	})

	t.Run("move", func(t *testing.T) {
		e, mgr, global := setup(t)
		e.node("prod/db/a/x", "prod/db/a")
		code, body := e.do(mgr, http.MethodPut, "/asset-groups/"+e.idStr("prod/db/a/x")+"/move", map[string]any{"parent_id": e.id("prod/db/b")})
		require.Equal(t, http.StatusOK, code, string(body))
		assert.Equal(t, false, e.lastDetails()["cross_assignment"], "同一筆內搬移")

		code, _ = e.do(mgr, http.MethodPut, "/asset-groups/"+e.idStr("prod/db/a/x")+"/move", map[string]any{"parent_id": e.id("prod/web")})
		assert.Equal(t, http.StatusNotFound, code, "目的在範圍外回同形 404")
		assert.Equal(t, e.id("prod/db/b"), *e.parentOf("prod/db/a/x"))

		code, _ = e.do(mgr, http.MethodPut, "/asset-groups/"+e.idStr("prod/db/a/x")+"/move", map[string]any{"parent_id": nil})
		assert.Equal(t, http.StatusForbidden, code, "節點範圍者搬到根層被拒")
		code, _ = e.do(global, http.MethodPut, "/asset-groups/"+e.idStr("prod/db/a/x")+"/move", map[string]any{"parent_id": nil})
		assert.Equal(t, http.StatusOK, code, "全域持有者搬到根層成功（子樹不含範圍節點）")
		_, hasCross := e.lastDetails()["cross_assignment"]
		assert.False(t, hasCross, "全域持有者的搬移審計不含 cross_assignment")

		// 子樹含他人範圍節點：節點範圍者與全域持有者皆拒、超管成功
		other := e.user("other")
		e.grantNodes(other, e.role(authz.PermAssetGroupManage), "prod/db/a")
		e.node("prod/db/c", "prod/db")
		for _, actor := range []uint{mgr, global} {
			code, _ = e.do(actor, http.MethodPut, "/asset-groups/"+e.idStr("prod/db/a")+"/move", map[string]any{"parent_id": e.id("prod/db/c")})
			assert.Equal(t, http.StatusForbidden, code, "子樹含範圍節點限超管")
		}
		super := e.superAdmin()
		code, _ = e.do(super, http.MethodPut, "/asset-groups/"+e.idStr("prod/db/a")+"/move", map[string]any{"parent_id": e.id("prod/db/c")})
		assert.Equal(t, http.StatusOK, code)
		_, hasCross = e.lastDetails()["cross_assignment"]
		assert.False(t, hasCross, "超管的搬移審計不含 cross_assignment")
	})

	t.Run("cross_assignment", func(t *testing.T) {
		e := newNodeScopeEnv(t)
		mgr := e.user("mgr")
		manage := e.role(authz.PermAssetGroupManage)
		e.grantNodes(mgr, manage, "prod/db/a")                                            // 直接指派範圍 A
		e.groupNodes("g-b", e.role(authz.PermAssetGroupManage), []uint{mgr}, "prod/db/b") // 群組指派範圍 B
		e.groupNodes("g-view", e.role(authz.PermAssetView), []uint{mgr}, "prod/web")      // 角色不含節點管理權限點
		e.node("prod/db/a/x", "prod/db/a")
		e.node("prod/db/a/y", "prod/db/a")
		e.node("prod/db/a/z", "prod/db/a")

		move := func(src, dst string) (int, string) {
			code, body := e.do(mgr, http.MethodPut, "/asset-groups/"+e.idStr(src)+"/move", map[string]any{"parent_id": e.id(dst)})
			return code, string(body)
		}
		code, body := move("prod/db/a/x", "prod/db/b")
		require.Equal(t, http.StatusOK, code, body)
		assert.Equal(t, true, e.lastDetails()["cross_assignment"], "A 到 B 跨指派")

		code, body = move("prod/db/a/y", "prod/db/a/z")
		require.Equal(t, http.StatusOK, code, body)
		assert.Equal(t, false, e.lastDetails()["cross_assignment"], "同一筆指派內")

		before := e.parentOf("prod/db/a/z")
		code, _ = move("prod/db/a/z", "prod/web")
		assert.Equal(t, http.StatusNotFound, code, "B 的角色不含節點管理權限點時回同形 404")
		assert.Equal(t, *before, *e.parentOf("prod/db/a/z"), "樹不變")

		// 另加一筆同時涵蓋 A 與 B 的指派後，同型搬移為 false（判定不看迭代順序）
		e.grantNodes(mgr, e.role(authz.PermAssetGroupManage), "prod/db")
		code, body = move("prod/db/a/z", "prod/db/b")
		require.Equal(t, http.StatusOK, code, body)
		assert.Equal(t, false, e.lastDetails()["cross_assignment"])
		assert.False(t, strings.Contains(body, "topology_coverage"), "回應不含涵蓋差異")
	})
}
