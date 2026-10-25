package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestScopedBindingRoutes 擋：使用者角色指派的讀取路由在登錄表與路由清冊都有、能力為使用者管理；
// 沒有該能力者被拒；節點範圍列帶 node_ids、全域列沒有此鍵（直接與群組兩端點）；
// 只有全域指派的使用者與群組，既有三個讀取的回應不多出節點欄位、群組列鍵集不變；
// 節點範圍的寫入經正式組裝的關卡接受存在的節點、拒絕不存在的節點。
func TestScopedBindingRoutes(t *testing.T) {
	const path = "/api/v1/users/:id/role-bindings"
	e, ok := authz.LookupRoute("GET", path)
	require.True(t, ok, "GET %s 未登錄", path)
	assert.Equal(t, authz.BasePerm, e.Base)
	assert.Equal(t, authz.PermUserManage, e.Perm)

	env := newBaselineEnv(t)
	inventory := false
	for _, r := range env.engine().Routes() {
		if r.Method == "GET" && r.Path == path {
			inventory = true
		}
	}
	assert.True(t, inventory, "路由清冊沒有 GET %s", path)

	keys := func(m map[string]any) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	rows := func(out map[string]any) []map[string]any {
		var res []map[string]any
		for _, r := range out["data"].([]any) {
			res = append(res, r.(map[string]any))
		}
		return res
	}
	byRole := func(rs []map[string]any, id uint) map[string]any {
		for _, r := range rs {
			if uint(r["role_id"].(float64)) == id {
				return r
			}
		}
		t.Fatalf("回應沒有角色 %d 的列：%v", id, rs)
		return nil
	}
	nodeIDs := func(r map[string]any) []uint {
		raw, ok := r["node_ids"].([]any)
		require.True(t, ok, "節點範圍列缺 node_ids：%v", r)
		out := make([]uint, 0, len(raw))
		for _, v := range raw {
			out = append(out, uint(v.(float64)))
		}
		return out
	}

	userPath := func(id uint) string { return fmt.Sprintf("/api/v1/users/%d/role-bindings", id) }

	t.Run("沒有使用者管理能力者被拒", func(t *testing.T) {
		target := env.createUser("sbr-denied-target", nil)
		for _, sub := range []string{"S02", "S03"} {
			c, _ := env.api(sub, "GET", userPath(target), nil)
			assert.Equal(t, http.StatusForbidden, c, sub)
		}
		c, _ := env.api("S00", "GET", userPath(target), nil)
		assert.Equal(t, http.StatusUnauthorized, c)
	})

	n1 := model.AssetGroup{Name: "sbr-node-1"}
	n2 := model.AssetGroup{Name: "sbr-node-2"}
	require.NoError(t, env.db.Create(&n1).Error)
	require.NoError(t, env.db.Create(&n2).Error)
	var scopedPerms []string
	for _, p := range authz.ScopedTemplateAssetAdminPermissions() {
		scopedPerms = append(scopedPerms, string(p))
	}
	c, out := env.api("S01", "POST", "/api/v1/role-definitions", map[string]any{
		"name": "sbr-assetmgr", "permissions": scopedPerms,
	})
	require.Equal(t, http.StatusCreated, c, "%v", out)
	scopedRole := uint(out["id"].(float64))
	auditor := env.roleID(model.RoleAuditor)
	code := func(m map[string]any) string { s, _ := m["code"].(string); return s }

	t.Run("直接指派：節點範圍列帶 node_ids，全域列沒有", func(t *testing.T) {
		u := env.createUser("sbr-user", nil)
		name := func(id uint) string {
			var r model.Role
			require.NoError(t, env.db.First(&r, id).Error)
			return r.Name
		}
		// 不存在的節點：經正式組裝的關卡拒絕（不是「尚未提供」）
		c, out := env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", u), map[string]any{
			"manual_roles": []string{name(scopedRole)}, "role_nodes": map[string][]uint{name(scopedRole): {999999}},
		})
		require.Equal(t, http.StatusBadRequest, c, "%v", out)
		assert.Equal(t, string(apierror.CodeValidationRoleBindingNodesInvalid), code(out))

		c, out = env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", u), map[string]any{
			"manual_roles": []string{name(scopedRole), model.RoleAuditor},
			"role_nodes":   map[string][]uint{name(scopedRole): {n1.ID, n2.ID}},
		})
		require.Equal(t, http.StatusOK, c, "%v", out)

		c, out = env.api("S01", "GET", userPath(u), nil)
		require.Equal(t, http.StatusOK, c, "%v", out)
		rs := rows(out)
		require.Len(t, rs, 2)
		scoped, global := byRole(rs, scopedRole), byRole(rs, auditor)
		assert.Equal(t, []uint{n1.ID, n2.ID}, nodeIDs(scoped))
		assert.Equal(t, "manual", scoped["source"])
		assert.Equal(t, []string{"builtin_key", "node_ids", "role_id", "role_name", "source"}, keys(scoped))
		assert.Equal(t, []string{"builtin_key", "role_id", "role_name", "source"}, keys(global))
		assert.Equal(t, model.RoleAuditor, global["builtin_key"])
		assert.Nil(t, scoped["builtin_key"])

		c, _ = env.api("S01", "GET", userPath(999999), nil)
		assert.Equal(t, http.StatusNotFound, c)
	})

	t.Run("群組：節點範圍列帶 node_ids，全域列鍵集照舊", func(t *testing.T) {
		g := model.UserGroup{Name: "sbr-group"}
		require.NoError(t, env.db.Create(&g).Error)
		c, out := env.api("S01", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", g.ID), map[string]any{
			"role_ids": []uint{scopedRole, auditor}, "role_nodes": map[string][]uint{fmt.Sprint(scopedRole): {n1.ID}},
		})
		require.Equal(t, http.StatusOK, c, "%v", out)
		c, out = env.api("S01", "GET", fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", g.ID), nil)
		require.Equal(t, http.StatusOK, c, "%v", out)
		rs := rows(out)
		require.Len(t, rs, 2)
		scoped, global := byRole(rs, scopedRole), byRole(rs, auditor)
		assert.Equal(t, []uint{n1.ID}, nodeIDs(scoped))
		assert.Equal(t, []string{"node_ids", "role_id", "role_name", "scope"}, keys(scoped))
		assert.Equal(t, []string{"role_id", "role_name", "scope"}, keys(global))
	})

	t.Run("只有全域指派：既有三個讀取不多出節點欄位", func(t *testing.T) {
		u := env.createUser("sbr-global-user", []string{model.RoleAuditor})
		g := model.UserGroup{Name: "sbr-global-group"}
		require.NoError(t, env.db.Create(&g).Error)
		c, out := env.api("S01", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", g.ID), map[string]any{"role_ids": []uint{auditor}})
		require.Equal(t, http.StatusOK, c, "%v", out)

		get := func(p string) (int, string, map[string]any) {
			req := httptest.NewRequest("GET", p, nil)
			req.Header.Set("Authorization", "Bearer "+env.subjects["S01"].Token)
			rec := env.serve(req)
			m := map[string]any{}
			_ = json.Unmarshal(rec.Body.Bytes(), &m)
			return rec.Code, rec.Body.String(), m
		}
		for _, p := range []string{
			fmt.Sprintf("/api/v1/users/%d", u),
			"/api/v1/user-groups",
			fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", g.ID),
			userPath(u),
		} {
			code, body, _ := get(p)
			require.Equal(t, http.StatusOK, code, p)
			assert.False(t, strings.Contains(body, "node_ids"), "%s 不應有 node_ids：%s", p, body)
		}
		_, _, m := get(fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", g.ID))
		for _, r := range rows(m) {
			assert.Equal(t, []string{"role_id", "role_name", "scope"}, keys(r))
		}
	})
}
