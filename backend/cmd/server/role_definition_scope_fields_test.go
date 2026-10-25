package main

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// TestRoleDefinitionScopeFields 擋角色定義回應的節點限定欄位：列表與單筆的兩個布林逐列等於
// 以角色輸入呼叫三態判定的結果、單筆的節點範圍指派筆數、草稿摘要的純集合判定與兩個範圍 token、
// 編輯描述的 scopable，以及草稿摘要不寫任何資料。
func TestRoleDefinitionScopeFields(t *testing.T) {
	env := newBaselineEnv(t)
	_, err := identity.SeedScopedTemplates(context.Background(), env.db, false)
	require.NoError(t, err)

	mkRole := func(name string, perms []string) uint {
		c, out := env.api("S01", "POST", "/api/v1/role-definitions", map[string]any{"name": name, "permissions": perms})
		require.Equal(t, http.StatusCreated, c, "%v", out)
		return uint(out["id"].(float64))
	}
	scopedOnly := mkRole("sf-scoped-only", permNames(authz.ScopedTemplateAssetAdminPermissions()))
	mixed := mkRole("sf-mixed", append(permNames(authz.ScopedTemplateAssetAdminPermissions()), string(authz.PermUserManage)))
	empty := mkRole("sf-empty", []string{})

	// 期望值：以角色輸入（內建識別加集合）直接呼叫三態判定函式
	expect := func(builtinKey string, perms []authz.Permission) (bool, bool, authz.NodeScopeNoEffectReason) {
		class, reason := authz.ClassifyNodeScopability(builtinKey, perms)
		return class != authz.NodeScopabilityRejected, class == authz.NodeScopabilityNoEffect, reason
	}
	toPerms := func(raw any) []authz.Permission {
		var ps []authz.Permission
		for _, p := range raw.([]any) {
			ps = append(ps, authz.Permission(p.(string)))
		}
		return ps
	}

	c, out := env.api("S01", "GET", "/api/v1/role-definitions", nil)
	require.Equal(t, http.StatusOK, c, "%v", out)
	rows := out["data"].([]any)
	seenBuiltin := map[string]bool{}
	seenCustom := map[uint]bool{}
	for _, r := range rows {
		row := r.(map[string]any)
		id := uint(row["id"].(float64))
		bk, _ := row["builtin_key"].(string)
		var perms []authz.Permission
		switch {
		case bk != "":
			perms = authz.TemplatePermissions(bk)
			seenBuiltin[bk] = true
		case row["definition_version"].(float64) >= 1:
			c, one := env.api("S01", "GET", fmt.Sprintf("/api/v1/role-definitions/%d", id), nil)
			require.Equal(t, http.StatusOK, c, "%v", one)
			perms = toPerms(one["permissions"])
			seenCustom[id] = true
		default:
			continue // 升級前存量角色沒有可判定的集合，不在驗點內
		}
		wantScopable, wantNoEffect, reason := expect(bk, perms)
		assert.Equal(t, wantScopable, row["scopable"], "角色 %v scopable", row["name"])
		assert.Equal(t, wantNoEffect, row["node_range_no_effect"], "角色 %v node_range_no_effect", row["name"])
		switch bk {
		case model.BuiltinUser, model.BuiltinApprover:
			assert.Equal(t, authz.NoEffectBuiltinGlobalOnly, reason, bk)
			assert.Equal(t, true, row["scopable"], bk)
			assert.Equal(t, true, row["node_range_no_effect"], bk)
		case model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin:
			assert.Equal(t, true, row["scopable"], bk)
			assert.Equal(t, false, row["node_range_no_effect"], bk)
		}
	}
	for _, k := range []string{model.BuiltinSuperAdmin, model.BuiltinAuditor, model.BuiltinUser, model.BuiltinApprover,
		model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin} {
		assert.True(t, seenBuiltin[k], "列表缺內建角色 %s", k)
	}
	for _, id := range []uint{scopedOnly, mixed, empty} {
		assert.True(t, seenCustom[id], "列表缺自訂角色 %d", id)
	}
	rowOf := func(id uint) map[string]any {
		for _, r := range rows {
			if uint(r.(map[string]any)["id"].(float64)) == id {
				return r.(map[string]any)
			}
		}
		t.Fatalf("列表缺角色 %d", id)
		return nil
	}
	assert.Equal(t, []any{true, false}, []any{rowOf(scopedOnly)["scopable"], rowOf(scopedOnly)["node_range_no_effect"]})
	assert.Equal(t, []any{false, false}, []any{rowOf(mixed)["scopable"], rowOf(mixed)["node_range_no_effect"]})
	assert.Equal(t, []any{true, true}, []any{rowOf(empty)["scopable"], rowOf(empty)["node_range_no_effect"]})
	_, _, emptyReason := expect("", nil)
	assert.Equal(t, authz.NoEffectNoScopedPermission, emptyReason)

	t.Run("單筆與列表同值，節點範圍指派筆數直接與群組合計", func(t *testing.T) {
		nodeA := env.apiID("S01", "POST", "/api/v1/asset-groups", map[string]any{"name": "sf-node-a"}, "node A")
		u := env.createUser("sf-user", nil)
		g := model.UserGroup{Name: "sf-group"}
		require.NoError(t, env.db.Create(&g).Error)
		name := "sf-scoped-only"
		c, o := env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", u), map[string]any{
			"manual_roles": []string{name}, "role_nodes": map[string][]uint{name: {nodeA}},
		})
		require.Equal(t, http.StatusOK, c, "%v", o)
		c, o = env.api("S01", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", g.ID), map[string]any{
			"role_ids": []uint{scopedOnly}, "role_nodes": map[string][]uint{fmt.Sprint(scopedOnly): {nodeA}},
		})
		require.Equal(t, http.StatusOK, c, "%v", o)
		// 同一角色的全域指派不計入
		other := env.createUser("sf-global", nil)
		c, o = env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", other), map[string]any{"manual_roles": []string{name}})
		require.Equal(t, http.StatusOK, c, "%v", o)

		c, one := env.api("S01", "GET", fmt.Sprintf("/api/v1/role-definitions/%d", scopedOnly), nil)
		require.Equal(t, http.StatusOK, c, "%v", one)
		assert.EqualValues(t, 2, one["node_scoped_binding_count"])
		assert.Equal(t, rowOf(scopedOnly)["scopable"], one["scopable"])
		assert.Equal(t, rowOf(scopedOnly)["node_range_no_effect"], one["node_range_no_effect"])
		c, one = env.api("S01", "GET", fmt.Sprintf("/api/v1/role-definitions/%d", empty), nil)
		require.Equal(t, http.StatusOK, c, "%v", one)
		assert.EqualValues(t, 0, one["node_scoped_binding_count"])
	})

	t.Run("草稿摘要：純集合判定與範圍 token，呼叫前後資料不變", func(t *testing.T) {
		count := func() [3]int64 {
			var n [3]int64
			require.NoError(t, env.db.Model(&model.AuditLog{}).Where("action IN ?", []model.AuditAction{
				model.ActionRoleDefinitionCreate, model.ActionRoleDefinitionCopy, model.ActionRoleDefinitionUpdate, model.ActionRoleDefinitionDelete,
			}).Count(&n[0]).Error)
			require.NoError(t, env.db.Table("roles").Count(&n[1]).Error)
			require.NoError(t, env.db.Model(&model.AuthzState{}).Select("version").Scan(&n[2]).Error)
			var sum int64
			require.NoError(t, env.db.Table("roles").Select("COALESCE(SUM(definition_version),0)").Scan(&sum).Error)
			n[1] += sum * 1000
			return n
		}
		before := count()
		draft := func(perms []string) map[string]any {
			c, o := env.api("S01", "POST", "/api/v1/role-definitions/summary", map[string]any{"permissions": perms})
			require.Equal(t, http.StatusOK, c, "%v", o)
			return o
		}
		sum := func(o map[string]any) map[string]any { return o["summary"].(map[string]any) }

		eff := draft(permNames(authz.ScopedTemplateAssetAdminPermissions()))
		assert.Equal(t, true, eff["scopable"])
		assert.Equal(t, false, eff["node_range_no_effect"])
		assert.Equal(t, true, sum(eff)["scope_node_selectable"])
		assert.Equal(t, false, sum(eff)["scope_mixed_global_only"])
		assert.Equal(t, false, sum(eff)["scope_global_only"])

		mix := draft(append(permNames(authz.ScopedTemplateAssetAdminPermissions()), string(authz.PermUserManage)))
		assert.Equal(t, false, mix["scopable"])
		assert.Equal(t, false, mix["node_range_no_effect"])
		assert.Equal(t, false, sum(mix)["scope_node_selectable"])
		assert.Equal(t, true, sum(mix)["scope_mixed_global_only"])

		emp := draft([]string{})
		assert.Equal(t, true, emp["scopable"])
		assert.Equal(t, true, emp["node_range_no_effect"])
		assert.Equal(t, true, sum(emp)["scope_global_only"], "空草稿沿用原有 token")
		assert.Equal(t, false, sum(emp)["scope_node_selectable"])
		assert.Equal(t, false, sum(emp)["scope_mixed_global_only"])

		one := draft([]string{string(authz.PermAssetView)})
		assert.Equal(t, true, one["scopable"])
		assert.Equal(t, false, one["node_range_no_effect"], "單鍵草稿不套用內建身分")
		assert.Equal(t, before, count())
	})

	t.Run("編輯描述：細項與獨立能力等於該鍵是否 scoped-enforced，入口依最後一態三態判定", func(t *testing.T) {
		c, o := env.api("S01", "GET", "/api/v1/role-definitions/descriptors", nil)
		require.Equal(t, http.StatusOK, c, "%v", o)
		entries := o["entries"].([]any)
		require.NotEmpty(t, entries)
		descs := authz.EntryDescriptors()
		require.Len(t, entries, len(descs))
		for i, e := range entries {
			em := e.(map[string]any)
			d := descs[i]
			last := d.States[len(d.States)-1].Keys
			class, _ := authz.ClassifyNodeScopability("", last)
			assert.Equal(t, class == authz.NodeScopabilityEffective, em["scopable"], "入口 %s", d.ID)
			for j, dm := range em["details"].([]any) {
				p, _ := authz.LookupPermission(d.Details[j].Key)
				assert.Equal(t, p.Scope == authz.ScopeEnforced, dm.(map[string]any)["scopable"], "細項 %s", d.Details[j].ID)
			}
		}
		for i, cp := range o["capabilities"].([]any) {
			k := authz.CapabilityDescriptors()[i].Key
			p, _ := authz.LookupPermission(k)
			assert.Equal(t, p.Scope == authz.ScopeEnforced, cp.(map[string]any)["scopable"], "能力 %s", k)
		}
	})
}
