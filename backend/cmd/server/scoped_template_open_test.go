package main

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// TestScopedTemplateOpen 擋兩個範圍化範本種入後的開放面：目標集合、全域與節點範圍指派、
// 起手與複製來源、鎖定識別與三態判定。
func TestScopedTemplateOpen(t *testing.T) {
	env := newBaselineEnv(t)
	_, err := identity.SeedScopedTemplates(context.Background(), env.db, false)
	require.NoError(t, err)
	code := func(m map[string]any) string { s, _ := m["code"].(string); return s }

	keys := []string{model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin}
	ids := map[string]uint{}
	versions := map[string]float64{}

	t.Run("列表兩範本 assignment_state 為 open", func(t *testing.T) {
		c, out := env.api("S01", "GET", "/api/v1/role-definitions", nil)
		require.Equal(t, http.StatusOK, c, "%v", out)
		rows, _ := out["data"].([]any)
		if rows == nil {
			rows, _ = out["roles"].([]any)
		}
		if rows == nil {
			rows, _ = out["items"].([]any)
		}
		require.NotEmpty(t, rows, "%v", out)
		for _, r := range rows {
			m := r.(map[string]any)
			bk, _ := m["builtin_key"].(string)
			for _, k := range keys {
				if bk == k {
					ids[k] = uint(m["id"].(float64))
					versions[k] = m["definition_version"].(float64)
					assert.Equal(t, identity.AssignmentStateOpen, m["assignment_state"], k)
				}
			}
		}
		require.Len(t, ids, 2)
	})

	nodeA := env.apiID("S01", "POST", "/api/v1/asset-groups", map[string]any{"name": "open-node-a"}, "node A")
	nodeB := env.apiID("S01", "POST", "/api/v1/asset-groups", map[string]any{"name": "open-node-b"}, "node B")
	mkAsset := func(name string, node uint) uint {
		return env.apiID("S01", "POST", "/api/v1/assets", map[string]any{
			"name": name, "host": "127.0.0.1", "protocol": "ssh", "port": env.recv.port("ssh"),
			"username": "open-root", "password": "Open-Pass-123", "node_ids": []uint{node},
		}, "asset "+name)
	}
	assetA, assetB := mkAsset("open-asset-a", nodeA), mkAsset("open-asset-b", nodeB)
	target := env.createUser("open-target", []string{model.RoleUser})

	t.Run("全域與節點範圍指派授權管理員範本都成功，真主體取得能力且範圍外與不存在同形", func(t *testing.T) {
		global := env.createUser("open-global", nil)
		scoped := env.createUser("open-scoped", nil)
		c, out := env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", global), map[string]any{
			"manual_roles": []string{model.BuiltinAuthzAdmin},
		})
		require.Equal(t, http.StatusOK, c, "%v", out)
		c, out = env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", scoped), map[string]any{
			"manual_roles": []string{model.BuiltinAuthzAdmin},
			"role_nodes":   map[string][]uint{model.BuiltinAuthzAdmin: {nodeA}},
		})
		require.Equal(t, http.StatusOK, c, "%v", out)
		env.subjects["OPEN_SCOPED"] = &baselineSubject{ID: "OPEN_SCOPED", Username: "open-scoped", UserID: scoped, Kind: "session", Token: env.issueSessionToken(scoped)}
		rule := func(asset uint) (int, map[string]any) {
			return env.api("OPEN_SCOPED", "POST", "/api/v1/authorizations", map[string]any{"user_id": target, "asset_id": asset, "permission": "connect"})
		}
		c, out = rule(assetA)
		assert.Equal(t, http.StatusOK, c, "範圍內：%v", out)
		c, out = rule(assetB)
		assert.Equal(t, http.StatusNotFound, c, "範圍外：%v", out)
		assert.Equal(t, string(apierror.CodeGrantReferenceNotFound), code(out))
		c, out = env.api("OPEN_SCOPED", "POST", "/api/v1/authorizations", map[string]any{"user_id": target, "asset_id": 999999, "permission": "connect"})
		assert.Equal(t, http.StatusNotFound, c, "不存在：%v", out)
		assert.Equal(t, string(apierror.CodeGrantReferenceNotFound), code(out))
	})

	t.Run("鎖定識別與三態判定", func(t *testing.T) {
		for _, k := range keys {
			assert.True(t, authz.IsLockedManagementTemplate(k), k)
			st, reason := authz.ClassifyNodeScopability(k, authz.TemplatePermissions(k))
			assert.Equal(t, authz.NodeScopabilityEffective, st, k)
			assert.Empty(t, reason, k)
		}
	})

	t.Run("起手新增與複製得到無內建識別、集合相同的自訂角色", func(t *testing.T) {
		src := ids[model.BuiltinAssetAdmin]
		want := permNames(authz.TemplatePermissions(model.BuiltinAssetAdmin))
		check := func(out map[string]any) {
			assert.Nil(t, out["builtin_key"])
			var got []string
			for _, p := range out["permissions"].([]any) {
				got = append(got, p.(string))
			}
			assert.ElementsMatch(t, want, got)
		}
		c, out := env.api("S01", "POST", "/api/v1/role-definitions", map[string]any{
			"name": "open-from-template", "permissions": want, "template_role_id": src,
		})
		require.Equal(t, http.StatusCreated, c, "%v", out)
		check(out)
		c, out = env.api("S01", "POST", fmt.Sprintf("/api/v1/role-definitions/%d/copy", src), map[string]any{"name": "open-copy"})
		require.Equal(t, http.StatusCreated, c, "%v", out)
		check(out)
	})

	t.Run("修改與刪除兩範本被拒且版本不變", func(t *testing.T) {
		for _, k := range keys {
			id := ids[k]
			c, out := env.api("S01", "PUT", fmt.Sprintf("/api/v1/role-definitions/%d", id), map[string]any{
				"name": "renamed", "permissions": []string{"asset:view"}, "expected_version": versions[k],
			})
			assert.Equal(t, http.StatusConflict, c, "%s：%v", k, out)
			assert.Equal(t, "ROLE_DEFINITION_LOCKED", code(out), k)
			c, out = env.api("S01", "DELETE", fmt.Sprintf("/api/v1/role-definitions/%d?expected_version=%v", id, versions[k]), nil)
			assert.Equal(t, http.StatusConflict, c, "%s：%v", k, out)
			assert.Equal(t, "ROLE_DEFINITION_LOCKED", code(out), k)
			var r model.Role
			require.NoError(t, env.db.First(&r, id).Error)
			assert.EqualValues(t, versions[k], r.DefinitionVersion, k)
			assert.False(t, r.DeletedAt.Valid, k)
		}
	})
}

func permNames(ps []authz.Permission) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, string(p))
	}
	return out
}
