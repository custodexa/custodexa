package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestScopedBindingEndToEnd 以正式組裝與真 API 寫入的指派，擋範圍化指派的端到端行為：
// 直接指派與群組指派各管各的節點、不互相拼接；節點因異常資料失效時不退回全域，
// 且依能力（而不是範圍）拒絕；指派角色權限點只有一個且為全域限定，沒有可發放子集或節點的端點。
func TestScopedBindingEndToEnd(t *testing.T) {
	env := newBaselineEnv(t)
	code := func(m map[string]any) string { s, _ := m["code"].(string); return s }

	mkRole := func(name string, perms []authz.Permission) (uint, string) {
		ps := make([]string, 0, len(perms))
		for _, p := range perms {
			ps = append(ps, string(p))
		}
		c, out := env.api("S01", "POST", "/api/v1/role-definitions", map[string]any{"name": name, "permissions": ps})
		require.Equal(t, http.StatusCreated, c, "%v", out)
		return uint(out["id"].(float64)), name
	}
	nodeA := env.apiID("S01", "POST", "/api/v1/asset-groups", map[string]any{"name": "e2e-node-a"}, "node A")
	nodeB := env.apiID("S01", "POST", "/api/v1/asset-groups", map[string]any{"name": "e2e-node-b"}, "node B")
	mkAsset := func(name string, node uint) uint {
		return env.apiID("S01", "POST", "/api/v1/assets", map[string]any{
			"name": name, "host": "127.0.0.1", "protocol": "ssh", "port": env.recv.port("ssh"),
			"username": "e2e-root", "password": "E2e-Pass-123", "node_ids": []uint{node},
		}, "asset "+name)
	}
	assetA, assetB := mkAsset("e2e-asset-a", nodeA), mkAsset("e2e-asset-b", nodeB)

	_, assetRoleName := mkRole("e2e-asset-admin-a", authz.ScopedTemplateAssetAdminPermissions())
	authRoleID, _ := mkRole("e2e-authz-admin-b", authz.ScopedTemplateAuthorizationAdminPermissions())
	_, assetRole2Name := mkRole("e2e-asset-admin-b", authz.ScopedTemplateAssetAdminPermissions())

	u := env.createUser("e2e-u", nil)
	target := env.createUser("e2e-target", []string{model.RoleUser})
	g := model.UserGroup{Name: "e2e-group"}
	require.NoError(t, env.db.Create(&g).Error)

	// 身分管理員經 HTTP 給 U 直接指派甲節點資產管理、給 U 所屬群組乙節點授權規則管理
	c, out := env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", u), map[string]any{
		"manual_roles": []string{assetRoleName}, "role_nodes": map[string][]uint{assetRoleName: {nodeA}},
	})
	require.Equal(t, http.StatusOK, c, "%v", out)
	c, out = env.api("S01", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/members", g.ID), map[string]any{"manual_user_ids": []uint{u}})
	require.Equal(t, http.StatusOK, c, "%v", out)
	c, out = env.api("S01", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", g.ID), map[string]any{
		"role_ids": []uint{authRoleID}, "role_nodes": map[string][]uint{fmt.Sprint(authRoleID): {nodeB}},
	})
	require.Equal(t, http.StatusOK, c, "%v", out)

	env.subjects["E2E"] = &baselineSubject{ID: "E2E", Username: "e2e-u", UserID: u, Kind: "session", Token: env.issueSessionToken(u)}
	rule := func(asset uint) (int, map[string]any) {
		return env.api("E2E", "POST", "/api/v1/authorizations", map[string]any{"user_id": target, "asset_id": asset, "permission": "connect"})
	}
	update := func(asset uint, name string) (int, map[string]any) {
		return env.api("E2E", "PUT", fmt.Sprintf("/api/v1/assets/%d", asset), map[string]any{"name": name})
	}

	t.Run("群組來源只管乙、直接來源只管甲，不拼接", func(t *testing.T) {
		c, out := rule(assetA)
		assert.Equal(t, http.StatusNotFound, c, "甲下資產建立授權規則：%v", out)
		assert.Equal(t, string(apierror.CodeGrantReferenceNotFound), code(out))

		c, out = rule(assetB)
		assert.Equal(t, http.StatusOK, c, "乙下資產建立授權規則：%v", out)

		c, out = update(assetB, "e2e-asset-b-renamed")
		assert.Equal(t, http.StatusNotFound, c, "乙在資產更新的來源之外：%v", out)
		assert.Equal(t, string(apierror.CodeAssetNotFound), code(out))
	})

	t.Run("目錄與路由清冊：指派角色權限點唯一且全域限定，沒有發放子集或節點的端點", func(t *testing.T) {
		var assignKeys []string
		for _, d := range authz.Catalog() {
			if strings.HasSuffix(string(d.Key), ":assign") {
				assignKeys = append(assignKeys, fmt.Sprintf("%s scope=%s", d.Key, d.Scope))
				assert.Equal(t, authz.ScopeGlobalOnly, d.Scope, string(d.Key))
			}
		}
		t.Logf("EVIDENCE catalog assign keys: %v", assignKeys)
		require.Len(t, assignKeys, 1)
		assert.Contains(t, assignKeys[0], string(authz.PermRoleAssign))

		var roleRoutes []string
		for _, r := range env.engine().Routes() {
			p := strings.ToLower(r.Path)
			if strings.Contains(p, "role") {
				roleRoutes = append(roleRoutes, r.Method+" "+r.Path)
			}
			for _, bad := range []string{"grantable", "delegat", "assignable", "role-subset", "allowed-roles", "role-scope"} {
				assert.NotContains(t, p, bad, "%s %s", r.Method, r.Path)
			}
		}
		sort.Strings(roleRoutes)
		t.Logf("EVIDENCE role routes (%d):\n%s", len(roleRoutes), strings.Join(roleRoutes, "\n"))
	})

	t.Run("甲節點異常失效：不退回全域，依能力拒絕", func(t *testing.T) {
		require.NoError(t, env.db.Delete(&model.AssetGroup{}, nodeA).Error)
		before := time.Now().Add(-time.Second)

		c, out := update(assetA, "e2e-asset-a-renamed")
		assert.Equal(t, http.StatusForbidden, c, "%v", out)
		assert.Equal(t, string(apierror.CodePermissionDenied), code(out))
		assertDenialRow(t, env, u, fmt.Sprintf("/api/v1/assets/%d", assetA), before, map[string]string{
			"denial": "capability", "basis": "all_of", "required": string(authz.PermAssetUpdate),
		})

		// U 沒有因此取得全域能力
		c, out = env.api("E2E", "GET", fmt.Sprintf("/api/v1/users/%d/role-bindings", target), nil)
		assert.Equal(t, http.StatusForbidden, c, "%v", out)
		assert.Equal(t, string(apierror.CodePermissionDenied), code(out))
	})

	t.Run("另給乙節點的資產管理直接指派：甲改回範圍拒絕、乙更新成功", func(t *testing.T) {
		c, out := env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", u), map[string]any{
			"manual_roles": []string{assetRoleName, assetRole2Name},
			"role_nodes":   map[string][]uint{assetRole2Name: {nodeB}},
		})
		require.Equal(t, http.StatusOK, c, "%v", out)

		c, out = update(assetA, "e2e-asset-a-renamed")
		assert.Equal(t, http.StatusNotFound, c, "%v", out)
		assert.Equal(t, string(apierror.CodeAssetNotFound), code(out))

		c, out = update(assetB, "e2e-asset-b-renamed")
		assert.Equal(t, http.StatusOK, c, "%v", out)
	})
}

// assertDenialRow 讀回 U 對 path 的最新審計列，斷言拒絕細節的鍵值。
func assertDenialRow(t *testing.T, env *baselineEnv, uid uint, path string, since time.Time, want map[string]string) {
	t.Helper()
	var row model.AuditLog
	var err error
	for i := 0; i < 40; i++ {
		err = env.db.Where("user_id = ? AND path = ? AND created_at >= ?", uid, path, since).Order("id desc").First(&row).Error
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.NoError(t, err, "找不到 %s 的審計列", path)
	d := map[string]string{}
	require.NoError(t, json.Unmarshal([]byte(row.Details), &d), row.Details)
	t.Logf("EVIDENCE audit details: %s", row.Details)
	_, hasReason := d["scope_reason"]
	assert.False(t, hasReason, "能力拒絕不帶範圍原因（%s）", row.Details)
	for k, v := range want {
		assert.Equal(t, v, d[k], "審計細節 %s（%s）", k, row.Details)
	}
}
