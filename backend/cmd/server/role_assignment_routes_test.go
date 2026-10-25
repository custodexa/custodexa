package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// TestRoleAssignmentRoutes 擋：三條新路由在登錄表有且能力正確；沒有對應能力者讀寫與預覽被拒；
// HTTP 層對保護目標的結果與直接呼叫服務一致；相容目錄下新範本被拒；既有群組列表回應形狀不變；
// 前端只經 api/ 模組呼叫這三條路由（畫面、元件、輔助模組不得自行寫死路徑）。
func TestRoleAssignmentRoutes(t *testing.T) {
	t.Run("三條路由登錄於正確能力", func(t *testing.T) {
		for _, c := range []struct {
			method, path string
			perm         authz.Permission
		}{
			{"GET", "/api/v1/user-groups/:id/role-bindings", authz.PermUserGroupManage},
			{"PUT", "/api/v1/user-groups/:id/role-bindings", authz.PermUserGroupManage},
			{"POST", "/api/v1/role-assignment-previews", authz.PermRoleAssign},
		} {
			e, ok := authz.LookupRoute(c.method, c.path)
			require.True(t, ok, "%s %s 未登錄", c.method, c.path)
			assert.Equal(t, authz.BasePerm, e.Base)
			assert.Equal(t, c.perm, e.Perm)
		}
	})

	env := newBaselineEnv(t)
	ida := env.createUser("route-ida", nil)
	k := model.BuiltinIdentityAdmin
	var idRole model.Role
	if err := env.db.Where("name = ?", "identity_admin").First(&idRole).Error; err != nil {
		idRole = model.Role{Name: "identity_admin", BuiltinKey: &k, DefinitionVersion: 1}
		require.NoError(t, env.db.Create(&idRole).Error)
	}
	require.NoError(t, model.AssignUserRoleWithSource(env.db, ida, idRole.ID, model.RoleSourceManual, model.RoleOriginSystem))
	env.subjects["IDA"] = &baselineSubject{ID: "IDA", Username: "route-ida", UserID: ida, Kind: "session", Token: env.issueSessionToken(ida)}

	group := model.UserGroup{Name: "route-group"}
	require.NoError(t, env.db.Create(&group).Error)
	member := env.createUser("route-member", nil)
	require.NoError(t, env.db.Create(&model.UserGroupMember{UserGroupID: group.ID, UserID: member, Manual: true}).Error)
	bindings := fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", group.ID)
	rid := func(name string) uint { return env.roleID(name) }
	code := func(m map[string]any) string { s, _ := m["code"].(string); return s }

	t.Run("沒有對應能力者讀取、寫入與預覽都被拒", func(t *testing.T) {
		for _, sub := range []string{"S02", "S03"} {
			c, _ := env.api(sub, "GET", bindings, nil)
			assert.Equal(t, http.StatusForbidden, c, sub)
			c, _ = env.api(sub, "PUT", bindings, map[string]any{"role_ids": []uint{}})
			assert.Equal(t, http.StatusForbidden, c, sub)
			c, _ = env.api(sub, "POST", "/api/v1/role-assignment-previews", map[string]any{"kind": "group_roles", "group_id": group.ID})
			assert.Equal(t, http.StatusForbidden, c, sub)
		}
		c, _ := env.api("S00", "GET", bindings, nil)
		assert.Equal(t, http.StatusUnauthorized, c)
	})

	t.Run("身分管理員：一般角色成功、保護目標與直接呼叫服務結果一致、範圍欄位整筆拒絕", func(t *testing.T) {
		c, out := env.api("IDA", "PUT", bindings, map[string]any{"role_ids": []uint{rid(model.RoleAuditor)}})
		require.Equal(t, http.StatusOK, c, "%v", out)
		c, out = env.api("IDA", "GET", bindings, nil)
		require.Equal(t, http.StatusOK, c)
		assert.EqualValues(t, 1, out["total"])

		// 保護目標：HTTP 與直接呼叫服務的錯誤碼相同
		c, out = env.api("IDA", "PUT", bindings, map[string]any{"role_ids": []uint{rid(model.RoleAdmin)}})
		assert.Equal(t, http.StatusForbidden, c)
		svc := identity.NewUserGroupService(env.db, audit.NewTxSink(), nil)
		svc.SetAssignmentGuard(newMappingAssignmentGuard()) // 與路由同一個正式組裝的關卡
		_, direct := svc.ReplaceRoleBindings(identity.Operator{UserID: ida}, group.ID, identity.GroupRoleBindingsRequest{RoleIDs: []uint{rid(model.RoleAdmin)}})
		var pe *identity.PrincipalError
		require.ErrorAs(t, direct, &pe)
		assert.Equal(t, string(pe.Code), code(out))
		assert.Equal(t, string(apierror.CodeAuthProtectedRoleAssignment), code(out))

		// 新範本：正式組裝的路由只代表它實際注入的那一種目錄，另一種以明示注入的服務驗同一個寫入
		assembledFull := assembledCatalogIsFull()
		t.Run("相容目錄（"+catalogVia(false)+"）：新範本被拒", func(t *testing.T) {
			if !assembledFull {
				// 相容目錄下新範本被拒
				c, out := env.api("IDA", "PUT", bindings, map[string]any{"role_ids": []uint{idRole.ID}})
				assert.GreaterOrEqual(t, c, 400, "%v", out)
				return
			}
			compat := identity.NewUserGroupService(env.db, audit.NewTxSink(), nil)
			compat.SetAssignmentGuard(identity.NewAssignmentGuard(identity.CompatCatalog()))
			_, err := compat.ReplaceRoleBindings(identity.Operator{UserID: ida}, group.ID, identity.GroupRoleBindingsRequest{RoleIDs: []uint{idRole.ID}})
			assert.ErrorIs(t, err, identity.ErrRoleNotFound)
		})
		t.Run("完整目錄（"+catalogVia(true)+"）：新範本放行", func(t *testing.T) {
			if assembledFull {
				c, out := env.api("IDA", "PUT", bindings, map[string]any{"role_ids": []uint{idRole.ID}})
				require.Equal(t, http.StatusOK, c, "%v", out)
			} else {
				full := identity.NewUserGroupService(env.db, audit.NewTxSink(), nil)
				full.SetAssignmentGuard(identity.NewAssignmentGuard(identity.FullCatalog()))
				_, err := full.ReplaceRoleBindings(identity.Operator{UserID: ida}, group.ID, identity.GroupRoleBindingsRequest{RoleIDs: []uint{idRole.ID}})
				require.NoError(t, err)
			}
			now, err := authz.UserGroupRoleIDs(env.db, group.ID)
			require.NoError(t, err)
			assert.Equal(t, []uint{idRole.ID}, now)
			// 還原成先前的一般角色，後續案例的現值不受影響
			c, out := env.api("S01", "PUT", bindings, map[string]any{"role_ids": []uint{rid(model.RoleAuditor)}})
			require.Equal(t, http.StatusOK, c, "%v", out)
		})

		// 範圍欄位與審核者
		c, out = env.api("IDA", "PUT", bindings, map[string]any{"role_ids": []uint{rid(model.RoleUser)}, "scope_kind": "node"})
		assert.Equal(t, http.StatusBadRequest, c)
		assert.Equal(t, string(apierror.CodeValidationRoleBindingScopeUnsupported), code(out))
		c, out = env.api("IDA", "PUT", bindings, map[string]any{"role_ids": []uint{rid(model.RoleApprover)}})
		assert.Equal(t, http.StatusBadRequest, c)
		assert.Equal(t, string(apierror.CodeValidationRoleNotGroupBindable), code(out))
		// 失敗的寫入不改現值
		c, out = env.api("IDA", "GET", bindings, nil)
		require.Equal(t, http.StatusOK, c)
		assert.EqualValues(t, 1, out["total"])
	})

	t.Run("超管可替換為保護角色", func(t *testing.T) {
		c, out := env.api("S01", "PUT", bindings, map[string]any{"role_ids": []uint{rid(model.RoleUser)}})
		require.Equal(t, http.StatusOK, c, "%v", out)
	})

	t.Run("等價自訂角色：身分管理員經直接追加、替換、群組角色指派、群組成員皆拒，超管放行，一般自訂角色與只含不保護專屬點者照常可指派", func(t *testing.T) {
		secPerms := []string{}
		for _, p := range authz.TemplatePermissions(model.BuiltinSecurityAdmin) {
			secPerms = append(secPerms, string(p))
		}
		mkRole := func(name string, perms []string) uint {
			c, out := env.api("S01", "POST", "/api/v1/role-definitions", map[string]any{"name": name, "permissions": perms})
			require.Equal(t, http.StatusCreated, c, "%v", out)
			return uint(out["id"].(float64))
		}
		equivID := mkRole("route-secequiv", secPerms)
		mkRole("route-plaincustom", []string{"asset:view"})
		mkRole("route-guardview", []string{"instanceguard:view"}) // 不保護的專屬點（唯讀）
		victim := env.createUser("route-equiv-victim", nil)
		manual := func(uid uint) []string {
			var names []string
			require.NoError(t, env.db.Table("user_roles").Joins("JOIN roles ON roles.id = user_roles.role_id").
				Where("user_roles.user_id = ?", uid).Pluck("roles.name", &names).Error)
			return names
		}
		denied := func(c int, out map[string]any, what string) {
			assert.Equal(t, http.StatusForbidden, c, "%s %v", what, out)
			assert.Equal(t, string(apierror.CodeAuthProtectedRoleAssignment), code(out), what)
		}

		c, out := env.api("IDA", "POST", fmt.Sprintf("/api/v1/users/%d/roles/route-secequiv", victim), nil)
		denied(c, out, "直接追加給他人")
		c, out = env.api("IDA", "POST", fmt.Sprintf("/api/v1/users/%d/roles/route-secequiv", ida), nil)
		denied(c, out, "直接追加給自己")
		c, out = env.api("IDA", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", victim), map[string]any{"manual_roles": []string{"route-secequiv"}})
		denied(c, out, "替換")
		g1 := model.UserGroup{Name: "route-equiv-g1"}
		require.NoError(t, env.db.Create(&g1).Error)
		c, out = env.api("IDA", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", g1.ID), map[string]any{"role_ids": []uint{equivID}})
		denied(c, out, "群組角色指派")
		assert.Zero(t, countBindings(t, env, g1.ID))
		g2 := model.UserGroup{Name: "route-equiv-g2"}
		require.NoError(t, env.db.Create(&g2).Error)
		c, out = env.api("S01", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", g2.ID), map[string]any{"role_ids": []uint{equivID}})
		require.Equal(t, http.StatusOK, c, "超管對群組指派等價角色 %v", out)
		c, out = env.api("IDA", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/members", g2.ID), map[string]any{"manual_user_ids": []uint{victim}})
		denied(c, out, "群組成員")
		assert.NotContains(t, manual(victim), "route-secequiv")
		assert.NotContains(t, manual(ida), "route-secequiv")

		c, out = env.api("IDA", "POST", fmt.Sprintf("/api/v1/users/%d/roles/route-plaincustom", victim), nil)
		require.Equal(t, http.StatusOK, c, "一般自訂角色 %v", out)
		c, out = env.api("IDA", "POST", fmt.Sprintf("/api/v1/users/%d/roles/route-guardview", victim), nil)
		require.Equal(t, http.StatusOK, c, "只含不保護專屬點的自訂角色 %v", out)
		assert.Contains(t, manual(victim), "route-guardview")
		c, out = env.api("S01", "POST", fmt.Sprintf("/api/v1/users/%d/roles/route-secequiv", victim), nil)
		require.Equal(t, http.StatusOK, c, "超管追加等價角色 %v", out)
		assert.Contains(t, manual(victim), "route-secequiv")
	})

	t.Run("預覽：唯讀、角色定義預覽限超管、無效輸入回 400", func(t *testing.T) {
		before := countBindings(t, env, group.ID)
		c, out := env.api("IDA", "POST", "/api/v1/role-assignment-previews",
			map[string]any{"kind": "group_roles", "group_id": group.ID, "role_ids": []uint{rid(model.RoleAuditor)}})
		require.Equal(t, http.StatusOK, c, "%v", out)
		assert.Contains(t, out, "total")
		assert.Equal(t, before, countBindings(t, env, group.ID), "預覽不得寫入")
		c, _ = env.api("IDA", "POST", "/api/v1/role-assignment-previews", map[string]any{"kind": "role_definition", "role_id": 1})
		assert.Equal(t, http.StatusForbidden, c)
		c, _ = env.api("S01", "POST", "/api/v1/role-assignment-previews", map[string]any{"kind": "nope"})
		assert.Equal(t, http.StatusBadRequest, c)
	})

	t.Run("既有群組列表形狀不變", func(t *testing.T) {
		c, out := env.api("S01", "GET", "/api/v1/user-groups", nil)
		require.Equal(t, http.StatusOK, c)
		rows, _ := out["data"].([]any)
		require.NotEmpty(t, rows)
		for _, r := range rows {
			for k := range r.(map[string]any) {
				assert.NotContains(t, strings.ToLower(k), "role", "群組列表不得多出角色欄位")
			}
		}
	})

	t.Run("前端只經 api 模組呼叫這三條路由", func(t *testing.T) {
		root := "../../../frontend/src"
		if _, err := os.Stat(root); err != nil {
			root = "../../frontend/src"
		}
		if _, err := os.Stat(root); err != nil {
			t.Skip("容器內沒有前端原始碼")
		}
		sep := string(filepath.Separator)
		var hits []string
		scanned := 0
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || strings.Contains(p, "node_modules") {
				return nil
			}
			// 允許：api/ 模組（唯一的路徑出處）與測試檔（以路徑斷言請求）。
			if strings.Contains(p, sep+"api"+sep) || strings.Contains(p, "__tests__") || strings.Contains(p, ".spec.") {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			scanned++
			for _, line := range strings.Split(string(b), "\n") {
				t := strings.TrimSpace(line)
				if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") {
					continue // 註解不算呼叫
				}
				if strings.Contains(line, "role-bindings") || strings.Contains(line, "role-assignment-previews") {
					hits = append(hits, p)
					break
				}
			}
			return nil
		})
		require.NotZero(t, scanned, "沒掃到任何前端檔，守衛失效")
		assert.Empty(t, hits, "畫面與元件不得直接寫死角色指派路徑，應經 api/ 模組")
	})
}

func countBindings(t *testing.T, env *baselineEnv, gid uint) int {
	t.Helper()
	ids, err := authz.UserGroupRoleIDs(env.db, gid)
	require.NoError(t, err)
	return len(ids)
}
