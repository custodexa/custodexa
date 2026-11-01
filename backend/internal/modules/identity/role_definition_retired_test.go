package identity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 升級前已存入自訂角色的「結束連線」鍵屬已收回的鍵：讀取與複製不帶它、修改前集合照實含它、
// 內建超管範本仍持有它。

// insertLegacyRole 直接寫入含指定鍵的自訂角色（模擬升級前合法建立，略過可指派檢查）。
func (e *roleDefEnv) insertLegacyRole(t *testing.T, name string, keys ...string) uint {
	t.Helper()
	r := model.Role{Name: name, DefinitionVersion: 1}
	require.NoError(t, e.db.Create(&r).Error)
	for _, k := range keys {
		require.NoError(t, e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: k}).Error)
	}
	return r.ID
}

func TestRetiredPermissionKeyOnCustomRole(t *testing.T) {
	ctx := context.Background()
	t.Run("讀取不帶已收回的鍵並另行列出", func(t *testing.T) {
		e := newRoleDefEnv(t)
		id := e.insertLegacyRole(t, "legacy-ops", "session:view", "session:terminate")
		d, err := e.svc.GetDefinition(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, []string{"session:view"}, d.Permissions)
		assert.Equal(t, []string{"session:terminate"}, d.RetiredPermissions)
		assert.Empty(t, d.MissingDependencies)
	})
	t.Run("複製只含可指派集合", func(t *testing.T) {
		e := newRoleDefEnv(t)
		id := e.insertLegacyRole(t, "legacy-ops", "session:view", "session:terminate")
		cp, err := e.svc.Copy(ctx, e.admin, id, "legacy-copy", "")
		require.NoError(t, err)
		assert.Equal(t, []string{"session:view"}, cp.Permissions)
		var rows []string
		require.NoError(t, e.db.Model(&model.RolePermission{}).Where("role_id = ?", cp.ID).Pluck("permission_key", &rows).Error)
		assert.Equal(t, []string{"session:view"}, rows)
	})
	t.Run("以讀取集合修改成功且修改前集合照實含舊鍵", func(t *testing.T) {
		e := newRoleDefEnv(t)
		id := e.insertLegacyRole(t, "legacy-ops", "session:view", "session:terminate")
		d, err := e.svc.GetDefinition(ctx, id)
		require.NoError(t, err)
		up, err := e.svc.Update(ctx, e.admin, id, d.DefinitionVersion, RoleInput{Name: "legacy-ops", Description: "說明", Permissions: d.Permissions})
		require.NoError(t, err)
		assert.Equal(t, []string{"session:view"}, up.Permissions)
		assert.Empty(t, up.RetiredPermissions)
		var rows []string
		require.NoError(t, e.db.Model(&model.RolePermission{}).Where("role_id = ?", id).Pluck("permission_key", &rows).Error)
		assert.Equal(t, []string{"session:view"}, rows, "儲存後舊鍵被移除")
		require.NotEmpty(t, e.events.events)
		last := e.events.events[len(e.events.events)-1]
		assert.Contains(t, last.Before, "session:terminate", "權限事件的修改前集合照實含舊鍵")
		assert.NotContains(t, last.After, "session:terminate")
		var log model.AuditLog
		require.NoError(t, e.db.Where("action = ?", model.ActionRoleDefinitionUpdate).Order("id desc").First(&log).Error)
		b, err := json.Marshal(log)
		require.NoError(t, err)
		assert.Contains(t, string(b), "session:terminate", "審計明細含修改前的舊鍵")
	})
	t.Run("含已收回鍵的集合新增或修改一律拒絕", func(t *testing.T) {
		e := newRoleDefEnv(t)
		_, err := e.svc.Create(ctx, e.admin, RoleInput{Name: "x", Permissions: []string{"session:view", "session:terminate"}})
		var inv *authz.ErrRolePermissionInvalid
		require.ErrorAs(t, err, &inv)
		id := e.insertLegacyRole(t, "legacy-ops", "session:view")
		_, err = e.svc.Update(ctx, e.admin, id, 1, RoleInput{Name: "legacy-ops", Permissions: []string{"session:view", "session:terminate"}})
		require.ErrorAs(t, err, &inv)
	})
}

func TestRetiredPermissionKeyBuiltinRolesUnchanged(t *testing.T) {
	ctx := context.Background()
	e := newRoleDefEnv(t)
	sa, err := e.svc.GetDefinition(ctx, e.roles["admin"])
	require.NoError(t, err)
	assert.Contains(t, sa.Permissions, "session:terminate", "內建超管範本照常持有")
	assert.Empty(t, sa.RetiredPermissions)
	b, err := json.Marshal(NewRoleDefinitionDetail(sa))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"retired_permissions":[]`, "恆為空陣列而非 null")

	au, err := e.svc.GetDefinition(ctx, e.roles["auditor"])
	require.NoError(t, err)
	assert.Empty(t, au.RetiredPermissions)
	b, err = json.Marshal(NewRoleDefinitionDetail(au))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"retired_permissions":[]`)
}

// 恢復核對：存 session:terminate 無發現；存 hostkey:reset 列為不可指派的保留鍵。
func TestRoleDefinitionRefChecksRetiredKey(t *testing.T) {
	run := func(t *testing.T, e *roleDefEnv, code string) []string {
		t.Helper()
		for _, c := range roleDefinitionRefChecks() {
			if c.Code == code {
				var out []string
				require.NoError(t, c.Query(e.db).Scan(&out).Error)
				return out
			}
		}
		t.Fatalf("找不到核對 %s", code)
		return nil
	}
	e := newRoleDefEnv(t)
	e.insertLegacyRole(t, "legacy-ops", "session:view", "session:terminate")
	assert.Empty(t, run(t, e, "non_assignable_role_permission_key"), "已收回的鍵不列為發現")
	assert.Empty(t, run(t, e, "unknown_role_permission_key"))
	e.insertLegacyRole(t, "legacy-hk", "hostkey:reset")
	got := run(t, e, "non_assignable_role_permission_key")
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "hostkey:reset")
}
