package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
)

// 保護角色（超級管理者、系統安全管理員）經每條路徑取得或失去的界線：
// 讓任何帳號取得或失去保護角色的寫入限超級管理者；保護角色不變、只增減其他角色或
// 只在不帶保護角色的群組增減成員的操作，持指派能力者照常。
//
// 直接指派與外部映射的同組案例在 TestRoleAssignmentGuard 與 TestMappingProtectedTargetGuard，
// 本檔補群組三條路徑（角色指派、成員異動、刪除群組）走服務層的放行與拒絕對照。

func (e *groupBindEnv) setRoles(t *testing.T, op Operator, gid uint, roles ...string) error {
	t.Helper()
	ids := make([]uint, 0, len(roles))
	for _, r := range roles {
		ids = append(ids, e.roles[r])
	}
	_, err := e.svc.ReplaceRoleBindings(op, gid, GroupRoleBindingsRequest{RoleIDs: ids})
	return err
}

func (e *groupBindEnv) roleNamesOf(t *testing.T, gid uint) []string {
	t.Helper()
	rows, err := e.svc.RoleBindings(gid)
	require.NoError(t, err)
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.RoleName)
	}
	return out
}

func TestProtectedRolePaths(t *testing.T) {
	denied := apierror.CodeAuthProtectedRoleAssignment

	t.Run("群組角色指派：非超管新增保護角色被拒，超管放行", func(t *testing.T) {
		e := newGroupBindEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		m := e.mkUser(t, "m")
		gid := e.group(t, "g", m)
		for _, role := range []string{"admin", "security_admin"} {
			assertCode(t, e.setRoles(t, e.op(ida), gid, role), denied)
			assertCode(t, e.setRoles(t, e.op(ida), gid, "auditor", role), denied)
			assert.Zero(t, e.bindings(t, gid), "被拒時群組不帶任何指派")
		}
		require.NoError(t, e.setRoles(t, e.op(e.admin), gid, "security_admin"))
		assert.Equal(t, []string{"security_admin"}, e.roleNamesOf(t, gid))
		require.NoError(t, e.setRoles(t, e.op(e.admin), gid, "admin"))
		assert.Equal(t, []string{"admin"}, e.roleNamesOf(t, gid))
	})

	t.Run("群組角色指派：非超管移除或換掉既有保護角色被拒，超管放行", func(t *testing.T) {
		e := newGroupBindEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		m := e.mkUser(t, "m")
		gid := e.group(t, "g", m)
		e.giveRole(t, gid, "security_admin")
		e.giveRole(t, gid, "auditor")
		// 整組清空、只留一般角色、換成另一個保護角色：三種都動到保護角色
		assertCode(t, e.setRoles(t, e.op(ida), gid), denied)
		assertCode(t, e.setRoles(t, e.op(ida), gid, "auditor"), denied)
		assertCode(t, e.setRoles(t, e.op(ida), gid, "admin", "auditor"), denied)
		assert.ElementsMatch(t, []string{"security_admin", "auditor"}, e.roleNamesOf(t, gid), "被拒時指派不變")
		require.NoError(t, e.setRoles(t, e.op(e.admin), gid, "auditor"))
		assert.Equal(t, []string{"auditor"}, e.roleNamesOf(t, gid))
	})

	t.Run("群組角色指派：群組帶保護角色但保護角色不變，非超管只增減其他角色照常", func(t *testing.T) {
		e := newGroupBindEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		m := e.mkUser(t, "m")
		for _, role := range []string{"security_admin", "admin"} {
			gid := e.group(t, "g-"+role, m)
			e.giveRole(t, gid, role)
			require.NoError(t, e.setRoles(t, e.op(ida), gid, role, "auditor"), "追加一般角色")
			assert.ElementsMatch(t, []string{role, "auditor"}, e.roleNamesOf(t, gid))
			require.NoError(t, e.setRoles(t, e.op(ida), gid, role), "移除一般角色")
			assert.Equal(t, []string{role}, e.roleNamesOf(t, gid))
		}
	})

	t.Run("群組角色指派：成員含超管帳號、群組不帶保護角色，非超管增減一般角色照常", func(t *testing.T) {
		e := newGroupBindEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		gid := e.group(t, "with-super", e.admin)
		require.NoError(t, e.setRoles(t, e.op(ida), gid, "auditor"))
		require.NoError(t, e.setRoles(t, e.op(ida), gid, "user"))
		assert.Equal(t, []string{"user"}, e.roleNamesOf(t, gid))
		// 但要讓這個群組帶保護角色，仍限超管
		assertCode(t, e.setRoles(t, e.op(ida), gid, "user", "admin"), denied)
	})

	t.Run("群組成員異動：帶保護角色的群組加人或移人非超管被拒，超管放行", func(t *testing.T) {
		e := newGroupBindEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		m1, m2 := e.mkUser(t, "m1"), e.mkUser(t, "m2")
		for _, role := range []string{"admin", "security_admin"} {
			gid := e.group(t, "g-"+role, m1)
			e.giveRole(t, gid, role)
			e.giveRole(t, gid, "auditor")
			_, err := e.svc.ReplaceMembersBy(e.op(ida), gid, ids(m1, m2), nil)
			assertCode(t, err, denied)
			_, err = e.svc.ReplaceMembersBy(e.op(ida), gid, ids(), nil)
			assertCode(t, err, denied)
			assert.True(t, e.memberOf(t, gid, m1))
			assert.False(t, e.memberOf(t, gid, m2))
			_, err = e.svc.ReplaceMembersBy(e.op(e.admin), gid, ids(m2), nil)
			require.NoError(t, err)
			assert.False(t, e.memberOf(t, gid, m1))
			assert.True(t, e.memberOf(t, gid, m2))
		}
	})

	t.Run("群組成員異動：不帶保護角色的群組，非超管可加減成員（含超管帳號）", func(t *testing.T) {
		e := newGroupBindEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		m := e.mkUser(t, "m")
		plain := e.group(t, "plain")
		_, err := e.svc.ReplaceMembersBy(e.op(ida), plain, ids(m, e.admin), nil)
		require.NoError(t, err)
		assert.True(t, e.memberOf(t, plain, e.admin))
		general := e.group(t, "general", e.admin)
		e.giveRole(t, general, "auditor")
		_, err = e.svc.ReplaceMembersBy(e.op(ida), general, ids(m), nil)
		require.NoError(t, err)
		assert.False(t, e.memberOf(t, general, e.admin))
		assert.True(t, e.memberOf(t, general, m))
	})

	t.Run("刪除群組：帶保護角色非超管被拒，超管放行；不帶保護角色者持指派能力即可", func(t *testing.T) {
		e := newGroupBindEnv(t)
		svc := NewUserGroupService(e.db, e.svc.auditTx, noopRevoker{})
		svc.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
		ida := e.mkUser(t, "ida", "identity_admin")
		m := e.mkUser(t, "m")
		for _, role := range []string{"admin", "security_admin"} {
			gid := e.group(t, "g-"+role, m)
			e.giveRole(t, gid, role)
			_, err := svc.DeleteBy(e.op(ida), gid)
			assertCode(t, err, denied)
			assert.True(t, e.memberOf(t, gid, m), "被拒時群組與成員不變")
			_, err = svc.DeleteBy(e.op(e.admin), gid)
			require.NoError(t, err)
			var n int64
			require.NoError(t, e.db.Model(&model.UserGroup{}).Where("id = ?", gid).Count(&n).Error)
			assert.Zero(t, n)
		}
		withSuper := e.group(t, "with-super", e.admin)
		e.giveRole(t, withSuper, "auditor")
		_, err := svc.DeleteBy(e.op(ida), withSuper)
		require.NoError(t, err)
	})
}
