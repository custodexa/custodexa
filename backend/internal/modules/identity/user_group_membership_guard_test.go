package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
)

func (e *groupBindEnv) giveRole(t *testing.T, gid uint, role string) {
	t.Helper()
	require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: gid, RoleID: e.roles[role], ScopeKind: model.ScopeKindGlobal}).Error)
}

func (e *groupBindEnv) memberOf(t *testing.T, gid, uid uint) bool {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.UserGroupMember{}).Where("user_group_id = ? AND user_id = ?", gid, uid).Count(&n).Error)
	return n > 0
}

func (e *groupBindEnv) memberAddedAudits(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.AuditLog{}).Where("details LIKE ?", "%user_group_manual_member_added%").Count(&n).Error)
	return n
}

func ids(v ...uint) *[]uint { return &v }

// TestUserGroupMembershipGuard 擋：帶保護角色指派群組的成員異動限超管、帶一般角色指派須持指派能力、
// agent 不得加入帶管理類指派的群組、刪除群組的同樣規則；加入同交易留痕。
func TestUserGroupMembershipGuard(t *testing.T) {
	t.Run("非超管異動帶保護指派群組的成員被拒，超管成功", func(t *testing.T) {
		e := newGroupBindEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		m1, m2 := e.mkUser(t, "m1"), e.mkUser(t, "m2")
		for _, role := range []string{"admin", "security_admin"} {
			gid := e.group(t, "g-"+role, m1)
			e.giveRole(t, gid, role)
			_, err := e.svc.ReplaceMembersBy(e.op(ida), gid, ids(m1, m2), nil) // 加
			assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
			_, err = e.svc.ReplaceMembersBy(e.op(ida), gid, ids(), nil) // 移
			assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
			assert.True(t, e.memberOf(t, gid, m1))
			assert.False(t, e.memberOf(t, gid, m2))
			_, err = e.svc.ReplaceMembersBy(e.op(e.admin), gid, ids(m1, m2), nil)
			require.NoError(t, err)
			assert.True(t, e.memberOf(t, gid, m2))
		}
	})

	t.Run("只持群組管理能力者：帶一般指派的群組加人被拒，無指派群組加人成功", func(t *testing.T) {
		e := newGroupBindEnv(t)
		// 稽核員範本不含指派能力，充當「只有群組管理（路由層）」的操作者
		mgr := e.mkUser(t, "mgr", "auditor")
		m := e.mkUser(t, "m")
		withRole := e.group(t, "with-role")
		e.giveRole(t, withRole, "auditor")
		_, err := e.svc.ReplaceMembersBy(e.op(mgr), withRole, ids(m), nil)
		assertAssignForbidden(t, err)
		assert.False(t, e.memberOf(t, withRole, m))
		plain := e.group(t, "plain")
		_, err = e.svc.ReplaceMembersBy(e.op(mgr), plain, ids(m), nil)
		require.NoError(t, err)
		assert.True(t, e.memberOf(t, plain, m))
		// 持指派能力者對帶一般指派群組加人成功
		ida := e.mkUser(t, "ida", "identity_admin")
		_, err = e.svc.ReplaceMembersBy(e.op(ida), withRole, ids(m), nil)
		require.NoError(t, err)
	})

	t.Run("agent 加入帶管理類指派群組被拒", func(t *testing.T) {
		e := newGroupBindEnv(t)
		ag := e.agent(t, "bot")
		gid := e.group(t, "mgmt")
		e.giveRole(t, gid, "identity_admin")
		_, err := e.svc.ReplaceMembersBy(e.op(e.admin), gid, ids(ag), nil)
		require.Error(t, err)
		assert.False(t, e.memberOf(t, gid, ag))
	})

	t.Run("加入同交易留痕，審計失敗則成員不變", func(t *testing.T) {
		e := newGroupBindEnv(t)
		m := e.mkUser(t, "m")
		gid := e.group(t, "g")
		_, err := e.svc.ReplaceMembersBy(e.op(e.admin), gid, ids(m), nil)
		require.NoError(t, err)
		assert.EqualValues(t, 1, e.memberAddedAudits(t))
		gid2 := e.group(t, "g2")
		failing := NewUserGroupService(e.db, failingSink{err: assert.AnError}, nil)
		failing.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
		_, err = failing.ReplaceMembersBy(e.op(e.admin), gid2, ids(m), nil)
		require.Error(t, err)
		assert.False(t, e.memberOf(t, gid2, m))
	})

	t.Run("刪除群組：非超管刪保護指派群組被拒；持指派能力者刪一般指派群組成功並移除指派與推進世代", func(t *testing.T) {
		e := newGroupBindEnv(t)
		svc := NewUserGroupService(e.db, e.svc.auditTx, noopRevoker{})
		svc.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
		ida := e.mkUser(t, "ida", "identity_admin")
		m := e.mkUser(t, "m")
		prot := e.group(t, "prot", m)
		e.giveRole(t, prot, "security_admin")
		_, err := svc.DeleteBy(e.op(ida), prot)
		assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
		assert.EqualValues(t, 1, e.bindings(t, prot))

		gen := e.group(t, "gen", m)
		e.giveRole(t, gen, "auditor")
		ep0 := e.epoch(t, m)
		_, err = svc.DeleteBy(e.op(ida), gen)
		require.NoError(t, err)
		assert.Zero(t, e.bindings(t, gen))
		assert.Greater(t, e.epoch(t, m), ep0)
		var n int64
		require.NoError(t, e.db.Model(&model.UserGroup{}).Where("id = ?", gen).Count(&n).Error)
		assert.Zero(t, n)
	})
}

type noopRevoker struct{}

func (noopRevoker) RevokeByUserGroup(*gorm.DB, uint) (int64, error) { return 0, nil }
func (noopRevoker) RevokeByUser(*gorm.DB, uint) error               { return nil }
