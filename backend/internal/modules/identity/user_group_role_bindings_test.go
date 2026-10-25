package identity

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

type groupBindEnv struct {
	*guardEnv
	svc *UserGroupService
}

func newGroupBindEnv(t *testing.T) *groupBindEnv {
	t.Helper()
	e := newGuardEnv(t, true)
	svc := NewUserGroupService(e.db, audit.NewTxSink(), nil)
	svc.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	return &groupBindEnv{guardEnv: e, svc: svc}
}

func (e *groupBindEnv) group(t *testing.T, name string, members ...uint) uint {
	t.Helper()
	g := model.UserGroup{Name: name}
	require.NoError(t, e.db.Create(&g).Error)
	for _, m := range members {
		require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: m, Manual: true}).Error)
	}
	return g.ID
}

func (e *groupBindEnv) epoch(t *testing.T, uid uint) int {
	t.Helper()
	var u model.User
	require.NoError(t, e.db.First(&u, uid).Error)
	return u.CredentialEpoch
}

// refresh 給使用者發一張有效的 refresh 憑證。
func (e *groupBindEnv) refresh(t *testing.T, uid uint) {
	t.Helper()
	now := time.Now()
	require.NoError(t, e.db.Create(&model.RefreshToken{UserID: uid, TokenHash: fmt.Sprintf("h-%d-%d", uid, now.UnixNano()),
		SessionStartedAt: now, ExpiresAt: now.Add(time.Hour), LastUsedAt: now}).Error)
}

// liveRefresh 使用者未撤銷的 refresh 憑證數。
func (e *groupBindEnv) liveRefresh(t *testing.T, uid uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", uid).Count(&n).Error)
	return n
}

func (e *groupBindEnv) bindings(t *testing.T, gid uint) int {
	t.Helper()
	ids, err := authz.UserGroupRoleIDs(e.db, gid)
	require.NoError(t, err)
	return len(ids)
}

func (e *groupBindEnv) groupAudits(t *testing.T, action model.AuditAction) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.AuditLog{}).Where("resource = ? AND action = ?", model.ResourceUserGroupRole, action).Count(&n).Error)
	return n
}

// TestUserGroupRoleBindings 擋：指派不推進世代、移除只讓失去角色者失效、審核者與節點範圍被拒、
// 審計或版本寫入失敗時整筆回滾。
func TestUserGroupRoleBindings(t *testing.T) {
	t.Run("指派一般使用者：成員下一請求取得、版本加一、成員世代不變", func(t *testing.T) {
		e := newGroupBindEnv(t)
		m := e.mkUser(t, "m")
		gid := e.group(t, "g", m)
		v0, ep0 := e.version(t), e.epoch(t, m)
		out, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["auditor"]}})
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "auditor", out[0].RoleName)
		p, err := authz.ResolveUserOn(e.db, m, authz.TokenFacts{})
		require.NoError(t, err)
		require.Len(t, p.Assignments, 1)
		assert.Equal(t, authz.ViaGroup, p.Assignments[0].Via)
		assert.Equal(t, v0+1, e.version(t))
		assert.Equal(t, ep0, e.epoch(t, m))
		assert.EqualValues(t, 1, e.groupAudits(t, model.ActionAssign))
	})

	t.Run("移除稽核員：只經該群組取得者世代推進，直接指派仍持有者不受影響", func(t *testing.T) {
		e := newGroupBindEnv(t)
		viaGroupOnly := e.mkUser(t, "a")
		alsoDirect := e.mkUser(t, "b", "auditor")
		viaOther := e.mkUser(t, "c")
		gid := e.group(t, "g", viaGroupOnly, alsoDirect, viaOther)
		other := e.group(t, "other", viaOther)
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: gid, RoleID: e.roles["auditor"], ScopeKind: model.ScopeKindGlobal}).Error)
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: other, RoleID: e.roles["auditor"], ScopeKind: model.ScopeKindGlobal}).Error)
		ea, eb, ec := e.epoch(t, viaGroupOnly), e.epoch(t, alsoDirect), e.epoch(t, viaOther)
		for _, uid := range []uint{viaGroupOnly, alsoDirect, viaOther} {
			e.refresh(t, uid)
		}
		v0 := e.version(t)
		_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: nil})
		require.NoError(t, err)
		assert.Zero(t, e.liveRefresh(t, viaGroupOnly), "失去角色者的 refresh 一併撤銷")
		assert.EqualValues(t, 1, e.liveRefresh(t, alsoDirect), "仍持有角色者的 refresh 不受影響")
		assert.EqualValues(t, 1, e.liveRefresh(t, viaOther))
		assert.Equal(t, ea+1, e.epoch(t, viaGroupOnly))
		assert.Equal(t, eb, e.epoch(t, alsoDirect))
		assert.Equal(t, ec, e.epoch(t, viaOther))
		assert.Equal(t, v0+1, e.version(t))
		assert.EqualValues(t, 1, e.groupAudits(t, model.ActionRevoke))
		assert.Zero(t, e.bindings(t, gid))
	})

	t.Run("審核者拒絕、節點範圍整筆拒絕、無寫入", func(t *testing.T) {
		e := newGroupBindEnv(t)
		gid := e.group(t, "g")
		v0 := e.version(t)
		_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["approver"]}})
		var pe *PrincipalError
		require.True(t, errors.As(err, &pe))
		assert.Equal(t, apierror.CodeValidationRoleNotGroupBindable, pe.Code)
		_, err = e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["user"]}, ScopeRequested: true})
		require.True(t, errors.As(err, &pe))
		assert.Equal(t, apierror.CodeValidationRoleBindingScopeUnsupported, pe.Code)
		assert.Zero(t, e.bindings(t, gid))
		assert.Equal(t, v0, e.version(t))
	})

	t.Run("審計寫入失敗與權限版本寫入失敗：指派、版本、成員世代全回滾", func(t *testing.T) {
		e := newGroupBindEnv(t)
		m := e.mkUser(t, "m")
		gid := e.group(t, "g", m)
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: gid, RoleID: e.roles["auditor"], ScopeKind: model.ScopeKindGlobal}).Error)
		v0, ep0 := e.version(t), e.epoch(t, m)

		failing := NewUserGroupService(e.db, failingSink{err: errors.New("audit down")}, nil)
		failing.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
		_, err := failing.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: nil})
		require.Error(t, err)
		assert.Equal(t, 1, e.bindings(t, gid))
		assert.Equal(t, v0, e.version(t))
		assert.Equal(t, ep0, e.epoch(t, m))

		// 版本表不可寫（權限狀態寫入面失敗）：同樣整筆回滾
		require.NoError(t, e.db.Exec("ALTER TABLE authz_state RENAME TO authz_state_off").Error)
		_, err = e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: nil})
		require.Error(t, err)
		assert.Equal(t, 1, e.bindings(t, gid))
		assert.Equal(t, ep0, e.epoch(t, m))
		assert.Zero(t, e.groupAudits(t, model.ActionRevoke))
	})
}
