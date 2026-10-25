package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 共用指派關卡的拒絕帶出被拒規則的原因碼（供審計 details），回給呼叫端的錯誤照舊比對得到；
// 原因碼是固定機器碼，不含角色名或權限名。
func TestAssignmentGuardDenyReason(t *testing.T) {
	e := newGuardEnv(t, true)
	e.create(t, "assetmgr", "asset:view", "asset:update")
	idAdmin := e.mkUser(t, "ida", "identity_admin")
	plain := e.mkUser(t, "plain")
	victim := e.mkUser(t, "victim")
	ag := e.agent(t, "bot")
	g := model.UserGroup{Name: "g-reason"}
	require.NoError(t, e.db.Create(&g).Error)
	check := func(guard *AssignmentGuard, op Operator, ch AssignmentChange) error {
		return e.db.Transaction(func(tx *gorm.DB) error { return guard.Check(tx, op, ch) })
	}

	cases := []struct {
		name   string
		err    error
		reason string
		is     error
	}{
		{"無可指認的操作者", check(NewAssignmentGuard(FullCatalog()), Operator{}, AssignmentChange{Path: PathAdd, TargetUserID: victim}),
			DenyReasonOperatorMissing, ErrRoleAssignmentForbidden},
		{"目標為超管帳號", e.users.AddRoleBy(e.op(idAdmin), e.admin, "auditor"), DenyReasonProtectedAccount, ErrProtectedAccountOperation},
		{"保護角色", e.users.AddRoleBy(e.op(idAdmin), victim, "admin"), DenyReasonProtectedRole, ErrProtectedRoleAssignment},
		{"缺指派能力", e.users.AddRoleBy(e.op(plain), victim, "auditor"), DenyReasonCapabilityMissing, ErrRoleAssignmentForbidden},
		{"範圍欄位", check(NewAssignmentGuard(FullCatalog()), e.op(e.admin), AssignmentChange{
			Path: PathGroupRoles, GroupID: g.ID, NewRoleIDs: []uint{e.roles["user"]}, ScopeRequested: true}),
			DenyReasonScopeUnsupported, ErrRoleBindingScopeUnsupported},
		{"agent 取得管理類角色", e.users.AddRoleBy(e.op(e.admin), ag, "assetmgr"), DenyReasonAgentRole, ErrAgentRoleForbidden},
		{"可指派目錄以外的角色", check(NewAssignmentGuard(CompatCatalog()), e.op(e.admin), AssignmentChange{
			Path: PathGroupRoles, GroupID: g.ID, NewRoleIDs: []uint{e.roles["identity_admin"]}}),
			DenyReasonRoleNotAssignable, ErrRoleNotFound},
	}
	for _, c := range cases {
		require.Error(t, c.err, c.name)
		assert.ErrorIs(t, c.err, c.is, c.name)
		assert.Equal(t, c.reason, AssignmentDenyReason(c.err), c.name)
	}
	// 放行與非關卡錯誤不帶原因碼
	assert.Empty(t, AssignmentDenyReason(nil))
	assert.Empty(t, AssignmentDenyReason(ErrUserNotFound))
	require.NoError(t, e.users.AddRoleBy(e.op(e.admin), victim, "auditor"))
}
