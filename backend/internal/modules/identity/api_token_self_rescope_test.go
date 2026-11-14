package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestAPITokenSelfRoleRescopeDenied token 改變所屬帳號本人某個角色的節點範圍（角色還在、範圍變了）被拒且範圍不變：
// 直接指派的整組替換只改範圍、本人所屬群組的角色只改範圍，兩條途徑都算本人的角色變更。
// 同一請求以人類工作階段送出照常成功（行為與修改前相同）。
func TestAPITokenSelfRoleRescopeDenied(t *testing.T) {
	e := newScopedEnv(t)
	e.create(t, "assetmgr", permStrings(authz.ScopedTemplateAssetAdminPermissions())...)
	a := e.node(t, "甲")
	owner := e.mkUser(t, "owner", "identity_admin")
	require.NoError(t, e.db.Create(&model.UserRole{UserID: owner, RoleID: e.rid(t, "assetmgr"),
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	token := e.tokenOp(t, owner, e.roles["identity_admin"], e.rid(t, "assetmgr"))
	rescope := DirectAssignOptions{RoleNodes: map[string]RoleNodesValue{"assetmgr": nodesOf(a)}}

	t.Run("直接指派只改範圍被拒", func(t *testing.T) {
		_, err := e.users.AssignRolesBy(token, owner, []string{"identity_admin", "assetmgr"}, rescope)
		assertSelfDenied(t, err)
		kind, ids := e.userScope(t, owner, "assetmgr")
		assert.Equal(t, model.ScopeKindGlobal, kind, "範圍不變")
		assert.Empty(t, ids)
	})

	g := e.group(t, "scoped-group", owner)
	require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g, RoleID: e.rid(t, "assetmgr"), ScopeKind: model.ScopeKindGlobal}).Error)
	groupRescope := GroupRoleBindingsRequest{RoleIDs: []uint{e.rid(t, "assetmgr")},
		RoleNodes: map[uint]RoleNodesValue{e.rid(t, "assetmgr"): nodesOf(a)}}
	groupScope := func() string {
		var r model.UserGroupRole
		require.NoError(t, e.db.Where("user_group_id = ? AND role_id = ?", g, e.rid(t, "assetmgr")).First(&r).Error)
		return r.ScopeKind
	}

	t.Run("本人所屬群組的角色只改範圍被拒", func(t *testing.T) {
		_, err := e.svc.ReplaceRoleBindings(token, g, groupRescope)
		assertSelfDenied(t, err)
		assert.Equal(t, model.ScopeKindGlobal, groupScope(), "群組角色範圍不變")
	})

	t.Run("人類工作階段的同一請求照常成功", func(t *testing.T) {
		human := e.op(owner)
		_, err := e.users.AssignRolesBy(human, owner, []string{"identity_admin", "assetmgr"}, rescope)
		require.NoError(t, err)
		kind, ids := e.userScope(t, owner, "assetmgr")
		assert.Equal(t, model.ScopeKindNodes, kind)
		assert.Equal(t, []uint{a}, ids)
		_, err = e.svc.ReplaceRoleBindings(human, g, groupRescope)
		require.NoError(t, err)
		assert.Equal(t, model.ScopeKindNodes, groupScope())
	})
}
