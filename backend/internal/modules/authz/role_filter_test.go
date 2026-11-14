package authz

import (
	"fmt"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 角色限定（TokenFacts.RoleFilter）的解析行為。

func resolveFiltered(t *testing.T, db *gorm.DB, userID uint, f *RoleFilter) *Principal {
	t.Helper()
	p, err := ResolveUserOn(db, userID, TokenFacts{SubjectKind: model.KindHuman, RoleFilter: f})
	require.NoError(t, err)
	return p
}

func addGroupRole(t *testing.T, db *gorm.DB, userID, roleID uint) *model.UserGroup {
	t.Helper()
	grp := &model.UserGroup{Name: fmt.Sprintf("grp-%d-%d", userID, roleID)}
	require.NoError(t, db.Create(grp).Error)
	require.NoError(t, db.Create(&model.UserGroupMember{UserGroupID: grp.ID, UserID: userID, Manual: true}).Error)
	require.NoError(t, db.Create(&model.UserGroupRole{UserGroupID: grp.ID, RoleID: roleID, ScopeKind: model.ScopeKindGlobal}).Error)
	return grp
}

func TestRoleFilterSubset(t *testing.T) {
	db := newPrincipalDB(t)
	idm := mkRole(t, db, "idm", model.BuiltinIdentityAdmin)
	assetAdm := mkRole(t, db, "assets", model.BuiltinAssetAdmin)
	u := mkUser(t, db, "subset")
	assignDirect(t, db, u.ID, idm.ID, model.ScopeKindGlobal)
	assignDirect(t, db, u.ID, assetAdm.ID, model.ScopeKindGlobal)

	full := resolveFiltered(t, db, u.ID, nil)
	require.True(t, full.Has(PermUserManage) && full.Has(PermAssetUpdate))

	p := resolveFiltered(t, db, u.ID, NewRoleFilter([]uint{idm.ID}))
	assert.True(t, p.Has(PermUserManage), "限定內角色的能力保留")
	assert.True(t, p.Has(PermRoleAssign))
	assert.False(t, p.Has(PermAssetUpdate), "限定外角色的能力不出現")
	require.Len(t, p.Assignments, 1)
	assert.Equal(t, idm.ID, p.Assignments[0].RoleID)
	assert.Equal(t, NewRoleFilter([]uint{idm.ID}).RoleIDs(), p.Facts.RoleFilter.RoleIDs(), "限定隨事實保留在主體上")
}

func TestRoleFilterIncludesUnheldRole(t *testing.T) {
	db := newPrincipalDB(t)
	idm := mkRole(t, db, "idm", model.BuiltinIdentityAdmin)
	admin := mkRole(t, db, "admin", model.BuiltinSuperAdmin)
	u := mkUser(t, db, "unheld")
	assignDirect(t, db, u.ID, idm.ID, model.ScopeKindGlobal)

	p := resolveFiltered(t, db, u.ID, NewRoleFilter([]uint{idm.ID, admin.ID}))
	assert.False(t, p.IsSuperAdmin(), "限定含本人未持有的角色不授予該角色")
	assert.ElementsMatch(t, permStrings(resolveFiltered(t, db, u.ID, nil).Capabilities()), permStrings(p.Capabilities()),
		"限定只能縮小、不能擴大：結果等於本人持有且在限定內的指派")
}

// TestRoleFilterNilUnchanged 未限定（nil）與修改前（不帶此欄的事實）結果逐項相同，含零指派的相容範本。
func TestRoleFilterNilUnchanged(t *testing.T) {
	db := newPrincipalDB(t)
	admin := mkRole(t, db, "admin", model.BuiltinSuperAdmin)
	aud := mkRole(t, db, "auditor", model.BuiltinAuditor)
	idm := mkRole(t, db, "idm", model.BuiltinIdentityAdmin)
	zero := mkUser(t, db, "zero")
	su := mkUser(t, db, "su")
	assignDirect(t, db, su.ID, admin.ID, model.ScopeKindGlobal)
	mixed := mkUser(t, db, "mixed")
	assignDirect(t, db, mixed.ID, aud.ID, model.ScopeKindGlobal)
	addGroupRole(t, db, mixed.ID, idm.ID)

	for _, u := range []*model.User{zero, su, mixed} {
		before, err := ResolveUserOn(db, u.ID, TokenFacts{SubjectKind: model.KindHuman})
		require.NoError(t, err)
		after := resolveFiltered(t, db, u.ID, nil)
		assert.Equal(t, permStrings(before.Capabilities()), permStrings(after.Capabilities()), u.Username)
		assert.Equal(t, before.LegacyRole(), after.LegacyRole(), u.Username)
		assert.Equal(t, before.IsSuperAdmin(), after.IsSuperAdmin(), u.Username)
		assert.Equal(t, before.Assignments, after.Assignments, u.Username)
	}
	assert.True(t, resolveFiltered(t, db, zero.ID, nil).Has(PermAssetView), "零指派帳號照舊取得一般使用者範本")
}

func TestRoleFilterEmptyNonNilHasNoAssetView(t *testing.T) {
	db := newPrincipalDB(t)
	idm := mkRole(t, db, "idm", model.BuiltinIdentityAdmin)
	zero := mkUser(t, db, "zero")
	held := mkUser(t, db, "held")
	assignDirect(t, db, held.ID, idm.ID, model.ScopeKindGlobal)
	for _, u := range []*model.User{zero, held} {
		p := resolveFiltered(t, db, u.ID, NewRoleFilter(nil))
		assert.False(t, p.Has(PermAssetView), "%s：非 nil 的空限定不得退回零指派相容範本", u.Username)
		assert.Empty(t, p.Capabilities(), u.Username)
		assert.Empty(t, p.Assignments, u.Username)
		assert.Equal(t, LegacyRoleNone, p.LegacyRole(), u.Username)
	}
	assert.Empty(t, NewPrincipal(1, TokenFacts{RoleFilter: &RoleFilter{}}, nil).Capabilities(), "零值限定同樣是限定為無")
}

func TestRoleFilterAllRevokedHasNoCapability(t *testing.T) {
	db := newPrincipalDB(t)
	idm := mkRole(t, db, "idm", model.BuiltinIdentityAdmin)
	u := mkUser(t, db, "revoked")
	assignDirect(t, db, u.ID, idm.ID, model.ScopeKindGlobal)
	f := NewRoleFilter([]uint{idm.ID})
	require.True(t, resolveFiltered(t, db, u.ID, f).Has(PermUserManage))

	require.NoError(t, db.Where("user_id = ? AND role_id = ?", u.ID, idm.ID).Delete(&model.UserRole{}).Error)
	p := resolveFiltered(t, db, u.ID, f)
	assert.Empty(t, p.Capabilities(), "授權角色全數收回後沒有任何能力")
	assert.False(t, p.Has(PermAssetView))
	assert.True(t, resolveFiltered(t, db, u.ID, nil).Has(PermAssetView), "對照：同一帳號未限定時是零指派相容範本")

	assignDirect(t, db, u.ID, idm.ID, model.ScopeKindGlobal)
	assert.True(t, resolveFiltered(t, db, u.ID, f).Has(PermUserManage), "指派回來即恢復")
}

func TestRoleFilterRoleDeleted(t *testing.T) {
	db := newPrincipalDB(t)
	require.NoError(t, db.AutoMigrate(&model.RolePermission{}))
	custom := mkCustomRole(t, db, "ops", PermUserManage)
	other := mkRole(t, db, "idm", model.BuiltinIdentityAdmin)
	u := mkUser(t, db, "role-deleted")
	assignDirect(t, db, u.ID, custom.ID, model.ScopeKindGlobal)
	assignDirect(t, db, u.ID, other.ID, model.ScopeKindGlobal)
	f := NewRoleFilter([]uint{custom.ID})
	require.True(t, resolveFiltered(t, db, u.ID, f).Has(PermUserManage))

	require.NoError(t, db.Delete(custom).Error)
	p := resolveFiltered(t, db, u.ID, f)
	assert.Empty(t, p.Capabilities(), "角色刪除後失去它，其餘未授權角色不補上")

	again := mkCustomRole(t, db, "ops-recreated", PermUserManage)
	assignDirect(t, db, u.ID, again.ID, model.ScopeKindGlobal)
	assert.Empty(t, resolveFiltered(t, db, u.ID, f).Capabilities(), "重建的新角色是另一個識別，不繼承")
}

func TestRoleFilterDualSourceRevokeOne(t *testing.T) {
	db := newPrincipalDB(t)
	idm := mkRole(t, db, "idm", model.BuiltinIdentityAdmin)
	u := mkUser(t, db, "dual")
	assignDirect(t, db, u.ID, idm.ID, model.ScopeKindGlobal)
	grp := addGroupRole(t, db, u.ID, idm.ID)
	f := NewRoleFilter([]uint{idm.ID})
	p := resolveFiltered(t, db, u.ID, f)
	require.Len(t, p.Assignments, 2, "直接與經群組兩個來源都保留")

	require.NoError(t, db.Where("user_id = ? AND role_id = ?", u.ID, idm.ID).Delete(&model.UserRole{}).Error)
	p = resolveFiltered(t, db, u.ID, f)
	assert.True(t, p.Has(PermUserManage), "收回直接指派後群組來源仍生效")
	require.Len(t, p.Assignments, 1)
	assert.Equal(t, ViaGroup, p.Assignments[0].Via)

	assignDirect(t, db, u.ID, idm.ID, model.ScopeKindGlobal)
	require.NoError(t, db.Where("user_group_id = ? AND user_id = ?", grp.ID, u.ID).Delete(&model.UserGroupMember{}).Error)
	p = resolveFiltered(t, db, u.ID, f)
	assert.True(t, p.Has(PermUserManage), "移出群組後直接指派仍生效")
	require.Len(t, p.Assignments, 1)
	assert.Equal(t, ViaDirect, p.Assignments[0].Via)
}

// TestRoleFilterBuiltinIdentityFromFilteredOnly 內建身分只由過濾後的指派決定：
// 超級管理者帳號的限定只含身分管理角色時，主體不是超級管理者。
func TestRoleFilterBuiltinIdentityFromFilteredOnly(t *testing.T) {
	db := newPrincipalDB(t)
	admin := mkRole(t, db, "admin", model.BuiltinSuperAdmin)
	sec := mkRole(t, db, "sec", model.BuiltinSecurityAdmin)
	idm := mkRole(t, db, "idm", model.BuiltinIdentityAdmin)
	u := mkUser(t, db, "super")
	assignDirect(t, db, u.ID, admin.ID, model.ScopeKindGlobal)
	assignDirect(t, db, u.ID, sec.ID, model.ScopeKindGlobal)
	addGroupRole(t, db, u.ID, idm.ID)

	require.True(t, resolveFiltered(t, db, u.ID, nil).IsSuperAdmin())
	p := resolveFiltered(t, db, u.ID, NewRoleFilter([]uint{idm.ID}))
	assert.False(t, p.IsSuperAdmin())
	assert.False(t, p.HasBuiltin(model.BuiltinSecurityAdmin))
	assert.False(t, p.ConnectionShortcut(model.PermissionConnect))
	assert.NotEqual(t, LegacyRoleAdmin, p.LegacyRole())
	assert.True(t, p.Has(PermUserManage))
	assert.False(t, p.Has(PermCredentialSetSecret), "限定外角色的能力不出現")

	p = resolveFiltered(t, db, u.ID, NewRoleFilter([]uint{admin.ID}))
	assert.True(t, p.IsSuperAdmin(), "授權了超級管理者角色才是超級管理者")
}

func TestRoleFilterNodeScopeFollows(t *testing.T) {
	db := newPrincipalDB(t)
	assets := mkRole(t, db, "assets", model.BuiltinAssetAdmin)
	idm := mkRole(t, db, "idm", model.BuiltinIdentityAdmin)
	node := mkNode(t, db, "n1", nil)
	u := mkUser(t, db, "scoped")
	assignDirect(t, db, u.ID, assets.ID, model.ScopeKindNodes)
	assignDirect(t, db, u.ID, idm.ID, model.ScopeKindGlobal)
	require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: u.ID, RoleID: assets.ID, NodeID: node.ID}).Error)

	f := NewRoleFilter([]uint{assets.ID})
	p := resolveFiltered(t, db, u.ID, f)
	require.Len(t, p.Assignments, 1)
	assert.Equal(t, []uint{node.ID}, p.Assignments[0].LiveNodeIDs, "節點範圍跟隨本人的指派")
	assert.True(t, p.Has(PermAssetUpdate))
	assert.False(t, p.Has(PermUserManage))

	require.NoError(t, db.Delete(node).Error)
	p = resolveFiltered(t, db, u.ID, f)
	assert.False(t, p.Has(PermAssetUpdate), "範圍節點全數消失時指派不生效")
	assert.Empty(t, p.Capabilities())
}

// TestRoleFilterCarriedThroughTransactionalReResolution 範圍判定在交易內以傳入主體的 UserID 與事實重解，
// 角色限定隨事實帶入，重解結果與帶限定的請求主體一致，不退回帳號的完整身分。
func TestRoleFilterCarriedThroughTransactionalReResolution(t *testing.T) {
	db := newPrincipalDB(t)
	idm := mkRole(t, db, "idm", model.BuiltinIdentityAdmin)
	admin := mkRole(t, db, "admin", model.BuiltinSuperAdmin)
	u := mkUser(t, db, "txre")
	assignDirect(t, db, u.ID, idm.ID, model.ScopeKindGlobal)
	assignDirect(t, db, u.ID, admin.ID, model.ScopeKindGlobal)
	ev := NewScopeEvaluator(ProductCatalogue(), nil)

	filtered := resolveFiltered(t, db, u.ID, NewRoleFilter([]uint{idm.ID}))
	require.False(t, filtered.IsSuperAdmin())
	re, err := ev.resolveInTx(db, filtered)
	require.NoError(t, err)
	assert.False(t, re.IsSuperAdmin(), "交易內重解保留限定")
	assert.False(t, re.Has(PermAssetUpdate))
	assert.True(t, re.Has(PermUserManage))

	full, err := ev.resolveInTx(db, resolveFiltered(t, db, u.ID, nil))
	require.NoError(t, err)
	assert.True(t, full.IsSuperAdmin(), "未限定的請求主體行為不變")
}
