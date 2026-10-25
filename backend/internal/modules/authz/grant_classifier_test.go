package authz

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
)

func gEntry(via string, group uint, roleID uint, name, builtin string, custom ...Permission) GrantEntry {
	a := Assignment{RoleID: roleID, RoleName: name, BuiltinKey: builtin, Via: via, GroupID: group, Scope: model.ScopeKindGlobal}
	if len(custom) > 0 {
		a.Custom, a.Permissions = true, custom
	}
	return entryOf(a)
}

func sum(rules []uint, es ...GrantEntry) GrantSummary {
	return GrantSummary{Entries: es, RuleIDs: rules}
}

// TestGrantChangeClassifier 擋：自我授權方向（增加高、純減少低、互換為高）、對他人的管理類發放、
// 管理類判定以能力類別為準（超管與資產管理類自訂角色算，稽核員、一般使用者、只帶授權規則的群組不算）。
func TestGrantChangeClassifier(t *testing.T) {
	user := gEntry(ViaDirect, 0, 1, "user", model.BuiltinUser)
	auditor := gEntry(ViaDirect, 0, 2, "auditor", model.BuiltinAuditor)
	super := gEntry(ViaDirect, 0, 3, "admin", model.BuiltinSuperAdmin)
	assetMgr := gEntry(ViaDirect, 0, 4, "asset-mgr", "", PermAssetUpdate)
	assetMgrGrp := gEntry(ViaGroup, 9, 4, "asset-mgr", "", PermAssetUpdate)
	nodesScoped := GrantEntry{Via: ViaDirect, RoleID: 4, RoleName: "asset-mgr", Scope: model.ScopeKindNodes}

	t.Run("管理類判定以能力類別為準", func(t *testing.T) {
		assert.True(t, super.Management)
		assert.True(t, assetMgr.Management)
		assert.False(t, auditor.Management, "稽核員範本的告警管理屬稽核組，不算管理類")
		assert.False(t, user.Management)
		assert.True(t, gEntry(ViaDirect, 0, 5, "idp", model.BuiltinIdentityAdmin).Management)
		assert.True(t, gEntry(ViaDirect, 0, 6, "sec", model.BuiltinSecurityAdmin).Management)
		assert.False(t, gEntry(ViaDirect, 0, 7, "view-only", "", PermAssetView).Management)
	})

	t.Run("自己：直接追加、替換、群組指派、加入群組的增加為高", func(t *testing.T) {
		for name, tc := range map[string]struct{ before, after GrantSummary }{
			"追加":         {sum(nil, user), sum(nil, user, auditor)},
			"替換換新角色":     {sum(nil, user), sum(nil, auditor)}, // 互換：有增有減
			"群組角色指派":     {sum(nil, user), sum(nil, user, gEntry(ViaGroup, 9, 2, "auditor", model.BuiltinAuditor))},
			"加入帶授權規則的群組": {sum(nil, user), sum([]uint{11}, user)},
			"加入帶角色的群組":   {sum(nil, user), sum(nil, user, assetMgrGrp)},
		} {
			c := ClassifyGrantChange(tc.before, tc.after, true)
			assert.Equal(t, GrantIncrease, c.SelfDirection, name)
			assert.Equal(t, []string{GrantMarkSelfAuthorization}, c.Marks, name)
			assert.Empty(t, c.ManagementGranted, "自己不算對他人的管理類發放: "+name)
		}
	})

	t.Run("自己：純減少為低，無變動不告警", func(t *testing.T) {
		for name, tc := range map[string]struct{ before, after GrantSummary }{
			"移除":      {sum(nil, user, auditor), sum(nil, user)},
			"群組角色移除":  {sum(nil, user, assetMgrGrp), sum(nil, user)},
			"移出帶規則群組": {sum([]uint{11}, user), sum(nil, user)},
		} {
			c := ClassifyGrantChange(tc.before, tc.after, true)
			assert.Equal(t, GrantDecrease, c.SelfDirection, name)
		}
		c := ClassifyGrantChange(sum([]uint{1}, user), sum([]uint{1}, user), true)
		assert.Equal(t, GrantNone, c.SelfDirection)
		assert.Empty(t, c.Marks)
	})

	t.Run("範圍變更以涵蓋比較：全域改為節點範圍是純縮小，節點範圍改全域或改別的節點是增加", func(t *testing.T) {
		scoped := func(nodes ...uint) GrantEntry {
			e := nodesScoped
			e.Nodes = nodes
			return e
		}
		c := ClassifyGrantChange(sum(nil, assetMgr), sum(nil, scoped()), true)
		assert.Equal(t, GrantDecrease, c.SelfDirection, "全域改為節點範圍＝有效範圍純縮小")
		c = ClassifyGrantChange(sum(nil, scoped(3)), sum(nil, assetMgr), true)
		assert.Equal(t, GrantIncrease, c.SelfDirection)
		c = ClassifyGrantChange(sum(nil, scoped(3)), sum(nil, scoped(4)), true)
		assert.Equal(t, GrantIncrease, c.SelfDirection, "互不涵蓋的互換有增有減，仍為增加")
	})

	t.Run("對他人：不產生自我授權；取得管理類角色為管理類發放，稽核員與一般使用者與規則不命中", func(t *testing.T) {
		c := ClassifyGrantChange(sum(nil, user), sum(nil, user, super), false)
		assert.Equal(t, GrantNone, c.SelfDirection)
		assert.Equal(t, []string{GrantMarkManagementGrant}, c.Marks)
		require.Len(t, c.ManagementGranted, 1)
		assert.Equal(t, "admin", c.ManagementGranted[0].RoleName)
		c = ClassifyGrantChange(sum(nil, user), sum(nil, user, assetMgr), false)
		assert.Equal(t, []string{GrantMarkManagementGrant}, c.Marks)
		for name, after := range map[string]GrantSummary{
			"稽核員":   sum(nil, user, auditor),
			"一般使用者": sum(nil, auditor, user),
			"只帶規則":  sum([]uint{5}, user),
		} {
			c = ClassifyGrantChange(sum(nil, user), after, false)
			assert.Empty(t, c.Marks, name)
		}
		// 管理類角色被移除不算發放
		c = ClassifyGrantChange(sum(nil, user, super), sum(nil, user), false)
		assert.Empty(t, c.Marks)
	})

	t.Run("群組新增的角色：只回管理類", func(t *testing.T) {
		got := ClassifyGroupManagementGrant([]GrantEntry{auditor, assetMgrGrp, user})
		require.Len(t, got, 1)
		assert.Equal(t, uint(4), got[0].RoleID)
	})

	t.Run("告警摘要欄位等於契約表，只含角色名稱、範圍與路徑代碼，無秘密", func(t *testing.T) {
		self := SelfPrivilegeParams("replace", []GrantEntry{user}, []GrantEntry{user, super})
		assert.Equal(t, map[string]string{"path": "replace", "roles_before": "user", "roles_after": "admin,user"}, self)
		assert.Equal(t, map[string]string{"path": "replace", "roles_before": "-", "roles_after": "-"},
			SelfPrivilegeParams("replace", nil, nil), "空集合以 - 表示（目錄要求必要參數非空）")
		mg := ManagementGrantParams("group_roles", "ops-team", []GrantEntry{assetMgrGrp, nodesScoped})
		assert.Equal(t, map[string]string{"path": "group_roles", "recipient": "ops-team", "role_name": "asset-mgr", "scope_summary": "global,nodes"}, mg)
		for _, params := range []map[string]string{self, mg} {
			for k, v := range params {
				assert.NotContains(t, []string{"password", "token", "subject", "secret"}, k)
				assert.NotContains(t, v, "subject")
			}
		}
	})

	t.Run("分級鍵：增加、減少與管理類發放各一把", func(t *testing.T) {
		assert.Equal(t, "self_privilege_increased", SelfPrivilegeAlertKey(GrantIncrease))
		assert.Equal(t, "self_privilege_decreased", SelfPrivilegeAlertKey(GrantDecrease))
		assert.Equal(t, "", SelfPrivilegeAlertKey(GrantNone))
		assert.Equal(t, "management_role_granted", AlertKeyManagementGranted)
	})

	t.Run("摘要從資料庫計算：直接、群組角色與群組帶來的授權規則", func(t *testing.T) {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		sqlDB, _ := db.DB()
		sqlDB.SetMaxOpenConns(1)
		require.NoError(t, migrateWithAuthz(db, &model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{},
			&model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}, &model.RolePermission{},
			&model.AssetGroup{}, &model.AssetAuthorization{}))
		u := model.User{Username: "u", Active: true}
		require.NoError(t, db.Create(&u).Error)
		rUser := model.Role{Name: "user"}
		rCustom := model.Role{Name: "asset-mgr", DefinitionVersion: 1}
		require.NoError(t, db.Create(&rUser).Error)
		require.NoError(t, db.Create(&rCustom).Error)
		require.NoError(t, db.Create(&model.RolePermission{RoleID: rCustom.ID, PermissionKey: string(PermAssetUpdate)}).Error)
		g := model.UserGroup{Name: "g"}
		require.NoError(t, db.Create(&g).Error)
		require.NoError(t, db.Create(&model.UserRole{UserID: u.ID, RoleID: rUser.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		before, err := SummarizeGrants(db, u.ID)
		require.NoError(t, err)

		require.NoError(t, db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: u.ID, Manual: true}).Error)
		require.NoError(t, db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: rCustom.ID, ScopeKind: model.ScopeKindGlobal}).Error)
		gid, aid := g.ID, uint(1)
		require.NoError(t, db.Create(&model.AssetAuthorization{UserGroupID: &gid, AssetID: &aid, Permission: model.PermissionConnect, Source: "manual"}).Error)
		after, err := SummarizeGrants(db, u.ID)
		require.NoError(t, err)
		assert.Len(t, after.Entries, 2)
		assert.Len(t, after.RuleIDs, 1)

		self := ClassifyGrantChange(before, after, true)
		assert.Equal(t, GrantIncrease, self.SelfDirection)
		other := ClassifyGrantChange(before, after, false)
		require.Len(t, other.ManagementGranted, 1)
		assert.Equal(t, "asset-mgr", other.ManagementGranted[0].RoleName)
		grp, err := GroupGrantEntries(db, g.ID)
		require.NoError(t, err)
		require.Len(t, grp, 1)
		assert.True(t, grp[0].Management)
	})
}
