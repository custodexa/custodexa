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

type previewEnv struct {
	db    *gorm.DB
	roles map[string]uint
}

func newPreviewEnv(t *testing.T) *previewEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, migrateWithAuthz(db, &model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{},
		&model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}, &model.RolePermission{},
		&model.AssetGroup{}, &model.AssetAuthorization{}, &model.AuditLog{}, &model.SystemAlertDetail{}, &model.SystemAlertOutbox{}, &model.AuthzState{}))
	require.NoError(t, db.Create(&model.AuthzState{ID: 1}).Error)
	env := &previewEnv{db: db, roles: map[string]uint{}}
	env.builtin(model.BuiltinSuperAdmin)
	env.builtin(model.BuiltinUser)
	env.builtin(model.BuiltinIdentityAdmin)
	env.builtin(model.BuiltinSecurityAdmin)
	env.custom("authz-mgr", PermAuthorizationManage, PermAssetView)
	env.custom("asset-mgr", PermAssetUpdate, PermAssetView)
	env.custom("viewer", PermAssetView)
	return env
}

func (e *previewEnv) builtin(key string) {
	k := key
	r := model.Role{Name: key, BuiltinKey: &k}
	if err := e.db.Create(&r).Error; err != nil {
		panic(err)
	}
	e.roles[key] = r.ID
}

func (e *previewEnv) custom(name string, perms ...Permission) {
	r := model.Role{Name: name, DefinitionVersion: 1}
	if err := e.db.Create(&r).Error; err != nil {
		panic(err)
	}
	for _, p := range perms {
		if err := e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(p)}).Error; err != nil {
			panic(err)
		}
	}
	e.roles[name] = r.ID
}

func (e *previewEnv) user(name string, roles ...string) uint {
	u := model.User{Username: name, Active: true}
	if err := e.db.Create(&u).Error; err != nil {
		panic(err)
	}
	for _, r := range roles {
		if err := e.db.Create(&model.UserRole{UserID: u.ID, RoleID: e.roles[r], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
			panic(err)
		}
	}
	return u.ID
}

func (e *previewEnv) group(name string, roles ...string) uint {
	g := model.UserGroup{Name: name}
	if err := e.db.Create(&g).Error; err != nil {
		panic(err)
	}
	for _, r := range roles {
		if err := e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.roles[r], ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
			panic(err)
		}
	}
	return g.ID
}

func (e *previewEnv) join(group, user uint) {
	if err := e.db.Create(&model.UserGroupMember{UserGroupID: group, UserID: user, Manual: true}).Error; err != nil {
		panic(err)
	}
}

func (e *previewEnv) ids(names ...string) []uint {
	out := make([]uint, 0, len(names))
	for _, n := range names {
		out = append(out, e.roles[n])
	}
	return out
}

func (e *previewEnv) counts(t *testing.T) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for name, m := range map[string]interface{}{"user_roles": &model.UserRole{}, "members": &model.UserGroupMember{},
		"group_roles": &model.UserGroupRole{}, "role_perms": &model.RolePermission{}, "audit": &model.AuditLog{},
		"alerts": &model.SystemAlertDetail{}, "alert_outbox": &model.SystemAlertOutbox{}} {
		var n int64
		require.NoError(t, e.db.Model(m).Count(&n).Error, name)
		out[name] = n
	}
	v, err := CurrentVersion(e.db)
	require.NoError(t, err)
	out["authz_version"] = v
	return out
}

func subjectOf(t *testing.T, r PreviewResult, uid uint) PreviewSubject {
	t.Helper()
	for _, s := range r.Subjects {
		if s.UserID == uid {
			return s
		}
	}
	t.Fatalf("結果中沒有使用者 %d: %+v", uid, r.Subjects)
	return PreviewSubject{}
}

// TestEffectiveCapabilityPreview 擋：五種危險組合由跨角色或跨群組的有效能力觸發（單一角色定義看不到）、
// 四種輸入各一案、本人與指派能力標示、清單上限截斷且總數正確、預覽唯讀。
func TestEffectiveCapabilityPreview(t *testing.T) {
	t.Run("直接指派：身分管理員加上授權管理自訂角色，跨角色命中身分加業務；本人被標示", func(t *testing.T) {
		env := newPreviewEnv(t)
		self := env.user("op", model.BuiltinIdentityAdmin)
		before := env.counts(t)
		res, err := PreviewEffectiveCapabilities(env.db, PreviewRequest{Kind: PreviewDirectRoles, OperatorID: self, UserID: self,
			RoleIDs: env.ids(model.BuiltinIdentityAdmin, "authz-mgr")})
		require.NoError(t, err)
		s := subjectOf(t, res, self)
		assert.True(t, s.Self)
		assert.True(t, s.AssignCapable, "持指派能力者本人被標示")
		assert.Contains(t, s.NewCombos, ComboIdentityWithBusinessOrConnect)
		assert.NotContains(t, s.NewCombos, ComboAuthzRulesWithAssetOrCredential, "授權管理單獨不構成")
		assert.Contains(t, s.EntriesGained, "authorizations")
		assert.Equal(t, GrantIncrease, s.SelfDirection)
		assert.Equal(t, []string{GrantMarkSelfAuthorization}, s.Marks)
		assert.Equal(t, before, env.counts(t), "預覽前後資料不變")
	})

	t.Run("五種組合各一案（跨角色或跨群組）", func(t *testing.T) {
		cases := []struct {
			name  string
			roles []string
			rule  bool
			want  string
		}{
			{"授權管理加資產管理", []string{"authz-mgr", "asset-mgr"}, false, ComboAuthzRulesWithAssetOrCredential},
			{"安全能力加資產管理", []string{model.BuiltinSecurityAdmin, "asset-mgr"}, false, ComboSecurityWithAssetOrAuthz},
			{"資產管理加連線授權", []string{"asset-mgr"}, true, ComboAssetManagementWithConnect},
			{"身分加安全", []string{model.BuiltinIdentityAdmin, model.BuiltinSecurityAdmin}, false, ComboIdentityWithSecurity},
			{"身分加連線授權", []string{model.BuiltinIdentityAdmin}, true, ComboIdentityWithBusinessOrConnect},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				env := newPreviewEnv(t)
				op := env.user("op", model.BuiltinSuperAdmin)
				target := env.user("target")
				if tc.rule {
					uid, aid := target, uint(1)
					require.NoError(t, env.db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, Source: "manual"}).Error)
				}
				// 單一角色逐一預覽都不命中，合起來才命中
				for _, r := range tc.roles {
					one, err := PreviewEffectiveCapabilities(env.db, PreviewRequest{Kind: PreviewDirectRoles, OperatorID: op, UserID: target, RoleIDs: env.ids(r)})
					require.NoError(t, err)
					if len(tc.roles) > 1 {
						for _, s := range one.Subjects {
							assert.NotContains(t, s.NewCombos, tc.want, "單一角色 "+r+" 看不到組合")
						}
					}
				}
				res, err := PreviewEffectiveCapabilities(env.db, PreviewRequest{Kind: PreviewDirectRoles, OperatorID: op, UserID: target, RoleIDs: env.ids(tc.roles...)})
				require.NoError(t, err)
				s := subjectOf(t, res, target)
				assert.Contains(t, s.NewCombos, tc.want)
				assert.False(t, s.Self)
			})
		}
	})

	t.Run("群組角色指派：成員原有直接角色加上群組角色跨來源命中；只列新命中者與本人", func(t *testing.T) {
		env := newPreviewEnv(t)
		op := env.user("op", model.BuiltinSuperAdmin)
		hit := env.user("hit", "asset-mgr")
		miss := env.user("miss", "viewer")
		g := env.group("g")
		env.join(g, hit)
		env.join(g, miss)
		res, err := PreviewEffectiveCapabilities(env.db, PreviewRequest{Kind: PreviewGroupRoles, OperatorID: op, GroupID: g, RoleIDs: env.ids("authz-mgr")})
		require.NoError(t, err)
		assert.Equal(t, 2, res.Total)
		require.Len(t, res.Subjects, 1, "未新命中者只計數")
		assert.Equal(t, hit, res.Subjects[0].UserID)
		assert.Contains(t, res.Subjects[0].NewCombos, ComboAuthzRulesWithAssetOrCredential)
		assert.True(t, res.Subjects[0].ManagementGranted)
	})

	t.Run("群組成員：加入帶角色與授權規則的群組，成員的直接角色與群組角色合起來命中；移除者不新命中", func(t *testing.T) {
		env := newPreviewEnv(t)
		op := env.user("op", model.BuiltinSuperAdmin)
		joiner := env.user("joiner", model.BuiltinSecurityAdmin)
		leaver := env.user("leaver", "asset-mgr")
		g := env.group("g", "asset-mgr")
		env.join(g, leaver)
		res, err := PreviewEffectiveCapabilities(env.db, PreviewRequest{Kind: PreviewGroupMembers, OperatorID: op, GroupID: g, MemberIDs: []uint{joiner}})
		require.NoError(t, err)
		assert.Equal(t, 2, res.Total, "加入一人、移除一人")
		s := subjectOf(t, res, joiner)
		assert.Contains(t, s.NewCombos, ComboSecurityWithAssetOrAuthz)
		for _, x := range res.Subjects {
			assert.NotEqual(t, leaver, x.UserID)
		}
	})

	t.Run("角色定義修改：改權限集合讓跨群組持有者新命中；內建角色拒絕", func(t *testing.T) {
		env := newPreviewEnv(t)
		op := env.user("op", model.BuiltinSuperAdmin)
		direct := env.user("direct", model.BuiltinIdentityAdmin, "viewer")
		viaGroup := env.user("viagroup", model.BuiltinSecurityAdmin)
		g := env.group("g", "viewer")
		env.join(g, viaGroup)
		res, err := PreviewEffectiveCapabilities(env.db, PreviewRequest{Kind: PreviewRoleDefinition, OperatorID: op, RoleID: env.roles["viewer"],
			Permissions: []string{string(PermAssetView), string(PermAssetUpdate)}, MappingRuleCounter: noMappingRules})
		require.NoError(t, err)
		require.NotNil(t, res.Operation)
		assert.Equal(t, []string{GrantMarkManagementGrant}, res.Operation.Marks, "他人持有者新取得管理類權限點")
		assert.Equal(t, 2, res.Total)
		assert.Contains(t, subjectOf(t, res, direct).NewCombos, ComboIdentityWithBusinessOrConnect)
		assert.Contains(t, subjectOf(t, res, viaGroup).NewCombos, ComboSecurityWithAssetOrAuthz)
		_, err = PreviewEffectiveCapabilities(env.db, PreviewRequest{Kind: PreviewRoleDefinition, RoleID: env.roles[model.BuiltinUser], Permissions: []string{string(PermAssetView)}})
		assert.ErrorIs(t, err, ErrPreviewRoleNotCustom)
		_, err = PreviewEffectiveCapabilities(env.db, PreviewRequest{Kind: PreviewRoleDefinition, OperatorID: op, RoleID: env.roles["viewer"],
			Permissions: []string{string(PermAssetView)}})
		assert.ErrorIs(t, err, ErrRoleMappingCounterMissing, "缺映射規則計數時不當成零")
	})

	t.Run("清單上限：超過時截斷、本人在最前、總數正確", func(t *testing.T) {
		env := newPreviewEnv(t)
		op := env.user("op", model.BuiltinSuperAdmin)
		g := env.group("g")
		var first uint
		for i := 0; i < 7; i++ {
			u := env.user("m"+string(rune('a'+i)), "asset-mgr")
			env.join(g, u)
			first = u
		}
		env.join(g, op)
		res, err := PreviewEffectiveCapabilities(env.db, PreviewRequest{Kind: PreviewGroupRoles, OperatorID: op, GroupID: g,
			RoleIDs: env.ids("authz-mgr"), Limit: 3})
		require.NoError(t, err)
		assert.Equal(t, 8, res.Total)
		assert.Equal(t, 8, res.Matched, "超管本人與七位新命中者")
		assert.True(t, res.Truncated)
		require.Len(t, res.Subjects, 3)
		assert.True(t, res.Subjects[0].Self, "本人排最前")
		assert.NotZero(t, first)
	})

	t.Run("輸入無效：種類不明、群組或角色不存在", func(t *testing.T) {
		env := newPreviewEnv(t)
		for name, req := range map[string]PreviewRequest{
			"種類不明":  {Kind: "x"},
			"群組不存在": {Kind: PreviewGroupRoles, GroupID: 99},
			"角色不存在": {Kind: PreviewDirectRoles, UserID: 1, RoleIDs: []uint{999}},
		} {
			_, err := PreviewEffectiveCapabilities(env.db, req)
			assert.ErrorIs(t, err, ErrPreviewInvalid, name)
		}
	})
}

func noMappingRules(*gorm.DB, uint) (int64, error) { return 0, nil }
