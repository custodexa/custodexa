package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 預覽契約測試的共用夾具：自訂角色與群組都以資料列直接建立，
// 讓同一份夾具能在不同提交上建立出相同的資料與編號。

type previewFixture struct {
	t   *testing.T
	env *baselineEnv
	sup uint // S01，超級管理者，也是所有預覽與寫入的操作者
}

func newPreviewFixture(t *testing.T, env *baselineEnv) *previewFixture {
	t.Helper()
	return &previewFixture{t: t, env: env, sup: env.subjects["S01"].UserID}
}

func (f *previewFixture) user(name string) uint {
	return f.env.createUser(name, nil)
}

// role 建立自訂角色（定義版本 1，權限集合為給定鍵）。
func (f *previewFixture) role(name string, perms ...string) uint {
	f.t.Helper()
	r := model.Role{Name: name, DefinitionVersion: 1}
	require.NoError(f.t, f.env.db.Create(&r).Error)
	for _, p := range perms {
		require.NoError(f.t, f.env.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: p}).Error)
	}
	return r.ID
}

func (f *previewFixture) hold(userID, roleID uint) {
	f.t.Helper()
	require.NoError(f.t, model.AssignUserRoleWithSource(f.env.db, userID, roleID, model.RoleSourceManual, model.RoleOriginSystem))
}

// holdMapped 目標只由外部群組映射持有該角色。
func (f *previewFixture) holdMapped(userID, roleID uint) {
	f.t.Helper()
	require.NoError(f.t, model.AssignUserRoleWithSource(f.env.db, userID, roleID, model.RoleSourceMapped, model.RoleOriginMapping))
}

// holdBoth 目標同時由管理者指派與外部群組映射持有該角色。
func (f *previewFixture) holdBoth(userID, roleID uint) {
	f.t.Helper()
	f.holdMapped(userID, roleID)
	require.NoError(f.t, model.SetUserRoleSource(f.env.db, userID, roleID, model.RoleSourceBoth))
}

// roleSource 讀一列指派目前的來源；列不存在回空字串。
func (f *previewFixture) roleSource(userID, roleID uint) string {
	f.t.Helper()
	src, ok, err := model.UserRoleSourceOf(f.env.db, userID, roleID)
	require.NoError(f.t, err)
	if !ok {
		return ""
	}
	return src
}

// group 建立群組：manual 為手動成員，mapped 為只受映射規則支持的成員，roleIDs 為群組帶的角色。
func (f *previewFixture) group(name string, manual, mapped, roleIDs []uint) uint {
	f.t.Helper()
	g := model.UserGroup{Name: name}
	require.NoError(f.t, f.env.db.Create(&g).Error)
	for _, id := range manual {
		require.NoError(f.t, f.env.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: id, Manual: true}).Error)
	}
	for _, id := range mapped {
		// manual 欄的資料庫預設為真：非手動成員必須明寫 false，不能靠零值
		require.NoError(f.t, f.env.db.Exec("INSERT INTO user_group_members(user_group_id,user_id,manual) VALUES (?,?,false)", g.ID, id).Error)
		require.NoError(f.t, f.env.db.Create(&model.UserGroupMappingRuleSupport{UserID: id, UserGroupID: g.ID, Channel: "oidc", RuleID: 1}).Error)
	}
	for _, rid := range roleIDs {
		require.NoError(f.t, f.env.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: rid, ScopeKind: model.ScopeKindGlobal}).Error)
	}
	return g.ID
}

// legacyPreviewRequests 舊用戶端的四種既有輸入（同一份夾具，供與基底實作逐欄對照）。
// 每種輸入都讓至少一位主體新命中危險組合，使逐主體欄位有內容可比。
func (f *previewFixture) legacyPreviewRequests() map[string]map[string]any {
	f.t.Helper()
	authzMgr := f.role("legacy-authz", "authorization:manage")
	cam := f.role("legacy-cam", "asset:view", "asset:update")
	rd := f.role("legacy-rd", "asset:view")
	tl := f.user("legacy-target")
	f.hold(tl, authzMgr)
	m1, m2, m3 := f.user("legacy-m1"), f.user("legacy-m2"), f.user("legacy-m3")
	f.hold(m1, authzMgr)
	f.hold(m1, rd)
	f.hold(m2, f.env.roleID(model.RoleAuditor))
	f.hold(m3, authzMgr)
	gl := f.group("legacy-roles-group", []uint{m1, m2}, nil, nil)
	gm := f.group("legacy-members-group", []uint{m2}, nil, []uint{cam})
	return map[string]map[string]any{
		"direct_roles":    {"kind": "direct_roles", "user_id": tl, "role_ids": []uint{authzMgr, cam}},
		"group_roles":     {"kind": "group_roles", "group_id": gl, "role_ids": []uint{cam}},
		"group_members":   {"kind": "group_members", "group_id": gm, "member_ids": []uint{m2, m3, f.sup}},
		"role_definition": {"kind": "role_definition", "role_id": rd, "permissions": []string{"asset:view", "asset:update"}},
	}
}
