package authz_test

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// p1bD8LocalAdminScopeMerged：最後本地超管查詢改成 builtin_key＋scope_kind='global'
// 之後設為 true。查詢若仍以角色名稱為準、不看 scope_kind，
// 「節點範圍／群組不計入」兩個案例便無從成立，故以此旗標控制是否執行。
const p1bD8LocalAdminScopeMerged = true

func newRestoreDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{},
		&model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}, &model.AuthzState{}, &model.AssetGroup{},
		&model.GroupRoleMapping{}, &model.GroupUserGroupMapping{}, &model.ExternalGroup{}, &model.LDAPDirectory{}, &model.OIDCProvider{}, &model.RolePermission{}))
	for i, bk := range []string{"super_admin", "auditor", "user", "approver"} {
		k := bk
		name := []string{"admin", "auditor", "user", "approver"}[i]
		require.NoError(t, db.Create(&model.Role{Name: name, BuiltinKey: &k}).Error)
	}
	return db
}

func mkAdmin(t *testing.T, db *gorm.DB, name string, mut func(u *model.User)) uint {
	u := &model.User{Username: name, Password: "hash", Active: true, Kind: "human", ProvisioningOrigin: model.AuthSourceLocal}
	if mut != nil {
		mut(u)
	}
	require.NoError(t, db.Create(u).Error)
	return u.ID
}

func seedValid(t *testing.T, db *gorm.DB) {
	a := mkAdmin(t, db, "root", nil)
	b := mkAdmin(t, db, "mapped-user", nil)
	require.NoError(t, db.Create(&model.UserRole{UserID: a, RoleID: 1, Source: "manual", ScopeKind: "global"}).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: b, RoleID: 2, Source: "mapped", ScopeKind: "nodes"}).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: b, RoleID: 3, Source: "both", ScopeKind: "global"}).Error)
	require.NoError(t, db.Create(&model.AssetGroup{Name: "n"}).Error)
	require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: "user", SubjectID: b, RoleID: 2, NodeID: 1}).Error)
	require.NoError(t, db.Create(&model.UserGroup{Name: "g"}).Error)
	require.NoError(t, db.Create(&model.UserGroupRole{UserGroupID: 1, RoleID: 2, ScopeKind: "global"}).Error)
}

func check(t *testing.T, db *gorm.DB) *authz.RestoreIntegrityReport {
	rep, err := authz.CheckRestoreIntegrity(db, identity.CountLocalAdmins, identity.RestoreMappingRefChecks())
	require.NoError(t, err)
	return rep
}

func codes(r *authz.RestoreIntegrityReport) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return out
}

func TestPermissionRestoreIntegrity(t *testing.T) {
	t.Run("有效 fixture 通過且不修資料", func(t *testing.T) {
		db := newRestoreDB(t)
		seedValid(t, db)
		rep := check(t, db)
		require.True(t, rep.OK(), "%v", rep.Findings)
		require.EqualValues(t, 1, rep.LocalSuperAdmins)
		var n int64
		db.Model(&model.UserRole{}).Count(&n)
		require.EqualValues(t, 3, n)
	})

	bad := map[string]struct{ stmt, code string }{
		"懸空 role":           {`INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (1, 99, 'manual', 'global')`, "dangling_user_role_role"},
		"懸空 user":           {`INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (99, 3, 'manual', 'global')`, "dangling_user_role_user"},
		"懸空 group（指派）":      {`INSERT INTO user_group_roles (user_group_id, role_id, scope_kind, created_at) VALUES (99, 3, 'global', CURRENT_TIMESTAMP)`, "dangling_group_role_group"},
		"懸空 group（成員）":      {`INSERT INTO user_group_members (user_group_id, user_id, manual) VALUES (99, 1, 1)`, "dangling_member_group"},
		"懸空 node":           {`INSERT INTO role_binding_nodes (subject_kind, subject_id, role_id, node_id) VALUES ('user', 2, 2, 99)`, "dangling_binding_node"},
		"刪除節點":              {`UPDATE asset_groups SET deleted_at = CURRENT_TIMESTAMP`, "deleted_binding_node"},
		"懸空 mapping target": {`INSERT INTO group_role_mappings (match_value, external_group_id, role_id, enabled, created_by, created_at, updated_at) VALUES ('x', 1, 99, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "dangling_role_mapping_target"},
		"懸空 mapping source": {`INSERT INTO external_groups (id, match_value, note, created_at, updated_at) VALUES (1, 'x', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP); INSERT INTO group_role_mappings (ldap_directory_id, match_value, external_group_id, role_id, enabled, created_by, created_at, updated_at) VALUES (77, 'x', 1, 3, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "dangling_role_mapping_source"},
		"懸空 owner":          {`UPDATE users SET owner_user_id = 99 WHERE id = 2`, "dangling_owner"},
		"空 nodes（使用者）":      {`DELETE FROM role_binding_nodes`, "empty_user_nodes"},
		"無效來源":              {`UPDATE user_roles SET source = 'bogus' WHERE user_id = 2 AND role_id = 3`, "invalid_user_role_source"},
		"無效範圍":              {`UPDATE user_roles SET scope_kind = 'bogus' WHERE user_id = 2 AND role_id = 3`, "invalid_user_role_scope"},
		"內建身分歧義（軟刪內建）":      {`UPDATE roles SET deleted_at = CURRENT_TIMESTAMP WHERE builtin_key = 'auditor'`, "builtin_identity_ambiguous"},
		"內建身分歧義（缺內建鍵）":      {`UPDATE roles SET builtin_key = NULL WHERE builtin_key = 'approver'`, "builtin_identity_ambiguous"},
		"binding 無對應指派":     {`INSERT INTO role_binding_nodes (subject_kind, subject_id, role_id, node_id) VALUES ('user', 1, 1, 1)`, "binding_without_assignment"},
	}
	for name, c := range bad {
		t.Run("拒絕/"+name, func(t *testing.T) {
			db := newRestoreDB(t)
			seedValid(t, db)
			for _, stmt := range splitStmts(c.stmt) {
				require.NoError(t, db.Exec(stmt).Error, stmt)
			}
			var before, after int64
			db.Raw(`SELECT (SELECT COUNT(*) FROM user_roles) + (SELECT COUNT(*) FROM role_binding_nodes) + (SELECT COUNT(*) FROM group_role_mappings)`).Scan(&before)
			rep := check(t, db)
			require.False(t, rep.OK())
			require.Contains(t, codes(rep), c.code, "%v", rep.Findings)
			db.Raw(`SELECT (SELECT COUNT(*) FROM user_roles) + (SELECT COUNT(*) FROM role_binding_nodes) + (SELECT COUNT(*) FROM group_role_mappings)`).Scan(&after)
			require.Equal(t, before, after, "檢查不得修資料")
		})
	}

	// 零本地超管：下列主體都不計入。
	notCounted := map[string]string{
		"純 mapped":   `UPDATE user_roles SET source = 'mapped' WHERE user_id = 1`,
		"外部託管":       `UPDATE users SET external_credential = 1 WHERE id = 1`,
		"停用":         `UPDATE users SET active = 0 WHERE id = 1`,
		"已刪除":        `UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = 1`,
		"LDAP":       `UPDATE users SET is_ldap = 1 WHERE id = 1`,
		"agent（無密碼）": `UPDATE users SET kind = 'agent', password = '' WHERE id = 1`,
	}
	for name, stmt := range notCounted {
		t.Run("零本地超管/"+name+"不計", func(t *testing.T) {
			db := newRestoreDB(t)
			seedValid(t, db)
			require.NoError(t, db.Exec(stmt).Error)
			rep := check(t, db)
			require.Contains(t, codes(rep), "no_local_super_admin")
			require.EqualValues(t, 0, rep.LocalSuperAdmins)
		})
	}
	t.Run("直接全域 both 的本地超管計入", func(t *testing.T) {
		db := newRestoreDB(t)
		seedValid(t, db)
		require.NoError(t, db.Exec(`UPDATE user_roles SET source = 'both' WHERE user_id = 1`).Error)
		require.True(t, check(t, db).OK())
	})
	t.Run("節點範圍與群組帶來的超管不計入", func(t *testing.T) {
		if !p1bD8LocalAdminScopeMerged {
			t.Skip("最後本地超管查詢尚未看 scope_kind，略過")
		}
		db := newRestoreDB(t)
		seedValid(t, db)
		require.NoError(t, db.Exec(`UPDATE user_roles SET scope_kind = 'nodes' WHERE user_id = 1`).Error)
		require.NoError(t, db.Exec(`INSERT INTO role_binding_nodes (subject_kind, subject_id, role_id, node_id) VALUES ('user', 1, 1, 1)`).Error)
		require.Contains(t, codes(check(t, db)), "no_local_super_admin")
	})
}

func splitStmts(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ';' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
