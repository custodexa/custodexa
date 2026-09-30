package database

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
)

func seedLegacyIdentityGroupUpgradePostgres(t *testing.T, schema string) *gorm.DB {
	t.Helper()
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), schema)
	if err := applyBaseline(db); err != nil {
		t.Fatal(err)
	}
	if err := applyGroupRoleMapping(db); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO users(id,username,password) VALUES (101,'member-a','x'),(102,'member-b','x')`,
		`INSERT INTO user_groups(id,name) VALUES (201,'operators'),(202,'reviewers')`,
		`INSERT INTO user_group_members(user_group_id,user_id) VALUES (201,101),(201,102),(202,102)`,
		`INSERT INTO roles(id,name) VALUES (301,'legacy-auditor'),(302,'legacy-orphan')`,
		`INSERT INTO oidc_providers(id,name,issuer,client_id,enabled) VALUES (401,'legacy-idp','https://idp.example.test','legacy-client',true)`,
		`INSERT INTO group_role_mappings(id,oidc_provider_id,match_value,role_id,enabled,created_by) VALUES (501,401,'external-a',301,true,101),(502,401,'external-b',301,true,101)`,
		`INSERT INTO user_role_mappings(user_id,role_id,channel,matched_at) VALUES (101,301,'provider:401',NOW()),(102,302,'provider:401',NOW())`,
		`INSERT INTO user_roles(user_id,role_id,source) VALUES (101,301,'mapped'),(102,302,'both')`,
		`INSERT INTO refresh_tokens(user_id,token_hash,session_started_at,expires_at,last_used_at) VALUES (101,repeat('a',64),NOW(),NOW()+interval '1 hour',NOW()),(102,repeat('b',64),NOW(),NOW()+interval '1 hour',NOW())`,
	} {
		if err := db.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestLegacyUserGroupMembersUpgradePostgres(t *testing.T) {
	db := seedLegacyIdentityGroupUpgradePostgres(t, "igm_members_upgrade_test")
	if err := db.Transaction(func(tx *gorm.DB) error { return applyIdentityGroupMappings(tx) }); err != nil {
		t.Fatal(err)
	}
	check := func() {
		var rows []struct {
			UserGroupID uint
			UserID      uint
			Manual      bool
		}
		if err := db.Table("user_group_members").Order("user_group_id,user_id").Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		if len(rows) != 3 {
			t.Fatalf("有效成員變成 %d 列，want 3", len(rows))
		}
		want := [][2]uint{{201, 101}, {201, 102}, {202, 102}}
		for i, row := range rows {
			if [2]uint{row.UserGroupID, row.UserID} != want[i] {
				t.Fatalf("有效成員[%d]=(%d,%d), want %v", i, row.UserGroupID, row.UserID, want[i])
			}
			if !row.Manual {
				t.Fatalf("既有成員 (%d,%d) manual=false", row.UserGroupID, row.UserID)
			}
		}
	}
	check()
	var supports []uint
	if err := db.Table("user_role_mapping_rule_supports").Where("user_id=? AND role_id=?", 101, 301).Order("rule_id").Pluck("rule_id", &supports).Error; err != nil {
		t.Fatal(err)
	}
	if len(supports) != 2 || supports[0] != 501 || supports[1] != 502 {
		t.Fatalf("舊角色事實的重疊支持=%v", supports)
	}
	var facts, roles, orphanAudits, revoked int64
	if err := db.Table("user_role_mappings").Count(&facts).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Table("user_roles").Count(&roles).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Table("audit_logs").Where("error_msg=?", "legacy_role_mapping_orphan_removed").Count(&orphanAudits).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Table("refresh_tokens").Where("revoked_at IS NOT NULL").Count(&revoked).Error; err != nil {
		t.Fatal(err)
	}
	if facts != 1 || roles != 2 || orphanAudits != 1 || revoked != 0 {
		t.Fatalf("升級後事實=%d 角色=%d 孤兒稽核=%d 刷新憑證撤銷=%d", facts, roles, orphanAudits, revoked)
	}
	var source string
	if err := db.Raw("SELECT source FROM user_roles WHERE user_id=102 AND role_id=302").Scan(&source).Error; err != nil {
		t.Fatal(err)
	}
	if source != "manual" {
		t.Fatalf("孤兒映射撤除後手動角色來源=%q", source)
	}
	var epoch int
	if err := db.Raw("SELECT credential_epoch FROM users WHERE id=101").Scan(&epoch).Error; err != nil {
		t.Fatal(err)
	}
	if epoch != 0 {
		t.Fatalf("升級推進憑證世代=%d", epoch)
	}
	// 重跑應保留每一筆已升級的手動事實。
	if _, err := backfillIdentityGroupMappings(db, nil); err != nil {
		t.Fatal(err)
	}
	check()
	var afterSupports, afterAudits int64
	if err := db.Table("user_role_mapping_rule_supports").Count(&afterSupports).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Table("audit_logs").Where("error_msg=?", "legacy_role_mapping_orphan_removed").Count(&afterAudits).Error; err != nil {
		t.Fatal(err)
	}
	if afterSupports != 2 || afterAudits != 1 {
		t.Fatalf("重跑後支持=%d 孤兒稽核=%d", afterSupports, afterAudits)
	}
}

func TestLegacyIdentityGroupMigrationRollbackPostgres(t *testing.T) {
	db := seedLegacyIdentityGroupUpgradePostgres(t, "igm_upgrade_rollback_test")
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := applyIdentityGroupMappings(tx); err != nil {
			return err
		}
		return errors.New("injected after schema and data conversion")
	})
	if err == nil {
		t.Fatal("注入失敗後遷移仍提交")
	}
	if db.Migrator().HasColumn("user_group_members", "manual") || db.Migrator().HasTable("external_groups") {
		t.Fatal("失敗後仍留下新版 schema")
	}
	var members, facts, supports, audits, revoked int64
	for _, item := range []struct {
		table string
		count *int64
	}{
		{"user_group_members", &members}, {"user_role_mappings", &facts}, {"user_roles", &supports}, {"audit_logs", &audits},
	} {
		if err := db.Table(item.table).Count(item.count).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Table("refresh_tokens").Where("revoked_at IS NOT NULL").Count(&revoked).Error; err != nil {
		t.Fatal(err)
	}
	if members != 3 || facts != 2 || supports != 2 || audits != 0 || revoked != 0 {
		t.Fatalf("回滾後成員=%d 事實=%d 有效角色=%d 稽核=%d 刷新撤銷=%d", members, facts, supports, audits, revoked)
	}
}
