package database

import (
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func legacyMappingDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE users (id integer primary key, username text, credential_epoch integer default 0)`,
		`CREATE TABLE roles (id integer primary key, name text)`,
		`CREATE TABLE group_role_mappings (id integer primary key, deleted_at datetime, ldap_directory_id integer, oidc_provider_id integer, match_value text, role_id integer, enabled boolean, external_group_id integer)`,
		`CREATE TABLE user_role_mappings (user_id integer, role_id integer, channel text, matched_at datetime, primary key(user_id,role_id,channel))`,
		`CREATE TABLE user_roles (user_id integer, role_id integer, source text, primary key(user_id,role_id))`,
		`CREATE TABLE external_groups (id integer primary key autoincrement, ldap_directory_id integer, oidc_provider_id integer, match_value text, note text)`,
		`CREATE TABLE user_role_mapping_rule_supports (user_id integer, role_id integer, channel text, rule_id integer, primary key(user_id,role_id,channel,rule_id))`,
		`CREATE TABLE audit_logs (id integer primary key autoincrement, action text, resource text, resource_id integer, status text, user_id integer, username text, client_ip text, error_msg text, details text)`,
		`CREATE TABLE refresh_tokens (id integer primary key, user_id integer, revoked_at datetime)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, stmt := range []string{
		`INSERT INTO users(id,username) VALUES (1,'demo')`,
		`INSERT INTO roles(id,name) VALUES (1,'viewer'),(2,'operator')`,
		`INSERT INTO group_role_mappings(id,oidc_provider_id,match_value,role_id,enabled) VALUES (10,2,'a',1,true),(11,2,'b',1,true),(12,2,'c',1,false),(13,3,'a',1,true)`,
		`INSERT INTO user_role_mappings(user_id,role_id,channel,matched_at) VALUES (1,1,'provider:2',CURRENT_TIMESTAMP)`,
		`INSERT INTO user_roles(user_id,role_id,source) VALUES (1,1,'both'),(1,2,'manual')`,
		`INSERT INTO refresh_tokens(id,user_id) VALUES (1,1)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestLegacyRoleMappingMigrationOverattributesAllEnabledRules(t *testing.T) {
	db := legacyMappingDB(t)
	stats, err := backfillIdentityGroupMappings(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ruleIDs []int
	if err := db.Table("user_role_mapping_rule_supports").Where("user_id = ?", 1).Order("rule_id").Pluck("rule_id", &ruleIDs).Error; err != nil {
		t.Fatal(err)
	}
	if len(ruleIDs) != 2 || ruleIDs[0] != 10 || ruleIDs[1] != 11 {
		t.Fatalf("支持 = %v", ruleIDs)
	}
	if stats.OverattributedSupports != 2 || stats.OrphanFacts != 0 {
		t.Fatalf("統計 = %+v", stats)
	}
	var groups int64
	db.Table("external_groups").Count(&groups)
	if groups != 4 {
		t.Fatalf("字典應按來源及原始值去重，got %d", groups)
	}
	var epoch int
	db.Raw("SELECT credential_epoch FROM users WHERE id=1").Scan(&epoch)
	if epoch != 0 {
		t.Fatal("遷移推進世代")
	}
	var revoked int64
	db.Raw("SELECT count(*) FROM refresh_tokens WHERE id=1 AND revoked_at IS NOT NULL").Scan(&revoked)
	if revoked != 0 {
		t.Fatal("遷移撤刷新憑證")
	}
}

func TestLegacyRoleMappingMigrationRemovesOrphanWithAudit(t *testing.T) {
	db := legacyMappingDB(t)
	if err := db.Exec("UPDATE group_role_mappings SET enabled=false WHERE oidc_provider_id=2").Error; err != nil {
		t.Fatal(err)
	}
	stats, err := backfillIdentityGroupMappings(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stats.OrphanFacts != 1 {
		t.Fatalf("無規則事實 = %+v", stats)
	}
	var n int64
	db.Table("user_role_mappings").Count(&n)
	if n != 0 {
		t.Fatal("孤兒事實未移除")
	}
	var source string
	db.Raw("SELECT source FROM user_roles WHERE user_id=1 AND role_id=1").Scan(&source)
	if source != "manual" {
		t.Fatalf("手動角色被收回: %s", source)
	}
	db.Table("audit_logs").Where("error_msg=?", "legacy_role_mapping_orphan_removed").Count(&n)
	if n != 1 {
		t.Fatalf("遷移稽核 = %d", n)
	}
	var epoch int
	db.Raw("SELECT credential_epoch FROM users WHERE id=1").Scan(&epoch)
	if epoch != 0 {
		t.Fatal("孤兒處理推進世代")
	}
}

func TestLegacyRoleMappingMigrationIsIdempotent(t *testing.T) {
	db := legacyMappingDB(t)
	for i := 0; i < 2; i++ {
		if _, err := backfillIdentityGroupMappings(db, nil); err != nil {
			t.Fatal(err)
		}
	}
	var n int64
	db.Table("user_role_mapping_rule_supports").Count(&n)
	if n != 2 {
		t.Fatalf("重跑支持 = %d", n)
	}
}

func TestLegacyRoleMappingMigrationRollsBack(t *testing.T) {
	db := legacyMappingDB(t)
	err := db.Transaction(func(tx *gorm.DB) error {
		_, err := backfillIdentityGroupMappings(tx, func() error { return errors.New("injected") })
		return err
	})
	if err == nil {
		t.Fatal("注入失敗未傳回")
	}
	var n int64
	db.Table("external_groups").Count(&n)
	if n != 0 {
		t.Fatalf("失敗後字典仍有 %d 列", n)
	}
	db.Table("user_role_mappings").Count(&n)
	if n != 1 {
		t.Fatalf("失敗後舊事實 = %d", n)
	}
}
