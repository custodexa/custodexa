package database

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

// The caller (RunMigrations) executes the entire schema and data conversion in
// one transaction. DDL is deliberately unconditional, like other migrations.
func identityGroupMappingsDDL() []string {
	return []string{
		`CREATE TABLE external_groups (id bigserial PRIMARY KEY, created_at timestamptz, updated_at timestamptz, ldap_directory_id bigint, oidc_provider_id bigint, match_value varchar(500) NOT NULL, note varchar(200) NOT NULL DEFAULT '', CONSTRAINT chk_external_group_source CHECK ((ldap_directory_id IS NOT NULL)::integer + (oidc_provider_id IS NOT NULL)::integer = 1), CONSTRAINT chk_external_group_note_length CHECK (char_length(note) <= 200))`,
		`ALTER TABLE external_groups ADD CONSTRAINT fk_external_groups_ldap FOREIGN KEY (ldap_directory_id) REFERENCES ldap_directories(id)`,
		`ALTER TABLE external_groups ADD CONSTRAINT fk_external_groups_oidc FOREIGN KEY (oidc_provider_id) REFERENCES oidc_providers(id)`,
		`CREATE UNIQUE INDEX idx_external_groups_ldap_value ON external_groups (ldap_directory_id, match_value) WHERE ldap_directory_id IS NOT NULL`,
		`CREATE UNIQUE INDEX idx_external_groups_oidc_value ON external_groups (oidc_provider_id, match_value) WHERE oidc_provider_id IS NOT NULL`,
		`ALTER TABLE group_role_mappings ADD COLUMN external_group_id bigint`,
		`CREATE TABLE group_user_group_mappings (id bigserial PRIMARY KEY, created_at timestamptz, updated_at timestamptz, deleted_at timestamptz, ldap_directory_id bigint, oidc_provider_id bigint, external_group_id bigint NOT NULL, user_group_id bigint NOT NULL, enabled boolean NOT NULL DEFAULT true, created_by bigint NOT NULL, CONSTRAINT chk_group_user_group_mapping_source CHECK ((ldap_directory_id IS NOT NULL)::integer + (oidc_provider_id IS NOT NULL)::integer = 1))`,
		`ALTER TABLE group_user_group_mappings ADD CONSTRAINT fk_group_user_group_mappings_ldap FOREIGN KEY (ldap_directory_id) REFERENCES ldap_directories(id)`,
		`ALTER TABLE group_user_group_mappings ADD CONSTRAINT fk_group_user_group_mappings_oidc FOREIGN KEY (oidc_provider_id) REFERENCES oidc_providers(id)`,
		`ALTER TABLE group_user_group_mappings ADD CONSTRAINT fk_group_user_group_mappings_external FOREIGN KEY (external_group_id) REFERENCES external_groups(id)`,
		`ALTER TABLE group_user_group_mappings ADD CONSTRAINT fk_group_user_group_mappings_target FOREIGN KEY (user_group_id) REFERENCES user_groups(id)`,
		`ALTER TABLE group_user_group_mappings ADD CONSTRAINT fk_group_user_group_mappings_creator FOREIGN KEY (created_by) REFERENCES users(id)`,
		`CREATE UNIQUE INDEX idx_group_user_group_mappings_external_target ON group_user_group_mappings (external_group_id, user_group_id) WHERE deleted_at IS NULL`,
		`CREATE INDEX idx_group_user_group_mappings_deleted_at ON group_user_group_mappings (deleted_at)`,
		`CREATE TABLE user_role_mapping_rule_supports (user_id bigint NOT NULL, role_id bigint NOT NULL, channel varchar(64) NOT NULL, rule_id bigint NOT NULL, CONSTRAINT user_role_mapping_rule_supports_pkey PRIMARY KEY (user_id,role_id,channel,rule_id))`,
		`ALTER TABLE user_role_mapping_rule_supports ADD CONSTRAINT fk_urmrs_user FOREIGN KEY (user_id) REFERENCES users(id)`,
		`ALTER TABLE user_role_mapping_rule_supports ADD CONSTRAINT fk_urmrs_role FOREIGN KEY (role_id) REFERENCES roles(id)`,
		`ALTER TABLE user_role_mapping_rule_supports ADD CONSTRAINT fk_urmrs_rule FOREIGN KEY (rule_id) REFERENCES group_role_mappings(id)`,
		`CREATE INDEX idx_urmrs_rule_user ON user_role_mapping_rule_supports (rule_id,user_id)`,
		`CREATE INDEX idx_urmrs_channel_user ON user_role_mapping_rule_supports (channel,user_id)`,
		`CREATE TABLE user_group_mapping_rule_supports (user_id bigint NOT NULL, user_group_id bigint NOT NULL, channel varchar(64) NOT NULL, rule_id bigint NOT NULL, CONSTRAINT user_group_mapping_rule_supports_pkey PRIMARY KEY (user_id,user_group_id,channel,rule_id))`,
		`ALTER TABLE user_group_mapping_rule_supports ADD CONSTRAINT fk_ugmrs_user FOREIGN KEY (user_id) REFERENCES users(id)`,
		`ALTER TABLE user_group_mapping_rule_supports ADD CONSTRAINT fk_ugmrs_group FOREIGN KEY (user_group_id) REFERENCES user_groups(id)`,
		`ALTER TABLE user_group_mapping_rule_supports ADD CONSTRAINT fk_ugmrs_rule FOREIGN KEY (rule_id) REFERENCES group_user_group_mappings(id)`,
		`CREATE INDEX idx_ugmrs_rule_user ON user_group_mapping_rule_supports (rule_id,user_id)`,
		`CREATE INDEX idx_ugmrs_channel_user ON user_group_mapping_rule_supports (channel,user_id)`,
		`CREATE INDEX idx_ugmrs_group_user ON user_group_mapping_rule_supports (user_group_id,user_id)`,
		`ALTER TABLE user_group_members ADD COLUMN manual boolean NOT NULL DEFAULT true`,
	}
}

type identityGroupMigrationStats struct {
	OverattributedSupports int64
	OrphanFacts            int64
}

// backfillIdentityGroupMappings never consults group snapshots. Every old role
// fact is attributed to all currently enabled rules for its source and role.
func backfillIdentityGroupMappings(db *gorm.DB, afterDictionary func() error) (identityGroupMigrationStats, error) {
	stats := identityGroupMigrationStats{}
	type rule struct {
		ID              uint
		LDAPDirectoryID *uint
		OIDCProviderID  *uint `gorm:"column:oidc_provider_id"`
		MatchValue      string
		RoleID          uint
		Enabled         bool
		DeletedAt       *time.Time
		ExternalGroupID *uint
	}
	var rules []rule
	if err := db.Table("group_role_mappings").Find(&rules).Error; err != nil {
		return stats, err
	}
	for _, r := range rules {
		column, sourceID := "ldap_directory_id", r.LDAPDirectoryID
		if r.OIDCProviderID != nil {
			column, sourceID = "oidc_provider_id", r.OIDCProviderID
		}
		if sourceID == nil {
			return stats, fmt.Errorf("role rule %d has no source", r.ID)
		}
		if err := db.Exec("INSERT INTO external_groups ("+column+",match_value) VALUES (?,?) ON CONFLICT DO NOTHING", *sourceID, r.MatchValue).Error; err != nil {
			return stats, err
		}
		var groupID uint
		if err := db.Raw("SELECT id FROM external_groups WHERE "+column+"=? AND match_value=?", *sourceID, r.MatchValue).Scan(&groupID).Error; err != nil {
			return stats, err
		}
		if groupID == 0 {
			return stats, fmt.Errorf("dictionary lookup failed for role rule %d", r.ID)
		}
		if err := db.Exec("UPDATE group_role_mappings SET external_group_id=? WHERE id=?", groupID, r.ID).Error; err != nil {
			return stats, err
		}
	}
	if afterDictionary != nil {
		if err := afterDictionary(); err != nil {
			return stats, err
		}
	}
	type fact struct {
		UserID  uint
		RoleID  uint
		Channel string
	}
	var facts []fact
	if err := db.Table("user_role_mappings").Find(&facts).Error; err != nil {
		return stats, err
	}
	for _, f := range facts {
		parts := strings.Split(f.Channel, ":")
		if len(parts) != 2 {
			return stats, fmt.Errorf("invalid legacy channel %q", f.Channel)
		}
		id, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return stats, err
		}
		column := ""
		switch parts[0] {
		case "directory":
			column = "ldap_directory_id"
		case "provider":
			column = "oidc_provider_id"
		default:
			return stats, fmt.Errorf("invalid legacy channel %q", f.Channel)
		}
		var eligible []uint
		if err := db.Table("group_role_mappings").Where(column+"=? AND role_id=? AND enabled=? AND deleted_at IS NULL", id, f.RoleID, true).Pluck("id", &eligible).Error; err != nil {
			return stats, err
		}
		if len(eligible) == 0 {
			if err := db.Exec("DELETE FROM user_role_mappings WHERE user_id=? AND role_id=? AND channel=?", f.UserID, f.RoleID, f.Channel).Error; err != nil {
				return stats, err
			}
			var remaining int64
			if err := db.Table("user_role_mappings").Where("user_id=? AND role_id=?", f.UserID, f.RoleID).Count(&remaining).Error; err != nil {
				return stats, err
			}
			var source string
			if err := db.Raw("SELECT source FROM user_roles WHERE user_id=? AND role_id=?", f.UserID, f.RoleID).Scan(&source).Error; err != nil {
				return stats, err
			}
			if remaining == 0 {
				switch source {
				case "mapped":
					if err := db.Exec("DELETE FROM user_roles WHERE user_id=? AND role_id=?", f.UserID, f.RoleID).Error; err != nil {
						return stats, err
					}
				case "both":
					if err := db.Exec("UPDATE user_roles SET source='manual' WHERE user_id=? AND role_id=?", f.UserID, f.RoleID).Error; err != nil {
						return stats, err
					}
				}
			}
			var username string
			if err := db.Raw("SELECT username FROM users WHERE id=?", f.UserID).Scan(&username).Error; err != nil {
				return stats, err
			}
			if err := db.Exec("INSERT INTO audit_logs (action,resource,resource_id,status,user_id,username,client_ip,error_msg,details) VALUES ('update','user',?,'success',?,?,'system','legacy_role_mapping_orphan_removed',?)", f.UserID, f.UserID, username, fmt.Sprintf(`{"channel":%q,"role_id":%d}`, f.Channel, f.RoleID)).Error; err != nil {
				return stats, err
			}
			stats.OrphanFacts++
			continue
		}
		for _, ruleID := range eligible {
			res := db.Exec("INSERT INTO user_role_mapping_rule_supports (user_id,role_id,channel,rule_id) VALUES (?,?,?,?) ON CONFLICT DO NOTHING", f.UserID, f.RoleID, f.Channel, ruleID)
			if res.Error != nil {
				return stats, res.Error
			}
			stats.OverattributedSupports += res.RowsAffected
		}
	}
	return stats, nil
}

func applyIdentityGroupMappings(db *gorm.DB) error {
	for _, stmt := range identityGroupMappingsDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("identity group mappings DDL: %w", err)
		}
	}
	stats, err := backfillIdentityGroupMappings(db, nil)
	if err != nil {
		return err
	}
	if err := db.Exec(`ALTER TABLE group_role_mappings ALTER COLUMN external_group_id SET NOT NULL`).Error; err != nil {
		return err
	}
	if err := db.Exec(`ALTER TABLE group_role_mappings ADD CONSTRAINT fk_group_role_mappings_external FOREIGN KEY (external_group_id) REFERENCES external_groups(id)`).Error; err != nil {
		return err
	}
	log.Printf("[IdentityGroupMigration] overattributed_supports=%d orphan_facts=%d", stats.OverattributedSupports, stats.OrphanFacts)
	return nil
}

// This migration loses source provenance if rolled back. Production rollback
// restores the pre-upgrade database backup instead.
func rollbackIdentityGroupMappings(*gorm.DB) error {
	return fmt.Errorf("identity group mappings migration is not reversible")
}
