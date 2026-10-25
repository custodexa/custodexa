package database

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 角色定義增量：角色定義版本、起手來源、自訂權限集合，
// 放寬 builtin_key 值域並種兩個鎖定的管理範本。
//
// 存量相容目錄＝definition_version = 0 的角色：既有列在 ADD COLUMN 時全部取預設 0，
// 新服務建立的角色與兩個範本一律 >= 1，所以舊入口以此欄區分存量，不靠可改名稱。
// 本增量不改任何 user_roles／user_group_roles／role_binding_nodes 列，也不指派任何人。
// 同名衝突（預定範本名稱已被其他角色佔用）整筆不套用，不冒認內建。
// Down 契約：不提供回滾，回退只走還原升級前備份。
func roleDefinitionsDDL() []string {
	return []string{
		`ALTER TABLE roles ADD COLUMN definition_version bigint DEFAULT 0 NOT NULL`,
		`ALTER TABLE roles ADD COLUMN template_role_id bigint`,
		`ALTER TABLE roles DROP CONSTRAINT roles_builtin_key_check`,
		`ALTER TABLE roles ADD CONSTRAINT roles_builtin_key_check CHECK (builtin_key IS NULL OR builtin_key IN ('super_admin','auditor','user','approver','identity_admin','security_admin'))`,
		`CREATE TABLE role_permissions (
 role_id bigint NOT NULL, permission_key character varying(64) NOT NULL,
 CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_key),
 CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id))`,
	}
}

// lockedTemplateSeeds 兩個鎖定管理範本的種子（名稱、說明、識別）；集合在程式中。
func lockedTemplateSeeds() []model.Role {
	k1, k2 := model.BuiltinIdentityAdmin, model.BuiltinSecurityAdmin
	return []model.Role{
		{Name: "identity_admin", Description: "身分管理員（鎖定範本）", BuiltinKey: &k1, DefinitionVersion: 1},
		{Name: "security_admin", Description: "系統安全管理員（鎖定範本）", BuiltinKey: &k2, DefinitionVersion: 1},
	}
}

// ErrRoleTemplateNameTaken 預定範本名稱已被其他角色使用（整筆不套用）。
var ErrRoleTemplateNameTaken = fmt.Errorf("role definitions migration refused: a template name is already used by another role")

// seedLockedTemplates 補建缺少的範本列；同名但不是該範本者整筆拒絕。冪等。
func seedLockedTemplates(db *gorm.DB) error {
	var toCreate []model.Role
	for _, seed := range lockedTemplateSeeds() {
		var existing []model.Role
		if err := db.Unscoped().Where("name = ? OR builtin_key = ?", seed.Name, *seed.BuiltinKey).Find(&existing).Error; err != nil {
			return fmt.Errorf("查詢範本 %s 失敗: %w", seed.Name, err)
		}
		if len(existing) == 0 {
			toCreate = append(toCreate, seed)
			continue
		}
		for _, e := range existing {
			if e.BuiltinKey == nil || *e.BuiltinKey != *seed.BuiltinKey || e.Name != seed.Name {
				return fmt.Errorf("%w: %s", ErrRoleTemplateNameTaken, seed.Name)
			}
		}
	}
	// 先全部檢查完才寫入：任一範本衝突時一列都不建。
	for _, seed := range toCreate {
		row := seed
		if err := db.Create(&row).Error; err != nil {
			return fmt.Errorf("建立範本 %s 失敗: %w", seed.Name, err)
		}
	}
	return nil
}

func applyRoleDefinitions(db *gorm.DB) error {
	// 前置檢查先於任何寫入：同名衝突不留下部分結構。
	for _, seed := range lockedTemplateSeeds() {
		var n int64
		if err := db.Unscoped().Model(&model.Role{}).Where("name = ?", seed.Name).Count(&n).Error; err != nil {
			return fmt.Errorf("前置檢查範本名稱 %s 失敗: %w", seed.Name, err)
		}
		if n > 0 {
			return fmt.Errorf("%w: %s", ErrRoleTemplateNameTaken, seed.Name)
		}
	}
	before, err := PlanRoleDefinitionsReport(db)
	if err != nil {
		return err
	}
	for _, stmt := range roleDefinitionsDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 role_definitions DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	if err := seedLockedTemplates(db); err != nil {
		return err
	}
	// 前後報告必須相同：存量角色與全部指派一列都不能變；不同即回滾（RunMigrations 的交易）。
	after, err := PlanRoleDefinitionsReport(db)
	if err != nil {
		return err
	}
	bj, err := before.JSON()
	if err != nil {
		return err
	}
	aj, err := after.JSON()
	if err != nil {
		return err
	}
	if bj != aj {
		return fmt.Errorf("%w: before=%s after=%s", ErrRoleDefinitionsReportMismatch, bj, aj)
	}
	return nil
}

func rollbackRoleDefinitions(db *gorm.DB) error {
	return fmt.Errorf("role definitions has no rollback; restore the pre-upgrade backup")
}
