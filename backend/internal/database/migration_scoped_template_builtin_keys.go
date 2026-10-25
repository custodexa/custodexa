package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 範圍化管理範本的內建識別值域。
//
// 結構：重建 roles_builtin_key_check，允許值在原有六個之外加入 asset_admin、authz_admin。
// 只有 DDL：不寫任何角色列、不改任何指派。兩個範本列由啟動資料步驟種入（需要權限附證來源
// 已注入，遷移交易內做不到），所以只跑本遷移時資料表沒有任何新角色列。
//
// # Down 契約
//
// 不提供回滾：回退只走還原升級前備份。
func scopedTemplateBuiltinKeysDDL() []string {
	return []string{
		`ALTER TABLE roles DROP CONSTRAINT roles_builtin_key_check`,
		`ALTER TABLE roles ADD CONSTRAINT roles_builtin_key_check CHECK (builtin_key IS NULL OR builtin_key IN ('super_admin','auditor','user','approver','identity_admin','security_admin','asset_admin','authz_admin'))`,
	}
}

func applyScopedTemplateBuiltinKeys(db *gorm.DB) error {
	for _, stmt := range scopedTemplateBuiltinKeysDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 scoped_template_builtin_keys DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackScopedTemplateBuiltinKeys 不提供回滾；見檔頭 Down 契約。
func rollbackScopedTemplateBuiltinKeys(_ *gorm.DB) error {
	return fmt.Errorf("scoped template builtin keys has no down migration; restore the pre-upgrade backup instead")
}
