package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 改密批次與計畫授權脈絡的範圍欄位增量。
//
// 結構：
//   - change_secret_batches 加 shared_credential_owner_kind（global｜node，非空、預設 global）與
//     shared_credential_owner_node_id（可空）：整批同一組模式要新建的共用憑證歸屬，建立批次時寫入、
//     執行時以同一驗證重驗。既有列由預設值取 global，與升級前的行為相同。
//   - credential_job_authorizations 加 target_mount_bound（非空、預設空字串）：範圍化發起者儲存
//     憑證目標計畫時該憑證當下全部掛載的上界（資產帳號列識別的 JSON 陣列）。既有列與全域發起者為空字串。
//
// 不回填、不改寫任何既有列；三條 DDL 皆為加欄，預設值即既有列的取值。
//
// # Down 契約
//
// 不提供回滾：回退只走還原升級前備份。
func changeSecretScopeColumnsDDL() []string {
	return []string{
		`ALTER TABLE change_secret_batches ADD COLUMN shared_credential_owner_kind character varying(16) NOT NULL DEFAULT 'global'`,
		`ALTER TABLE change_secret_batches ADD COLUMN shared_credential_owner_node_id bigint`,
		`ALTER TABLE credential_job_authorizations ADD COLUMN target_mount_bound text NOT NULL DEFAULT ''`,
	}
}

func applyChangeSecretScopeColumns(db *gorm.DB) error {
	for _, stmt := range changeSecretScopeColumnsDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 change_secret_scope_columns DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackChangeSecretScopeColumns 不提供回滾；見檔頭 Down 契約。
func rollbackChangeSecretScopeColumns(_ *gorm.DB) error {
	return fmt.Errorf("change secret scope columns has no down migration; restore the pre-upgrade backup instead")
}
