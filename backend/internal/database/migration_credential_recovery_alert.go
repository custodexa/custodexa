package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 失權後有限驗證的告警去重增量。
//
// 結構：change_secret_candidates、credential_rotation_members 各加 recovery_alerted_at
// （可為空的時刻）：該列首次進入有限驗證、發出告警的時間。「進入有限驗證」的告警據此
// 每個候選、每個輪替成員只發一次，去重靠本模組自己的列。
//
// 只加欄、不回填：既有列為空，升級後若有正在有限驗證中的候選或成員，至多再發一次告警
// （失敗方向是重複，不是遺漏）。
//
// # Down 契約
//
// 不提供回滾：回退只走升級前備份。
func credentialRecoveryAlertDDL() []string {
	return []string{
		`ALTER TABLE change_secret_candidates ADD COLUMN recovery_alerted_at timestamp with time zone`,
		`ALTER TABLE credential_rotation_members ADD COLUMN recovery_alerted_at timestamp with time zone`,
	}
}

func applyCredentialRecoveryAlert(db *gorm.DB) error {
	for _, stmt := range credentialRecoveryAlertDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 credential_recovery_alert DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackCredentialRecoveryAlert 不提供回滾；見檔頭 Down 契約。
func rollbackCredentialRecoveryAlert(_ *gorm.DB) error {
	return fmt.Errorf("credential recovery alert columns have no rollback; restore the pre-upgrade backup instead")
}
