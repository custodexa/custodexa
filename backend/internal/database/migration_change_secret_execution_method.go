package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 改密紀錄的執行方式欄增量。
//
// 結構：change_secret_records 加四欄——execution_method（self 與三種代改模式）、
// executor_account_id、executor_username、executor_credential_id（代改當下堡壘機專用帳號的快照）。
// 四欄皆非空且帶預設值，既有列由預設值得到等同升級前的事實：自改、無專用帳號。
//
// 不回填、不改寫任何既有列。
//
// # Down 契約
//
// 不提供回滾：回退只走還原升級前備份。
func changeSecretExecutionMethodDDL() []string {
	return []string{
		`ALTER TABLE change_secret_records ADD COLUMN execution_method character varying(32) NOT NULL DEFAULT 'self'`,
		`ALTER TABLE change_secret_records ADD COLUMN executor_account_id bigint NOT NULL DEFAULT 0`,
		`ALTER TABLE change_secret_records ADD COLUMN executor_username character varying(100) NOT NULL DEFAULT ''`,
		`ALTER TABLE change_secret_records ADD COLUMN executor_credential_id bigint NOT NULL DEFAULT 0`,
	}
}

func applyChangeSecretExecutionMethod(db *gorm.DB) error {
	for _, stmt := range changeSecretExecutionMethodDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 change_secret_execution_method DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackChangeSecretExecutionMethod 不提供回滾；見檔頭 Down 契約。
func rollbackChangeSecretExecutionMethod(_ *gorm.DB) error {
	return fmt.Errorf("change secret execution method has no down migration; restore the pre-upgrade backup instead")
}
