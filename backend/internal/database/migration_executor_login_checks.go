package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 堡壘機專用帳號的測試登入結果。
//
// 內容：一張新表 executor_login_checks，每個專用帳號掛載一列（以掛載識別為主鍵，重測即覆蓋），
// 只存最近一次的結果碼、方式與盤點讀取檢查值，不存任何秘密與遠端原文。只建表與索引，
// 不回填、不改既有表、不設外鍵：掛載被清除時列留著，讀取端以當下掛載識別查詢，舊列自然不再出現。
//
// # Down 契約
//
// 不提供回滾：回退只走還原升級前備份。
func executorLoginChecksDDL() []string {
	return []string{
		`CREATE TABLE executor_login_checks (
		asset_account_id bigint NOT NULL,
		asset_id bigint NOT NULL,
		credential_id bigint NOT NULL,
		credential_version_id bigint NOT NULL,
		result character varying(64) DEFAULT ''::character varying NOT NULL,
		method character varying(32) DEFAULT ''::character varying NOT NULL,
		inventory_read character varying(16) DEFAULT ''::character varying NOT NULL,
		checked_by bigint DEFAULT 0 NOT NULL,
		checked_by_name character varying(100) DEFAULT ''::character varying NOT NULL,
		checked_at timestamp with time zone NOT NULL,
		CONSTRAINT executor_login_checks_pkey PRIMARY KEY (asset_account_id)
	)`,
		`CREATE INDEX idx_executor_login_checks_asset ON executor_login_checks USING btree (asset_id)`,
	}
}

func applyExecutorLoginChecks(db *gorm.DB) error {
	for _, stmt := range executorLoginChecksDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 executor_login_checks DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackExecutorLoginChecks 不提供回滾；見檔頭 Down 契約。
func rollbackExecutorLoginChecks(_ *gorm.DB) error {
	return fmt.Errorf("executor login checks has no down migration; restore the pre-upgrade backup instead")
}
