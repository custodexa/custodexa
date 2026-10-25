package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 主機金鑰不符觀察紀錄增量。
//
// 內容：新表 asset_host_key_mismatches，每列是一個資產連線時出示過、與記錄不符且尚未被
// 超級管理者確認的主機金鑰；（asset_id, observed_fingerprint）唯一，同一指紋再出現只累計。
// 不回填：升級前因不符而被拒的連線沒有留下可回填的觀察；升級後第一次連線才寫入。
// 既有 asset_host_keys 不動。
//
// # Down 契約
//
// 不提供回滾：觀察紀錄是安全事件的證據，回退只走升級前備份。
func hostKeyMismatchDDL() []string {
	return []string{
		`CREATE TABLE asset_host_key_mismatches (
		id bigserial,
		asset_id bigint NOT NULL,
		host character varying(255) DEFAULT ''::character varying NOT NULL,
		port bigint DEFAULT 0 NOT NULL,
		recorded_fingerprint character varying(128) NOT NULL,
		observed_algorithm character varying(64) NOT NULL,
		observed_fingerprint character varying(128) NOT NULL,
		observed_public_key text NOT NULL,
		first_seen_at timestamp with time zone NOT NULL,
		last_seen_at timestamp with time zone NOT NULL,
		first_allowed_at timestamp with time zone,
		seen_count bigint DEFAULT 1 NOT NULL,
		CONSTRAINT asset_host_key_mismatches_pkey PRIMARY KEY (id)
	)`,
		`CREATE UNIQUE INDEX idx_asset_host_key_mismatches_asset_fp ON asset_host_key_mismatches USING btree (asset_id, observed_fingerprint)`,
	}
}

func applyHostKeyMismatch(db *gorm.DB) error {
	for _, stmt := range hostKeyMismatchDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 host_key_mismatch DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackHostKeyMismatch 不提供回滾；見檔頭 Down 契約。
func rollbackHostKeyMismatch(_ *gorm.DB) error {
	return fmt.Errorf("host key mismatch observations retain evidence; restore the pre-upgrade backup instead")
}
