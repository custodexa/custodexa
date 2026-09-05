package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 以帳號為主軸的批次改密的資料層增量 migration：一張新表、兩張既有表加欄。
// 沿 migration_rotation_evidence_report.go 的紀律：DDL 無條件、不用 IF NOT EXISTS
// ——在已套用的庫上重跑必須大聲失敗，而非靜默 no-op。
//
// # Up 做什麼
//
//  1. change_secret_batches：一列一次批次（帳號名、密碼模式、密碼策略、目標數、
//     四種結果計數、狀態、發起者、起迄時刻）。shared_group 是整批同一組模式下
//     成功帳號歸入的憑證群組識別，可空＝每台各自隨機。**本表不存任何密碼**。
//  2. change_secret_records.batch_id：記錄的來源批次，0＝來自計劃。存量列以
//     default 回填為 0——這張表在本欄出現之前只承載計劃的記錄，回填值即其實際
//     語義，不是猜測。
//  3. change_secret_candidates.batch_id／shared_group：候選的來源批次與轉正後要
//     歸入的憑證群組。放在候選上是因為重試轉正時批次可能早已完成，候選必須
//     自帶處置；shared_group 可空，語義同 asset_accounts.credential_group。
//
// # 索引
//
//   - change_secret_batches (username)：看板與最近批次列表都以帳號名為軸。
//   - change_secret_records (batch_id)：單一批次的逐目標記錄查詢。
//
// # Down 契約（讀完再用）
//
// **本 Down 有損。** 刪表即失去全部批次的彙總計數與發起者；刪欄即失去記錄與
// 候選的來源辨識（再次 Up 之後全部回到「來自計劃」）。故本函式只供 parity 守衛
// 與開發環境使用。**生產沒有回滾入口**：RollbackMigration 無產品碼呼叫者，
// 回退的唯一手段是部署回舊版映像並還原升級前備份。
func accountBatchRotationDDL() []string {
	return []string{
		`CREATE TABLE change_secret_batches (
		id bigserial,
		username character varying(100) NOT NULL,
		password_mode character varying(16) NOT NULL,
		shared_group character varying(36),
		password_length bigint DEFAULT 16,
		password_include_symbol boolean DEFAULT true,
		password_exclude_ambiguous boolean DEFAULT true,
		target_count bigint NOT NULL DEFAULT 0,
		success_count bigint NOT NULL DEFAULT 0,
		failed_count bigint NOT NULL DEFAULT 0,
		unverified_count bigint NOT NULL DEFAULT 0,
		skipped_count bigint NOT NULL DEFAULT 0,
		status character varying(16) NOT NULL,
		requested_by bigint,
		requested_by_name character varying(100),
		started_at timestamp with time zone,
		finished_at timestamp with time zone,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		CONSTRAINT change_secret_batches_pkey PRIMARY KEY (id)
	)`,
		`CREATE INDEX idx_change_secret_batches_username ON change_secret_batches (username)`,

		`ALTER TABLE change_secret_records ADD COLUMN batch_id bigint NOT NULL DEFAULT 0`,
		`CREATE INDEX idx_change_secret_records_batch_id ON change_secret_records (batch_id)`,

		`ALTER TABLE change_secret_candidates ADD COLUMN batch_id bigint NOT NULL DEFAULT 0`,
		`ALTER TABLE change_secret_candidates ADD COLUMN shared_group character varying(36)`,
	}
}

func applyAccountBatchRotation(db *gorm.DB) error {
	for _, stmt := range accountBatchRotationDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 account_batch_rotation DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackAccountBatchRotation 反序還原結構。
//
// **有損**：見本檔檔頭的 Down 契約。開發庫限定；生產回退不走這裡。
func rollbackAccountBatchRotation(db *gorm.DB) error {
	stmts := []string{
		`ALTER TABLE change_secret_candidates DROP COLUMN shared_group`,
		`ALTER TABLE change_secret_candidates DROP COLUMN batch_id`,
		`DROP INDEX idx_change_secret_records_batch_id`,
		`ALTER TABLE change_secret_records DROP COLUMN batch_id`,
		`DROP INDEX idx_change_secret_batches_username`,
		`DROP TABLE change_secret_batches`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 account_batch_rotation 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
