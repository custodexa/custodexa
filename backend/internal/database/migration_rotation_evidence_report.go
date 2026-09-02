package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 輪替證據報告的資料層增量 migration：三張既有表各加一欄、一張新表。
// 沿 migration_audit_export_jobs.go 與 migration_db_query_console.go 的紀律：
// DDL 無條件、不用 IF NOT EXISTS——在已套用的庫上重跑必須大聲失敗，而非靜默 no-op。
//
// # Up 做什麼
//
//  1. asset_accounts.credential_group：同值＝系統已知這些帳號共用同一組憑證。
//     值為 UUID，由第一次歸組時產生；NULL＝無群組。**可空是語義的一部分**——
//     絕大多數帳號不屬於任何群組，空字串與 NULL 在此若同時存在會多出一個
//     沒有意義的第三態，故欄位不設 NOT NULL、也不設預設。
//  2. change_secret_plans.max_age_days：計劃層的憑證最長使用天數覆蓋，
//     0＝沿用全域政策鍵。**只影響報告的適用天數計算**，不改變計劃的執行時機。
//     既有列以 default 回填為 0，故升級後報告口徑與升級前的全域值一致。
//  3. audit_export_jobs.kind：匯出工作單的種類（閉集：evidence_bundle、
//     rotation_report）。存量列以 default 回填為 evidence_bundle——這張表在本欄
//     出現之前只承載證據包，回填值即其實際語義，不是猜測。
//  4. rotation_report_schedules：報告排程，一列一排程。period_anchor 是下一份
//     報告的記錄區間起點，使連續兩期的區間首尾相接而不重疊、不漏。
//
// # 索引
//
//   - asset_accounts (credential_group)：報告要對範圍內每個帳號判定共用憑證，
//     以及脫組後的「群組是否只剩一員」計數，兩者都以群組值為軸。
//   - audit_export_jobs (kind, status)：下載中心兩個分頁的列表與 worker 領件都
//     先以種類分流，再看狀態。
//   - rotation_report_schedules (name) UNIQUE：排程名是管理介面與報告封面上的
//     人可讀識別，重名會使「這份報告是哪個排程產的」無法回答。
//
// # 為什麼不動 change_secret_records
//
// 最後成功改密時刻由記錄推導，不在帳號表加冗餘欄。冗餘欄會與記錄漂移，而
// 記錄才是稽核要看的證據；候選列已定過「不另設會漂移的狀態欄位」的同一原則。
//
// # Down 契約（讀完再用）
//
// **本 Down 有損。** 刪掉的四項性質不同：credential_group 與 max_age_days 是
// 系統推導出的標示與政策設定（刪了即消失，再次 Up 之後全部回到未設定）；
// rotation_report_schedules 整張表刪除即失去全部排程定義。工作單的 kind 欄刪除
// 後，兩種產物混在同一個列表裡而無從分辨，下載授權的種類分支也一併失效。
//
// 故本函式只供 parity 守衛與開發環境使用。**生產沒有回滾入口**：
// RollbackMigration 無產品碼呼叫者，回退的唯一手段是部署回舊版映像並還原
// 升級前備份（docs/ops/upgrade-sop.md §4）。
func rotationEvidenceReportDDL() []string {
	return []string{
		`ALTER TABLE asset_accounts ADD COLUMN credential_group character varying(36)`,
		`CREATE INDEX idx_asset_accounts_credential_group ON asset_accounts (credential_group)`,

		`ALTER TABLE change_secret_plans ADD COLUMN max_age_days bigint NOT NULL DEFAULT 0`,

		`ALTER TABLE audit_export_jobs ADD COLUMN kind character varying(32) NOT NULL DEFAULT 'evidence_bundle'`,
		`CREATE INDEX idx_audit_export_jobs_kind_status ON audit_export_jobs (kind, status)`,

		`CREATE TABLE rotation_report_schedules (
		id bigserial,
		name character varying(128) NOT NULL,
		cron character varying(64) NOT NULL,
		enabled boolean DEFAULT true,
		scope_kind character varying(16) NOT NULL,
		scope_id bigint NOT NULL,
		retention_days bigint NOT NULL,
		language character varying(8) NOT NULL,
		period_anchor timestamp with time zone NOT NULL,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		CONSTRAINT rotation_report_schedules_pkey PRIMARY KEY (id)
	)`,
		`CREATE UNIQUE INDEX idx_rotation_report_schedules_name ON rotation_report_schedules (name)`,
	}
}

func applyRotationEvidenceReport(db *gorm.DB) error {
	for _, stmt := range rotationEvidenceReportDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 rotation_evidence_report DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackRotationEvidenceReport 反序還原結構。
//
// **有損**：見本檔檔頭的 Down 契約。開發庫限定；生產回退不走這裡。
func rollbackRotationEvidenceReport(db *gorm.DB) error {
	stmts := []string{
		`DROP INDEX idx_rotation_report_schedules_name`,
		`DROP TABLE rotation_report_schedules`,
		`DROP INDEX idx_audit_export_jobs_kind_status`,
		`ALTER TABLE audit_export_jobs DROP COLUMN kind`,
		`ALTER TABLE change_secret_plans DROP COLUMN max_age_days`,
		`DROP INDEX idx_asset_accounts_credential_group`,
		`ALTER TABLE asset_accounts DROP COLUMN credential_group`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 rotation_evidence_report 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
