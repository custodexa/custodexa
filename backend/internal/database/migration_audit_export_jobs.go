package database

import (
	"fmt"

	"gorm.io/gorm"
)

// audit_export_jobs 表。
//
// # 為何是 baseline 之後的增量 migration、而非改寫 baseline
//
// baseline（20260816）是壓縮時點的 schema 快照；RunMigrations 明文保留
// 「baseline 之後的增量 migration 仍走同一條路徑」（migrations.go 的
// RollbackMigration 註解）。本表是純新表、無加密欄、無資料回填，增量 DDL 在
// 全新資料庫（baseline → 本條）與既有開發資料庫（僅本條）上收斂到同一形狀，
// 不需要 B1 剪貼簿轉換那種「baseline 終態＋post-unseal 回填」的雙軌——那一軌
// 的存在理由是回填需要 codec，本表沒有這個依賴。
//
// DDL 沿 baseline 紀律：無條件、無 IF NOT EXISTS——在已有此表的庫上重跑
// 必須大聲失敗，而非靜默 no-op。
//
// # 索引
//
//   - (requester_id, status)：下載中心清單與每申請者進行中計數的查詢面。
//   - (status)：worker 領件（pending 最舊優先）與過期清掃的查詢面。
//   - 部分唯一索引 (requester_id, filter_hash) WHERE status IN
//     ('pending','running')：pending/running 去重的資料庫層防線（admission
//     交易是第一道，本索引擋住任何繞過服務層的寫入路徑）。failed/done 不在
//     WHERE 內，故不阻擋重新發起、也不使舊包被復用。
//
// （函式而非包級 var：包級全域須逐項登記 lifecycle manifest，本清單只在
// migration 執行時讀一次，無時序語義）
func auditExportJobsDDL() []string {
	return []string{
		`CREATE TABLE audit_export_jobs (
		id bigserial,
		requester_id bigint NOT NULL,
		requester_name character varying(50) NOT NULL,
		filter_json text NOT NULL,
		filter_hash character varying(64) NOT NULL,
		status character varying(16) NOT NULL,
		attempts bigint NOT NULL,
		artifact_path character varying(500) NOT NULL,
		artifact_sha256 character varying(64) NOT NULL,
		artifact_size bigint NOT NULL,
		error_summary character varying(64) NOT NULL,
		requested_at timestamp with time zone NOT NULL,
		packaged_at timestamp with time zone,
		expires_at timestamp with time zone,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		CONSTRAINT audit_export_jobs_pkey PRIMARY KEY (id)
	)`,
		`CREATE INDEX idx_audit_export_jobs_requester_status ON audit_export_jobs (requester_id, status)`,
		`CREATE INDEX idx_audit_export_jobs_status ON audit_export_jobs (status)`,
		`CREATE UNIQUE INDEX uniq_audit_export_jobs_active_filter ON audit_export_jobs (requester_id, filter_hash)
		WHERE status IN ('pending', 'running')`,
	}
}

func applyAuditExportJobs(db *gorm.DB) error {
	for _, stmt := range auditExportJobsDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 audit_export_jobs DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackAuditExportJobs 本表為純狀態表（產物與審計證據皆不在其中）：
// job 列是申請者的追蹤憑據、產物檔另有保留期清理，drop 表僅失去追蹤面，
// 不觸及任何證據——design 明載「audit_export_jobs 為新表（可棄，可逆）」。
func rollbackAuditExportJobs(db *gorm.DB) error {
	return db.Exec(`DROP TABLE audit_export_jobs`).Error
}
