package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 主機帳號盤點增量。
//
// 內容：兩張新表。host_account_scans 每列是一次盤點；host_account_findings 以
// （asset_id, username）為單位保存最新結果。只建表與索引，不回填、不改既有表。
//
//   - 部分唯一索引 (asset_id) WHERE status IN ('queued','running')：同一資產至多一筆
//     未結束的盤點，併發發起由索引衝突擋下。
//   - 部分索引 (asset_id) WHERE status='open' AND privileged AND present：全域清單的預設篩選。
//   - 兩張表都不設外鍵：資產刪除不連動刪除結果（保留追溯），讀取端以資產的 deleted_at 過濾。
//
// # Down 契約
//
// 不提供回滾：回退只走還原升級前備份。
func hostAccountInventoryDDL() []string {
	return []string{
		`CREATE TABLE host_account_scans (
		id bigserial,
		asset_id bigint NOT NULL,
		platform character varying(16) NOT NULL,
		identity_mode character varying(20) NOT NULL,
		identity_account_id bigint NOT NULL,
		initiated_by bigint NOT NULL,
		initiated_by_name character varying(100) DEFAULT ''::character varying NOT NULL,
		status character varying(16) NOT NULL,
		failure_reason character varying(48) DEFAULT ''::character varying NOT NULL,
		privileged_groups text NOT NULL,
		coverage text DEFAULT '[]'::text NOT NULL,
		accounts_total bigint DEFAULT 0 NOT NULL,
		privileged_total bigint DEFAULT 0 NOT NULL,
		unmanaged_privileged_total bigint DEFAULT 0 NOT NULL,
		reopened_total bigint DEFAULT 0 NOT NULL,
		started_at timestamp with time zone,
		finished_at timestamp with time zone,
		created_at timestamp with time zone,
		CONSTRAINT host_account_scans_pkey PRIMARY KEY (id),
		CONSTRAINT host_account_scans_platform_check CHECK (platform IN ('posix','windows')),
		CONSTRAINT host_account_scans_identity_mode_check CHECK (identity_mode IN ('default_account','executor')),
		CONSTRAINT host_account_scans_status_check CHECK (status IN ('queued','running','succeeded','partial','failed','interrupted'))
	)`,
		`CREATE INDEX idx_host_account_scans_asset ON host_account_scans USING btree (asset_id)`,
		`CREATE UNIQUE INDEX uniq_host_account_scans_active ON host_account_scans USING btree (asset_id) WHERE status IN ('queued','running')`,
		`CREATE TABLE host_account_findings (
		id bigserial,
		asset_id bigint NOT NULL,
		username character varying(256) NOT NULL,
		uid character varying(32) DEFAULT ''::character varying NOT NULL,
		uid_conflict boolean DEFAULT false NOT NULL,
		login_capable boolean DEFAULT false NOT NULL,
		privileged boolean DEFAULT false NOT NULL,
		incomplete boolean DEFAULT false NOT NULL,
		present boolean DEFAULT true NOT NULL,
		privileged_reasons text DEFAULT '[]'::text NOT NULL,
		status character varying(12) NOT NULL,
		ignore_reason character varying(500) DEFAULT ''::character varying NOT NULL,
		ignored_by bigint DEFAULT 0 NOT NULL,
		ignored_by_name character varying(100) DEFAULT ''::character varying NOT NULL,
		ignored_at timestamp with time zone,
		ignored_reasons text DEFAULT '[]'::text NOT NULL,
		alerted boolean DEFAULT false NOT NULL,
		first_seen_scan_id bigint NOT NULL,
		last_seen_scan_id bigint NOT NULL,
		first_seen_at timestamp with time zone NOT NULL,
		last_seen_at timestamp with time zone NOT NULL,
		CONSTRAINT host_account_findings_pkey PRIMARY KEY (id),
		CONSTRAINT host_account_findings_status_check CHECK (status IN ('open','ignored'))
	)`,
		`CREATE UNIQUE INDEX idx_host_account_findings_asset_user ON host_account_findings USING btree (asset_id, username)`,
		`CREATE INDEX idx_host_account_findings_open_privileged ON host_account_findings USING btree (asset_id) WHERE status = 'open' AND privileged AND present`,
	}
}

func applyHostAccountInventory(db *gorm.DB) error {
	for _, stmt := range hostAccountInventoryDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 host_account_inventory DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackHostAccountInventory 不提供回滾；見檔頭 Down 契約。
func rollbackHostAccountInventory(_ *gorm.DB) error {
	return fmt.Errorf("host account inventory has no down migration; restore the pre-upgrade backup instead")
}
