package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 鍵盤紀錄中繼資料表。
//
// 內容：一張新表 keystroke_records（一個會話一列）與其索引。純新增，無資料步驟，
// 不設外鍵：會話列被清除時紀錄列與檔案各依自己的保留期處理。
//
// # Down 契約
//
// 不提供回滾：回退只走還原升級前備份；舊版忽略新表與新目錄。
func keystrokeRecordsDDL() []string {
	return []string{
		`CREATE TABLE keystroke_records (
		id bigserial,
		record_uuid character varying(36) NOT NULL,
		session_id bigint NOT NULL,
		protocol character varying(16) DEFAULT ''::character varying NOT NULL,
		status character varying(16) NOT NULL,
		coverage_reason character varying(32) DEFAULT ''::character varying NOT NULL,
		file_path character varying(255) DEFAULT ''::character varying NOT NULL,
		file_key_enc text DEFAULT ''::text NOT NULL,
		failure_cause character varying(64) DEFAULT ''::character varying NOT NULL,
		writer_instance character varying(64) DEFAULT ''::character varying NOT NULL,
		event_count bigint DEFAULT 0 NOT NULL,
		byte_size bigint DEFAULT 0 NOT NULL,
		segment_count bigint DEFAULT 0 NOT NULL,
		started_at timestamp with time zone NOT NULL,
		last_write_at timestamp with time zone,
		ended_at timestamp with time zone,
		purged_at timestamp with time zone,
		CONSTRAINT keystroke_records_pkey PRIMARY KEY (id)
	)`,
		`CREATE UNIQUE INDEX idx_keystroke_records_record_uuid ON keystroke_records USING btree (record_uuid)`,
		`CREATE UNIQUE INDEX idx_keystroke_records_session_id ON keystroke_records USING btree (session_id)`,
		`CREATE INDEX idx_keystroke_records_status ON keystroke_records USING btree (status)`,
	}
}

func applyKeystrokeRecords(db *gorm.DB) error {
	for _, stmt := range keystrokeRecordsDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 keystroke_records DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackKeystrokeRecords 不提供回滾；見檔頭 Down 契約。
func rollbackKeystrokeRecords(_ *gorm.DB) error {
	return fmt.Errorf("keystroke records has no down migration; restore the pre-upgrade backup instead")
}
