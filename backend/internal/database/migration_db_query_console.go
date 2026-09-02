package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 查詢主控台（db-query-console）的增量 migration：三張既有表加欄，
// 全部是純加法，無資料轉換、無回填。沿 migration_audit_export_jobs.go 的紀律：
// DDL 無條件、不用 IF NOT EXISTS——在已套用的庫上重跑必須大聲失敗。
//
// # Up 做什麼
//
//  1. assets.allowed_databases：允許作為主控台執行目標的資料庫名清單（JSON 陣列
//     文字，`[]`＝不限制）。**不是 jsonb 也不是 text[]**：schema 內既無此類欄，
//     為單一欄位引入新的型別族會讓備份還原與工具鏈多一個變數；也不是逗號分隔
//     字串——資料庫名稱本身可含逗號與空白。
//  2. sessions.db_console：該會話是否為主控台會話（列表、詳情、監看以此分流）。
//  3. session_commands 十一個結果事實欄：主控台的每個執行單位一列，記下事件 ID、
//     目標資料庫、終態、原因碼、列數、影響列數、結果集數、目標端錯誤碼、耗時、
//     截斷旗標與單位執行後的交易態。命令列（CLI）列的這些欄一律留在預設值，
//     `result_status=''` 即「這不是主控台列」。
//
// # 為什麼是三條 CHECK
//
// `result_status` 與 `tx_state_after` 是值域受控的機器碼，散文語義寫在
// model.SessionCommand 的常數上；值域漂移（例如新增狀態卻沒同步 UI 與匯出）
// 的症狀是稽核報表出現無人認得的狀態字串，而那在應用層看不出來。
// `event_id` 的長度約束擋的是另一種形態：ID 產生器改實作而長度變了，
// 但既有列與新列的定址方式（匯出 URL、轉錄行、錨點）都假設同一形狀。
//
// # 為什麼 partial unique 而不是普通 unique
//
// 事件 ID 只有主控台列才有，CLI 列一律空字串。普通唯一索引會讓第二筆 CLI 列
// 就撞上唯一衝突。`WHERE event_id <> ''` 把約束限縮到真正需要唯一的那一側，
// 形態沿 baseline 既有的部分唯一索引先例。
//
// # Down 契約（讀完再用）
//
// **本 Down 有損。** 它刪掉的兩類東西性質不同：
// `assets.allowed_databases` 是政策（管理者設定的執行目標限制，刪了即靜默解除，
// 再次 Up 之後全部資產回到不限制）；`session_commands` 的十一欄是**稽核證據**
// （每個執行單位的終態、目標庫、事件 ID），刪了就沒有第二個來源可補——轉錄錄影
// 是自同一事件派生的閱讀面，不是事實來源。
//
// 故本函式只供 parity 守衛與開發環境使用。**生產沒有回滾入口**：RollbackMigration
// 無產品碼呼叫者，回退的唯一手段是部署回舊版映像並還原升級前備份
// （docs/ops/upgrade-sop.md §4），而該備份必須含 session_commands 全表。
func dbQueryConsoleDDL() []string {
	return []string{
		`ALTER TABLE assets ADD COLUMN allowed_databases text NOT NULL DEFAULT '[]'`,
		`ALTER TABLE sessions ADD COLUMN db_console boolean NOT NULL DEFAULT false`,

		`ALTER TABLE session_commands ADD COLUMN event_id character varying(26) NOT NULL DEFAULT ''`,
		`ALTER TABLE session_commands ADD COLUMN target_database character varying(128) NOT NULL DEFAULT ''`,
		`ALTER TABLE session_commands ADD COLUMN result_status character varying(16) NOT NULL DEFAULT ''`,
		`ALTER TABLE session_commands ADD COLUMN result_reason character varying(32) NOT NULL DEFAULT ''`,
		`ALTER TABLE session_commands ADD COLUMN result_rows bigint`,
		`ALTER TABLE session_commands ADD COLUMN rows_affected bigint`,
		`ALTER TABLE session_commands ADD COLUMN result_sets integer`,
		`ALTER TABLE session_commands ADD COLUMN error_code character varying(64) NOT NULL DEFAULT ''`,
		`ALTER TABLE session_commands ADD COLUMN duration_ms integer`,
		`ALTER TABLE session_commands ADD COLUMN result_truncated boolean NOT NULL DEFAULT false`,
		`ALTER TABLE session_commands ADD COLUMN tx_state_after character varying(8) NOT NULL DEFAULT ''`,

		`ALTER TABLE session_commands ADD CONSTRAINT session_commands_result_status_domain
		CHECK (result_status IN ('', 'running', 'ok', 'error', 'blocked',
		                         'cancelled', 'timeout', 'partial', 'effect_unknown'))`,
		`ALTER TABLE session_commands ADD CONSTRAINT session_commands_tx_state_domain
		CHECK (tx_state_after IN ('', 'none', 'active', 'failed', 'unknown'))`,
		`ALTER TABLE session_commands ADD CONSTRAINT session_commands_event_id_shape
		CHECK (event_id = '' OR length(event_id) = 26)`,

		`CREATE UNIQUE INDEX idx_session_commands_event_id ON session_commands (event_id) WHERE event_id <> ''`,
		`CREATE INDEX idx_session_commands_result_status ON session_commands (result_status) WHERE result_status <> ''`,
		`CREATE INDEX idx_session_commands_target_database ON session_commands (target_database) WHERE target_database <> ''`,
	}
}

func applyDBQueryConsole(db *gorm.DB) error {
	for _, stmt := range dbQueryConsoleDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 db_query_console DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackDBQueryConsole 反序還原結構。
//
// **有損**：見本檔檔頭的 Down 契約——政策欄與十一欄稽核證據一併消失。
// 開發庫限定；生產回退不走這裡。
func rollbackDBQueryConsole(db *gorm.DB) error {
	stmts := []string{
		`DROP INDEX idx_session_commands_target_database`,
		`DROP INDEX idx_session_commands_result_status`,
		`DROP INDEX idx_session_commands_event_id`,
		`ALTER TABLE session_commands DROP CONSTRAINT session_commands_event_id_shape`,
		`ALTER TABLE session_commands DROP CONSTRAINT session_commands_tx_state_domain`,
		`ALTER TABLE session_commands DROP CONSTRAINT session_commands_result_status_domain`,
		`ALTER TABLE session_commands DROP COLUMN tx_state_after`,
		`ALTER TABLE session_commands DROP COLUMN result_truncated`,
		`ALTER TABLE session_commands DROP COLUMN duration_ms`,
		`ALTER TABLE session_commands DROP COLUMN error_code`,
		`ALTER TABLE session_commands DROP COLUMN result_sets`,
		`ALTER TABLE session_commands DROP COLUMN rows_affected`,
		`ALTER TABLE session_commands DROP COLUMN result_rows`,
		`ALTER TABLE session_commands DROP COLUMN result_reason`,
		`ALTER TABLE session_commands DROP COLUMN result_status`,
		`ALTER TABLE session_commands DROP COLUMN target_database`,
		`ALTER TABLE session_commands DROP COLUMN event_id`,
		`ALTER TABLE sessions DROP COLUMN db_console`,
		`ALTER TABLE assets DROP COLUMN allowed_databases`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 db_query_console 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
