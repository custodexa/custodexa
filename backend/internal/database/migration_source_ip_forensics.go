package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 來源位址追查（稽核工作台位址樞紐、帳號新來源位址告警、使用者允許來源網段）
// 的增量 migration。沿 migration_audit_export_jobs.go 形態：無條件 DDL、不用
// IF NOT EXISTS，在已套用的庫上重跑必須大聲失敗。
//
// # Up 做什麼（純加法，不動既有資料）
//
//  1. users 加 allowed_cidrs（逗號分隔的正規化前綴；空＝不限）。
//  2. 建 user_source_ips：帳號 × 位址的「已見」基準（判定依據，不是證據、不受
//     保留政策清除）。first_session_id 是並發首連線的單勝者判定鍵。
//  3. sessions (client_ip, start_time) 索引：位址樞紐的會話查詢與三表 join 都以
//     sessions.client_ip 為鍵，現況無索引會掃表；時間窗 keyset 需第二鍵。
//  4. user_source_ips (client_ip varchar_pattern_ops, last_seen_at) 覆蓋索引：
//     位址候選查詢是「前綴 LIKE ＋ 依 MAX(last_seen_at) 降序」。首欄以
//     varchar_pattern_ops 建立，因非 C collation 下 LIKE 'p%' 不走一般 btree。
//  5. command_alerts 的 kind 值域擴為含 new_source_ip（CHECK 重建，名稱不變）。
//  6. 回填：自 sessions 全史（含首次建線會話 id）與 audit_logs 的登入成功列合併，
//     使部署當下已見的位址不觸發告警。空或 NULL 位址跳過；全新庫兩表皆空、回填零列。
//
// # Down 契約（讀完再用）
//
// **本 Down 銷毀資料，只供開發庫使用。** 還原舊 CHECK 前必須先刪除既存的
// new_source_ip 告警列（否則 ADD CONSTRAINT 失敗）；DROP TABLE 丟掉整份已見位址基準；
// DROP COLUMN 丟掉每位使用者的來源限定。再次 Up 之後，所有使用者的清單為空
// （來源限制靜默消失）、基準為空（全部位址重新判為新）。RollbackMigration 沒有
// 生產入口、產品碼無呼叫者；**生產回退的唯一手段＝部署回舊版映像並還原升級前備份**
// （docs/ops/upgrade-sop.md §4）。
func sourceIPForensicsDDL() []string {
	return []string{
		`ALTER TABLE users ADD COLUMN allowed_cidrs text NOT NULL DEFAULT ''`,
		`CREATE TABLE user_source_ips (
		user_id bigint NOT NULL,
		client_ip character varying(50) NOT NULL,
		first_seen_at timestamp with time zone NOT NULL,
		last_seen_at timestamp with time zone NOT NULL,
		first_session_at timestamp with time zone,
		first_session_id bigint,
		CONSTRAINT user_source_ips_pkey PRIMARY KEY (user_id, client_ip)
	)`,
		`CREATE INDEX idx_sessions_client_ip_start ON sessions USING btree (client_ip, start_time)`,
		`CREATE INDEX idx_user_source_ips_ip_seen ON user_source_ips USING btree (client_ip varchar_pattern_ops, last_seen_at)`,
		`ALTER TABLE command_alerts DROP CONSTRAINT command_alerts_kind_check`,
		`ALTER TABLE command_alerts ADD CONSTRAINT command_alerts_kind_check CHECK (kind IN ('rule','audit_degraded','new_source_ip'))`,
	}
}

// sourceIPForensicsBackfill 冷啟動回填（只在 Up 執行，不在 schemaDDLStatements 內）。
//
// sessions：每組 (user_id, client_ip) 取最早會話為首次建線（first_session_at 與
// first_session_id 一併填），MAX(start_time) 為最近見到。
// audit_logs：登入成功列只補 first_seen_at／last_seen_at，不動首次建線兩欄——
// 「先登入再建線」的典型流程要在建線時才響，登入不得抹掉「新」。
// 軟刪列不計；空位址或 NULL 位址跳過（無位址可記）。
func sourceIPForensicsBackfill() []string {
	return []string{
		`INSERT INTO user_source_ips (user_id, client_ip, first_seen_at, last_seen_at, first_session_at, first_session_id)
		SELECT g.user_id, g.client_ip, g.first_at, g.last_at, g.first_at, f.id
		FROM (
			SELECT user_id, client_ip, MIN(start_time) AS first_at, MAX(start_time) AS last_at
			FROM sessions
			WHERE deleted_at IS NULL AND user_id > 0 AND start_time IS NOT NULL
			  AND client_ip IS NOT NULL AND client_ip <> ''
			GROUP BY user_id, client_ip
		) g
		JOIN LATERAL (
			SELECT s.id FROM sessions s
			WHERE s.user_id = g.user_id AND s.client_ip = g.client_ip
			  AND s.deleted_at IS NULL AND s.start_time IS NOT NULL
			ORDER BY s.start_time, s.id LIMIT 1
		) f ON true`,
		`INSERT INTO user_source_ips (user_id, client_ip, first_seen_at, last_seen_at)
		SELECT a.user_id, a.client_ip, MIN(a.created_at), MAX(a.created_at)
		FROM audit_logs a
		WHERE a.deleted_at IS NULL AND a.user_id > 0
		  AND a.action = 'login' AND a.status = 'success'
		  AND a.client_ip IS NOT NULL AND a.client_ip <> ''
		GROUP BY a.user_id, a.client_ip
		ON CONFLICT (user_id, client_ip) DO UPDATE SET
			first_seen_at = LEAST(user_source_ips.first_seen_at, EXCLUDED.first_seen_at),
			last_seen_at = GREATEST(user_source_ips.last_seen_at, EXCLUDED.last_seen_at)`,
	}
}

func applySourceIPForensics(db *gorm.DB) error {
	for _, stmt := range sourceIPForensicsDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 source_ip_forensics DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	for _, stmt := range sourceIPForensicsBackfill() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 source_ip_forensics 回填失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackSourceIPForensics 反序還原結構。
//
// 本函式銷毀資料：先刪 new_source_ip 告警列（否則舊 CHECK 加不回去），
// 再丟掉整份已見位址基準（DROP TABLE）與每位使用者的來源限定（DROP COLUMN）。
// 開發庫限定；生產回退不走這裡，見 docs/ops/upgrade-sop.md §4（還原升級前備份）。
func rollbackSourceIPForensics(db *gorm.DB) error {
	stmts := []string{
		`DROP INDEX idx_user_source_ips_ip_seen`,
		`DROP INDEX idx_sessions_client_ip_start`,
		`DELETE FROM command_alerts WHERE kind = 'new_source_ip'`,
		`ALTER TABLE command_alerts DROP CONSTRAINT command_alerts_kind_check`,
		`ALTER TABLE command_alerts ADD CONSTRAINT command_alerts_kind_check CHECK (kind IN ('rule','audit_degraded'))`,
		`DROP TABLE user_source_ips`,
		`ALTER TABLE users DROP COLUMN allowed_cidrs`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 source_ip_forensics 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
