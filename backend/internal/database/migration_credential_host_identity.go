package database

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// 憑證主機身分增量。
//
// 結構：
//   - asset_host_keys.trust_generation：主機信任世代，一般欄位（預設 1）。世代只由新版服務的
//     採用、生效的重置、重置後首連換鑰三條路徑在同一交易以欄位運算推進；資料庫層不建任何
//     觸發器或預設運算——不經新版服務的寫入不推進世代，這是已接受的風險，不是保證。
//   - change_secret_candidates、credential_rotation_members 各加綁定欄（host_key_binding 與
//     傳輸、記錄、演算法、指紋、世代、綁定時刻）與停止通知去重鍵；成員另加派送標記
//     secret_sent_at（單調，只由 NULL 寫成時刻）。
//   - credential_host_identity_confirmations：逐工作、只驗證的人工承接紀錄；無外鍵、不 cascade
//     （一般候選轉正後被刪，承接證據必須留下）。
//
// # 資料步驟
//
// 只有一個：對 host_key_binding='legacy' 且 secret_sent_at 尚為空的成員，依既有證據保守寫入
// 派送標記（寫 migration 時刻）。這是派送歷史的證據，不是身分回填：快照欄全部維持零值。
// 依所屬輪替的模式分兩套判準：
//   - 整組：成員狀態為 changing／changed_unverified／applied；該帳號有候選列；或改密紀錄有同
//     帳號、同目標版本且狀態為 unverified／success 的列。
//   - 拆分：不看候選列（起始交易就替每個成員建好候選，乾淨失敗也不刪）；只看成員狀態為
//     changing／changed_unverified／applied，或改密紀錄有同帳號、同憑證、執行時刻不早於該輪
//     開始時刻、狀態為 unverified／success 的列（就位前紀錄的目標版本為 0，不比對）。
//
// 資料步驟可重入：只處理標記為空的 legacy 成員，不覆寫已寫入的時刻。
//
// # Down 契約
//
// 不提供回滾：承接紀錄屬於證據，回退只走升級前備份。
func credentialHostIdentityDDL() []string {
	pinColumns := func(table string) []string {
		return []string{
			`ALTER TABLE ` + table + ` ADD COLUMN host_key_binding character varying(16) DEFAULT 'legacy'::character varying NOT NULL`,
			`ALTER TABLE ` + table + ` ADD COLUMN host_key_transport character varying(16) DEFAULT ''::character varying NOT NULL`,
			`ALTER TABLE ` + table + ` ADD COLUMN host_key_record_id bigint DEFAULT 0 NOT NULL`,
			`ALTER TABLE ` + table + ` ADD COLUMN host_key_algorithm character varying(64) DEFAULT ''::character varying NOT NULL`,
			`ALTER TABLE ` + table + ` ADD COLUMN host_key_fingerprint character varying(128) DEFAULT ''::character varying NOT NULL`,
			`ALTER TABLE ` + table + ` ADD COLUMN host_key_generation bigint DEFAULT 0 NOT NULL`,
			`ALTER TABLE ` + table + ` ADD COLUMN host_key_bound_at timestamp with time zone`,
			`ALTER TABLE ` + table + ` ADD COLUMN host_identity_alerted_key character varying(64)`,
		}
	}
	out := []string{
		`ALTER TABLE asset_host_keys ADD COLUMN trust_generation bigint DEFAULT 1 NOT NULL`,
	}
	out = append(out, pinColumns("change_secret_candidates")...)
	out = append(out, pinColumns("credential_rotation_members")...)
	out = append(out,
		`ALTER TABLE credential_rotation_members ADD COLUMN secret_sent_at timestamp with time zone`,
		`CREATE TABLE credential_host_identity_confirmations (
		id bigserial,
		kind character varying(16) NOT NULL,
		job_id bigint NOT NULL,
		revision bigint DEFAULT 1 NOT NULL,
		asset_id bigint NOT NULL,
		account_id bigint DEFAULT 0 NOT NULL,
		confirmed_by bigint NOT NULL,
		confirmed_by_name character varying(100) DEFAULT ''::character varying NOT NULL,
		confirmed_transport character varying(16) NOT NULL,
		confirmed_record_id bigint DEFAULT 0 NOT NULL,
		confirmed_algorithm character varying(64) DEFAULT ''::character varying NOT NULL,
		confirmed_fingerprint character varying(128) DEFAULT ''::character varying NOT NULL,
		confirmed_generation bigint DEFAULT 0 NOT NULL,
		accept_different_key boolean DEFAULT false NOT NULL,
		original_binding character varying(16) DEFAULT ''::character varying NOT NULL,
		original_transport character varying(16) DEFAULT ''::character varying NOT NULL,
		original_record_id bigint DEFAULT 0 NOT NULL,
		original_fingerprint character varying(128) DEFAULT ''::character varying NOT NULL,
		original_generation bigint DEFAULT 0 NOT NULL,
		original_initiator_id bigint DEFAULT 0 NOT NULL,
		original_initiator_unknown boolean DEFAULT false NOT NULL,
		authz_version bigint DEFAULT 0 NOT NULL,
		restore_generation character varying(64) DEFAULT ''::character varying NOT NULL,
		client_ip character varying(64) DEFAULT ''::character varying NOT NULL,
		created_at timestamp with time zone,
		started_at timestamp with time zone,
		consumed_at timestamp with time zone,
		outcome character varying(24) DEFAULT ''::character varying NOT NULL,
		CONSTRAINT credential_host_identity_confirmations_pkey PRIMARY KEY (id)
	)`,
		`CREATE UNIQUE INDEX idx_credential_host_identity_confirmations_job ON credential_host_identity_confirmations USING btree (kind, job_id, revision)`,
		`CREATE INDEX idx_credential_host_identity_confirmations_consumed ON credential_host_identity_confirmations USING btree (kind, job_id, consumed_at)`,
	)
	return out
}

func applyCredentialHostIdentity(db *gorm.DB) error {
	for _, stmt := range credentialHostIdentityDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 credential_host_identity DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return backfillMemberSecretSent(db, time.Now())
}

// 成員所屬輪替為拆分模式的條件；其餘（含空值）一律照整組判準。
const memberIsSplitSQL = `EXISTS (SELECT 1 FROM credential_rotations r WHERE r.id = credential_rotation_members.rotation_id AND r.mode = 'split')`

// backfillMemberSecretSent 依既有證據保守寫入 legacy 成員的派送標記（可重入，不覆寫已寫值）。
// 不讀寫任何秘密欄位；兩個語句在 PostgreSQL 與 SQLite 上同形。
func backfillMemberSecretSent(db *gorm.DB, now time.Time) error {
	const base = `UPDATE credential_rotation_members SET secret_sent_at = ?
		WHERE host_key_binding = 'legacy' AND secret_sent_at IS NULL AND `
	stmts := []string{
		// 整組模式
		base + `NOT ` + memberIsSplitSQL + ` AND (
			state IN ('changing','changed_unverified','applied')
			OR EXISTS (SELECT 1 FROM change_secret_candidates c WHERE c.account_id = credential_rotation_members.account_id)
			OR EXISTS (SELECT 1 FROM change_secret_records s
				WHERE s.account_id = credential_rotation_members.account_id
				  AND s.target_version_id = COALESCE(credential_rotation_members.target_version_id, 0)
				  AND s.status IN ('unverified','success')))`,
		// 拆分模式：不看候選列
		base + memberIsSplitSQL + ` AND (
			state IN ('changing','changed_unverified','applied')
			OR EXISTS (SELECT 1 FROM change_secret_records s, credential_rotations r
				WHERE r.id = credential_rotation_members.rotation_id
				  AND s.account_id = credential_rotation_members.account_id
				  AND s.credential_id = credential_rotation_members.credential_id
				  AND s.executed_at >= r.started_at
				  AND s.status IN ('unverified','success')))`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt, now).Error; err != nil {
			return fmt.Errorf("寫入 legacy 成員派送標記失敗: %w", err)
		}
	}
	return nil
}

// rollbackCredentialHostIdentity 不提供回滾；見檔頭 Down 契約。
func rollbackCredentialHostIdentity(_ *gorm.DB) error {
	return fmt.Errorf("credential host identity confirmations retain evidence; restore the pre-upgrade backup instead")
}
