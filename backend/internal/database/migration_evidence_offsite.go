package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 離機儲存（evidence-offsite-storage）的兩張表與兩張擁有表的指標欄。
//
// # 為何兩張表同一條 migration
//
// `offsite_objects`（保管帳冊）的 `storage_generation_id` 是指向
// `offsite_profiles.generation_id` 的**邏輯外鍵**（不建 FK 約束，沿本專案既有慣例）。
// 兩者分兩條 migration 會產生一個「帳冊已存在而世代表尚未存在」的中間形狀，
// 那個形狀下的健檢（Ledger.CheckProfileContinuity）無法判讀。同批落地即無此窗口。
//
// # 為何是 baseline 之後的增量 migration
//
// 同 audit_export_jobs 的理由（見 migration_audit_export_jobs.go 檔頭）：純新表、
// 對既有表只加欄，增量 DDL 在全新資料庫（baseline → 本條）與既有開發資料庫
// （僅本條）上收斂到同一形狀。**加密欄的資料回填不在本條**——`credentials_enc`
// 由管理介面寫入或由 post-unseal 佇列的 env seed 寫入，
// migration 本身不需要 codec。
//
// DDL 沿 baseline 紀律：無條件、無 IF NOT EXISTS——在已有此表的庫上重跑必須大聲失敗。
// **語句內不得出現 SQL 註解**：第 1 層 parity 守衛以正則解析 CREATE TABLE 的欄位
// 清單，`--` 註解會被當成欄位定義（解析器的既有形狀，見 schema_parity_test.go）。
//
// （函式而非包級 var：理由同 auditExportJobsDDL）
func evidenceOffsiteDDL() []string {
	return []string{evidenceOffsiteProfilesTableDDL, evidenceOffsiteObjectsTableDDL,
		`CREATE UNIQUE INDEX idx_offsite_profiles_current ON offsite_profiles USING btree (singleton) WHERE (retired_at IS NULL)`,
		`CREATE UNIQUE INDEX uniq_offsite_objects_owner_generation ON offsite_objects USING btree (kind, owner_id, storage_generation_id)`,
		`CREATE INDEX idx_offsite_objects_due ON offsite_objects USING btree (origin, next_attempt_at, id) WHERE (state = 'pending')`,
		`CREATE INDEX idx_offsite_objects_lease ON offsite_objects USING btree (lease_until) WHERE (state = 'uploading')`,
		`CREATE INDEX idx_offsite_objects_state ON offsite_objects USING btree (state)`,
		`ALTER TABLE sessions ADD COLUMN offsite_object_id bigint`,
		`ALTER TABLE sessions ADD COLUMN offsite_status character varying(20) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE audit_export_jobs ADD COLUMN offsite_object_id bigint`,
		`ALTER TABLE audit_export_jobs ADD COLUMN offsite_status character varying(20) DEFAULT ''::character varying NOT NULL`,
		`CREATE INDEX idx_sessions_offsite_backfill ON sessions USING btree (id) WHERE ((offsite_object_id IS NULL) AND has_recording)`,
		`CREATE INDEX idx_sessions_offsite_retention ON sessions USING btree (end_time) WHERE (offsite_object_id IS NOT NULL)`,
	}
}

// evidenceOffsiteProfilesTableDDL 離機儲存設定世代表。
//
// # generation_id 為主鍵而非指紋
//
// 指紋（profile_fingerprint）是連線參數的函數：`s3 → gcs → 切回原 s3 參數` 會算出
// 與已退役列**相同**的指紋。以指紋為主鍵則第三個世代必然撞主鍵；改成「重啟舊列」
// 則會把兩個時間世代及其**各自不同的憑證**合併成一列。故識別取不可重用的
// `bigserial`（序列不回頭），指紋降為**可重複**的比較與顯示欄。
// 取 bigserial 而非 ULID／UUID 是沿本 repo 慣例——baseline 每張表皆 `id bigserial`，
// 無 ULID／UUID 主鍵先例，且跨庫合併與離線產號不是本專案需求。
//
// # 現行世代「至多一列（0 或 1）」
//
// 不是「恰一列」：零現行世代＝**已停用**（管理介面的「停止離機」退役現行列而不建
// 新列），歷史世代仍可取回。唯一性沿 ldap_directories 的既有形態：`singleton` 常數欄
// ＋具名 CHECK `(singleton = 1)` ＋ partial unique index `(singleton) WHERE retired_at IS NULL`。
// **CHECK 不可省**：unique index 只禁止相同值重複，`singleton=2` 仍可與 `singleton=1`
// 並存而使「至多一列」失效。
//
// # credential_mode 的三值與 CHECK
//
// `stored`（用本世代自己的憑證）／`default_chain`（部署方刻意選 SDK 預設鏈／ADC）／
// `revoked`（曾有憑證、已由管理員撤銷）。以「空密文」同時表達「用預設鏈」與「已撤銷」
// 是歧義——撤銷後仍可能靜默走預設鏈繼續取回。`stored ⇔ credentials_enc <> ''`
// 由具名 CHECK 釘住：交給應用層等於沒有機器盯著。
//
// # credentials_enc
//
// 信封加密（依 provider 的 JSON：s3＝access key 兩欄、gcs＝SA JSON 原文）。
// **必須登記於 keyvault 的 cipher_refs.go 與 envelopeMigrationTargets**——該清單同時
// 驅動 DEK 輪替重加密與退役 DEK 銷毀前的引用掃描，漏登會誤判零引用而銷毀仍在用的
// 金鑰材料，歷史世代憑證即永久不可解、該世代物件永不可取回。
const evidenceOffsiteProfilesTableDDL = `CREATE TABLE offsite_profiles (
	generation_id bigserial,
	profile_fingerprint character varying(16) NOT NULL,
	singleton integer DEFAULT 1 NOT NULL,
	provider character varying(8) NOT NULL,
	endpoint text DEFAULT ''::text NOT NULL,
	bucket character varying(255) NOT NULL,
	prefix character varying(255) DEFAULT ''::character varying NOT NULL,
	region character varying(64) DEFAULT ''::character varying NOT NULL,
	path_style boolean DEFAULT false NOT NULL,
	credential_mode character varying(16) NOT NULL,
	credentials_enc text DEFAULT ''::text NOT NULL,
	credential_revision bigint DEFAULT 0 NOT NULL,
	created_at timestamp with time zone,
	activated_at timestamp with time zone,
	retired_at timestamp with time zone,
	credentials_cleared_at timestamp with time zone,
	CONSTRAINT offsite_profiles_singleton_check CHECK ((singleton = 1)),
	CONSTRAINT offsite_profiles_credential_mode_check CHECK ((((credential_mode)::text = 'stored'::text) = (credentials_enc <> ''::text))),
	CONSTRAINT offsite_profiles_pkey PRIMARY KEY (generation_id)
)`

// evidenceOffsiteObjectsTableDDL 保管帳冊：每個上傳目標一列，
// 是遠端物件的身分與狀態機所在。**帳冊即佇列**（state='pending' 的 partial index）。
//
// `kind`／`origin`／`state` 的值域走應用層常數、**不加 CHECK**：加 CHECK 會動
// baselineCheckConstraints 的總量斷言（燒盡清單），而這三個欄位的值域只由本包寫入。
//
// `storage_generation_id` 指向 offsite_profiles.generation_id（邏輯外鍵，不建 FK 約束）。
// 唯一鍵含世代：同一擁有者在新世代可有新物件，舊世代的列不被覆蓋。
// **不得以可重複的指紋作外鍵**——「A→B→A」的第一與第三世代指紋相同，
// 以它作外鍵會把兩個世代的物件混為一談而在取回時拿到另一個世代的憑證。
//
// `provider` 是冗餘的明文身分欄（值域同 internal/offsite.ProviderS3／ProviderGCS）：
// 對帳與管理介面顯示直讀，免 join。
//
// `version_id` 為**參考性記錄**：儲存端回的版本識別有帶就記，
// 任何路徑不依賴；非版本化 bucket 為空字串。
const evidenceOffsiteObjectsTableDDL = `CREATE TABLE offsite_objects (
	id bigserial,
	kind character varying(16) NOT NULL,
	owner_id bigint NOT NULL,
	origin character varying(8) NOT NULL,
	provider character varying(8) NOT NULL,
	storage_generation_id bigint NOT NULL,
	bucket character varying(255) NOT NULL,
	object_key character varying(1024) NOT NULL,
	version_id character varying(255) NOT NULL,
	sha256 character varying(64) NOT NULL,
	size bigint NOT NULL,
	state character varying(20) NOT NULL,
	attempts bigint NOT NULL,
	lease_expiries bigint NOT NULL,
	next_attempt_at timestamp with time zone,
	lease_until timestamp with time zone,
	uploaded_at timestamp with time zone,
	error_code character varying(64) NOT NULL,
	created_at timestamp with time zone,
	updated_at timestamp with time zone,
	CONSTRAINT offsite_objects_pkey PRIMARY KEY (id)
)`

func applyEvidenceOffsite(db *gorm.DB) error {
	for _, stmt := range evidenceOffsiteDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 evidence_offsite DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackEvidenceOffsite 回退＝**資料追蹤不可逆**（design §8）。
//
// drop `offsite_objects` 即失去「哪個錄影的遠端副本在哪個 bucket、哪個 key、
// 上傳當下的 SHA-256 是多少」；drop `offsite_profiles` 更失去「哪個物件要用哪組
// 憑證取回」的對應。**遠端物件不隨回退消失**（產品從不刪遠端），故回退後
// 那些物件成為孤兒——升級 SOP 明載回退前須 `pg_dump --data-only -t offsite_objects`
// 匯出清冊與備份集同保管，重新升級時先還原清冊即零重傳。
func rollbackEvidenceOffsite(db *gorm.DB) error {
	for _, stmt := range []string{
		`DROP INDEX idx_sessions_offsite_retention`,
		`DROP INDEX idx_sessions_offsite_backfill`,
		`ALTER TABLE audit_export_jobs DROP COLUMN offsite_status`,
		`ALTER TABLE audit_export_jobs DROP COLUMN offsite_object_id`,
		`ALTER TABLE sessions DROP COLUMN offsite_status`,
		`ALTER TABLE sessions DROP COLUMN offsite_object_id`,
		`DROP TABLE offsite_objects`,
		`DROP TABLE offsite_profiles`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回退 evidence_offsite 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
