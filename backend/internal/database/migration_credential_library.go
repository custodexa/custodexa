package database

import (
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 帳號憑證庫的資料層增量 migration：四張新表、資產帳號列的兩個新欄與其唯一鍵、
// 三張改密表的快照欄，以及把既有的「帳號自持密文」轉為專用憑證的存量搬移。
// 沿 migration_account_batch_rotation.go 的紀律：DDL 一律無條件建立，不加存在性檢查
// ——在已套用的庫上重跑必須大聲失敗，而非靜默 no-op。
//
// # Up 做什麼
//
//  1. credentials：登入秘密的本體（範圍、帳號名、秘密型別、協定族、輪替指標）。
//     共用名稱以 partial unique 唯一（scope='shared' 且未軟刪），使專用憑證的
//     NULL 名稱不互撞、共用改名或刪除後名稱可立即重用。
//  2. credential_secret_versions：不可變的密文版本，唯一鍵 (credential_id, version_no)。
//     版本不可變是「這台用舊版、那台用新版」得以成立的前提。
//  3. credential_rotations／credential_rotation_members：一次輪替與其逐掛載成員。
//     成員列帶四個快照欄（憑證、帳號名、資產與資產名），因為拆分收斂後掛載會改指
//     別的憑證，事後回頭 join 讀到的是現況而不是當時。
//  4. asset_accounts.credential_id／effective_version_id：帳號列退化為掛載列。
//     credential_id 以 NOT NULL DEFAULT 0 加欄、回填後卸除 DEFAULT——存量列必須先有值
//     才能加上 NOT NULL，而終態不該留一個「0 也算合法」的預設。
//  5. 存量搬移（同一交易）：每筆存活的帳號列各得一筆專用憑證；帳號原本持有密文者
//     另建其 v1 密文版本（**密文原樣搬、不解密重加密**——信封密文自帶 DEK 版本前綴、
//     AAD 綁 表|欄 而非列，跨表可解），回填 credential_id 與 effective_version_id。
//     兩欄皆空的帳號不建版本：那是「該掛載尚未取得任何密文」，就位版本留空才誠實。
//     軟刪的帳號列不建憑證，其 credential_id 留 0（墓碑列不參與任何連線或輪替）。
//     **所屬資產已軟刪的存活帳號列**照樣建憑證與版本（密文不丟），但兩者於同一交易
//     一併軟刪——舊版刪資產不連動掛載，那批殘列不處理就會變成憑證庫裡一排指向
//     不存在主機的專用憑證（詳見 convertAccountsToDedicatedCredentials 的說明）。
//  6. 存量搬移完成後才建 (asset_id, credential_id) 的 partial unique——回填前
//     全部存量列的 credential_id 都是 0，先建索引必然撞鍵。
//  7. 三張改密表加欄：計劃的目標種類與目標憑證，記錄與候選各三個憑證快照欄。
//
// # 隱性共用關係的合併不在本 migration 內
//
// 既有 credential_group 的合併需要**解密後比對明文**（同一組明文的兩份信封密文
// 不相等，密文層無從判定），而啟動段 1 沒有 codec——需要 codec 的資料轉換一律
// 登記進解封後佇列（見 internal/modules/keyvault/post_unseal_migration.go 檔頭的
// 架構裁決）。故合併落在 credential_secret_conversion.go 的佇列項，以執行期 marker 冪等。
// 本 migration 先讓每個成員各得一筆專用憑證，合併時再改指共用憑證並刪除多餘的專用列。
//
// # 過渡期保留的五個舊欄
//
// asset_accounts 的 username／password_enc／private_key_enc／auth_method／
// credential_group 在本 migration **不移除**：讀寫這些欄的服務碼尚未全部切換到憑證版本，
// 提前移除會讓整個後端編不過。移除是收縮階段的事，屆時於本檔追加一步。
//
// # Down 契約（讀完再用）
//
// **本 Down 有損。** 刪四張新表即失去全部共用憑證關係與密文版本歷史；
// asset_accounts 的兩個新欄刪除後，「這台用哪筆憑證、就位在哪一版」無來源可還原。
// Down 只還原結構、**不還原資料**（存量搬移沒有反向——舊欄雖仍在，但搬移後任何
// 新增的憑證與版本在舊欄裡沒有位置）。故本函式只供 parity 守衛與開發庫使用；
// **生產沒有回滾入口**：RollbackMigration 無產品碼呼叫者，回退的唯一手段是部署回
// 舊版映像並還原升級前備份（docs/ops/upgrade-sop.md §4）。

// credentialLibraryPreConversionDDL 存量搬移**之前**必須先到位的結構。
func credentialLibraryPreConversionDDL() []string {
	return []string{
		`CREATE TABLE credentials (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		deleted_at timestamp with time zone,
		name character varying(128),
		scope character varying(16) NOT NULL,
		username character varying(100) NOT NULL,
		secret_type character varying(16) NOT NULL,
		auth_method character varying(20) NOT NULL DEFAULT 'sql'::character varying,
		protocol_family character varying(16) NOT NULL,
		note character varying(255),
		current_version_id bigint,
		pending_version_id bigint,
		active_rotation_id bigint,
		rotation_epoch bigint NOT NULL DEFAULT 0,
		CONSTRAINT credentials_pkey PRIMARY KEY (id)
	)`,
		`CREATE INDEX idx_credentials_deleted_at ON credentials (deleted_at)`,
		`CREATE INDEX idx_credentials_username ON credentials (username)`,
		// 列表過濾以「範圍」為軸，且一律排除軟刪列
		`CREATE INDEX idx_credentials_scope_deleted_at ON credentials (scope, deleted_at)`,
		// 共用名稱唯一：專用的 NULL 名稱不入索引，故不互撞；
		// 軟刪列排除使名稱在刪除後可立即重用
		`CREATE UNIQUE INDEX idx_credentials_shared_name ON credentials (name) WHERE scope = 'shared' AND deleted_at IS NULL`,

		`CREATE TABLE credential_secret_versions (
		id bigserial,
		credential_id bigint NOT NULL,
		version_no bigint NOT NULL,
		secret_type character varying(16) NOT NULL,
		password_enc text,
		private_key_enc text,
		public_key text,
		previous_public_key text,
		created_reason character varying(16) NOT NULL,
		created_at timestamp with time zone,
		CONSTRAINT credential_secret_versions_pkey PRIMARY KEY (id)
	)`,
		`CREATE UNIQUE INDEX idx_credential_secret_versions_no ON credential_secret_versions (credential_id, version_no)`,

		`CREATE TABLE credential_rotations (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		credential_id bigint NOT NULL,
		epoch bigint NOT NULL,
		mode character varying(16) NOT NULL,
		target_version_id bigint,
		status character varying(16) NOT NULL,
		requested_by bigint,
		requested_by_name character varying(100),
		password_length bigint DEFAULT 16,
		password_include_symbol boolean DEFAULT true,
		password_exclude_ambiguous boolean DEFAULT true,
		started_at timestamp with time zone,
		finished_at timestamp with time zone,
		CONSTRAINT credential_rotations_pkey PRIMARY KEY (id)
	)`,
		`CREATE INDEX idx_credential_rotations_credential_id ON credential_rotations (credential_id)`,

		`CREATE TABLE credential_rotation_members (
		id bigserial,
		created_at timestamp with time zone,
		updated_at timestamp with time zone,
		rotation_id bigint NOT NULL,
		account_id bigint NOT NULL,
		credential_id bigint NOT NULL,
		username character varying(100),
		asset_id bigint NOT NULL,
		asset_name character varying(128),
		from_version_id bigint,
		target_version_id bigint,
		state character varying(24) NOT NULL,
		attempt_count bigint DEFAULT 0,
		next_attempt_at timestamp with time zone,
		last_error character varying(64),
		applied_at timestamp with time zone,
		CONSTRAINT credential_rotation_members_pkey PRIMARY KEY (id)
	)`,
		// 一次輪替內一個掛載只有一列成員（補跑重用同一列，不疊加第二筆）
		`CREATE UNIQUE INDEX idx_credential_rotation_members_target ON credential_rotation_members (rotation_id, account_id)`,

		// DEFAULT 0 僅供存量列過渡（NOT NULL 加欄需要），回填後即卸除
		`ALTER TABLE asset_accounts ADD COLUMN credential_id bigint NOT NULL DEFAULT 0`,
		`ALTER TABLE asset_accounts ADD COLUMN effective_version_id bigint`,

		`ALTER TABLE change_secret_plans ADD COLUMN target_kind character varying(16) NOT NULL DEFAULT 'account'::character varying`,
		`ALTER TABLE change_secret_plans ADD COLUMN target_credential_id bigint`,

		`ALTER TABLE change_secret_records ADD COLUMN credential_id bigint NOT NULL DEFAULT 0`,
		`ALTER TABLE change_secret_records ADD COLUMN credential_name character varying(128)`,
		`ALTER TABLE change_secret_records ADD COLUMN target_version_id bigint NOT NULL DEFAULT 0`,

		`ALTER TABLE change_secret_candidates ADD COLUMN credential_id bigint NOT NULL DEFAULT 0`,
		`ALTER TABLE change_secret_candidates ADD COLUMN credential_name character varying(128)`,
		`ALTER TABLE change_secret_candidates ADD COLUMN target_version_id bigint NOT NULL DEFAULT 0`,
	}
}

// credentialLibraryPostConversionDDL 存量搬移**之後**才能建立的結構。
//
// 次序寫死：回填前全部存量列的 credential_id 都是 0，同一資產有兩個帳號時
// 先建唯一索引必然撞鍵；DEFAULT 也必須等回填完才卸除。
func credentialLibraryPostConversionDDL() []string {
	return []string{
		`ALTER TABLE asset_accounts ALTER COLUMN credential_id DROP DEFAULT`,
		`CREATE UNIQUE INDEX idx_asset_accounts_credential ON asset_accounts (asset_id, credential_id) WHERE deleted_at IS NULL`,
	}
}

// credentialLibraryDDL 本 migration 的全部 schema 語句（供 parity 守衛解析）。
//
// **不供執行**：執行面在 applyCredentialLibrary，兩段 DDL 中間夾著存量搬移。
func credentialLibraryDDL() []string {
	return append(credentialLibraryPreConversionDDL(), credentialLibraryPostConversionDDL()...)
}

func applyCredentialLibrary(db *gorm.DB) error {
	for _, stmt := range credentialLibraryPreConversionDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 credential_library DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	stats, err := convertAccountsToDedicatedCredentials(db)
	if err != nil {
		return err
	}
	for _, stmt := range credentialLibraryPostConversionDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 credential_library 後置 DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	if stats.Live+stats.Retired > 0 {
		log.Printf("  credential_library：既有帳號轉專用憑證完成，存活 %d 筆、隨已移除資產一併移除 %d 筆",
			stats.Live, stats.Retired)
	}
	return nil
}

// credentialConversionStats 存量搬移的分項計數。
//
// 兩項分開報而不是給一個總數：升級日誌上「轉了 105 筆」與「轉了 31 筆、
// 另有 74 筆隨已移除的資產一併移除」是兩個不同的現場，後者才看得出
// 憑證庫為何不是 105 列。
type credentialConversionStats struct {
	// Live 所屬資產仍存活的掛載列
	Live int
	// Retired 所屬資產已軟刪、故隨資產一併移除的掛載列
	Retired int
}

// convertAccountsToDedicatedCredentials 存量搬移：每筆存活帳號列各得一筆專用憑證。
//
// 回傳分項計數。**呼叫端已在交易內**（RunMigrations 把整個 Up 包在交易裡），
// 任一步失敗即整批回滾，資料庫回到轉換前的形狀。
//
// # 所屬資產已軟刪的帳號列
//
// 舊版刪資產只軟刪 assets 一張列、不連動掛載，故升上來的庫裡會留著一批
// 「自身存活、但所屬資產已移除」的帳號列。這些列在此視同**隨資產一起移除**：
// 仍建專用憑證與 v1 密文版本，再把掛載列與憑證於同一交易一併軟刪。
//
// 三件事各有理由：建版本是因為收縮 migration 會卸掉帳號表的密文欄，不建就是
// 真的把密文丟了；軟刪掛載列是因為那台主機已不在，留著會讓憑證庫顯示一排
// 指向不存在主機的專用憑證；憑證跟著軟刪是因為專用憑證的生滅綁在它唯一的掛載上
// ——與本版「刪資產連動回收專用憑證」是同一條不變式，只是補做在搬移當下。
func convertAccountsToDedicatedCredentials(db *gorm.DB) (credentialConversionStats, error) {
	var stats credentialConversionStats
	type accountRow struct {
		ID            uint
		AssetID       uint
		Username      string
		PasswordEnc   string
		PrivateKeyEnc string
		AuthMethod    string
	}
	var accounts []accountRow
	if err := db.Raw(`SELECT id, asset_id, COALESCE(username, '') AS username,
		COALESCE(password_enc, '') AS password_enc,
		COALESCE(private_key_enc, '') AS private_key_enc,
		COALESCE(auth_method, '') AS auth_method
		FROM asset_accounts WHERE deleted_at IS NULL ORDER BY id`).Scan(&accounts).Error; err != nil {
		return stats, fmt.Errorf("讀取既有帳號列失敗: %w", err)
	}
	if len(accounts) == 0 {
		return stats, nil
	}

	assets, err := assetConversionFacts(db)
	if err != nil {
		return stats, err
	}
	// 同一時刻蓋在掛載列與其憑證上：兩者是同一個「隨資產一起移除」的動作，
	// 事後查起來要看得出是同一筆搬移做的，而不是兩次各自的刪除
	retiredAt := time.Now()

	for _, acc := range accounts {
		asset, ok := assets[acc.AssetID]
		if !ok {
			// 帳號指向不存在的資產：轉換不得靜默丟掉它（丟了就是一筆連得上卻無憑證
			// 可查的殘列），亦不得猜協定族——大聲失敗，讓部署者先修資料
			return stats, fmt.Errorf("帳號 #%d 指向不存在的資產 #%d：轉換中止，請先清理孤兒帳號列",
				acc.ID, acc.AssetID)
		}
		authMethod := acc.AuthMethod
		if authMethod == "" {
			authMethod = "sql"
		}
		secretType := model.ChangeSecretTypePassword
		if acc.PrivateKeyEnc != "" {
			secretType = model.ChangeSecretTypeSSHKey
		}
		cred := model.Credential{
			Scope:          model.CredentialScopeDedicated,
			Username:       acc.Username,
			SecretType:     secretType,
			AuthMethod:     authMethod,
			ProtocolFamily: asset.ProtocolFamily,
		}
		if err := db.Create(&cred).Error; err != nil {
			return stats, fmt.Errorf("為帳號 #%d 建立專用憑證失敗: %w", acc.ID, err)
		}

		updates := map[string]interface{}{"credential_id": cred.ID}
		if acc.PasswordEnc != "" || acc.PrivateKeyEnc != "" {
			version := model.CredentialSecretVersion{
				CredentialID:  cred.ID,
				VersionNo:     1,
				SecretType:    secretType,
				PasswordEnc:   acc.PasswordEnc,
				PrivateKeyEnc: acc.PrivateKeyEnc,
				CreatedReason: model.CredentialVersionReasonMigration,
			}
			if err := db.Create(&version).Error; err != nil {
				return stats, fmt.Errorf("為帳號 #%d 建立密文版本失敗: %w", acc.ID, err)
			}
			if err := db.Model(&model.Credential{}).Where("id = ?", cred.ID).
				Update("current_version_id", version.ID).Error; err != nil {
				return stats, fmt.Errorf("回填憑證 #%d 的現行版本失敗: %w", cred.ID, err)
			}
			// 就位版本直指 v1 是誠實的：那是該台當下實際在用的密文
			updates["effective_version_id"] = version.ID
		}
		// 所屬資產已移除者，掛載列的軟刪與憑證指標的回填走同一句 UPDATE：
		// 中間不存在「已軟刪但還沒指到憑證」的形狀
		if asset.Deleted {
			updates["deleted_at"] = retiredAt
		}
		if err := db.Model(&model.AssetAccount{}).Where("id = ?", acc.ID).
			Updates(updates).Error; err != nil {
			return stats, fmt.Errorf("回填帳號 #%d 的憑證指標失敗: %w", acc.ID, err)
		}
		if !asset.Deleted {
			stats.Live++
			continue
		}
		if err := db.Model(&model.Credential{}).Where("id = ?", cred.ID).
			Update("deleted_at", retiredAt).Error; err != nil {
			return stats, fmt.Errorf("隨已移除資產 #%d 一併移除憑證 #%d 失敗: %w",
				acc.AssetID, cred.ID, err)
		}
		stats.Retired++
	}
	return stats, nil
}

// assetConversionFact 存量搬移需要知道的資產事實。
type assetConversionFact struct {
	// ProtocolFamily 憑證的協定族（由協定與輪替通道推導）
	ProtocolFamily string
	// Deleted 資產本身已軟刪：其掛載列隨之一併移除（見搬移函式的檔內說明）
	Deleted bool
}

// assetConversionFacts 每個資產（含軟刪）的協定族與存活狀態。
//
// 含軟刪資產：帳號列可能還在而資產已軟刪，此時仍要給它一筆憑證，
// 否則該帳號的 credential_id 會留 0 而違反新的 NOT NULL 語義；
// 存活狀態則決定那筆憑證與掛載是否隨資產一併移除。
func assetConversionFacts(db *gorm.DB) (map[uint]assetConversionFact, error) {
	type assetRow struct {
		ID              uint
		Protocol        string
		RotationChannel string
		Deleted         bool
	}
	var assets []assetRow
	if err := db.Raw(`SELECT id, protocol, COALESCE(rotation_channel, '') AS rotation_channel,
		deleted_at IS NOT NULL AS deleted
		FROM assets`).Scan(&assets).Error; err != nil {
		return nil, fmt.Errorf("讀取資產協定失敗: %w", err)
	}
	out := make(map[uint]assetConversionFact, len(assets))
	for _, a := range assets {
		asset := model.Asset{Protocol: model.ProtocolType(a.Protocol), RotationChannel: a.RotationChannel}
		out[a.ID] = assetConversionFact{
			ProtocolFamily: model.ProtocolFamilyForAsset(&asset),
			Deleted:        a.Deleted,
		}
	}
	return out, nil
}

// rollbackCredentialLibrary 反序還原結構。
//
// **有損**：見本檔檔頭的 Down 契約。開發庫限定；生產回退不走這裡。
func rollbackCredentialLibrary(db *gorm.DB) error {
	stmts := []string{
		`DROP INDEX idx_asset_accounts_credential`,
		`ALTER TABLE change_secret_candidates DROP COLUMN target_version_id`,
		`ALTER TABLE change_secret_candidates DROP COLUMN credential_name`,
		`ALTER TABLE change_secret_candidates DROP COLUMN credential_id`,
		`ALTER TABLE change_secret_records DROP COLUMN target_version_id`,
		`ALTER TABLE change_secret_records DROP COLUMN credential_name`,
		`ALTER TABLE change_secret_records DROP COLUMN credential_id`,
		`ALTER TABLE change_secret_plans DROP COLUMN target_credential_id`,
		`ALTER TABLE change_secret_plans DROP COLUMN target_kind`,
		`ALTER TABLE asset_accounts DROP COLUMN effective_version_id`,
		`ALTER TABLE asset_accounts DROP COLUMN credential_id`,
		`DROP INDEX idx_credential_rotation_members_target`,
		`DROP TABLE credential_rotation_members`,
		`DROP INDEX idx_credential_rotations_credential_id`,
		`DROP TABLE credential_rotations`,
		`DROP INDEX idx_credential_secret_versions_no`,
		`DROP TABLE credential_secret_versions`,
		`DROP INDEX idx_credentials_shared_name`,
		`DROP INDEX idx_credentials_scope_deleted_at`,
		`DROP INDEX idx_credentials_username`,
		`DROP INDEX idx_credentials_deleted_at`,
		`DROP TABLE credentials`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 credential_library 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
