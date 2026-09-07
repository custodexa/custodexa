package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 帳號憑證庫的**收縮**增量 migration：把已無讀寫面的過渡欄位卸下。
// 沿 migration_credential_library.go 的紀律：DDL 一律無條件、不加存在性檢查
// ——在已套用的庫上重跑必須大聲失敗，而非靜默 no-op。
//
// # 為什麼是第二條 migration 而不是在第一條裡追加
//
// 第一條已套用於開發庫，同檔追加語句不會再執行，會留下「程式碼宣告已收縮、
// 資料庫仍有舊欄」的落差。故收縮自成一條版本，兩條依序執行的結果與一次寫完等價。
//
// # Up 卸下什麼
//
//  1. asset_accounts.password_enc／private_key_enc：登入秘密的落點已改為
//     credential_secret_versions，兩欄自存量搬移之後零讀者。**同時自
//     envelopeMigrationTargets 除名**——留著登記而欄位已不存在，DEK 輪替會逐欄失敗。
//  2. change_secret_candidates.shared_group／change_secret_batches.shared_group：
//     共用關係的真相已是憑證本體（具名共用憑證與掛載列），兩欄零寫入點。
//  3. idx_asset_accounts_credential_group：群組索引已無查詢走它。
//
// # 為什麼 asset_accounts.credential_group 這一欄留著
//
// 它的**唯一讀者是解封後的存量轉換**（credential_secret_conversion.go 的
// 隱性共用關係合併），而解封後佇列必然晚於段 1 的全部 migration：本收縮若把它
// 卸掉，轉換會在「欄位不存在」上失敗，而合併與密文改綁同交易，一起回滾的後果是
// 搬移進來的密文永遠停在舊的欄位身分上、取密路徑全面失敗。
// 該欄自本版起不再由任何產品路徑寫入，model 亦不再宣告它，
// 於 schema_parity_test.go 的 baselineColumnExceptions 具名登記唯一讀者。
//
// # 為什麼 asset_accounts.username／auth_method 這兩欄留著
//
// 兩者仍由帳號服務寫入、並由連線與改密路徑在憑證讀不到名字時回退讀取，
// 尚不是唯讀欄。卸下它們是另一件事的範圍，不在本次收縮內。
//
// # Down 契約（讀完再用）
//
// **本 Down 有損。** 只還原欄位的空殼與索引，**不還原任何資料**：卸下的四欄在
// 卸下當下即失去內容，再次 Up 之後全部回到空值。故本函式只供 parity 守衛與
// 開發環境使用。**生產沒有回滾入口**：RollbackMigration 無產品碼呼叫者，
// 回退的唯一手段是部署回舊版映像並還原升級前備份（docs/ops/upgrade-sop.md §4）。

// credentialLibraryContractDDL 本 migration 的全部 schema 語句。
func credentialLibraryContractDDL() []string {
	return []string{
		`DROP INDEX idx_asset_accounts_credential_group`,
		`ALTER TABLE asset_accounts DROP COLUMN password_enc`,
		`ALTER TABLE asset_accounts DROP COLUMN private_key_enc`,
		`ALTER TABLE change_secret_candidates DROP COLUMN shared_group`,
		`ALTER TABLE change_secret_batches DROP COLUMN shared_group`,
	}
}

func applyCredentialLibraryContract(db *gorm.DB) error {
	for _, stmt := range credentialLibraryContractDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 credential_library_contract DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackCredentialLibraryContract 反序還原結構（空殼）。
//
// **有損**：見本檔檔頭的 Down 契約。開發庫限定；生產回退不走這裡。
func rollbackCredentialLibraryContract(db *gorm.DB) error {
	stmts := []string{
		`ALTER TABLE change_secret_batches ADD COLUMN shared_group character varying(36)`,
		`ALTER TABLE change_secret_candidates ADD COLUMN shared_group character varying(36)`,
		`ALTER TABLE asset_accounts ADD COLUMN private_key_enc text`,
		`ALTER TABLE asset_accounts ADD COLUMN password_enc text`,
		`CREATE INDEX idx_asset_accounts_credential_group ON asset_accounts (credential_group)`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 credential_library_contract 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
