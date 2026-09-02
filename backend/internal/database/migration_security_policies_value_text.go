package database

import "gorm.io/gorm"

// security_policies.value 由 varchar(128) 放寬為 text。
//
// # 為什麼要放寬
//
// 政策值一律以字串存放，型別語義由 service 層的常數表定義。既有鍵全是整數、
// 布林與短枚舉，128 位元組綽綽有餘；文字型政策鍵（上限二千個 Unicode 字元、
// 可含換行）放不進去。放寬欄位而非另立一張表，是為了讓文字型鍵直接沿用政策
// 機制既有的批次原子、變更審計、快取與錯誤碼，不必把那一整套重做一份。
//
// # 形態
//
// 純型別放寬、無資料回填：varchar(128) → text 在 PostgreSQL 是相容的擴張，
// 存量列原值不動。DDL 沿基準線紀律：無條件、無 IF NOT EXISTS——在已放寬的
// 庫上重跑必須大聲失敗，而非靜默 no-op。
//
// 本語句不列入 schemaDDLStatements()：該清單的解析器只認 CREATE TABLE 與
// ADD COLUMN（欄名層級的比對），型別改動屬第 2 層 parity 的射程，而第 2 層
// 以「基準線 + 依序跑完全部增量」建庫，本 migration 自然涵蓋其中。
//
// # Down 沒有生產入口
//
// 回滾函式只在開發期由 RollbackMigration 手動呼叫，服務本身不提供任何路徑
// 觸發它。收窄回 varchar(128) 時，若存量值已超過 128 位元組，資料庫會直接
// 報錯並使整個交易回滾——故不另寫前置檢查：真正的退版路徑是部署舊映像並
// 還原備份，不是就地收窄。
func applySecurityPoliciesValueText(db *gorm.DB) error {
	return db.Exec(`ALTER TABLE security_policies ALTER COLUMN value TYPE text`).Error
}

func rollbackSecurityPoliciesValueText(db *gorm.DB) error {
	return db.Exec(`ALTER TABLE security_policies ALTER COLUMN value TYPE character varying(128)`).Error
}
