package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 資產帳號用途：asset_accounts 加 purpose 欄與「每資產至多一筆執行身分」的部分唯一索引。
//
// 純加法，無資料轉換、無回填：既有列由欄位預設值取得 login，升級後連線、授權與改密
// 的結果與升級前逐項相同。沿既有增量的紀律：DDL 無條件、不用 IF NOT EXISTS——在已
// 套用的庫上重跑必須大聲失敗，而非靜默 no-op。
//
// 「執行身分不得為預設」不寫成 CHECK：既有的預設不變式同樣只在服務層交易內維護，
// 落點保持一致。
//
// # Down 契約
//
// Down 有損（刪欄即失去全部用途標記，執行身分變回登入帳號），只供 parity 守衛與開發
// 環境使用；生產回退只走部署回舊版映像並還原升級前備份。
func assetAccountPurposeDDL() []string {
	return []string{
		`ALTER TABLE asset_accounts ADD COLUMN purpose character varying(16) DEFAULT 'login'::character varying NOT NULL`,
		`CREATE UNIQUE INDEX idx_asset_accounts_executor ON asset_accounts USING btree (asset_id) WHERE (((purpose)::text = 'executor'::text) AND (deleted_at IS NULL))`,
	}
}

func applyAssetAccountPurpose(db *gorm.DB) error {
	for _, stmt := range assetAccountPurposeDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 asset_account_purpose DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackAssetAccountPurpose 見檔頭 Down 契約。
func rollbackAssetAccountPurpose(db *gorm.DB) error {
	for _, stmt := range []string{
		`DROP INDEX idx_asset_accounts_executor`,
		`ALTER TABLE asset_accounts DROP COLUMN purpose`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 asset_account_purpose 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
