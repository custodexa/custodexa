package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 執行身分來源：asset_accounts 加 executor_source 欄，記錄執行身分是怎麼設定的
// （generate｜inline｜shared｜convert），供讀取端點回傳，畫面據此顯示秘密來源。
//
// 純加法，無資料轉換、無回填：既有列取空字串，讀取端點遇空值整欄省略，畫面退回推斷。
// 來源不由審計反查（審計可被保留期限清除，不能當讀取來源）。DDL 無條件、不用 IF NOT EXISTS，
// 在已套用的庫上重跑必須大聲失敗。
//
// # Down 契約
//
// Down 有損（刪欄即失去來源記錄），只供 parity 守衛與開發環境使用；生產回退只走部署回舊版映像
// 並還原升級前備份。
func assetAccountExecutorSourceDDL() []string {
	return []string{
		`ALTER TABLE asset_accounts ADD COLUMN executor_source character varying(16) DEFAULT ''::character varying NOT NULL`,
	}
}

func applyAssetAccountExecutorSource(db *gorm.DB) error {
	for _, stmt := range assetAccountExecutorSourceDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 asset_account_executor_source DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackAssetAccountExecutorSource 見檔頭 Down 契約。
func rollbackAssetAccountExecutorSource(db *gorm.DB) error {
	if err := db.Exec(`ALTER TABLE asset_accounts DROP COLUMN executor_source`).Error; err != nil {
		return fmt.Errorf("回滾 asset_account_executor_source 失敗: %w", err)
	}
	return nil
}
