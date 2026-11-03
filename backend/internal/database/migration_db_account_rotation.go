package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 改密紀錄的傳輸風險欄增量。
//
// 結構：change_secret_records 加 transport_risk（非空、預設空字串）。值為這筆處理以秘密
// 連過目標時的傳輸風險鍵；空字串＝沒有連過目標或連線已加密。
//
// 不回填、不改寫任何既有列：升級前沒有資料庫帳號自改，既有紀錄的空字串就是正確的事實。
//
// # Down 契約
//
// 不提供回滾：回退只走還原升級前備份。
func dbAccountRotationDDL() []string {
	return []string{
		`ALTER TABLE change_secret_records ADD COLUMN transport_risk character varying(32) NOT NULL DEFAULT ''`,
	}
}

func applyDBAccountRotation(db *gorm.DB) error {
	for _, stmt := range dbAccountRotationDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 db_account_rotation DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackDBAccountRotation 不提供回滾；見檔頭 Down 契約。
func rollbackDBAccountRotation(_ *gorm.DB) error {
	return fmt.Errorf("db account rotation has no down migration; restore the pre-upgrade backup instead")
}
