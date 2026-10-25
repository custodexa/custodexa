package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 系統安全告警投遞識別增量。
//
// 結構：system_alert_outbox 加 delivery_key（32 個十六進位字元、唯一索引）。送給收端的投遞識別改用
// 這個排入當下隨機產生的值，不再用自增列編號：還原備份會把序列退回備份當時，之後新建的列會拿到
// 備份後已經發過的編號，照識別去重的收端會把還原後的新告警當成重複丟掉。隨機識別存在列上，
// 備份內待送的列重送時識別不變，還原後新建的列必為新值。
//
// 資料步驟：加欄之後、建唯一索引之前，對既有列各回填一個隨機值一次（既有部署升級時佇列通常為空；
// 有列也只是給它們各一個不重複的識別，不改投遞狀態）。回填語句不在 DDL 清單內。
//
// # Down 契約
//
// 不提供回滾：投遞紀錄屬於證據，回退只走升級前備份。
func systemAlertDeliveryKeyDDL() []string {
	return []string{
		`ALTER TABLE system_alert_outbox ADD COLUMN delivery_key character varying(32) DEFAULT ''::character varying NOT NULL`,
		`CREATE UNIQUE INDEX idx_system_alert_outbox_delivery_key ON system_alert_outbox USING btree (delivery_key)`,
	}
}

const systemAlertDeliveryKeyBackfill = `UPDATE system_alert_outbox SET delivery_key = md5(random()::text || id::text) WHERE delivery_key = ''`

func applySystemAlertDeliveryKey(db *gorm.DB) error {
	ddl := systemAlertDeliveryKeyDDL()
	for _, stmt := range []string{ddl[0], systemAlertDeliveryKeyBackfill, ddl[1]} {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 system_alert_delivery_key 語句失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackSystemAlertDeliveryKey 不提供回滾；見檔頭 Down 契約。
func rollbackSystemAlertDeliveryKey(_ *gorm.DB) error {
	return fmt.Errorf("system alert delivery keys retain evidence; restore the pre-upgrade backup instead")
}
