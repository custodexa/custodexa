package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 待投遞紀錄的最近一次失敗時刻：system_alert_outbox 加 last_failed_at（可空）。
//
// 投遞程序每登記一次失敗（單筆失敗、目的地層級失敗、限流被拒）時寫入當下時刻；送達時不清除。
// 通道列表的「最近一次失敗的時間與原因」由此欄與既有的 last_error 彙總。純加法，無資料步驟：
// 升級前的紀錄為空，代表沒有記錄到失敗時刻。DDL 無條件、不用 IF NOT EXISTS，在已套用的庫上重跑必須大聲失敗。
//
// # Down 契約
//
// Down 刪欄（有損，失去失敗時刻），只供 parity 守衛與開發環境使用；生產回退只走部署回舊版映像並還原升級前備份。
const notificationDeliveryLastFailedVersion = "20261121_notification_delivery_last_failed"

func notificationDeliveryLastFailedDDL() []string {
	return []string{
		`ALTER TABLE system_alert_outbox ADD COLUMN last_failed_at timestamp with time zone`,
	}
}

func applyNotificationDeliveryLastFailed(db *gorm.DB) error {
	for _, stmt := range notificationDeliveryLastFailedDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 notification_delivery_last_failed DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// 待投遞紀錄轉為放棄或已取消的時刻：system_alert_outbox 加 ended_at（可空）。
//
// 投遞放棄的通知要帶「該通道近 24 小時被放棄的筆數」、通道列表要呈現「近 7 天放棄筆數」，兩者都以這個時刻計算
// （建立時刻與最近一次失敗時刻都不等於放棄時刻：型別已移除或因限流延後而放棄的紀錄可能從未失敗）。
// 純加法，無資料步驟：升級前已是終態的紀錄為空，不計入上述統計。Down 刪欄（有損，只供 parity 守衛與開發環境）。
const notificationDeliveryEndedAtVersion = "20261121_notification_delivery_ended_at"

func notificationDeliveryEndedAtDDL() []string {
	return []string{
		`ALTER TABLE system_alert_outbox ADD COLUMN ended_at timestamp with time zone`,
	}
}

func applyNotificationDeliveryEndedAt(db *gorm.DB) error {
	for _, stmt := range notificationDeliveryEndedAtDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 notification_delivery_ended_at DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

func rollbackNotificationDeliveryEndedAt(db *gorm.DB) error {
	if err := db.Exec(`ALTER TABLE system_alert_outbox DROP COLUMN ended_at`).Error; err != nil {
		return fmt.Errorf("回滾 notification_delivery_ended_at 失敗: %w", err)
	}
	return nil
}

// rollbackNotificationDeliveryLastFailed 見檔頭 Down 契約。
func rollbackNotificationDeliveryLastFailed(db *gorm.DB) error {
	if err := db.Exec(`ALTER TABLE system_alert_outbox DROP COLUMN last_failed_at`).Error; err != nil {
		return fmt.Errorf("回滾 notification_delivery_last_failed 失敗: %w", err)
	}
	return nil
}
