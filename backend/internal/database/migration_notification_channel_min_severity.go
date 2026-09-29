package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 通知通道推送門檻：min_severity＋CHECK。既有列由 DEFAULT 取得 low（全部告警），
// 升級後推送行為不變，無回填語句。DDL 無條件，不用 IF NOT EXISTS；
// migration 版本集合負責避免重跑。
//
// # Down 契約
//
// 有損：門檻設定沒有第二處存放，卸欄後再 Up 一律回到 low。方向安全（回到全部推送），
// 但不能視為可逆升級；生產沒有回滾入口，回退以舊版映像＋升級前備份為準。
func notificationChannelMinSeverityDDL() []string {
	return []string{
		`ALTER TABLE notification_channels ADD COLUMN min_severity character varying(10) DEFAULT 'low'::character varying NOT NULL`,
		`ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_min_severity_check CHECK (min_severity IN ('low','medium','high'))`,
	}
}

func applyNotificationChannelMinSeverity(db *gorm.DB) error {
	for _, stmt := range notificationChannelMinSeverityDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 notification_channel_min_severity DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackNotificationChannelMinSeverity 有損卸欄；見檔頭 Down 契約。
func rollbackNotificationChannelMinSeverity(db *gorm.DB) error {
	for _, stmt := range []string{
		`ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_min_severity_check`,
		`ALTER TABLE notification_channels DROP COLUMN min_severity`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 notification_channel_min_severity 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
