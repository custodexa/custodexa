package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 定向通知：通道的「對個人派送」設定與待投遞紀錄的收件對象。
//
// notification_channels：
//   - direct_message_enabled（預設假）：是否把需要處理的通知另以個人訊息送給該處理的人。
//     至多一列為真（部分唯一索引，運算式為常數，WHERE 只取為真的列）；只有能以個人為對象的型別
//     （本版只有 slack_app）可為真（CHECK）。
//   - dm_issue_notified_at（可空）：最近一次產生「個人訊息未能送達」系統事件的時刻（24 小時節流，以條件更新判斷）。
//
// system_alert_outbox：
//   - audience（預設 channel，CHECK channel／user）與 recipient_user_id（可空，不設外鍵）。
//     audience = user 時收件人必填且類別必為 system_event；audience = channel 時收件人必為空。
//     收件人不設外鍵：使用者被硬刪時若置空，個人訊息紀錄會變得像頻道紀錄而被送進頻道；保留識別碼，
//     送出前查不到使用者時以 recipient_ineligible 取消。
//   - end_reason 值域加六個值（送出前重驗的兩種取消、對個人派送已關閉、三種位址解析的放棄）。
//   - (message_id, recipient_user_id) WHERE audience = 'user' 部分唯一索引：同一則內容對同一人至多一筆。
//   - 到期部分索引改為含 audience：投遞程序以（通道, 目的地版本, 收件對象）分組輪流取件。
//
// 純加法加約束重建，無資料步驟：升級後既有通道皆為假、既有紀錄 audience = channel 且收件人為空，
// 行為與升級前相同。DDL 無條件、不用 IF NOT EXISTS，在已套用的庫上重跑必須大聲失敗。
//
// # Down 契約
//
// **不提供 Down**（與通知投遞層一致）：回退以舊版映像加升級前備份為準。
const targetedNotificationVersion = "20261121_targeted_notification"

// targetedNotificationEndReasons 待投遞紀錄終態原因的完整值域（通知投遞層的九個值加本增量的六個）。
const targetedNotificationEndReasons = `'','max_attempts','snapshot_unreadable','type_unregistered','render_failed','channel_disabled','channel_deleted','precheck_canceled','rate_limited','request_resolved','recipient_ineligible','direct_message_disabled','no_email','email_ambiguous','recipient_not_found'`

func targetedNotificationDDL() []string {
	return []string{
		`ALTER TABLE notification_channels ADD COLUMN direct_message_enabled boolean DEFAULT false NOT NULL`,
		`ALTER TABLE notification_channels ADD COLUMN dm_issue_notified_at timestamp with time zone`,
		`ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_direct_message_type_check CHECK (NOT direct_message_enabled OR type = 'slack_app')`,
		`CREATE UNIQUE INDEX idx_notification_channels_direct_message ON notification_channels USING btree ((1)) WHERE direct_message_enabled`,

		`ALTER TABLE system_alert_outbox ADD COLUMN audience character varying(16) DEFAULT 'channel'::character varying NOT NULL`,
		`ALTER TABLE system_alert_outbox ADD COLUMN recipient_user_id bigint`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT system_alert_outbox_audience_check CHECK (audience IN ('channel','user'))`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT system_alert_outbox_recipient_ref CHECK ((audience = 'channel' AND recipient_user_id IS NULL) OR (audience = 'user' AND recipient_user_id IS NOT NULL AND category = 'system_event'))`,
		`ALTER TABLE system_alert_outbox DROP CONSTRAINT system_alert_outbox_end_reason_check`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT system_alert_outbox_end_reason_check CHECK (end_reason IN (` + targetedNotificationEndReasons + `))`,
		`CREATE UNIQUE INDEX idx_system_alert_outbox_message_recipient ON system_alert_outbox USING btree (message_id, recipient_user_id) WHERE audience = 'user'`,
		`DROP INDEX idx_system_alert_outbox_due`,
		`CREATE INDEX idx_system_alert_outbox_due ON system_alert_outbox USING btree (source_channel_id, dest_version, audience, next_attempt_at) WHERE state IN ('pending','retrying')`,
	}
}

func applyTargetedNotification(db *gorm.DB) error {
	for _, stmt := range targetedNotificationDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 targeted_notification DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackTargetedNotification 不提供回滾；見檔頭 Down 契約。
func rollbackTargetedNotification(_ *gorm.DB) error {
	return fmt.Errorf("targeted notification keeps delivery evidence; restore the pre-upgrade backup instead")
}
