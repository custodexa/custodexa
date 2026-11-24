package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 通知投遞層增量。
//
// 內容：
//   - notification_messages：指令告警與系統事件的通知內容（一則通知一列）。產生點只寫識別碼與參數，
//     狀態為待分派；投遞程序分派時解析名稱、決定站內路徑、為每個通道建立待投遞紀錄。
//     指令告警的內容列以 alert_id 指向告警列，告警列被保留政策清除時連帶刪除。
//   - system_alert_outbox：成為所有通知類別共用的待投遞紀錄。新增類別、內容列外鍵、分級、
//     目標快照、終態原因、因限流延後的起點與目的地版本；alert_id 改為可空。兩條約束區分
//     「帶快照」（系統安全告警：指向告警列、目的地欄位為產生當下的快照）與「不帶快照」
//     （其他類別：指向內容列、目的地欄位一律為空字串，送出時讀通道當下的設定）。
//     到期索引改以 (來源通道, 目的地版本, 下次嘗試時間) 排序，供依目的地輪流取件。
//   - notification_channels：型別加 slack_app；新增目標、目的地最後變更時間與版本、
//     投遞放棄通知的節流時刻。
//
// 資料步驟：既有待投遞紀錄的分級以其告警列的分級回填一次（加欄之後、加約束之前）。
// 回填語句不在 DDL 清單內。既有紀錄的類別由欄位預設值取得 system_security_alert，
// 快照、投遞識別與嘗試次數不變。
//
// # Down 契約
//
// 不提供回滾：新欄位與新狀態值在舊結構無處存放，投遞紀錄屬於證據；回退以舊版映像加升級前備份為準。
// notificationDeliveryLayerVersion 本增量在 migrations 清單中的版本。
const notificationDeliveryLayerVersion = "20261120_notification_delivery_layer"

func notificationDeliveryLayerDDL() []string {
	return []string{
		`CREATE TABLE notification_messages (id bigserial, category character varying(32) NOT NULL, event_key character varying(64) NOT NULL, alert_id bigint, severity character varying(10) NOT NULL, occurred_at timestamp with time zone NOT NULL, actor_user_id bigint, actor_name character varying(255) DEFAULT ''::character varying NOT NULL, target_kind character varying(32) DEFAULT ''::character varying NOT NULL, target_id character varying(128) DEFAULT ''::character varying NOT NULL, target_name character varying(255) DEFAULT ''::character varying NOT NULL, params text DEFAULT '{}'::text NOT NULL, name_refs text DEFAULT '{}'::text NOT NULL, link_path character varying(512) DEFAULT ''::character varying NOT NULL, degraded boolean DEFAULT false NOT NULL, state character varying(16) DEFAULT 'pending'::character varying NOT NULL, dispatch_attempts integer DEFAULT 0 NOT NULL, lease_until timestamp with time zone, fail_reason character varying(32) DEFAULT ''::character varying NOT NULL, dispatched_at timestamp with time zone, created_at timestamp with time zone NOT NULL, CONSTRAINT notification_messages_pkey PRIMARY KEY (id), CONSTRAINT fk_notification_messages_alert FOREIGN KEY (alert_id) REFERENCES command_alerts(id) ON DELETE CASCADE, CONSTRAINT notification_messages_category_check CHECK (category IN ('command_alert','system_event')), CONSTRAINT notification_messages_severity_check CHECK (severity IN ('high','medium','low')), CONSTRAINT notification_messages_state_check CHECK (state IN ('pending','dispatched','failed')), CONSTRAINT notification_messages_fail_reason_check CHECK (fail_reason IN ('','category_unknown','dispatch_error')), CONSTRAINT notification_messages_alert_ref CHECK (category <> 'command_alert' OR alert_id IS NOT NULL))`,
		`CREATE INDEX idx_notification_messages_pending ON notification_messages USING btree (created_at) WHERE state = 'pending'`,
		`CREATE INDEX idx_notification_messages_state_created ON notification_messages USING btree (state, created_at)`,
		`CREATE INDEX idx_notification_messages_alert ON notification_messages USING btree (alert_id)`,

		`ALTER TABLE system_alert_outbox ADD COLUMN category character varying(32) DEFAULT 'system_security_alert'::character varying NOT NULL`,
		`ALTER TABLE system_alert_outbox ADD COLUMN message_id bigint`,
		`ALTER TABLE system_alert_outbox ADD COLUMN severity character varying(10) DEFAULT 'low'::character varying NOT NULL`,
		`ALTER TABLE system_alert_outbox ADD COLUMN dest_target character varying(64) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE system_alert_outbox ADD COLUMN end_reason character varying(32) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE system_alert_outbox ADD COLUMN throttled_since timestamp with time zone`,
		`ALTER TABLE system_alert_outbox ADD COLUMN dest_version integer DEFAULT 0 NOT NULL`,
		`ALTER TABLE system_alert_outbox ALTER COLUMN alert_id DROP NOT NULL`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT fk_system_alert_outbox_message FOREIGN KEY (message_id) REFERENCES notification_messages(id) ON DELETE CASCADE`,
		`ALTER TABLE system_alert_outbox DROP CONSTRAINT system_alert_outbox_state_check`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT system_alert_outbox_state_check CHECK (state IN ('pending','retrying','delivered','abandoned','canceled'))`,
		`ALTER TABLE system_alert_outbox DROP CONSTRAINT system_alert_outbox_dest_type_check`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT system_alert_outbox_dest_type_check CHECK (dest_type IN ('webhook','slack','slack_app',''))`,
		`ALTER TABLE system_alert_outbox DROP CONSTRAINT system_alert_outbox_language_check`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT system_alert_outbox_language_check CHECK (dest_language IN ('zh-TW','en-US','ja-JP',''))`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT system_alert_outbox_category_check CHECK (category IN ('system_security_alert','command_alert','system_event'))`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT system_alert_outbox_severity_check CHECK (severity IN ('high','medium','low'))`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT system_alert_outbox_end_reason_check CHECK (end_reason IN ('','max_attempts','snapshot_unreadable','type_unregistered','render_failed','channel_disabled','channel_deleted','precheck_canceled','rate_limited'))`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT system_alert_outbox_snapshot_ref CHECK (category <> 'system_security_alert' OR (alert_id IS NOT NULL AND message_id IS NULL AND dest_type <> '' AND dest_language <> ''))`,
		`ALTER TABLE system_alert_outbox ADD CONSTRAINT system_alert_outbox_live_ref CHECK (category = 'system_security_alert' OR (message_id IS NOT NULL AND alert_id IS NULL AND source_channel_id IS NOT NULL AND dest_type = '' AND dest_name = '' AND dest_language = '' AND url_enc = '' AND secret_enc = '' AND dest_version = 0))`,
		`CREATE INDEX idx_system_alert_outbox_source_created ON system_alert_outbox USING btree (source_channel_id, created_at)`,
		`CREATE INDEX idx_system_alert_outbox_message ON system_alert_outbox USING btree (message_id)`,
		`DROP INDEX idx_system_alert_outbox_due`,
		`CREATE INDEX idx_system_alert_outbox_due ON system_alert_outbox USING btree (source_channel_id, dest_version, next_attempt_at) WHERE state IN ('pending','retrying')`,

		`ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_type_check`,
		`ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check CHECK (type IN ('webhook','slack','slack_app'))`,
		`ALTER TABLE notification_channels ADD COLUMN target character varying(64) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE notification_channels ADD COLUMN destination_changed_at timestamp with time zone`,
		`ALTER TABLE notification_channels ADD COLUMN destination_version integer DEFAULT 0 NOT NULL`,
		`ALTER TABLE notification_channels ADD COLUMN abandon_notified_at timestamp with time zone`,
	}
}

// notificationDeliveryLayerSeverityBackfill 既有待投遞紀錄的分級取自其告警列（系統安全告警產生當下的有效分級）。
const notificationDeliveryLayerSeverityBackfill = `UPDATE system_alert_outbox o SET severity = a.severity FROM command_alerts a WHERE a.id = o.alert_id`

// notificationDeliveryLayerBackfillAfter 回填語句插在 DDL 清單的哪一句之後執行（分級欄加入之後、約束之前）。
const notificationDeliveryLayerBackfillAfter = `ALTER TABLE system_alert_outbox ADD COLUMN severity character varying(10) DEFAULT 'low'::character varying NOT NULL`

func applyNotificationDeliveryLayer(db *gorm.DB) error {
	backfilled := false
	for _, stmt := range notificationDeliveryLayerDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 notification_delivery_layer DDL 失敗（%.80s…）: %w", stmt, err)
		}
		if stmt == notificationDeliveryLayerBackfillAfter {
			if err := db.Exec(notificationDeliveryLayerSeverityBackfill).Error; err != nil {
				return fmt.Errorf("回填待投遞紀錄分級失敗: %w", err)
			}
			backfilled = true
		}
	}
	if !backfilled {
		return fmt.Errorf("notification_delivery_layer 的分級回填沒有執行：回填位置的語句不在 DDL 清單內")
	}
	return nil
}

// rollbackNotificationDeliveryLayer 不提供回滾；見檔頭 Down 契約。
func rollbackNotificationDeliveryLayer(_ *gorm.DB) error {
	return fmt.Errorf("notification delivery layer keeps delivery evidence; restore the pre-upgrade backup instead")
}
