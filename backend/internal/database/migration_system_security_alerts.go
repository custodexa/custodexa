package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 系統安全告警增量。
//
// 內容：
//   - command_alerts.kind 值域加 system_security，並讓沒有會話的系統告警通過會話參照檢查；
//     rule_id 必為空由既有的 kind／rule_id 檢查自動成立。
//   - system_alert_details：每筆系統告警的結構化明細（類型鍵、目標、宣告參數、關聯識別、
//     離機轉發完成時刻）。
//   - system_alert_outbox：每個目的地一列的持久投遞佇列；目的地網址與簽章密鑰以信封加密保存。
//   - system_alert_severity_overrides：每個類型的有效分級覆寫（無列＝預設分級）。
//
// 只加結構、不回填；升級本身不產生任何系統告警或投遞列。
//
// # Down 契約
//
// 不提供回滾：告警與投遞紀錄屬於證據，回退只走升級前備份。
func systemSecurityAlertsDDL() []string {
	return []string{
		`ALTER TABLE command_alerts DROP CONSTRAINT command_alerts_kind_check`,
		`ALTER TABLE command_alerts ADD CONSTRAINT command_alerts_kind_check CHECK (kind IN ('rule','audit_degraded','new_source_ip','agent_breaker_tripped','sensitive_reveal','system_security'))`,
		`ALTER TABLE command_alerts DROP CONSTRAINT command_alerts_session_ref`,
		`ALTER TABLE command_alerts ADD CONSTRAINT command_alerts_session_ref CHECK (session_id IS NOT NULL OR kind IN ('agent_breaker_tripped','system_security'))`,
		`CREATE TABLE system_alert_details (alert_id bigint NOT NULL, alert_type character varying(64) NOT NULL, target_kind character varying(32) NOT NULL, target_id character varying(128) DEFAULT ''::character varying NOT NULL, params text DEFAULT '{}'::text NOT NULL, correlation_id character varying(64) DEFAULT ''::character varying NOT NULL, published_at timestamp with time zone, created_at timestamp with time zone NOT NULL, CONSTRAINT system_alert_details_pkey PRIMARY KEY (alert_id), CONSTRAINT fk_system_alert_details_alert FOREIGN KEY (alert_id) REFERENCES command_alerts(id) ON DELETE CASCADE)`,
		`CREATE INDEX idx_system_alert_details_type ON system_alert_details USING btree (alert_type)`,
		`CREATE INDEX idx_system_alert_details_unpublished ON system_alert_details USING btree (alert_id) WHERE published_at IS NULL`,
		`CREATE TABLE system_alert_outbox (id bigserial, alert_id bigint NOT NULL, dest_type character varying(20) NOT NULL, dest_name character varying(100) DEFAULT ''::character varying NOT NULL, dest_language character varying(8) NOT NULL, source_channel_id bigint, url_enc text NOT NULL, secret_enc text DEFAULT ''::text NOT NULL, state character varying(16) DEFAULT 'pending'::character varying NOT NULL, attempts integer DEFAULT 0 NOT NULL, next_attempt_at timestamp with time zone NOT NULL, lease_until timestamp with time zone, last_error text DEFAULT ''::text NOT NULL, delivered_at timestamp with time zone, created_at timestamp with time zone NOT NULL, CONSTRAINT system_alert_outbox_pkey PRIMARY KEY (id), CONSTRAINT fk_system_alert_outbox_alert FOREIGN KEY (alert_id) REFERENCES command_alerts(id) ON DELETE CASCADE, CONSTRAINT system_alert_outbox_state_check CHECK (state IN ('pending','retrying','delivered','abandoned')), CONSTRAINT system_alert_outbox_dest_type_check CHECK (dest_type IN ('webhook','slack')), CONSTRAINT system_alert_outbox_language_check CHECK (dest_language IN ('zh-TW','en-US','ja-JP')))`,
		`CREATE INDEX idx_system_alert_outbox_alert ON system_alert_outbox USING btree (alert_id)`,
		`CREATE INDEX idx_system_alert_outbox_due ON system_alert_outbox USING btree (next_attempt_at) WHERE state IN ('pending','retrying')`,
		`CREATE TABLE system_alert_severity_overrides (alert_type character varying(64) NOT NULL, severity character varying(10) NOT NULL, updated_by bigint NOT NULL, updated_at timestamp with time zone NOT NULL, CONSTRAINT system_alert_severity_overrides_pkey PRIMARY KEY (alert_type), CONSTRAINT system_alert_severity_overrides_severity_check CHECK (severity IN ('high','medium','low')))`,
	}
}

func applySystemSecurityAlerts(db *gorm.DB) error {
	for _, stmt := range systemSecurityAlertsDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 system_security_alerts DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackSystemSecurityAlerts 不提供回滾；見檔頭 Down 契約。
func rollbackSystemSecurityAlerts(_ *gorm.DB) error {
	return fmt.Errorf("system security alerts retain evidence; restore the pre-upgrade backup instead")
}
