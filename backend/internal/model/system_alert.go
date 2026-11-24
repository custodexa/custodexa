package model

import "time"

// AlertKindSystemSecurity 系統安全告警的來源類別。
//
// 與其他非規則類別同理由：系統告警不掛在可 CRUD 的規則列上，管理員無從刪除或停用；
// rule_id 必為空，session_id 為空。結構化參數放在 system_alert_details，不塞進 command 欄。
const AlertKindSystemSecurity = "system_security"

// SystemAlertDetail 系統告警明細（alert_id 即 command_alerts 主鍵，告警被保留政策清除時級聯刪除）。
type SystemAlertDetail struct {
	AlertID       uint       `gorm:"primaryKey;autoIncrement:false" json:"alert_id"`
	AlertType     string     `gorm:"size:64;not null" json:"alert_type"`
	TargetKind    string     `gorm:"size:32;not null" json:"target_kind"`
	TargetID      string     `gorm:"size:128;not null" json:"target_id"`
	Params        string     `gorm:"type:text;not null" json:"params"`
	CorrelationID string     `gorm:"size:64;not null" json:"correlation_id"`
	PublishedAt   *time.Time `json:"published_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// TableName 指定表名
func (SystemAlertDetail) TableName() string { return "system_alert_details" }

// SystemAlertSeverityOverride 類型分級覆寫；沒有列＝使用登錄的預設分級。
type SystemAlertSeverityOverride struct {
	AlertType string    `gorm:"primaryKey;size:64" json:"alert_type"`
	Severity  string    `gorm:"size:10;not null" json:"severity"`
	UpdatedBy uint      `gorm:"not null" json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (SystemAlertSeverityOverride) TableName() string { return "system_alert_severity_overrides" }
