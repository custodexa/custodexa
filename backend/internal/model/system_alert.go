package model

import "time"

// AlertKindSystemSecurity 系統安全告警的來源類別。
//
// 與其他非規則類別同理由：系統告警不掛在可 CRUD 的規則列上，管理員無從刪除或停用；
// rule_id 必為空，session_id 為空。結構化參數放在 system_alert_details，不塞進 command 欄。
const AlertKindSystemSecurity = "system_security"

// 投遞佇列列的狀態。
const (
	SystemAlertOutboxPending   = "pending"
	SystemAlertOutboxRetrying  = "retrying"
	SystemAlertOutboxDelivered = "delivered"
	SystemAlertOutboxAbandoned = "abandoned"
)

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

// SystemAlertOutbox 每個目的地一列的持久投遞佇列。
// 目的地網址與簽章密鑰是產生當下的快照，以信封加密保存；之後通道改址或刪除都不影響重送。
type SystemAlertOutbox struct {
	ID              uint       `gorm:"primarykey" json:"id"`
	AlertID         uint       `gorm:"not null" json:"alert_id"`
	DestType        string     `gorm:"size:20;not null" json:"dest_type"`
	DestName        string     `gorm:"size:100;not null" json:"dest_name"`
	DestLanguage    string     `gorm:"size:8;not null" json:"dest_language"`
	SourceChannelID *uint      `json:"source_channel_id,omitempty"`
	URLEnc          string     `gorm:"column:url_enc;type:text;not null" json:"-"`
	SecretEnc       string     `gorm:"column:secret_enc;type:text;not null" json:"-"`
	State           string     `gorm:"size:16;not null" json:"state"`
	Attempts        int        `gorm:"not null" json:"attempts"`
	NextAttemptAt   time.Time  `gorm:"not null" json:"next_attempt_at"`
	LeaseUntil      *time.Time `json:"lease_until,omitempty"`
	LastError       string     `gorm:"type:text;not null" json:"last_error"`
	DeliveredAt     *time.Time `json:"delivered_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	// DeliveryKey 送給收端的投遞識別（32 個十六進位字元，排入當下隨機產生）：同一列重送不變，
	// 還原備份後新建的列必為新值，不會與還原前發出的識別重複。
	DeliveryKey string `gorm:"size:32;not null;default:'';uniqueIndex:idx_system_alert_outbox_delivery_key" json:"-"`
}

// TableName 指定表名
func (SystemAlertOutbox) TableName() string { return "system_alert_outbox" }

// SystemAlertSeverityOverride 類型分級覆寫；沒有列＝使用登錄的預設分級。
type SystemAlertSeverityOverride struct {
	AlertType string    `gorm:"primaryKey;size:64" json:"alert_type"`
	Severity  string    `gorm:"size:10;not null" json:"severity"`
	UpdatedBy uint      `gorm:"not null" json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (SystemAlertSeverityOverride) TableName() string { return "system_alert_severity_overrides" }
