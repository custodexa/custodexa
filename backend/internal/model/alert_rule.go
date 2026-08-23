package model

import "time"

// Alert severity 等級（command-alerts）：
// 字串 enum + DB CHECK 約束，避免 magic string 散落
const (
	AlertSeverityHigh   = "high"
	AlertSeverityMedium = "medium"
	AlertSeverityLow    = "low"
)

// ValidAlertSeverity 檢查 severity 是否為合法值；
// API 與 DB CHECK 雙層驗證，API 層先擋掉可給出友善錯誤訊息
func ValidAlertSeverity(s string) bool {
	return s == AlertSeverityHigh || s == AlertSeverityMedium || s == AlertSeverityLow
}

// AlertRule 危險指令告警規則（command-alerts）
// 注意：本表由 migration v7.9 以原生 SQL 建立，不走 AutoMigrate，
// 欄位定義需與 migration 保持一致
type AlertRule struct {
	ID       uint   `gorm:"primarykey" json:"id"`
	Name     string `gorm:"size:100;not null" json:"name"`
	Pattern  string `gorm:"type:text;not null" json:"pattern"`            // regex，入庫前以 regexp.Compile 驗證
	Severity string `gorm:"size:10;not null" json:"severity"`             // high/medium/low（CHECK 約束）
	Action   string `gorm:"size:10;not null;default:alert" json:"action"` // alert=告警 block=阻斷（command-blocking）
	// Protocols 逗號分隔的適用協議（如 "ssh,k8s" 或 "mysql,postgres,redis"）；
	// 空＝全協議。shell 指令規則與 SQL 危險規則的語法不通用，故依會話協議分流，
	// 避免 shell 正則誤掃 SQL 字面值（如 SELECT 內含 'rm -rf'）造成誤報。
	Protocols string `gorm:"size:64;not null;default:''" json:"protocols"`
	Enabled   bool   `gorm:"not null;default:true" json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (AlertRule) TableName() string {
	return "alert_rules"
}
