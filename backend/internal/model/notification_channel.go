package model

import "time"

// 通知通道類型（alert-notifications）：
//   - webhook：送通用 JSON payload，secret 非空時附 HMAC 簽名（自建端點用）
//   - slack：送 Slack mrkdwn text，不簽名（Slack 不驗自訂標頭，靠 webhook URL 保密）
//
// 字串 enum + DB CHECK 約束預留 email/SMS/Teams 等擴充空間
const (
	NotificationChannelTypeWebhook = "webhook"
	NotificationChannelTypeSlack   = "slack"
)

// ValidNotificationChannelType 檢查通道類型是否為合法值；
// API 與 DB CHECK 雙層驗證，API 層先擋掉可給出友善錯誤訊息
func ValidNotificationChannelType(t string) bool {
	return t == NotificationChannelTypeWebhook || t == NotificationChannelTypeSlack
}

// 通道語系：per-channel 語系決定 Slack 渲染
// 與（未來）webhook payload 查譯用的語言；webhook 型可設但目前無作用（UI 註明）。
// 嚴格三值，字串 enum + DB CHECK 約束，同 type 欄雙層驗證慣例
const (
	NotificationChannelLanguageZhTW = "zh-TW"
	NotificationChannelLanguageEnUS = "en-US"
	NotificationChannelLanguageJaJP = "ja-JP"

	// NotificationChannelLanguageDefault Create 未給 language 時的預設值
	NotificationChannelLanguageDefault = NotificationChannelLanguageZhTW
)

// ValidNotificationChannelLanguage 檢查通道語系是否為合法值（嚴格匹配三值）
func ValidNotificationChannelLanguage(s string) bool {
	switch s {
	case NotificationChannelLanguageZhTW, NotificationChannelLanguageEnUS, NotificationChannelLanguageJaJP:
		return true
	default:
		return false
	}
}

// NotificationChannel 告警通知通道（alert-notifications）
// secret 用於 HMAC-SHA256 簽名（X-OT-Signature），非空時推送會附簽名 header；
// 整組端點 admin only；secret 不隨 JSON 回傳（json:"-"）。
// Update 時空 secret＝沿用既有值，清除簽名需顯式 clear_secret（見 notification_channel_service.Update）
// 注意：本表由 migration v7.10 以原生 SQL 建立，不走 AutoMigrate，
// 欄位定義需與 migration 保持一致
type NotificationChannel struct {
	ID      uint   `gorm:"primarykey" json:"id"`
	Name    string `gorm:"size:100;not null" json:"name"`
	Type    string `gorm:"size:20;not null;default:webhook" json:"type"` // webhook/slack（CHECK 約束）
	URL     string `gorm:"type:text;not null" json:"url"`                // 僅允許 http/https
	Secret  string `gorm:"type:text" json:"-"`                           // HMAC 簽名密鑰，空字串=不簽名
	Enabled bool   `gorm:"not null;default:true" json:"enabled"`

	// Language per-channel 語系：Create 未給預設 zh-TW，
	// 嚴格匹配三值（CHECK 約束同 type 欄慣例）
	Language string `gorm:"size:8;not null;default:zh-TW" json:"language"`

	// HasSecret 供前端顯示「是否已設定簽名密鑰」狀態（secret 本身不回傳）；
	// 非 DB 欄位，由 service 讀取時依 Secret 是否為空填入
	HasSecret bool `gorm:"-" json:"has_secret"`

	// TransmissionDeviation 傳輸偏離標示（存量 http 通道不回溯停用，
	// 列表誠實標偏離）；非 DB 欄位，service 讀取時填入
	TransmissionDeviation bool `gorm:"-" json:"transmission_deviation"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (NotificationChannel) TableName() string {
	return "notification_channels"
}
