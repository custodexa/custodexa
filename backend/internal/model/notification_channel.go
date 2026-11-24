package model

import (
	"sync"
	"time"
)

// 通知通道類型（alert-notifications）。型別的設定欄位、能力與請求格式由 audit 模組的型別登錄描述；
// 本處只放常數與「登錄了哪些鍵」的查詢，API 與 DB CHECK 雙層驗證。
//   - webhook：送通用 JSON payload，secret 非空時附 HMAC 簽名（自建端點用）
//   - slack：送 Slack mrkdwn text，不簽名（Slack 不驗自訂標頭，靠 webhook URL 保密）
//   - slack_app：以機器人 token 呼叫 Slack 送訊息 API，送往指定頻道
const (
	NotificationChannelTypeWebhook  = "webhook"
	NotificationChannelTypeSlack    = "slack"
	NotificationChannelTypeSlackApp = "slack_app"
)

var (
	notificationChannelTypesMu sync.RWMutex
	notificationChannelTypes   = map[string]bool{}
)

// RegisterNotificationChannelType 由型別登錄在初始化時呼叫，宣告一個可用的通道型別鍵。
func RegisterNotificationChannelType(t string) {
	notificationChannelTypesMu.Lock()
	defer notificationChannelTypesMu.Unlock()
	notificationChannelTypes[t] = true
}

// ValidNotificationChannelType 檢查通道類型是否為型別登錄中的鍵；
// API 與 DB CHECK 雙層驗證，API 層先擋掉可給出友善錯誤訊息
func ValidNotificationChannelType(t string) bool {
	notificationChannelTypesMu.RLock()
	defer notificationChannelTypesMu.RUnlock()
	return notificationChannelTypes[t]
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

// 通道推送門檻：最低推送等級，值域沿用告警等級三值（AlertSeverity*），
// 故前端可直讀同一組常數做雙向比對。low＝全部告警（預設）、medium＝中、高等級、
// high＝只有高等級。刻意沒有「全部不推送」：改密告警寫死 high 且推送是唯一出口，
// 要完全不收請停用通道。DB CHECK 約束同 type／language 欄雙層驗證慣例
const NotificationChannelMinSeverityDefault = AlertSeverityLow

// ValidNotificationChannelMinSeverity 檢查推送門檻是否為合法值（嚴格匹配三值）
func ValidNotificationChannelMinSeverity(s string) bool {
	return ValidAlertSeverity(s)
}

// NotificationChannel 告警通知通道（alert-notifications）
// secret 用於 HMAC-SHA256 簽名（X-OT-Signature），非空時推送會附簽名 header；
// 整組端點 admin only；secret 不隨 JSON 回傳（json:"-"）。
// Update 時空 secret＝沿用既有值，清除簽名需顯式 clear_secret（見 notification_channel_service.Update）
// 注意：本表由 baseline 以原生 SQL 建立（min_severity 由增量 migration 加欄），不走 AutoMigrate，
// 欄位定義需與 migration 保持一致
type NotificationChannel struct {
	ID      uint   `gorm:"primarykey" json:"id"`
	Name    string `gorm:"size:100;not null" json:"name"`
	Type    string `gorm:"size:20;not null;default:webhook" json:"type"` // 型別登錄的鍵（CHECK 約束）
	URL     string `gorm:"type:text;not null" json:"url"`                // 僅允許 http/https
	Secret  string `gorm:"type:text" json:"-"`                           // webhook 的 HMAC 簽名密鑰（空字串=不簽名）或 slack_app 的機器人 token
	Enabled bool   `gorm:"not null;default:true" json:"enabled"`

	// Language per-channel 語系：Create 未給預設 zh-TW，
	// 嚴格匹配三值（CHECK 約束同 type 欄慣例）
	Language string `gorm:"size:8;not null;default:zh-TW" json:"language"`

	// MinSeverity 推送門檻（最低推送等級）：Create 未給預設 low（全部告警），
	// 只作用於告警佇列的推送；系統事件與測試發送不受影響（見 alert_notifier.notify）
	MinSeverity string `gorm:"size:10;not null;default:low" json:"min_severity"`

	// Target 目標（slack_app 的頻道識別碼；非秘密、明文）。其他型別為空字串
	Target string `gorm:"size:64;not null;default:''" json:"target"`

	// DestinationChangedAt 目的地最後變更時間：網址、秘密、目標、型別任一變更時於同一交易設為當下；
	// 升級後沒變過為空。通道健康欄位只統計之後建立的待投遞紀錄
	DestinationChangedAt *time.Time `json:"destination_changed_at"`

	// DestinationVersion 目的地版本：與 DestinationChangedAt 同時遞增；帶快照的待投遞紀錄記下產生當下的值，
	// 投遞程序以（通道, 版本）分組，舊網址的紀錄不拖累改址後的設定
	DestinationVersion int `gorm:"type:integer;not null;default:0" json:"destination_version"`

	// AbandonNotifiedAt 最近一次產生「通知投遞已放棄」的時刻（24 小時節流，以條件更新判斷）
	AbandonNotifiedAt *time.Time `json:"-"`

	// DirectMessageEnabled 對個人派送：需要處理的通知另以個人訊息送給該處理的人（頻道照送）。
	// 至多一個通道為真（部分唯一索引），且只有能以個人為對象的型別可為真（CHECK）
	DirectMessageEnabled bool `gorm:"not null;default:false" json:"direct_message_enabled"`

	// DMIssueNotifiedAt 最近一次產生「個人訊息未能送達」系統事件的時刻（24 小時節流，以條件更新判斷）
	DMIssueNotifiedAt *time.Time `gorm:"column:dm_issue_notified_at" json:"-"`

	// HasSecret 供前端顯示「是否已設定簽名密鑰」狀態（secret 本身不回傳）；
	// 非 DB 欄位，由 service 讀取時依 Secret 是否為空填入
	HasSecret bool `gorm:"-" json:"has_secret"`

	// TransmissionDeviation 傳輸偏離標示（存量 http 通道不回溯停用，
	// 列表誠實標偏離）；非 DB 欄位，service 讀取時填入
	TransmissionDeviation bool `gorm:"-" json:"transmission_deviation"`

	// DirectMessageURLAllowed 目前網址的主機是否在對個人派送的允許清單內（官方主機加部署者另外允許的主機）；
	// 畫面據此事先停用開關。非 DB 欄位，service 讀取時依明文網址填入；網址解不開時為假
	DirectMessageURLAllowed bool `gorm:"-" json:"direct_message_url_allowed"`

	// Health 送達狀況（列表回應填入；非 DB 欄位）：只統計目的地最後變更時間之後建立的待投遞紀錄
	Health *NotificationChannelHealth `gorm:"-" json:"health,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NotificationChannelHealth 通道的送達狀況（由待投遞紀錄彙總，不另存）。畫面的狀態標籤由這幾個值與啟用狀態推得。
type NotificationChannelHealth struct {
	// LastDeliveredAt 最近一次送達時間
	LastDeliveredAt *time.Time `json:"last_delivered_at"`
	// LastFailedAt、LastFailureReason、LastFailureCode 最近一次失敗的時間、原因（已遮蔽）與語句代碼
	LastFailedAt      *time.Time `json:"last_failed_at"`
	LastFailureReason string     `json:"last_failure_reason"`
	LastFailureCode   string     `json:"last_failure_code"`
	// Abandoned7d 近 7 天放棄筆數
	Abandoned7d int64 `json:"abandoned_7d"`
}

// TableName 指定表名
func (NotificationChannel) TableName() string {
	return "notification_channels"
}
