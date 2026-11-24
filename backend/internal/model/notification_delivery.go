package model

import "time"

// 通知類別：決定待投遞紀錄指向哪裡、目的地取自快照或通道當下的設定。
//   - system_security_alert：指向告警列，目的地是產生當下的加密快照（帶快照）
//   - command_alert、system_event：指向通知內容列，送出時讀通道當下的設定（不帶快照）
//   - test：只出現在 webhook 新物件，不建立任何紀錄
const (
	NotificationCategorySystemSecurityAlert = "system_security_alert"
	NotificationCategoryCommandAlert        = "command_alert"
	NotificationCategorySystemEvent         = "system_event"
	NotificationCategoryTest                = "test"
)

// 待投遞紀錄的狀態。delivered、abandoned、canceled 為終態，不自動恢復。
const (
	NotificationDeliveryPending   = "pending"
	NotificationDeliveryRetrying  = "retrying"
	NotificationDeliveryDelivered = "delivered"
	NotificationDeliveryAbandoned = "abandoned"
	NotificationDeliveryCanceled  = "canceled"
)

// 待投遞紀錄的終態原因（放棄或取消），值域與資料表約束一致。
const (
	NotificationEndMaxAttempts        = "max_attempts"
	NotificationEndSnapshotUnreadable = "snapshot_unreadable"
	NotificationEndTypeUnregistered   = "type_unregistered"
	NotificationEndRenderFailed       = "render_failed"
	NotificationEndChannelDisabled    = "channel_disabled"
	NotificationEndChannelDeleted     = "channel_deleted"
	NotificationEndPrecheckCanceled   = "precheck_canceled"
	NotificationEndRateLimited        = "rate_limited"
	// 以下為個人訊息紀錄專用：送出前重驗的兩種取消、對個人派送已關閉，以及位址解析的三種放棄
	NotificationEndRequestResolved       = "request_resolved"
	NotificationEndRecipientIneligible   = "recipient_ineligible"
	NotificationEndDirectMessageDisabled = "direct_message_disabled"
	NotificationEndNoEmail               = "no_email"
	NotificationEndEmailAmbiguous        = "email_ambiguous"
	NotificationEndRecipientNotFound     = "recipient_not_found"
)

// 待投遞紀錄的收件對象，值域與資料表約束一致。channel＝送往通道設定的目的地；
// user＝送給 RecipientUserID 指的那位使用者（個人訊息，只用於系統事件）。
const (
	NotificationAudienceChannel = "channel"
	NotificationAudienceUser    = "user"
)

// NotificationDelivery 每個目的地一列的持久待投遞紀錄（所有通知類別共用；表名沿用 system_alert_outbox）。
//
// 帶快照（系統安全告警）：AlertID 非空、MessageID 為空，目的地欄位是產生當下的值，網址與秘密以
// 信封加密保存，之後通道改址、停用或刪除都不影響重送。
// 不帶快照（指令告警、系統事件）：MessageID 非空、AlertID 為空，目的地欄位一律為空字串、DestVersion 為 0，
// 送出時以 SourceChannelID 讀通道當下的設定。兩者由資料表約束區分。
type NotificationDelivery struct {
	ID              uint       `gorm:"primarykey" json:"id"`
	Category        string     `gorm:"size:32;not null;default:system_security_alert" json:"category"`
	AlertID         *uint      `json:"alert_id,omitempty"`
	MessageID       *uint      `json:"message_id,omitempty"`
	Severity        string     `gorm:"size:10;not null;default:low" json:"severity"`
	DestType        string     `gorm:"size:20;not null" json:"dest_type"`
	DestName        string     `gorm:"size:100;not null;default:''" json:"dest_name"`
	DestLanguage    string     `gorm:"size:8;not null" json:"dest_language"`
	DestTarget      string     `gorm:"size:64;not null;default:''" json:"dest_target"`
	SourceChannelID *uint      `json:"source_channel_id,omitempty"`
	URLEnc          string     `gorm:"column:url_enc;type:text;not null" json:"-"`
	SecretEnc       string     `gorm:"column:secret_enc;type:text;not null;default:''" json:"-"`
	State           string     `gorm:"size:16;not null;default:pending" json:"state"`
	Attempts        int        `gorm:"type:integer;not null;default:0" json:"attempts"`
	NextAttemptAt   time.Time  `gorm:"not null" json:"next_attempt_at"`
	LeaseUntil      *time.Time `json:"lease_until,omitempty"`
	LastError       string     `gorm:"type:text;not null;default:''" json:"last_error"`
	EndReason       string     `gorm:"size:32;not null;default:''" json:"end_reason"`
	ThrottledSince  *time.Time `json:"throttled_since,omitempty"`
	DestVersion     int        `gorm:"type:integer;not null;default:0" json:"dest_version"`
	// Audience 收件對象（channel／user）；user 時 RecipientUserID 必填且類別必為系統事件
	Audience string `gorm:"size:16;not null;default:channel" json:"audience"`
	// RecipientUserID 個人訊息的收件人（系統使用者識別碼；不設外鍵，使用者被刪除後保留原值）
	RecipientUserID *uint      `json:"recipient_user_id,omitempty"`
	DeliveredAt     *time.Time `json:"delivered_at,omitempty"`
	// LastFailedAt 最近一次登記失敗的時刻（送達時不清除；升級前的紀錄為空）
	LastFailedAt *time.Time `json:"last_failed_at,omitempty"`
	// EndedAt 轉為放棄或已取消的時刻（升級前已是終態的紀錄為空）
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	CreatedAt time.Time  `gorm:"not null" json:"created_at"`
	// DeliveryKey 送給收端的投遞識別（32 個十六進位字元，建立紀錄當下隨機產生）：同一列重送不變，
	// 還原備份後新建的列必為新值，不會與還原前發出的識別重複。
	DeliveryKey string `gorm:"size:32;not null;default:'';uniqueIndex:idx_system_alert_outbox_delivery_key" json:"-"`
}

// TableName 指定表名（沿用系統安全告警時期的表名，不搬動密文）
func (NotificationDelivery) TableName() string { return "system_alert_outbox" }

// 通知內容列的狀態。
const (
	NotificationMessagePending    = "pending"
	NotificationMessageDispatched = "dispatched"
	NotificationMessageFailed     = "failed"
)

// 通知內容列的分派失敗原因，值域與資料表約束一致。
const (
	NotificationMessageFailCategoryUnknown = "category_unknown"
	NotificationMessageFailDispatchError   = "dispatch_error"
)

// NotificationMessage 指令告警與系統事件的通知內容（一則通知一列）。
//
// 產生點只寫識別碼、參數與需要解析的名稱參照，狀態為待分派；投遞程序分派時把名稱寫回、
// 決定站內路徑、為每個通道建立一筆不帶快照的待投遞紀錄，最後標為已分派。
// 指令告警的內容另包含 AlertID 指向的告警列（寫入後不再改動）。
type NotificationMessage struct {
	ID               uint       `gorm:"primarykey" json:"id"`
	Category         string     `gorm:"size:32;not null" json:"category"`
	EventKey         string     `gorm:"size:64;not null" json:"event_key"`
	AlertID          *uint      `json:"alert_id,omitempty"`
	Severity         string     `gorm:"size:10;not null" json:"severity"`
	OccurredAt       time.Time  `gorm:"not null" json:"occurred_at"`
	ActorUserID      *uint      `json:"actor_user_id,omitempty"`
	ActorName        string     `gorm:"size:255;not null;default:''" json:"actor_name"`
	TargetKind       string     `gorm:"size:32;not null;default:''" json:"target_kind"`
	TargetID         string     `gorm:"size:128;not null;default:''" json:"target_id"`
	TargetName       string     `gorm:"size:255;not null;default:''" json:"target_name"`
	Params           string     `gorm:"type:text;not null;default:'{}'" json:"-"`
	NameRefs         string     `gorm:"type:text;not null;default:'{}'" json:"-"`
	LinkPath         string     `gorm:"size:512;not null;default:''" json:"link_path"`
	Degraded         bool       `gorm:"not null;default:false" json:"degraded"`
	State            string     `gorm:"size:16;not null;default:pending" json:"state"`
	DispatchAttempts int        `gorm:"type:integer;not null;default:0" json:"dispatch_attempts"`
	LeaseUntil       *time.Time `json:"lease_until,omitempty"`
	FailReason       string     `gorm:"size:32;not null;default:''" json:"fail_reason"`
	DispatchedAt     *time.Time `json:"dispatched_at,omitempty"`
	CreatedAt        time.Time  `gorm:"not null" json:"created_at"`
}

// TableName 指定表名
func (NotificationMessage) TableName() string { return "notification_messages" }
