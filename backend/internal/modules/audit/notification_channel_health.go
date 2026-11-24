package audit

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 通道健康欄位與投遞紀錄（沒送到看得到）。
//
// 一律由待投遞紀錄彙總，不另存計數。通道列表的三個值只統計 created_at 不早於「目的地最後變更時間」的紀錄
// （為空時全部）：改網址或輪替 token 之後，舊設定留下的失敗不再算在新設定頭上。投遞紀錄照樣列出較早的紀錄，
// 其中帶快照者（系統安全告警，依排入當時的設定投遞）以旗標標示。健康欄位只統計收件對象為通道的紀錄：一位收件人
// 沒填電子郵件不代表這個通道送不出去；個人訊息的狀況看投遞紀錄（可依收件對象篩選）與未能送達事件。

// channelHealthWindow 通道列表「近 7 天放棄筆數」的時窗。
const channelHealthWindow = 7 * 24 * time.Hour

// fillChannelHealth 為通道列（顯示用）補上健康欄位；查詢失敗時該列不帶健康欄位，不擋列表。
func (s *NotificationChannelService) fillChannelHealth(ch *model.NotificationChannel, now time.Time) error {
	scope := func() *gorm.DB {
		q := s.db.Model(&model.NotificationDelivery{}).Where("source_channel_id = ? AND audience = ?", ch.ID, deliveryAudienceChannel)
		if ch.DestinationChangedAt != nil {
			q = q.Where("created_at >= ?", *ch.DestinationChangedAt)
		}
		return q
	}
	h := &model.NotificationChannelHealth{}
	var delivered []model.NotificationDelivery
	if err := scope().Select("delivered_at").Where("state = ? AND delivered_at IS NOT NULL", model.NotificationDeliveryDelivered).
		Order("delivered_at DESC").Limit(1).Find(&delivered).Error; err != nil {
		return fmt.Errorf("查詢最近送達失敗: %w", err)
	}
	if len(delivered) == 1 {
		h.LastDeliveredAt = delivered[0].DeliveredAt
	}
	var failed []model.NotificationDelivery
	// 只取帶錯誤文字的列：升級前送達時錯誤文字已被清空的列沒有原因可顯示
	if err := scope().Select("last_failed_at, last_error, end_reason").Where("last_failed_at IS NOT NULL AND last_error <> ''").
		Order("last_failed_at DESC, id DESC").Limit(1).Find(&failed).Error; err != nil {
		return fmt.Errorf("查詢最近失敗失敗: %w", err)
	}
	if len(failed) == 1 {
		h.LastFailedAt = failed[0].LastFailedAt
		h.LastFailureReason = DisplayDeliveryError(failed[0].LastError)
		h.LastFailureCode = DeliveryReasonOf("", failed[0].LastError)
	}
	if err := scope().Where("state = ? AND ended_at >= ?", model.NotificationDeliveryAbandoned, now.Add(-channelHealthWindow)).
		Count(&h.Abandoned7d).Error; err != nil {
		return fmt.Errorf("查詢近 7 天放棄筆數失敗: %w", err)
	}
	ch.Health = h
	return nil
}

// deliveryHTTPStatusPattern、deliveryPlatformErrorPattern 從投遞錯誤文字取出可顯示的部分。
var (
	deliveryHTTPStatusPattern    = regexp.MustCompile(`HTTP ([1-5][0-9]{2})`)
	deliveryPlatformErrorPattern = regexp.MustCompile(`platform error: ([a-z0-9_]{1,64})`)
)

// DisplayDeliveryError 投遞錯誤文字的對外版本：只留 HTTP 狀態碼與平台錯誤碼（例如 `HTTP 404`、
// `HTTP 200, platform error: not_in_channel`），其餘一律不回（連線錯誤的主機與位址、對方回應的任何文字）。
// 原因的種類以原因代碼（DeliveryReasonOf）表達；這個版本只補上代碼裡沒有的狀態碼與平台錯誤碼。
func DisplayDeliveryError(raw string) string {
	var parts []string
	if m := deliveryHTTPStatusPattern.FindStringSubmatch(raw); m != nil {
		parts = append(parts, "HTTP "+m[1])
	}
	if m := deliveryPlatformErrorPattern.FindStringSubmatch(raw); m != nil {
		parts = append(parts, "platform error: "+m[1])
	}
	return strings.Join(parts, ", ")
}

// ChannelDelivery 投遞紀錄的一列（API 回應）。不含網址、秘密與通知參數的值；LastError 是 DisplayDeliveryError 的版本。
type ChannelDelivery struct {
	ID            uint       `json:"id"`
	Category      string     `json:"category"`
	EventKey      string     `json:"event_key"`
	Severity      string     `json:"severity"`
	State         string     `json:"state"`
	Attempts      int        `json:"attempts"`
	NextAttemptAt *time.Time `json:"next_attempt_at"`
	DeliveredAt   *time.Time `json:"delivered_at"`
	LastFailedAt  *time.Time `json:"last_failed_at"`
	LastError     string     `json:"last_error"`
	ReasonCode    string     `json:"reason_code"`
	EndReason     string     `json:"end_reason"`
	EndedAt       *time.Time `json:"ended_at"`
	// ThrottledSince 這一筆因平台限流而延後的起點（未被限流或限流已解除時為空）。
	ThrottledSince *time.Time `json:"throttled_since"`
	CreatedAt      time.Time  `json:"created_at"`
	// SnapshotBeforeChange 帶快照（依排入當時的設定投遞）且建立早於目的地最後變更時間。
	SnapshotBeforeChange bool `json:"snapshot_before_change"`
	// Audience 收件對象：channel（頻道）或 user（個人訊息）。
	Audience string `json:"audience"`
	// RecipientUsername 個人訊息收件人的登入帳號名稱（讀取時查，涵蓋已刪除的帳號；查不到為空）。不含電子郵件。
	RecipientUsername string `json:"recipient_username,omitempty"`
	// RecipientSlackID 個人訊息對應到的平台使用者識別碼（解析後才有）。
	RecipientSlackID string `json:"recipient_slack_id,omitempty"`
}

// 投遞紀錄分頁的預設與上限。
const (
	channelDeliveriesDefaultPageSize = 20
	channelDeliveriesMaxPageSize     = 100
)

// ErrInvalidDeliveryState 投遞紀錄的狀態篩選不在值域內。
var ErrInvalidDeliveryState = errors.New("投遞紀錄的狀態篩選不在值域內")

// targetedEndReasons 個人訊息特有的結束原因：畫面依 end_reason 呈現，不另給 reason_code（避免歸成無關的連線類原因）。
var targetedEndReasons = map[string]bool{
	model.NotificationEndRequestResolved: true, model.NotificationEndRecipientIneligible: true,
	model.NotificationEndDirectMessageDisabled: true, model.NotificationEndNoEmail: true,
	model.NotificationEndEmailAmbiguous: true, model.NotificationEndRecipientNotFound: true,
}

// ErrInvalidDeliveryAudience 投遞紀錄的收件對象篩選不是 channel 或 user。
var ErrInvalidDeliveryAudience = errors.New("投遞紀錄的收件對象篩選不在值域內")

// ChannelDeliveryQuery 投遞紀錄的查詢條件。States 為空＝全部狀態；非空時每個值都要在狀態值域內。
type ChannelDeliveryQuery struct {
	Page     int
	PageSize int
	States   []string
	// Audience 收件對象篩選：空字串＝全部；channel 或 user。
	Audience string
}

// ChannelPendingCounts 該通道目前等待中與重送中的筆數（不受狀態篩選影響），依類別分兩類：
// 帶快照的系統安全告警依排入當時的設定送出，改網址後仍送往原位址；其他通知送出時讀通道當下的設定。
type ChannelPendingCounts struct {
	General             int64 `json:"general"`
	SystemSecurityAlert int64 `json:"system_security_alert"`
}

// ChannelDeliveryPage 投遞紀錄的一頁。
type ChannelDeliveryPage struct {
	Rows          []ChannelDelivery
	Total         int64
	PendingCounts ChannelPendingCounts
}

// validDeliveryState 狀態篩選的值域（與資料表約束一致）。
func validDeliveryState(v string) bool {
	switch v {
	case model.NotificationDeliveryPending, model.NotificationDeliveryRetrying, model.NotificationDeliveryDelivered,
		model.NotificationDeliveryAbandoned, model.NotificationDeliveryCanceled:
		return true
	}
	return false
}

// ListDeliveries 列出某個通道的投遞紀錄（依建立時間倒序、分頁，可依狀態篩選）。
// 通道不存在回 ErrChannelNotFound；狀態篩選不在值域內回 ErrInvalidDeliveryState。
func (s *NotificationChannelService) ListDeliveries(channelID uint, q ChannelDeliveryQuery) (*ChannelDeliveryPage, error) {
	for _, st := range q.States {
		if !validDeliveryState(st) {
			return nil, ErrInvalidDeliveryState
		}
	}
	if q.Audience != "" && q.Audience != deliveryAudienceChannel && q.Audience != deliveryAudienceUser {
		return nil, ErrInvalidDeliveryAudience
	}
	page, pageSize := q.Page, q.PageSize
	var chs []model.NotificationChannel
	if err := s.db.Select("id, destination_changed_at").Where("id = ?", channelID).Limit(1).Find(&chs).Error; err != nil {
		return nil, fmt.Errorf("查詢通知通道失敗: %w", err)
	}
	if len(chs) == 0 {
		return nil, ErrChannelNotFound
	}
	changedAt := chs[0].DestinationChangedAt
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = channelDeliveriesDefaultPageSize
	}
	if pageSize > channelDeliveriesMaxPageSize {
		pageSize = channelDeliveriesMaxPageSize
	}
	scope := func() *gorm.DB {
		db := s.db.Model(&model.NotificationDelivery{}).Where("source_channel_id = ?", channelID)
		if len(q.States) > 0 {
			db = db.Where("state IN ?", q.States)
		}
		if q.Audience != "" {
			db = db.Where("audience = ?", q.Audience)
		}
		return db
	}
	result := &ChannelDeliveryPage{}
	if err := scope().Count(&result.Total).Error; err != nil {
		return nil, fmt.Errorf("計算投遞紀錄失敗: %w", err)
	}
	counts, err := s.channelPendingCounts(channelID)
	if err != nil {
		return nil, err
	}
	result.PendingCounts = counts
	var rows []model.NotificationDelivery
	if err := scope().Order("created_at DESC, id DESC").
		Offset((page - 1) * pageSize).Limit(pageSize).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢投遞紀錄失敗: %w", err)
	}
	eventKeys, err := s.deliveryEventKeys(rows)
	if err != nil {
		return nil, err
	}
	var recipientIDs []uint
	for _, r := range rows {
		if r.RecipientUserID != nil {
			recipientIDs = append(recipientIDs, *r.RecipientUserID)
		}
	}
	recipientNames := lookupUserNamesDB(s.db, recipientIDs)
	out := make([]ChannelDelivery, 0, len(rows))
	for _, r := range rows {
		d := ChannelDelivery{
			ID: r.ID, Category: r.Category, Severity: r.Severity, State: r.State, Attempts: r.Attempts,
			DeliveredAt: r.DeliveredAt, LastFailedAt: r.LastFailedAt, LastError: DisplayDeliveryError(r.LastError),
			EndReason: r.EndReason, EndedAt: r.EndedAt, ThrottledSince: r.ThrottledSince, CreatedAt: r.CreatedAt,
		}
		if r.State == model.NotificationDeliveryPending || r.State == model.NotificationDeliveryRetrying {
			next := r.NextAttemptAt
			d.NextAttemptAt = &next
		}
		if (r.State == model.NotificationDeliveryAbandoned || r.LastError != "") && !targetedEndReasons[r.EndReason] {
			d.ReasonCode = DeliveryReasonOf(r.EndReason, r.LastError)
		}
		d.EventKey = eventKeys.of(r)
		d.SnapshotBeforeChange = r.Category == model.NotificationCategorySystemSecurityAlert &&
			changedAt != nil && r.CreatedAt.Before(*changedAt)
		d.Audience = audienceOfRow(r)
		if d.Audience == deliveryAudienceUser {
			if r.RecipientUserID != nil {
				d.RecipientUsername = recipientNames[*r.RecipientUserID]
			}
			d.RecipientSlackID = r.DestTarget
		}
		out = append(out, d)
	}
	result.Rows = out
	return result, nil
}

// channelPendingCounts 該通道等待中與重送中的筆數，分系統安全告警與其他。
func (s *NotificationChannelService) channelPendingCounts(channelID uint) (ChannelPendingCounts, error) {
	var groups []struct {
		Category string
		N        int64
	}
	if err := s.db.Model(&model.NotificationDelivery{}).Select("category, COUNT(*) AS n").
		Where("source_channel_id = ? AND state IN ?", channelID,
			[]string{model.NotificationDeliveryPending, model.NotificationDeliveryRetrying}).
		Group("category").Scan(&groups).Error; err != nil {
		return ChannelPendingCounts{}, fmt.Errorf("計算未送達筆數失敗: %w", err)
	}
	var out ChannelPendingCounts
	for _, g := range groups {
		if g.Category == model.NotificationCategorySystemSecurityAlert {
			out.SystemSecurityAlert += g.N
		} else {
			out.General += g.N
		}
	}
	return out, nil
}

type deliveryEventKeyIndex struct {
	byAlert   map[uint]string
	byMessage map[uint]string
}

func (x deliveryEventKeyIndex) of(r model.NotificationDelivery) string {
	switch {
	case r.AlertID != nil:
		return x.byAlert[*r.AlertID]
	case r.MessageID != nil:
		return x.byMessage[*r.MessageID]
	}
	return ""
}

// deliveryEventKeys 事件鍵：系統安全告警取告警明細的類型鍵，其他類別取內容列的事件鍵。
func (s *NotificationChannelService) deliveryEventKeys(rows []model.NotificationDelivery) (deliveryEventKeyIndex, error) {
	idx := deliveryEventKeyIndex{byAlert: map[uint]string{}, byMessage: map[uint]string{}}
	var alertIDs, msgIDs []uint
	for _, r := range rows {
		if r.AlertID != nil {
			alertIDs = append(alertIDs, *r.AlertID)
		}
		if r.MessageID != nil {
			msgIDs = append(msgIDs, *r.MessageID)
		}
	}
	if len(alertIDs) > 0 {
		var details []model.SystemAlertDetail
		if err := s.db.Select("alert_id, alert_type").Where("alert_id IN ?", alertIDs).Find(&details).Error; err != nil {
			return idx, fmt.Errorf("查詢告警類型失敗: %w", err)
		}
		for _, d := range details {
			idx.byAlert[d.AlertID] = d.AlertType
		}
	}
	if len(msgIDs) > 0 {
		var msgs []model.NotificationMessage
		if err := s.db.Select("id, event_key").Where("id IN ?", msgIDs).Find(&msgs).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return idx, fmt.Errorf("查詢通知事件失敗: %w", err)
		}
		for _, m := range msgs {
			idx.byMessage[m.ID] = m.EventKey
		}
	}
	return idx, nil
}
