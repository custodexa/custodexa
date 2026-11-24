package audit

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 投遞放棄的通知（事件 notification_delivery_abandoned）。
//
// 投遞程序把一筆紀錄轉為放棄時，在同一個放棄交易內：
//  1. 以通道列上的條件更新節流（同一通道 24 小時一則）：UPDATE notification_channels SET abandon_notified_at = now
//     WHERE id = ? AND (abandon_notified_at IS NULL OR abandon_notified_at <= now - 24h)。兩個執行個體同時放棄
//     同一通道時，後者的更新等前者提交後條件不成立而影響 0 列，所以不重複。
//  2. 影響 1 列才寫一列內容（系統事件，目標為該通道；分派時排除目標通道）。筆數是放棄交易內計算的該通道近 24 小時
//     放棄筆數（以紀錄的 ended_at 計）。
//  3. 1、2 以 savepoint 包住：內容寫不進去時回到 savepoint，節流欄連同回復，放棄照常記錄。
//
// 不觸發的情形：這個事件自己的紀錄被放棄；通道已刪除（條件更新影響 0 列）；收件對象不是通道的紀錄（個人訊息的
// 放棄改由未能送達事件呈現，見 notification_targeted.go）；
// 產生當下就放棄的系統安全告警紀錄（那一步在產生點的業務交易內，不經投遞程序）。

const (
	abandonNoticeSavepoint = "notification_abandon_notice"
	abandonNoticeThrottle  = 24 * time.Hour
)

// abandonNoticeInTx 見檔頭；寫入失敗只記 log，不讓放棄交易失敗。
func (w *SystemAlertOutboxWorker) abandonNoticeInTx(tx *gorm.DB, row model.NotificationDelivery, reason string, now time.Time) {
	if row.SourceChannelID == nil || deliveryAudienceOf(row) != deliveryAudienceChannel {
		return
	}
	if row.MessageID != nil {
		var keys []string
		if err := tx.Model(&model.NotificationMessage{}).Where("id = ?", *row.MessageID).Pluck("event_key", &keys).Error; err != nil {
			log.Printf("[NotificationOutbox] 讀取被放棄紀錄的事件鍵失敗 (outbox_id=%d): %v", row.ID, err)
			return
		}
		if len(keys) == 1 && keys[0] == string(notifycat.EventNotificationDeliveryAbandoned) {
			return
		}
	}
	channelID := *row.SourceChannelID
	if err := tx.SavePoint(abandonNoticeSavepoint).Error; err != nil {
		log.Printf("[NotificationOutbox] 建立投遞放棄通知的 savepoint 失敗 (outbox_id=%d): %v", row.ID, err)
		return
	}
	rollback := func(cause error) {
		if rerr := tx.RollbackTo(abandonNoticeSavepoint).Error; rerr != nil {
			log.Printf("[NotificationOutbox] 回到投遞放棄通知的 savepoint 失敗 (outbox_id=%d): %v", row.ID, rerr)
		}
		log.Printf("[NotificationOutbox] 投遞放棄通知未寫入 (channel_id=%d, outbox_id=%d): %v", channelID, row.ID, cause)
	}
	if w.hooks.beforeAbandonThrottle != nil {
		w.hooks.beforeAbandonThrottle()
	}
	res := tx.Model(&model.NotificationChannel{}).
		Where("id = ? AND (abandon_notified_at IS NULL OR abandon_notified_at <= ?)", channelID, now.Add(-abandonNoticeThrottle)).
		Update("abandon_notified_at", now)
	if res.Error != nil {
		rollback(res.Error)
		return
	}
	if res.RowsAffected != 1 {
		return
	}
	var count int64
	if err := tx.Model(&model.NotificationDelivery{}).
		Where("source_channel_id = ? AND state = ? AND ended_at >= ?", channelID, model.NotificationDeliveryAbandoned, now.Add(-abandonNoticeThrottle)).
		Count(&count).Error; err != nil {
		rollback(err)
		return
	}
	var lastErr []string
	_ = tx.Model(&model.NotificationDelivery{}).Where("id = ?", row.ID).Pluck("last_error", &lastErr).Error
	le := row.LastError
	if len(lastErr) == 1 {
		le = lastErr[0]
	}
	id := strconv.FormatUint(uint64(channelID), 10)
	notice := SystemEventNotice(notifycat.EventNotificationDeliveryAbandoned, map[string]string{
		"abandoned_24h": strconv.FormatInt(count, 10),
		"reason":        DeliveryReasonOf(reason, le),
	})
	notice.TargetKind = string(notifycat.IDKindNotificationChannel)
	notice.TargetID = id
	notice.OccurredAt = now
	notice.NameRefs = map[string]NotificationNameRef{"channel_name": {Kind: notifycat.IDKindNotificationChannel, ID: channelID}}
	msg, err := buildNotificationMessage(notice, now)
	if err == nil && w.hooks.beforeAbandonNotice != nil {
		err = w.hooks.beforeAbandonNotice()
	}
	if err == nil {
		err = tx.Create(&msg).Error
	}
	if err != nil {
		rollback(err)
	}
}

// deliveryAudienceOf 紀錄的收件對象（依 audience 欄）。投遞放棄的通知與通道健康只統計通道收件對象的紀錄。
func deliveryAudienceOf(row model.NotificationDelivery) string {
	return audienceOfRow(row)
}

// DeliveryReasonOf 把終態原因與（已遮蔽的）最近一次錯誤歸成語句代碼（notifycat 詞庫 delivery_reason 的鍵）。
// 畫面與通知文字只用代碼呈現，不直接顯示對方回傳的字串。
func DeliveryReasonOf(endReason, lastError string) string {
	switch endReason {
	case model.NotificationEndRateLimited:
		return "rate_limited"
	case model.NotificationEndTypeUnregistered:
		return "type_unregistered"
	case model.NotificationEndRenderFailed:
		return "render_failed"
	case model.NotificationEndSnapshotUnreadable:
		return "snapshot_unreadable"
	}
	return deliveryErrorReason(lastError)
}

// deliveryErrorReason 依最近一次錯誤的文字歸類（文字由投遞程序產生，形狀固定）。
func deliveryErrorReason(e string) string {
	lower := strings.ToLower(e)
	if i := strings.Index(lower, "platform error: "); i >= 0 {
		switch code := strings.TrimSpace(lower[i+len("platform error: "):]); code {
		case "channel_not_found":
			return "slack_channel"
		case "not_in_channel", "no_permission":
			return "slack_not_in"
		case "invalid_auth", "token_revoked", "token_expired", "account_inactive", "not_authed":
			return "slack_auth"
		case "missing_scope":
			return "slack_scope"
		case "ratelimited", "rate_limited":
			return "slack_rate"
		default:
			return "slack_other"
		}
	}
	switch {
	case e == "":
		return "http_other"
	case e == channelUnreadableText:
		return "channel_unreadable"
	case e == notifyRedirectNotFollowedText:
		return "redirect_not_followed"
	case e == errRedirectPolicy.Error():
		return "redirect_policy"
	case e == errRedirectTooMany.Error():
		return "redirect_too_many"
	case strings.HasPrefix(e, "HTTP 404"):
		return "http_404"
	case strings.HasPrefix(e, "HTTP 401"):
		return "http_401"
	case strings.HasPrefix(e, "HTTP 429"):
		return "rate_limited"
	case strings.HasPrefix(e, "HTTP 5"):
		return "http_5xx"
	case strings.HasPrefix(e, "HTTP "):
		return "http_other"
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded"):
		return "timeout"
	default:
		return "connect"
	}
}
