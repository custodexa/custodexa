package audit

import (
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// 通道的「對個人派送」設定（design 決策 5）。
//
//   - 只有型別描述宣告能以個人為對象、且網址主機屬允許清單的通道可以開啟；同一時間至多一個通道開啟（服務層在
//     交易內判斷並回傳那個通道的名稱，資料庫另以部分唯一索引兜底）。
//   - 型別改為不能以個人為對象、或網址改到清單外時，同一個更新交易把設定關閉，通道變更告警註明自動關閉。
//   - 由開改為關時，在途的個人訊息在通道更新交易提交之後另以只碰待投遞紀錄的短交易取消（依編號分批）；
//     已被認領、正在處理的那一筆不碰，交給送出前的通道條件收尾。通道更新交易不更新任何既有的待投遞紀錄
//     （全系統的鎖序：先待投遞紀錄、後通道列）。

// checkDirectMessageAllowed 要開啟對個人派送時的型別與網址檢查。
func checkDirectMessageAllowed(desc ChannelTypeDescriptor, effectiveURL string) error {
	if !desc.Caps.CanTargetUser || desc.lookupUser == nil {
		return ErrDirectMessageUnsupportedType
	}
	if !directMessageHostAllowed(effectiveURL) {
		return ErrDirectMessageURLNotAllowed
	}
	return nil
}

// planDirectMessage 依現值、請求與存檔後生效的型別與網址算出更新後的設定。requested 為 nil＝沿用現值；
// urlKnown 為假（網址解不開且請求沒有帶新網址）時不以網址判斷自動關閉。回傳更新後的值與自動關閉的原因。
func planDirectMessage(current bool, requested *bool, desc ChannelTypeDescriptor, effectiveURL string, urlKnown bool) (bool, string, error) {
	if requested != nil {
		if !*requested {
			return false, "", nil
		}
		if err := checkDirectMessageAllowed(desc, effectiveURL); err != nil {
			return false, "", err
		}
		return true, "", nil
	}
	if !current {
		return false, "", nil
	}
	if !desc.Caps.CanTargetUser || desc.lookupUser == nil {
		return false, notifycat.DMAutoOffType, nil
	}
	if urlKnown && !directMessageHostAllowed(effectiveURL) {
		return false, notifycat.DMAutoOffHost, nil
	}
	return true, "", nil
}

// lockChannelsForDirectMessage 依編號鎖住全部通道列（PostgreSQL；SQLite 的寫入本來就序列化）。
func lockChannelsForDirectMessage(tx *gorm.DB) error {
	if tx.Dialector.Name() != "postgres" {
		return nil
	}
	var ids []uint
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Model(&model.NotificationChannel{}).
		Order("id").Pluck("id", &ids).Error; err != nil {
		return fmt.Errorf("鎖定通知通道失敗: %w", err)
	}
	return nil
}

// directMessageConflict 是否已有另一個通道（編號不是 self）開啟對個人派送；有則回傳帶名稱的錯誤。
func directMessageConflict(tx *gorm.DB, self uint) error {
	var others []model.NotificationChannel
	if err := tx.Select("id, name").Where("direct_message_enabled = ? AND id <> ?", true, self).
		Order("id").Limit(1).Find(&others).Error; err != nil {
		return fmt.Errorf("查詢對個人派送的通道失敗: %w", err)
	}
	if len(others) > 0 {
		return &DirectMessageConflictError{Name: others[0].Name}
	}
	return nil
}

// dmCancelBatch 關閉對個人派送時每批取消的筆數。
const dmCancelBatch = 100

// cancelPendingDirectMessages 取消某個通道等待中與重送中、未被認領的個人訊息（direct_message_disabled）。
// 失敗只記 log：正確性不依賴這一步，下一次送出前的通道條件會讀到設定已關閉而取消。
func (s *NotificationChannelService) cancelPendingDirectMessages(channelID uint) {
	if dmCancelHook != nil {
		dmCancelHook(channelID)
	}
	active := []string{model.NotificationDeliveryPending, model.NotificationDeliveryRetrying}
	for {
		now := time.Now().UTC()
		var ids []uint
		if err := s.db.Model(&model.NotificationDelivery{}).
			Where("source_channel_id = ? AND audience = ? AND state IN ? AND (lease_until IS NULL OR lease_until < ?)",
				channelID, deliveryAudienceUser, active, now).
			Order("id").Limit(dmCancelBatch).Pluck("id", &ids).Error; err != nil {
			log.Printf("[NotificationChannel] 讀取待取消的個人訊息失敗 (channel_id=%d): %v", channelID, err)
			return
		}
		if len(ids) == 0 {
			return
		}
		if err := s.db.Transaction(func(tx *gorm.DB) error {
			return tx.Model(&model.NotificationDelivery{}).
				Where("id IN ? AND audience = ? AND state IN ? AND (lease_until IS NULL OR lease_until < ?)",
					ids, deliveryAudienceUser, active, now).
				Updates(map[string]any{"state": model.NotificationDeliveryCanceled,
					"end_reason": model.NotificationEndDirectMessageDisabled, "lease_until": nil, "ended_at": now}).Error
		}); err != nil {
			log.Printf("[NotificationChannel] 取消個人訊息失敗 (channel_id=%d): %v", channelID, err)
			return
		}
		if len(ids) < dmCancelBatch {
			return
		}
	}
}

// dmCancelHook 測試掛鉤：關閉對個人派送後、開始取消在途個人訊息之前呼叫（正式組裝為 nil）。
var dmCancelHook func(channelID uint)
