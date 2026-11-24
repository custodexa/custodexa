package audit

import (
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// notificationMessageRetentionDays 通知內容與一般通知（指令告警、系統事件）待投遞紀錄的保存天數。
//
// 這兩者屬投遞的營運資料，不是告警證據，所以不跟告警記錄保留天數（預設永久）走；
// 固定期限比通道列表的 7 天統計窗長，投遞紀錄至少看得到一個月。刻意是程式常數、不是政策鍵：
// 它不是 retentionTargets 的一列（那份清單每列綁一個政策鍵）。
// 系統安全告警的待投遞紀錄指向告警列、隨告警記錄保存與清除，不受本步驟影響。
const notificationMessageRetentionDays = 30

// notificationPurgeTarget 清除結果與審計中的目標名。
const notificationPurgeTarget = "notification_messages"

// purgeNotificationMessages 清除已分派或分派失敗、建立超過 30 天、且其待投遞紀錄全部為終態的通知內容，
// 連同其待投遞紀錄。仍待分派的內容、仍有待送或重試中紀錄的內容跳過。ran=false 表示本輪沒有需要
// 留痕的結果（沒有刪除也沒有錯誤）。
//
// 待投遞紀錄先刪、內容列後刪，於同一交易內：PostgreSQL 上外鍵本來就會連帶刪除，顯式刪除讓
// 沒有外鍵的環境結果相同，也讓刪除筆數可以計入留痕。
func (s *RetentionService) purgeNotificationMessages(now time.Time) (PurgeResult, bool) {
	result := PurgeResult{Target: notificationPurgeTarget, Days: notificationMessageRetentionDays}
	if !s.db.Migrator().HasTable(&model.NotificationMessage{}) {
		// 結構未就緒（只出現在不含通知表的精簡測試夾具）：沒有可清除的對象
		return result, false
	}
	cutoff := now.Add(-time.Duration(notificationMessageRetentionDays) * 24 * time.Hour)
	limit := s.maxPerRunNow()
	batch := s.batchSize
	if batch <= 0 || batch > limit {
		batch = limit
	}
	var total int64
	for total < int64(limit) {
		var ids []uint
		err := s.db.Model(&model.NotificationMessage{}).
			Where("state IN ? AND created_at < ?", []string{model.NotificationMessageDispatched, model.NotificationMessageFailed}, cutoff).
			Where("NOT EXISTS (SELECT 1 FROM system_alert_outbox o WHERE o.message_id = notification_messages.id AND o.state IN ?)",
				[]string{model.NotificationDeliveryPending, model.NotificationDeliveryRetrying}).
			Order("id").Limit(batch).Pluck("id", &ids).Error
		if err != nil {
			result.Error = fmt.Sprintf("讀取到期的通知內容失敗: %v", err)
			break
		}
		if len(ids) == 0 {
			break
		}
		tx := s.db.Begin()
		if err := tx.Where("message_id IN ?", ids).Delete(&model.NotificationDelivery{}).Error; err != nil {
			tx.Rollback()
			result.Error = fmt.Sprintf("清除通知的待投遞紀錄失敗: %v", err)
			break
		}
		res := tx.Where("id IN ?", ids).Delete(&model.NotificationMessage{})
		if res.Error != nil {
			tx.Rollback()
			result.Error = fmt.Sprintf("清除通知內容失敗: %v", res.Error)
			break
		}
		if err := tx.Commit().Error; err != nil {
			result.Error = fmt.Sprintf("清除通知內容的交易提交失敗: %v", err)
			break
		}
		total += res.RowsAffected
		if len(ids) < batch {
			break
		}
	}
	result.Deleted = total
	result.Partial = total >= int64(limit)
	if result.Error != "" {
		log.Printf("[Retention] 通知投遞紀錄清除失敗（已刪 %d 筆）: %s", total, result.Error)
	}
	return result, total > 0 || result.Error != ""
}
