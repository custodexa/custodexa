package policy

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/reviewcal"
	"gorm.io/gorm"
)

// historyKeys 保留變更歷史的政策鍵：每日簽核「哪些日子要簽、各用哪個時區切」
// 由它們的歷史推得，所以每一次變更都要在寫入現值的同一交易內留下一列
var historyKeys = map[string]bool{
	PolicyDailyReviewEnabled:  true,
	PolicyDailyReviewTimezone: true,
}

// policyHistoryLockKey 保留歷史鍵寫入序列化用的交易級鎖鍵（pg advisory lock）。
// 一把鎖而不是逐鍵鎖：免去多鍵批次的鎖順序問題，也不依賴政策列是否已存在；
// 這兩個鍵寫入極少，不構成瓶頸
const policyHistoryLockKey int64 = 0x6372_6576_6965_77 // "review" 的位元組，僅需全庫唯一

// policyHistoryHooks 測試同步點（生產為 nil）：控制並行寫入的取鎖次序、在交易內注入失敗
var policyHistoryHooks struct {
	beforeLock func(updatedBy string)
	afterLock  func(updatedBy string)
	afterWrite func(updatedBy string) error
}

func batchHasHistoryKey(updates map[string]string) bool {
	for key := range updates {
		if historyKeys[key] {
			return true
		}
	}
	return false
}

// lockPolicyHistory 取交易級鎖。sqlite 單一寫入者本身已序列化，不需要
func lockPolicyHistory(tx *gorm.DB) error {
	if tx.Dialector.Name() != "postgres" {
		return nil
	}
	if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", policyHistoryLockKey).Error; err != nil {
		return fmt.Errorf("取得政策歷史寫入鎖失敗: %w", err)
	}
	return nil
}

// historySourceFor 依寫入者判定歷史來源：啟動播種與管理端寫入分開
func historySourceFor(updatedBy string) string {
	if updatedBy == PolicySeededBy {
		return model.PolicyHistorySourceSeed
	}
	return model.PolicyHistorySourcePolicyUpdate
}

// History 保留歷史鍵的變更歷史（依變更時刻與寫入順序遞增）。
// audit 模組經此取歷史推每日簽核的行事曆，不直接查表
func (s *SecurityPolicyService) History(keys ...string) ([]model.SecurityPolicyHistory, error) {
	var rows []model.SecurityPolicyHistory
	q := s.db.Order("changed_at, id")
	if len(keys) > 0 {
		q = q.Where("policy_key IN ?", keys)
	}
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取政策變更歷史失敗: %w", err)
	}
	return rows, nil
}

// SeedDailyReviewTimezone 首次啟動以偵測到的伺服器時區播種業務時區
// （TZ → /etc/localtime → UTC）。走 SeedValue：已有列時不覆蓋管理者設定的值
func (s *SecurityPolicyService) SeedDailyReviewTimezone(getenv func(string) string, localtimeTarget func() (string, error)) {
	tz := reviewcal.DetectTimezone(getenv, localtimeTarget)
	s.SeedValue(PolicyDailyReviewTimezone, tz, "偵測到的伺服器時區 "+tz)
}
