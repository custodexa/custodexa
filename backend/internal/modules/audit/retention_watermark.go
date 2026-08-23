package audit

import (
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// RetentionWatermarkService 保留期清除水位的讀寫。
//
// 這張表存在的唯一理由是「清除留痕自己會過期」：retention 的留痕是一筆
// audit_logs 列，下一輪 retention 會把它清掉，於是在區間夠舊、最需要標記的
// 時候標記剛好不見。水位表永不清除，故不會自我湮滅。
type RetentionWatermarkService struct {
	db *gorm.DB
}

func NewRetentionWatermarkService(db *gorm.DB) *RetentionWatermarkService {
	return &RetentionWatermarkService{db: db}
}

// Advance 單調前進地更新水位。
//
// **只可前進不可倒退**是本函式的全部重點。保留天數由 90 調為 365 時，
// 新的 cutoff 會比舊水位更早；若照寫，早先確實已被清除的那段就會被重新
// 宣稱為 present，工作台於是把「已依政策清除」呈現成「本來就沒發生」——
// 那正是本 change 要消滅的誤讀。故時間上界一律取 GREATEST。
//
// `policy_days`／`last_purge_at`／`partial` 描述的是**最近一次執行**，
// 照實覆寫（它們不是不變式，是給 UI 講「保留 N 天，最後清除於 T」用的）。
func (s *RetentionWatermarkService) Advance(class model.RetentionClass, through time.Time, policyDays int, partial bool) error {
	if s == nil || s.db == nil {
		return nil
	}
	// 永久保留（0 天）不更新水位：沒有任何區間被清除，寫入只會憑空製造
	// 一條「此前已清除」的宣稱
	if policyDays <= 0 {
		return nil
	}
	now := time.Now()
	// ON CONFLICT 而非 SELECT-then-UPDATE：清除排程可能與手動觸發並行，
	// 讀改寫之間的空隙會讓兩個 runner 互相覆蓋（後寫者若持較舊 cutoff 即倒退）。
	// 取大值在 SQL 內求值，倒退在資料庫層即不可能發生。
	// 用 CASE 而非 GREATEST：後者是 postgres 專屬，sqlite（單元測試路徑）沒有，
	// 只在 pg 上成立的不變式等於單測完全測不到它
	sql := `INSERT INTO audit_retention_watermarks
			(class, purged_through_at, last_purge_at, policy_days, partial, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (class) DO UPDATE SET
			purged_through_at = CASE
				WHEN EXCLUDED.purged_through_at > audit_retention_watermarks.purged_through_at
				THEN EXCLUDED.purged_through_at
				ELSE audit_retention_watermarks.purged_through_at END,
			last_purge_at = EXCLUDED.last_purge_at,
			policy_days = EXCLUDED.policy_days,
			partial = EXCLUDED.partial,
			updated_at = EXCLUDED.updated_at`
	if err := s.db.Exec(sql, string(class), through, now, policyDays, partial, now).Error; err != nil {
		return fmt.Errorf("更新保留水位 %s 失敗: %w", class, err)
	}
	return nil
}

// Load 讀出全部水位，以 class 為鍵。
//
// **無列不是 unknown 而是 present**（冷啟動語義）：從未清除過該類別，
// 就代表該類別在窗內完整。回 unknown 會讓每個新部署的工作台都掛滿
// 「無法確認」，而那是假的不確定性——確定的事實是「沒清除過」。
func (s *RetentionWatermarkService) Load() (map[model.RetentionClass]model.AuditRetentionWatermark, error) {
	out := make(map[model.RetentionClass]model.AuditRetentionWatermark, 5)
	if s == nil || s.db == nil {
		return out, nil
	}
	var rows []model.AuditRetentionWatermark
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取保留水位失敗: %w", err)
	}
	for _, r := range rows {
		out[r.Class] = r
	}
	return out, nil
}

// retentionClassForTable 把 retention 的目標表名對應到水位類別。
// 未登記的表回空字串——新增清除目標而忘了對應時，寧可不寫水位
//（缺水位＝present＝可能過度樂觀），也不亂掛到別的類別上造成錯誤標記
func retentionClassForTable(table string) model.RetentionClass {
	switch table {
	case "audit_logs":
		return model.RetentionClassAuditLog
	case "session_commands":
		return model.RetentionClassSessionCommand
	case "command_alerts":
		return model.RetentionClassCommandAlert
	case "recordings":
		return model.RetentionClassRecording
	}
	return ""
}
