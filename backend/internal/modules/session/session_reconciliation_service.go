package session

import (
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 掃描節奏常數（可調的實作細節）
const (
	// ReconcileInterval 孤兒偵測排程間隔
	ReconcileInterval = 60 * time.Second
	// reconcileGracePeriod 建線寬限期：覆蓋「DB 先寫 active、Register 後掛」
	// 的建線短窗與正常收線的反向短窗，期內不判孤兒
	reconcileGracePeriod = 120 * time.Second
	// reconcileBatchSize 單「批」查詢上限。單輪掃至候選集清空（正確性優先：孤兒
	// 要清乾淨），非固定單輪上限；每批 keyset（id > cursor）有界、cursor 前進不
	// 重掃不無限迴圈，且排程層 SkipIfStillRunning 防重入避免疊掃
	reconcileBatchSize = 500
)

// ConnectionLiveness 活連線存活查詢（proxy.ConnectionRegistry.Has）：
// registry 成員資格是活連線的權威訊號——所有建立 active session 的路徑
// 都會註冊（spec「連線註冊完整性」）
type ConnectionLiveness interface {
	Has(sessionID uint) bool
}

// SessionReconciliationService session 持久化狀態與實際連線的一致性收斂
// （session-reconciliation）：啟動清掃＋週期孤兒偵測。單一後端實例前提，
// 多實例部署時本服務需重設計（會誤殺他實例的活連線）
type SessionReconciliationService struct {
	liveness ConnectionLiveness
}

// NewSessionReconciliationService 建立一致性收斂服務。
// typed-nil 正規化：傳入 nil 指標轉介面時 `liveness != nil` 仍為
// true，後續 Has() 會 panic；統一在建構時正規化為 interface nil（比照 SessionService）
func NewSessionReconciliationService(liveness ConnectionLiveness) *SessionReconciliationService {
	if liveness != nil {
		v := reflect.ValueOf(liveness)
		if v.Kind() == reflect.Ptr && v.IsNil() {
			liveness = nil
		}
	}
	return &SessionReconciliationService{liveness: liveness}
}

// ReconcileStartup 啟動清掃：重啟後不可能有存活連線，殘留 active 一律
// 收斂為 ended（end_reason=backend_restart）。須於受理新連線前呼叫
func (s *SessionReconciliationService) ReconcileStartup() (int, error) {
	return s.sweep(model.EndReasonBackendRestart, time.Time{}, nil)
}

// ReconcileOrphans 週期孤兒偵測：active 且建立已過寬限期、registry 無對應
// 活連線者收斂為 ended（end_reason=orphaned）
func (s *SessionReconciliationService) ReconcileOrphans() (int, error) {
	cutoff := time.Now().Add(-reconcileGracePeriod)
	return s.sweep(model.EndReasonOrphaned, cutoff, s.liveness)
}

// sweep keyset 分批掃描 active 候選並收斂。cutoff 非零時僅掃 start_time
// 早於 cutoff 者；liveness 非 nil 時跳過仍有活連線登記的 session
func (s *SessionReconciliationService) sweep(reason string, cutoff time.Time, liveness ConnectionLiveness) (int, error) {
	now := time.Now()
	total := 0
	cursor := uint(0)
	for {
		query := database.DB.Model(&model.Session{}).
			Select("id", "start_time").
			Where("status = ? AND id > ?", model.SessionStatusActive, cursor).
			Order("id").
			Limit(reconcileBatchSize)
		if !cutoff.IsZero() {
			query = query.Where("start_time < ?", cutoff)
		}

		var sessions []model.Session
		if err := query.Find(&sessions).Error; err != nil {
			return total, fmt.Errorf("查詢 active session 候選失敗: %w", err)
		}
		if len(sessions) == 0 {
			return total, nil
		}

		for i := range sessions {
			sess := &sessions[i]
			cursor = sess.ID
			if liveness != nil && liveness.Has(sess.ID) {
				continue // 有活連線，非孤兒
			}
			converged, err := s.closeAsEnded(sess, reason, now)
			if err != nil {
				log.Printf("[Reconcile] 收斂 session 失敗 (ID=%d, reason=%s): %v", sess.ID, reason, err)
				continue
			}
			if converged {
				total++
			}
		}

		if len(sessions) < reconcileBatchSize {
			return total, nil
		}
	}
}

// closeAsEnded 單筆收斂。WHERE 守衛 status=active：與正常收線競態時讓先到者
// 贏，不覆寫已寫入的 end_reason/end_time（RowsAffected=0 視為已被收線）
func (s *SessionReconciliationService) closeAsEnded(sess *model.Session, reason string, now time.Time) (bool, error) {
	duration := int(now.Sub(sess.StartTime).Seconds())
	if duration < 0 {
		duration = 0
	}

	res := database.DB.Model(&model.Session{}).
		Where("id = ? AND status = ?", sess.ID, model.SessionStatusActive).
		Updates(map[string]interface{}{
			"status":     model.SessionStatusDisconnected,
			"end_time":   now,
			"duration":   duration,
			"end_reason": reason,
		})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}
