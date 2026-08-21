package scheduler

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"log"
	"time"

	"github.com/robfig/cron/v3"
)

// RetentionScheduler 保留政策執行排程器（audit-log-compliance，PCI 10.5.1）。
// 取代原 RecordingCleanupScheduler：錄影＋三類 DB 審計資料統一由
// RetentionService 依政策值清除；政策值於每次執行時讀取，變更無需重啟
type RetentionScheduler struct {
	cron      *cron.Cron
	retention *audit.RetentionService
}

// NewRetentionScheduler 建立保留政策排程器
func NewRetentionScheduler(retention *audit.RetentionService) *RetentionScheduler {
	return &RetentionScheduler{
		cron:      cron.New(cron.WithSeconds()),
		retention: retention,
	}
}

// Start 啟動排程器（沿既有清理慣例：每天凌晨 2:00）
func (s *RetentionScheduler) Start() error {
	_, err := s.cron.AddFunc("0 0 2 * * *", func() {
		s.run()
	})
	if err != nil {
		return err
	}
	s.cron.Start()
	log.Printf("[Retention] 排程器已啟動（每日 02:00，保留天數依安全政策）")
	return nil
}

// Stop 停止排程器
func (s *RetentionScheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
	log.Printf("[Retention] 排程器已停止")
}

// RunNow 立即執行一次（測試/驗證用）
func (s *RetentionScheduler) RunNow() {
	log.Printf("[Retention] 手動觸發保留清除")
	s.run()
}

func (s *RetentionScheduler) run() {
	start := time.Now()
	results := s.retention.PurgeAll()
	if len(results) == 0 {
		log.Printf("[Retention] 全部保留政策為永久保留，無需清除")
		return
	}
	log.Printf("[Retention] 清除完成，%d 類處理，耗時 %v", len(results), time.Since(start))
}
