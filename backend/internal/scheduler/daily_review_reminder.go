package scheduler

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"log"
	"time"

	"github.com/robfig/cron/v3"
)

// DailyReviewReminderScheduler 每日審閱逾期提醒（audit-log-compliance，PCI 10.4.1）。
// 每日 09:00 檢查昨日簽核：功能啟用且昨日未簽 → 經通知通道提醒；
// 功能關閉時空轉無副作用
type DailyReviewReminderScheduler struct {
	cron   *cron.Cron
	review *audit.DailyReviewService
}

// NewDailyReviewReminderScheduler 建立逾期提醒排程器
func NewDailyReviewReminderScheduler(review *audit.DailyReviewService) *DailyReviewReminderScheduler {
	return &DailyReviewReminderScheduler{
		cron:   cron.New(cron.WithSeconds()),
		review: review,
	}
}

// Start 啟動排程器
func (s *DailyReviewReminderScheduler) Start() error {
	_, err := s.cron.AddFunc("0 0 9 * * *", func() {
		s.review.CheckOverdue(time.Now())
	})
	if err != nil {
		return err
	}
	s.cron.Start()
	log.Printf("[DailyReview] 逾期提醒排程器已啟動（每日 09:00）")
	return nil
}

// Stop 停止排程器
func (s *DailyReviewReminderScheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
	log.Printf("[DailyReview] 逾期提醒排程器已停止")
}
