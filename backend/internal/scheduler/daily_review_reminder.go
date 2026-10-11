package scheduler

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"log"
	"time"

	"github.com/robfig/cron/v3"
)

// DailyReviewReminderScheduler 每日審閱逾期提醒（PCI 10.4.1）。
// 每 15 分鐘檢查一次：業務時區當地時間過了 09:00、今天尚未送過、且有任何一天
// 已逾準時期限 → 經通知通道送一則列出全部未簽日的提醒。09:00 與「今天」由服務
// 依目前生效的業務時區判定，不看伺服器時區；功能關閉時空轉無副作用
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
	_, err := s.cron.AddFunc("0 */15 * * * *", func() {
		s.review.CheckOverdue(time.Now())
	})
	if err != nil {
		return err
	}
	s.cron.Start()
	log.Printf("[DailyReview] 逾期提醒排程器已啟動（每 15 分鐘檢查，業務時區 09:00 後送出）")
	return nil
}

// Stop 停止排程器
func (s *DailyReviewReminderScheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
	log.Printf("[DailyReview] 逾期提醒排程器已停止")
}
