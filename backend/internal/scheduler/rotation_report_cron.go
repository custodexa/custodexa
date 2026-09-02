package scheduler

import (
	"log"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/robfig/cron/v3"
)

// RotationReportScheduler 輪替證據報告排程器：載入 enabled 的排程，
// 到點時建立一張報告工作單（打包由既有的匯出 worker 承擔）。
// 排程 CUD 後呼叫 Reload 重建。
type RotationReportScheduler struct {
	mu       sync.Mutex
	cron     *cron.Cron
	schedule *asset.RotationReportScheduleService
}

// NewRotationReportScheduler 建立排程器。
func NewRotationReportScheduler(svc *asset.RotationReportScheduleService) *RotationReportScheduler {
	return &RotationReportScheduler{
		cron:     cron.New(), // 標準 5 欄（與排程服務的驗證一致）
		schedule: svc,
	}
}

// Start 載入排程並啟動。
func (s *RotationReportScheduler) Start() {
	s.Reload()
	s.cron.Start()
	log.Println("[RotationReportScheduler] 輪替報告排程器已啟動")
}

// Stop 停止排程器。
func (s *RotationReportScheduler) Stop() {
	s.cron.Stop()
}

// Reload 重建全部排程項。
func (s *RotationReportScheduler) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range s.cron.Entries() {
		s.cron.Remove(entry.ID)
	}

	rows, err := s.schedule.List()
	if err != nil {
		log.Printf("[RotationReportScheduler] 載入排程失敗: %v", err)
		return
	}
	count := 0
	for _, row := range rows {
		if !row.Enabled || row.Cron == "" {
			continue
		}
		id := row.ID
		name := row.Name
		if _, err := s.cron.AddFunc(row.Cron, func() { s.run(id, name) }); err != nil {
			log.Printf("[RotationReportScheduler] 排程 %s 註冊失敗: %v", name, err)
			continue
		}
		count++
	}
	log.Printf("[RotationReportScheduler] 已載入 %d 個報告排程", count)
}

// run 觸發：以觸發時刻建單。**建單失敗只留 log**——排程器是旁路，
// 一份報告沒產出不該影響服務，而錨點未推進使下一次觸發自然補回這一段。
func (s *RotationReportScheduler) run(id uint, name string) {
	job, err := s.schedule.Trigger(id, time.Now())
	if err != nil {
		log.Printf("[RotationReportScheduler] 排程 %s 建單失敗: %v", name, err)
		return
	}
	log.Printf("[RotationReportScheduler] 排程 %s 已建立報告工作單 job=%d", name, job.ID)
}
