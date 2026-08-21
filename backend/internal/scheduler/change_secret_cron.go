package scheduler

import (
	"log"
	"sync"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/robfig/cron/v3"
)

// ChangeSecretScheduler 改密計劃排程器（change-secret 階段 3）：
// 載入 enabled 且含 cron 的計劃；計劃 CUD 後呼叫 Reload 重建排程
type ChangeSecretScheduler struct {
	mu      sync.Mutex
	cron    *cron.Cron
	planSvc *asset.ChangeSecretPlanService
	runner  *asset.ChangeSecretRunner
}

// NewChangeSecretScheduler 建立排程器
func NewChangeSecretScheduler(planSvc *asset.ChangeSecretPlanService, runner *asset.ChangeSecretRunner) *ChangeSecretScheduler {
	return &ChangeSecretScheduler{
		cron:    cron.New(), // 標準 5 欄（與 PlanService 驗證一致）
		planSvc: planSvc,
		runner:  runner,
	}
}

// Start 載入計劃並啟動
func (s *ChangeSecretScheduler) Start() {
	s.Reload()
	s.cron.Start()
	log.Println("[ChangeSecretScheduler] 改密排程器已啟動")
}

// Stop 停止排程器
func (s *ChangeSecretScheduler) Stop() {
	s.cron.Stop()
}

// Reload 重建全部排程項（計劃 CUD 後呼叫）
func (s *ChangeSecretScheduler) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range s.cron.Entries() {
		s.cron.Remove(entry.ID)
	}

	plans, err := s.planSvc.List()
	if err != nil {
		log.Printf("[ChangeSecretScheduler] 載入計劃失敗: %v", err)
		return
	}
	count := 0
	for _, plan := range plans {
		if !plan.Enabled || plan.Cron == "" {
			continue
		}
		p := plan // capture
		if _, err := s.cron.AddFunc(p.Cron, func() { s.runPlan(p.ID) }); err != nil {
			log.Printf("[ChangeSecretScheduler] 計劃 %s 排程註冊失敗: %v", p.Name, err)
			continue
		}
		count++
	}
	log.Printf("[ChangeSecretScheduler] 已載入 %d 個排程計劃", count)
}

// runPlan 排程觸發：以最新計劃內容執行
func (s *ChangeSecretScheduler) runPlan(planID uint) {
	plan, err := s.planSvc.Get(planID)
	if err != nil || !plan.Enabled {
		return
	}
	log.Printf("[ChangeSecretScheduler] 排程觸發改密: plan=%s", plan.Name)
	records := s.runner.RunPlan(plan)
	logChangeSecretSummary(plan, records)
}

func logChangeSecretSummary(plan *model.ChangeSecretPlan, records []model.ChangeSecretRecord) {
	var ok, failed int
	for _, r := range records {
		if r.Status == model.ChangeSecretSuccess {
			ok++
		} else if r.Status != model.ChangeSecretSkipped {
			failed++
		}
	}
	log.Printf("[ChangeSecret] plan=%s 完成: success=%d failed=%d total=%d", plan.Name, ok, failed, len(records))
}
