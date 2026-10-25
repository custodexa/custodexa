package scheduler

import (
	"fmt"
	"log"
	"strings"
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
	// notify 升級後因無從歸屬發起者而暫停的計畫告警（nil＝只寫日誌）
	notify func(rule, message string)
}

// WithPausedPlanNotifier 注入暫停計畫的告警推送（組裝根）。
func (s *ChangeSecretScheduler) WithPausedPlanNotifier(fn func(rule, message string)) *ChangeSecretScheduler {
	s.notify = fn
	return s
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
	var paused []string
	for _, plan := range plans {
		if !plan.Enabled || plan.Cron == "" {
			continue
		}
		// 升級時完全查不到可歸屬發起者的計畫：不排程（cron 與啟用設定保留），
		// 由具權者一鍵重新授權後恢復
		if plan.AuthorizationState == model.PlanAuthNeedsReauthorization {
			paused = append(paused, fmt.Sprintf("%s(id=%d)", plan.Name, plan.ID))
			continue
		}
		// 待重新確認（掛載超出確認範圍）：轉入當下已告警，載入時不排程也不再告警
		if plan.AuthorizationState == model.PlanAuthNeedsReconfirmation {
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
	if len(paused) > 0 {
		msg := fmt.Sprintf("%d 個排程計畫因無法歸屬發起者而暫停，需具權者重新授權: %s", len(paused), strings.Join(paused, ", "))
		log.Printf("[ChangeSecretScheduler] %s", msg)
		if s.notify != nil {
			s.notify("改密排程計畫需重新授權", msg)
		}
	}
}

// runPlan 排程觸發：以最新計劃內容執行
func (s *ChangeSecretScheduler) runPlan(planID uint) {
	plan, err := s.planSvc.Get(planID)
	if err != nil || !plan.Enabled {
		return
	}
	// 已停在待重新授權的計畫（升級時查無發起者，或授權脈絡留自一次還原之前）：
	// 停止當下已告警並留痕，之後的觸發不重複告警，等具權者重新授權
	if plan.AuthorizationState == model.PlanAuthNeedsReauthorization ||
		plan.AuthorizationState == model.PlanAuthNeedsReconfirmation {
		log.Printf("[ChangeSecretScheduler] 計畫待重新授權或待重新確認，略過觸發: plan=%d", plan.ID)
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
