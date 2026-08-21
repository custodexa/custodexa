package scheduler

import (
	"log"
	"time"

	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/robfig/cron/v3"
)

// kekRetirementCronSpec 每日 10:00 評估（含秒欄位）。固定每日、不新增政策鍵——
// 對齊每日簽核卡片的既有節奏（kek-rewrap-hygiene-hardening D5）
const kekRetirementCronSpec = "0 0 10 * * *"

// KEKRetirementScheduler KEK 退役收斂 degraded 週期評估（kek-rewrap-hygiene-hardening
// D5）。每日評估 retire backlog 謂詞：持續 > 0 → 直投提醒（不受失效事件族
// 「進行中即去重」抑制）；由 > 0 轉 0 → 結束 open 事件並發恢復通知。
// 判定與投遞邏輯全在 keyvault.KEKRetirementMonitor，本型別僅為 cron 外殼，
// 沿 DailyReviewReminderScheduler 前例
type KEKRetirementScheduler struct {
	cron    *cron.Cron
	monitor *keyvault.KEKRetirementMonitor
}

// NewKEKRetirementScheduler 建立週期評估排程器。
// SkipIfStillRunning 防重入（沿 SessionReconciliation 前例）：評估含通知投遞，
// 前一輪未結束時跳過而非疊發
func NewKEKRetirementScheduler(monitor *keyvault.KEKRetirementMonitor) *KEKRetirementScheduler {
	return &KEKRetirementScheduler{
		cron: cron.New(cron.WithSeconds(),
			cron.WithChain(cron.SkipIfStillRunning(cron.DefaultLogger))),
		monitor: monitor,
	}
}

// Start 啟動排程器
func (s *KEKRetirementScheduler) Start() error {
	if _, err := s.cron.AddFunc(kekRetirementCronSpec, func() {
		s.monitor.Evaluate(time.Now())
	}); err != nil {
		return err
	}
	s.cron.Start()
	log.Printf("[KeyManager] KEK 退役收斂評估排程器已啟動（每日 10:00）")
	return nil
}

// Stop 停止排程器
func (s *KEKRetirementScheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
}
