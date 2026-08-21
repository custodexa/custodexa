package scheduler

import (
	"testing"

	"github.com/robfig/cron/v3"
)

// TestKEKRetirementCronSpecValid cron 運算式須與 WithSeconds 解析器相容——
// 不符時 main 於啟動即 log.Fatalf（Start 回錯），此測試把該失敗提前到單測
func TestKEKRetirementCronSpecValid(t *testing.T) {
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour |
		cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	if _, err := parser.Parse(kekRetirementCronSpec); err != nil {
		t.Fatalf("每日評估 cron 運算式非法 (%q): %v", kekRetirementCronSpec, err)
	}
}

// TestKEKRetirementSchedulerStartStop 註冊與停止不報錯（評估邏輯本身由
// keyvault.KEKRetirementMonitor 的三態測試覆蓋）。monitor 傳 nil 安全：
// 每日 10:00 的 job 在本測試生命週期內不會觸發
func TestKEKRetirementSchedulerStartStop(t *testing.T) {
	s := NewKEKRetirementScheduler(nil)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	s.Stop()
}
