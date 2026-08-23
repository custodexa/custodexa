package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/robfig/cron/v3"
)

// CheckpointScheduler 審計檢查點封章排程器（audit-checkpoint-chain）。
//
// **每分鐘檢查一次觸發條件**，而非每小時跑一次：兩個門檻是「先到先觸發」
// （滿 1 小時 或 累積 10000 筆），筆數門檻要能在小時內生效就必須高頻檢查。
// 檢查本身是兩個索引查詢（鏈尾檢查點、MAX(id)），成本可忽略。
//
// 封章是旁路批次工作：本排程器停擺、報錯或被關閉，審計寫入完全不受影響，
// 只是鏈的尾端窗口（誠實邊界 R5）變長。
type CheckpointScheduler struct {
	cron    *cron.Cron
	service *audit.CheckpointService

	// ctx／cancel 供 Stop 中斷進行中的 grace 等待——單次 Tick 含 grace
	// 可達數十秒，收束時不該乾等它睡完
	ctx    context.Context
	cancel context.CancelFunc
}

// NewCheckpointScheduler 建立封章排程器
func NewCheckpointScheduler(service *audit.CheckpointService) *CheckpointScheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &CheckpointScheduler{
		cron:    cron.New(cron.WithSeconds()),
		service: service,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start 建立 genesis（若鏈為空）並啟動每分鐘檢查。
//
// **genesis 失敗即啟動失敗**：沒有 genesis 就沒有鏈，之後每一次 Tick 都會
// 以 ErrCheckpointNoChain 失敗——那是一個「排程器活著但什麼都沒在保護」的
// 靜默狀態，正是本 change 要消滅的形態
func (s *CheckpointScheduler) Start() error {
	if err := s.service.EnsureGenesis(); err != nil {
		return err
	}
	if _, err := s.cron.AddFunc("0 * * * * *", s.run); err != nil {
		return err
	}
	s.cron.Start()
	log.Printf("[Checkpoint] 封章排程器已啟動（每分鐘檢查；門檻 %v／%d 筆，grace %v）",
		s.service.Interval(), s.service.RowThreshold(), s.service.Grace())
	return nil
}

// Stop 停止排程器並中斷進行中的 grace 等待
func (s *CheckpointScheduler) Stop() {
	s.cancel()
	ctx := s.cron.Stop()
	<-ctx.Done()
	log.Printf("[Checkpoint] 封章排程器已停止")
}

// RunNow 立即跑一次觸發檢查（測試／驗證用；仍走門檻與 grace）
func (s *CheckpointScheduler) RunNow() {
	s.run()
}

func (s *CheckpointScheduler) run() {
	start := time.Now()
	if err := s.service.Tick(s.ctx); err != nil {
		// 失敗只記錄不重試：下一分鐘會再檢查一次，且區間上界會重新觀測。
		// 重試迴圈在這裡沒有價值——失敗成因（DB 不可用、簽章鑰不可用）
		// 都不是毫秒級可恢復的
		log.Printf("[Checkpoint] 封章檢查失敗（耗時 %v）: %v", time.Since(start), err)
	}
}
