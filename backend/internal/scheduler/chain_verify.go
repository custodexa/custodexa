package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/robfig/cron/v3"
)

// chainVerifyCronSpec 每分鐘一次的到期判定（含秒欄位）。
//
// **每分鐘檢查、而非「每個驗證間隔跑一次」**：兩層的到期條件不同源——近期層是
// 觀測式（最新已封 seq 前進即到期，其節奏由封章決定且可隨寫入量變動），全鏈層
// 才是週期式。cron 只能表達後者；把 cron spec 綁到政策間隔上還會讓「改政策」
// 變成「重排 cron」，而政策一改要下一分鐘生效、不能等重啟。到期判定成本是
// 兩個索引查詢（鏈尾檢查點、狀態單列），可忽略。
const chainVerifyCronSpec = "0 * * * * *"

// ChainVerifyScheduler 檢查點鏈兩層自動驗證的排程外殼
// （audit-chain-scheduled-verification D1／D2）。
//
// **本型別只負責節奏，不負責判斷**：到期判定、兩層編排、滾動游標、失敗區間集合
// 與告警全在 audit.ChainVerifyService.Tick——那是唯一入口。排程器若自行判斷
// 「該不該跑」就會出現第二份到期規則，兩份規則遲早分歧而沒有任何測試看得出來。
//
// **SkipIfStillRunning 不是可選的**（沿 KEKRetirementScheduler／SessionReconciliation
// 前例）：單輪的內容層掃描可達列預算上限（出廠 100 萬列/小時 × 1 小時間隔），
// 耗時遠超一分鐘。無防重入時第二輪會與第一輪並行推進同一份狀態列與同一份失敗
// 區間集合，結果是游標互相覆寫、集合成員在兩輪之間丟失——而丟失的成員正是
// 「未結案的竄改事件」，其後果是假恢復（D9 要防的正是這件事）。
//
// **驗證是旁路唯讀工作**：本排程器停擺、報錯或被關閉，審計寫入與封章完全不受
// 影響，失去的只是「自動發現」——驗證頁的人工入口仍在，兩層的最近執行時點會
// 停在舊值，故停擺本身可由驗證頁判讀（D8）。
type ChainVerifyScheduler struct {
	cron    *cron.Cron
	service *audit.ChainVerifyService

	// ctx／cancel 供 Stop 中斷進行中的掃描——單輪可掃到列預算上限，
	// 收束時不該乾等它掃完
	ctx    context.Context
	cancel context.CancelFunc
}

// NewChainVerifyScheduler 建立鏈驗證排程器
func NewChainVerifyScheduler(service *audit.ChainVerifyService) *ChainVerifyScheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &ChainVerifyScheduler{
		cron: cron.New(cron.WithSeconds(),
			cron.WithChain(cron.SkipIfStillRunning(cron.DefaultLogger))),
		service: service,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start 啟動每分鐘到期判定。
//
// **刻意不做任何前置建立**（與 CheckpointScheduler 的 genesis 相反）：鏈為空是
// 驗證要回報的結論，不是啟動失敗。在此建立或修補任何鏈上物件都會讓「驗證者」
// 同時成為「被驗者的作者」，而那正是本機制存在的理由所反對的。
func (s *ChainVerifyScheduler) Start() error {
	if _, err := s.cron.AddFunc(chainVerifyCronSpec, s.run); err != nil {
		return err
	}
	s.cron.Start()
	log.Printf("[ChainVerify] 鏈驗證排程器已啟動（每分鐘判定兩層到期；近期層隨封章觸發、全鏈層依政策週期）")
	return nil
}

// Stop 停止排程器並中斷進行中的掃描
func (s *ChainVerifyScheduler) Stop() {
	s.cancel()
	ctx := s.cron.Stop()
	<-ctx.Done()
	log.Printf("[ChainVerify] 鏈驗證排程器已停止")
}

// RunNow 立即跑一次到期判定（測試／人工驗證用；仍走完整的 due 判定與自檢）
func (s *ChainVerifyScheduler) RunNow() {
	s.run()
}

func (s *ChainVerifyScheduler) run() {
	start := time.Now()
	if err := s.service.Tick(s.ctx); err != nil {
		// 失敗只記錄不重試：下一分鐘會再判一次到期。重試迴圈在這裡沒有價值——
		// 失敗成因（DB 不可用、簽章鑰不可用）都不是毫秒級可恢復的，且
		// 「驗證本身失敗」已由 Tick 內部上報為獨立機制，不靠這行 log 被發現
		log.Printf("[ChainVerify] 鏈驗證輪次失敗（耗時 %v）: %v", time.Since(start), err)
	}
}
