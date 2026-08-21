package scheduler

import (
	"log"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/robfig/cron/v3"
)

// changeSecretRetryCron 掃描間隔。實際的重試節奏由候選列的 next_attempt_at
// （指數退避）決定，本排程只負責「到期即撈」——把節奏放在資料上，
// 重啟後不會因排程重建而丟失退避進度
const changeSecretRetryCron = "@every 1m"

// ChangeSecretRetryScheduler 未驗證候選憑證的重試排程（change-secret-ssh-deepening D4）。
//
// 沿 access_request_timeout 的既有形態：固定間隔 ＋ 單輪有界批次 ＋ SkipIfStillRunning
// 防重入（一輪要對多台目標機建線，慢輪疊輪會使同一候選被兩個 goroutine 同時提交）。
type ChangeSecretRetryScheduler struct {
	cron   *cron.Cron
	runner *asset.ChangeSecretRetryRunner
}

// NewChangeSecretRetryScheduler 建立排程器
func NewChangeSecretRetryScheduler(runner *asset.ChangeSecretRetryRunner) *ChangeSecretRetryScheduler {
	return &ChangeSecretRetryScheduler{
		cron:   cron.New(cron.WithChain(cron.SkipIfStillRunning(cron.DefaultLogger))),
		runner: runner,
	}
}

// Start 啟動排程
func (s *ChangeSecretRetryScheduler) Start() {
	if _, err := s.cron.AddFunc(changeSecretRetryCron, func() {
		s.runner.RunDue()
	}); err != nil {
		log.Printf("[ChangeSecretRetry] 排程註冊失敗: %v", err)
		return
	}
	s.cron.Start()
	log.Println("[ChangeSecretRetry] 候選憑證重試排程已啟動")
}

// Stop 停止排程
func (s *ChangeSecretRetryScheduler) Stop() {
	s.cron.Stop()
}
