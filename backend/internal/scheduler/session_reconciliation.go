package scheduler

import (
	"log"
	"time"

	"github.com/custodexa/backend/internal/modules/session"
	"github.com/robfig/cron/v3"
)

// SessionReconciliationScheduler 孤兒 session 偵測排程器
// （session-reconciliation）：週期比對 DB active 與連線註冊表存活，
// 無對應活連線且過寬限期者收斂為 ended。啟動清掃另由 main 於受理
// 新連線前同步執行，不在本排程器
type SessionReconciliationScheduler struct {
	cron    *cron.Cron
	service *session.SessionReconciliationService
}

// NewSessionReconciliationScheduler 建立孤兒偵測排程器。
// SkipIfStillRunning 防重入：DB 緩慢或 backlog 使一輪逾 60s 時，
// 下一輪跳過而非疊掃同批資料造成工作放大
func NewSessionReconciliationScheduler(svc *session.SessionReconciliationService) *SessionReconciliationScheduler {
	return &SessionReconciliationScheduler{
		cron:    cron.New(cron.WithChain(cron.SkipIfStillRunning(cron.DefaultLogger))),
		service: svc,
	}
}

// Start 啟動排程器：每 ReconcileInterval 掃一輪（單輪工作量有界）
func (s *SessionReconciliationScheduler) Start() error {
	if _, err := s.cron.AddFunc("@every "+session.ReconcileInterval.String(), func() { s.run() }); err != nil {
		return err
	}
	s.cron.Start()
	log.Printf("[Reconcile] 孤兒 session 偵測排程器已啟動（每 %s）", session.ReconcileInterval)
	return nil
}

// Stop 停止排程器
func (s *SessionReconciliationScheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
}

func (s *SessionReconciliationScheduler) run() {
	start := time.Now()
	n, err := s.service.ReconcileOrphans()
	if err != nil {
		log.Printf("[Reconcile] 孤兒偵測失敗: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[Reconcile] 孤兒偵測：收斂 %d 筆無活連線的 active session（orphaned），耗時 %v", n, time.Since(start))
	}
}
