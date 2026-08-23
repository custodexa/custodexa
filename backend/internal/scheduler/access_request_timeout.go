package scheduler

import (
	"github.com/custodexa/backend/internal/modules/authz"
	"log"
	"time"

	"github.com/robfig/cron/v3"
)

// accessRequestSweepInterval pending 超時掃描週期。時限單位是小時（政策鍵），
// 分鐘級掃描已足；讀取端另有惰性過濾雙保險，掃描延遲不影響正確性
const accessRequestSweepInterval = 5 * time.Minute

// AccessRequestTimeoutScheduler pending 申請超時作廢排程器
// 週期將逾 pending_expires_at 的申請 CAS 轉
// expired（與人工決定併發時僅一方成立）。SkipIfStillRunning 防重入
// （session-reconciliation 前例）
type AccessRequestTimeoutScheduler struct {
	cron    *cron.Cron
	service *authz.AccessRequestService
}

// NewAccessRequestTimeoutScheduler 建立申請超時排程器
func NewAccessRequestTimeoutScheduler(svc *authz.AccessRequestService) *AccessRequestTimeoutScheduler {
	return &AccessRequestTimeoutScheduler{
		cron:    cron.New(cron.WithChain(cron.SkipIfStillRunning(cron.DefaultLogger))),
		service: svc,
	}
}

// Start 啟動排程器（單輪工作量有界：expireBatchLimit）
func (s *AccessRequestTimeoutScheduler) Start() error {
	if _, err := s.cron.AddFunc("@every "+accessRequestSweepInterval.String(), func() { s.run() }); err != nil {
		return err
	}
	s.cron.Start()
	log.Printf("[AccessRequest] pending 超時作廢排程器已啟動（每 %s）", accessRequestSweepInterval)
	return nil
}

// Stop 停止排程器
func (s *AccessRequestTimeoutScheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
}

func (s *AccessRequestTimeoutScheduler) run() {
	now := time.Now()
	n, err := s.service.ExpireOverdue(now)
	if err != nil {
		log.Printf("[AccessRequest] pending 超時掃描失敗: %v", err)
	} else if n > 0 {
		log.Printf("[AccessRequest] pending 超時作廢 %d 筆", n)
	}

	// 破窗補審逾期升級告警：同輪掃描、防重標記，
	// 失敗不影響超時作廢（兩者獨立）
	m, err := s.service.NotifyOverdueReviews(now)
	if err != nil {
		log.Printf("[AccessRequest] 補審逾期掃描失敗: %v", err)
	} else if m > 0 {
		log.Printf("[AccessRequest] 補審逾期告警 %d 筆", m)
	}
}
