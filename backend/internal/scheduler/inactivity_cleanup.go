package scheduler

import (
	"github.com/custodexa/backend/internal/modules/identity"
	"log"
	"time"

	"github.com/robfig/cron/v3"
)

// InactivityCleanupScheduler 閒置帳號自動停用排程器（PCI 8.2.6，auth-hardening D8）：
// 每日固定時刻掃描＋啟動時補跑一次（補伺服器在排程時刻停機的漏掃）
type InactivityCleanupScheduler struct {
	cron    *cron.Cron
	service *identity.InactivityService
}

// NewInactivityCleanupScheduler 建立閒置停用排程器
func NewInactivityCleanupScheduler(svc *identity.InactivityService) *InactivityCleanupScheduler {
	return &InactivityCleanupScheduler{
		cron:    cron.New(cron.WithSeconds()),
		service: svc,
	}
}

// Start 啟動排程器：每天凌晨 3:00 掃描（避開 2:00 的錄製清理），並於啟動時補跑一次。
// 政策 inactive_disable_days=0 時 DisableInactive 直接返回，排程空轉無副作用
func (s *InactivityCleanupScheduler) Start() error {
	if _, err := s.cron.AddFunc("0 0 3 * * *", func() { s.run() }); err != nil {
		return err
	}
	s.cron.Start()
	log.Println("[Inactivity] 閒置帳號停用排程器已啟動（每日 3:00＋啟動補跑）")
	// 啟動補跑：非阻塞，避免拖慢開服
	go s.run()
	return nil
}

// Stop 停止排程器
func (s *InactivityCleanupScheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
}

func (s *InactivityCleanupScheduler) run() {
	start := time.Now()
	n, err := s.service.DisableInactive()
	if err != nil {
		log.Printf("[Inactivity] 閒置帳號掃描失敗: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[Inactivity] 掃描完成：停用 %d 個閒置帳號，耗時 %v", n, time.Since(start))
	}
}
