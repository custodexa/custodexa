package audit

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 段 D 的 PostgreSQL 專屬行為（TEST_PG_DSN gated）：通道更新的規則在列鎖內判斷、投遞放棄通知的節流在並行下不重複。

// TestChannelUpdateRulesUnderRowLockPG 請求 A（webhook 改 slack_app、帶 token 與網址 U1）取得列鎖後暫停，
// 同時送出請求 B（只改網址為 U2、不帶 token）；放行 A 後 B 以 A 提交後的型別判斷而被拒，U2 收不到帶授權標頭的請求。
func TestChannelUpdateRulesUnderRowLockPG(t *testing.T) {
	e := newNDLEnvPG(t)
	if err := e.db.AutoMigrate(&model.AuditLog{}, &model.SystemAlertSeverityOverride{}); err != nil {
		t.Fatal(err)
	}
	svc := newChannelSvcPG(e)
	u0 := newStubSrv(t, nil, nil)
	u1 := newStubSrv(t, nil, respondJSON(200, `{"ok":true}`))
	u2 := newStubSrv(t, nil, respondJSON(200, `{"ok":true}`))
	created, err := svc.Create(&NotificationChannelRequest{Name: "w", URL: u0.srv.URL, ActorID: 1, ActorName: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	aLocked := make(chan struct{})
	releaseA := make(chan struct{})
	var once sync.Once
	channelUpdateLockedHook = func(uint) {
		first := false
		once.Do(func() { first = true })
		if first {
			close(aLocked)
			<-releaseA
		}
	}
	t.Cleanup(func() { channelUpdateLockedHook = nil })

	var errA, errB error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, errA = svc.Update(created.ID, &NotificationChannelRequest{Name: "w", Type: model.NotificationChannelTypeSlackApp,
			URL: u1.srv.URL, Secret: testSlackToken, Target: "C1", ActorID: 1, ActorName: "admin"})
	}()
	<-aLocked
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, errB = svc.Update(created.ID, &NotificationChannelRequest{Name: "w", URL: u2.srv.URL, ActorID: 2, ActorName: "other"})
	}()
	time.Sleep(300 * time.Millisecond) // B 此時應卡在列鎖上
	close(releaseA)
	wg.Wait()
	if errA != nil {
		t.Fatalf("A 應成功: %v", errA)
	}
	if !errors.Is(errB, ErrChannelURLChangeNeedsSecret) {
		t.Fatalf("B 應以 A 提交後的型別判斷而被拒: %v", errB)
	}
	var ch model.NotificationChannel
	e.db.First(&ch, created.ID)
	if ch.Type != model.NotificationChannelTypeSlackApp || ch.URL != u1.srv.URL {
		t.Fatalf("通道應為 slack_app 且網址為 U1: type=%s url=%s", ch.Type, ch.URL)
	}
	w := fastWorker(e.db)
	for i := 0; i < 3; i++ {
		w.RunOnce()
		time.Sleep(1100 * time.Millisecond)
	}
	if n := authorizedRequests(u2); n != 0 {
		t.Fatalf("U2 不應收到帶授權標頭的請求，得 %d", n)
	}
}

// newChannelSvcPG PG 測試環境的通道服務（審計與系統告警落地面同交易）。
func newChannelSvcPG(e *ndlEnv) *NotificationChannelService {
	svc := NewNotificationChannelService(e.db, nil)
	svc.SetAuditTxSink(NewTxSink())
	svc.SetSystemAlertSink(NewSystemAlertSink(nil))
	return svc
}

// TestDeliveryAbandonedNoticeConcurrentPG 兩個交易各自放棄通道 A 的一筆紀錄，在節流條件更新之前會合再同時執行：
// 內容列只有一列，兩筆紀錄都是 abandoned。
func TestDeliveryAbandonedNoticeConcurrentPG(t *testing.T) {
	e := newNDLEnvPG(t)
	srv := newStubSrv(t, e.clock, nil)
	chA := e.channel("chan-A", "webhook", srv.srv.URL, true, "low")
	e.channel("chan-B", "webhook", srv.srv.URL, true, "low")
	r1 := e.liveRow(chA.ID, model.AlertSeverityMedium, 48)
	r2 := e.liveRow(chA.ID, model.AlertSeverityMedium, 48)
	var arrived sync.WaitGroup
	arrived.Add(2)
	e.w.hooks.beforeAbandonThrottle = func() {
		arrived.Done()
		arrived.Wait()
	}
	var wg sync.WaitGroup
	for _, r := range []model.NotificationDelivery{r1, r2} {
		r := r
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.w.abandon(r, model.NotificationEndMaxAttempts, e.clock.now(), true)
		}()
	}
	wg.Wait()
	if n := len(abandonNotices(e)); n != 1 {
		t.Fatalf("內容列應只有一列，得 %d", n)
	}
	for _, r := range []model.NotificationDelivery{r1, r2} {
		if got := e.row(r.ID); got.State != model.NotificationDeliveryAbandoned {
			t.Fatalf("紀錄 %d 應為 abandoned: %s", r.ID, got.State)
		}
	}
}
