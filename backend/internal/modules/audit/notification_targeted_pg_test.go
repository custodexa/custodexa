package audit

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// 定向通知的 PostgreSQL 專屬行為（TEST_PG_DSN gated）：未能送達事件的並行節流、
// 兩個通道並行開啟對個人派送（4.1 (b)）、放棄交易與關閉對個人派送並行的鎖序（4.1 (d)）。

type tnlPGEnv struct {
	*ndlEnv
	svc *NotificationChannelService
}

func newTNLPGEnv(t *testing.T) *tnlPGEnv {
	t.Helper()
	e := newNDLEnvPG(t)
	if err := e.db.AutoMigrate(&model.AuditLog{}, &model.SystemAlertSeverityOverride{}); err != nil {
		t.Fatal(err)
	}
	// 與 migration 相同的部分唯一索引（資料庫兜底「至多一個通道開啟」）
	if err := e.db.Exec(`CREATE UNIQUE INDEX idx_notification_channels_direct_message ON notification_channels ((1)) WHERE direct_message_enabled`).Error; err != nil {
		t.Fatal(err)
	}
	t.Setenv(dmExtraHostsEnv, "127.0.0.1")
	resetDMCache()
	t.Cleanup(resetDMCache)
	return &tnlPGEnv{ndlEnv: e, svc: newChannelSvcPG(e)}
}

// userRow 直接建一筆重送中的個人紀錄。
func (e *tnlPGEnv) userRow(chID uint, recipient uint) model.NotificationDelivery {
	e.t.Helper()
	msg := model.NotificationMessage{Category: model.NotificationCategorySystemEvent, EventKey: string(notifycat.EventAccessRequestCreated),
		Severity: model.AlertSeverityMedium, OccurredAt: e.clock.now(), Params: `{"request_id":"1"}`, NameRefs: `{}`,
		State: model.NotificationMessageDispatched, CreatedAt: e.clock.now()}
	if err := e.db.Create(&msg).Error; err != nil {
		e.t.Fatal(err)
	}
	key, _ := newDeliveryKey()
	ch, mid, uid := chID, msg.ID, recipient
	row := model.NotificationDelivery{Category: model.NotificationCategorySystemEvent, MessageID: &mid, Severity: model.AlertSeverityMedium,
		SourceChannelID: &ch, State: model.NotificationDeliveryRetrying, Attempts: 1, NextAttemptAt: e.clock.now(),
		CreatedAt: e.clock.now(), DeliveryKey: key, Audience: deliveryAudienceUser, RecipientUserID: &uid}
	if err := e.db.Create(&row).Error; err != nil {
		e.t.Fatal(err)
	}
	return row
}

func (e *tnlPGEnv) appChannel(name string, dm bool) model.NotificationChannel {
	e.t.Helper()
	r := &NotificationChannelRequest{Name: name, Type: model.NotificationChannelTypeSlackApp, URL: "http://127.0.0.1:9/api",
		Secret: tnlToken, Target: tnlTarget, ActorID: 5, ActorName: "sec-admin"}
	if dm {
		r.DirectMessageEnabled = boolp(true)
	}
	ch, err := e.svc.Create(r)
	if err != nil {
		e.t.Fatal(err)
	}
	return *ch
}

// TestTargetedUndeliveredConcurrentPG 兩個交易並行放棄同一通道的個人紀錄，只產生一則未能送達事件。
func TestTargetedUndeliveredConcurrentPG(t *testing.T) {
	e := newTNLPGEnv(t)
	ch := e.appChannel("dm", true)
	r1, r2 := e.userRow(ch.ID, 101), e.userRow(ch.ID, 102)
	var arrived sync.WaitGroup
	arrived.Add(2)
	e.w.hooks.beforeTargetedThrottle = func() {
		arrived.Done()
		arrived.Wait()
	}
	var wg sync.WaitGroup
	for _, r := range []model.NotificationDelivery{r1, r2} {
		r := r
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.w.abandon(r, model.NotificationEndNoEmail, e.clock.now(), true)
		}()
	}
	wg.Wait()
	var n int64
	e.db.Model(&model.NotificationMessage{}).Where("event_key = ?", string(notifycat.EventTargetedNotificationUndelivered)).Count(&n)
	if n != 1 {
		t.Fatalf("應只產生一則未能送達事件，得 %d", n)
	}
	for _, r := range []model.NotificationDelivery{r1, r2} {
		if got := e.row(r.ID); got.State != model.NotificationDeliveryAbandoned || got.EndReason != model.NotificationEndNoEmail {
			t.Fatalf("紀錄 %d: state=%s end=%q", r.ID, got.State, got.EndReason)
		}
	}
}

// TestTargetedChannelConcurrentEnablePG 兩個請求並行在兩個通道開啟，只有一個成功，另一個收到帶名稱的可讀錯誤。
func TestTargetedChannelConcurrentEnablePG(t *testing.T) {
	e := newTNLPGEnv(t)
	a, b := e.appChannel("通道甲", false), e.appChannel("通道乙", false)
	for i := 0; i < 10; i++ {
		e.db.Model(&model.NotificationChannel{}).Where("id IN ?", []uint{a.ID, b.ID}).Update("direct_message_enabled", false)
		start := make(chan struct{})
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for j, ch := range []model.NotificationChannel{a, b} {
			j, ch := j, ch
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[j] = e.svc.Update(ch.ID, &NotificationChannelRequest{Name: ch.Name, DirectMessageEnabled: boolp(true), ActorID: 5, ActorName: "sec-admin"})
			}()
		}
		close(start)
		wg.Wait()
		ok := 0
		for j, err := range errs {
			if err == nil {
				ok++
				continue
			}
			var conflict *DirectMessageConflictError
			other := []string{"通道乙", "通道甲"}[j]
			if !errors.As(err, &conflict) || conflict.Name != other {
				t.Fatalf("第 %d 輪：失敗的一方應收到指出 %s 的錯誤，得 %v", i, other, err)
			}
		}
		if ok != 1 {
			t.Fatalf("第 %d 輪：應恰好一個成功，得 %d（%v）", i, ok, errs)
		}
	}
}

// TestTargetedAbandonVersusDisablePG 放棄交易（含 dm_issue_notified_at 條件更新）與關閉對個人派送同時進行 50 次，
// 兩者都成功，沒有死鎖錯誤。放棄交易先持有待投遞紀錄、在更新通道列前暫停，期間關閉對個人派送。
func TestTargetedAbandonVersusDisablePG(t *testing.T) {
	e := newTNLPGEnv(t)
	ch := e.appChannel("dm", true)
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	for i := 0; i < 50; i++ {
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).Updates(map[string]any{"direct_message_enabled": true, "dm_issue_notified_at": nil})
		victim := e.userRow(ch.ID, uint(1000+i))
		others := []model.NotificationDelivery{e.userRow(ch.ID, uint(2000+i)), e.userRow(ch.ID, uint(3000+i))}
		holding := make(chan struct{})
		release := make(chan struct{})
		e.w.hooks.beforeTargetedThrottle = func() {
			close(holding)
			<-release
		}
		var wg sync.WaitGroup
		var abandoned bool
		wg.Add(2)
		go func() {
			defer wg.Done()
			abandoned = e.w.abandon(victim, model.NotificationEndNoEmail, e.clock.now(), true)
		}()
		var updErr error
		go func() {
			defer wg.Done()
			<-holding
			done := make(chan struct{})
			go func() {
				_, updErr = e.svc.Update(ch.ID, &NotificationChannelRequest{Name: "dm", DirectMessageEnabled: boolp(false), ActorID: 5, ActorName: "sec-admin"})
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(300 * time.Millisecond):
			}
			close(release)
			<-done
		}()
		wg.Wait()
		e.w.hooks.beforeTargetedThrottle = nil
		if updErr != nil {
			t.Fatalf("第 %d 次：關閉對個人派送失敗: %v", i, updErr)
		}
		if !abandoned {
			t.Fatalf("第 %d 次：放棄應成立", i)
		}
		for _, o := range others {
			if got := e.row(o.ID); got.State != model.NotificationDeliveryCanceled {
				t.Fatalf("第 %d 次：其他個人紀錄應取消: %s", i, got.State)
			}
		}
	}
	if s := buf.String(); strings.Contains(s, "deadlock") || strings.Contains(s, "40P01") {
		t.Fatalf("出現死鎖錯誤:\n%s", lastLines(s, 20))
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

var _ = fmt.Sprint
