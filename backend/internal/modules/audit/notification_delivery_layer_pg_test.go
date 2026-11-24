package audit

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 通知投遞層的 PostgreSQL 專屬行為（TEST_PG_DSN gated）：savepoint 讓交易免於 aborted、分派收尾的條件更新
// 在並行下只讓一個交易成功、依目的地輪流取件的視窗函式。

func newNDLEnvPG(t *testing.T) *ndlEnv {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	schema := "ndl_" + hex.EncodeToString(b[:])
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	for _, s := range []string{
		`CREATE TABLE command_alerts (id BIGSERIAL PRIMARY KEY, rule_id BIGINT, rule_name TEXT NOT NULL, session_id BIGINT,
			user_id BIGINT NOT NULL, asset_id BIGINT, command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at TIMESTAMPTZ NOT NULL,
			reviewed_by BIGINT, reviewed_at TIMESTAMPTZ, disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
			blocked BOOLEAN NOT NULL DEFAULT false, kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE users (id BIGINT PRIMARY KEY, username TEXT NOT NULL DEFAULT '', deleted_at TIMESTAMPTZ)`,
		`CREATE TABLE assets (id BIGINT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', deleted_at TIMESTAMPTZ)`,
		`CREATE TABLE sessions (id BIGINT PRIMARY KEY, client_ip TEXT NOT NULL DEFAULT '', deleted_at TIMESTAMPTZ)`,
		`CREATE TABLE session_commands (id BIGSERIAL PRIMARY KEY, session_id BIGINT, degraded BOOLEAN NOT NULL DEFAULT false,
			executed_at TIMESTAMPTZ, degrade_reason TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE biz (id BIGSERIAL PRIMARY KEY, v TEXT)`,
	} {
		if err := db.Exec(s).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AutoMigrate(&model.SystemAlertDetail{}, &model.NotificationDelivery{}, &model.NotificationChannel{},
		&model.NotificationMessage{}); err != nil {
		t.Fatal(err)
	}
	clock := newFakeClock()
	n := NewAlertNotifier(db, nil)
	n.now = clock.now
	w := NewSystemAlertOutboxWorker(db, nil)
	w.tee = func(model.CommandAlert) {}
	w.now = clock.now
	w.UseEnqueueStats(n.EnqueueStats())
	rep := newRecordingReporter()
	w.reporter = rep
	w.sleep = clock.advance
	return &ndlEnv{t: t, db: db, clock: clock, n: n, w: w, rep: rep}
}

func TestEnqueueInTxSavepointPG(t *testing.T) {
	e := newNDLEnvPG(t)
	// (a) 業務交易回滾時內容列一起消失
	_ = e.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`INSERT INTO biz (v) VALUES ('a')`).Error; err != nil {
			return err
		}
		if err := e.n.EnqueueInTx(tx, SystemEventNotice(notifycat.EventDailyReviewOverdue, nil)); err != nil {
			t.Fatalf("排入應成功: %v", err)
		}
		return errors.New("rollback")
	})
	if n := len(e.messages()); n != 0 {
		t.Fatalf("(a) 內容列應為 0，得 %d", n)
	}
	// (b) 觸發器讓內容列 INSERT 失敗：回到 savepoint 後業務交易仍能繼續並提交
	for _, s := range []string{
		`CREATE FUNCTION fail_msg() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$ LANGUAGE plpgsql`,
		`CREATE TRIGGER fail_msg BEFORE INSERT ON notification_messages FOR EACH ROW EXECUTE FUNCTION fail_msg()`,
	} {
		if err := e.db.Exec(s).Error; err != nil {
			t.Fatal(err)
		}
	}
	err := e.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`INSERT INTO biz (v) VALUES ('b')`).Error; err != nil {
			return err
		}
		if err := e.n.EnqueueInTx(tx, SystemEventNotice(notifycat.EventDailyReviewOverdue, nil)); err == nil {
			t.Fatal("故障注入下排入應回錯")
		}
		if events, _, _ := e.rep.state(model.MechanismNotificationDelivery); events != 0 {
			t.Fatal("提交前不得有失效事件")
		}
		return tx.Exec(`INSERT INTO biz (v) VALUES ('b2')`).Error
	})
	if err != nil {
		t.Fatalf("(b) 業務交易應提交（savepoint 讓交易免於 aborted）: %v", err)
	}
	var biz int64
	e.db.Raw(`SELECT COUNT(*) FROM biz WHERE v IN ('b','b2')`).Scan(&biz)
	if biz != 2 || len(e.messages()) != 0 {
		t.Fatalf("(b) 業務列 %d（應 2）內容列 %d（應 0）", biz, len(e.messages()))
	}
	e.w.RunOnce()
	if events, _, open := e.rep.state(model.MechanismNotificationDelivery); events != 1 || !open {
		t.Fatalf("(b) 一輪後應回報: events=%d open=%v", events, open)
	}
	e.db.Exec(`DROP TRIGGER fail_msg ON notification_messages`)
	e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
	e.w.RunOnce()
	if _, ended, open := e.rep.state(model.MechanismNotificationDelivery); ended != 1 || open {
		t.Fatalf("(c) 成功排入後一輪應結束: ended=%d open=%v", ended, open)
	}
}

func TestDispatchConcurrentClaimPG(t *testing.T) {
	e := newNDLEnvPG(t)
	e.channel("a", "webhook", "http://127.0.0.1:1/a", true, "low")
	e.channel("b", "webhook", "http://127.0.0.1:1/b", true, "low")
	e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
	id := e.messages()[0].ID

	var arrive sync.WaitGroup
	arrive.Add(2)
	release := make(chan struct{})
	barrier := func(*gorm.DB, uint) {
		arrive.Done()
		<-release
	}
	mk := func(offset time.Duration) *SystemAlertOutboxWorker {
		w := NewSystemAlertOutboxWorker(e.db, nil)
		w.tee = func(model.CommandAlert) {}
		w.lease = 0
		base := e.clock.now().Add(offset)
		w.now = func() time.Time { return base }
		w.reporter = nopFailureReporter{}
		w.hooks.beforeDispatchFinalize = barrier
		return w
	}
	w1, w2 := mk(0), mk(time.Millisecond)
	if !w1.claimMessage(id, w1.now()) || !w2.claimMessage(id, w2.now()) {
		t.Fatal("租約為 0 時兩個執行個體都應能認領")
	}
	var done sync.WaitGroup
	done.Add(2)
	go func() { defer done.Done(); w1.dispatchClaimed(id) }()
	go func() { defer done.Done(); w2.dispatchClaimed(id) }()
	waitCh := make(chan struct{})
	go func() { arrive.Wait(); close(waitCh) }()
	select {
	case <-waitCh:
	case <-time.After(10 * time.Second):
		t.Fatal("兩個分派交易沒有在收尾前會合")
	}
	close(release)
	done.Wait()
	if n := len(e.deliveries()); n != 2 {
		t.Fatalf("並行分派後紀錄應恰兩筆，得 %d", n)
	}
	if m := e.messages()[0]; m.State != model.NotificationMessageDispatched {
		t.Fatalf("內容列應已分派: %s", m.State)
	}
}

func TestDeliveryRoundRobinQueryPG(t *testing.T) {
	e := newNDLEnvPG(t)
	bad := newStubSrv(t, nil, respondStatus(http.StatusServiceUnavailable))
	good := newStubSrv(t, nil, nil)
	cd := e.channel("D", "webhook", bad.srv.URL, true, "low")
	ch := e.channel("H", "webhook", good.srv.URL, true, "low")
	for i := 0; i < 300; i++ {
		e.liveRow(cd.ID, "high", 0)
	}
	for i := 0; i < 5; i++ {
		e.liveRow(ch.ID, "low", 0)
	}
	e.w.RunOnce()
	if good.count() != 5 || bad.count() != 1 {
		t.Fatalf("H=%d（應 5）D=%d（應 1）", good.count(), bad.count())
	}
	var notOne int64
	e.db.Model(&model.NotificationDelivery{}).Where("source_channel_id = ? AND attempts <> 1", cd.ID).Count(&notOne)
	if notOne != 0 {
		t.Fatalf("D 的 300 筆應全部計一次，有 %d 筆不是", notOne)
	}
}
