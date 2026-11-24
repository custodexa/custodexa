package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 通知投遞層段 C：各產生點改為排入後的行為（指令告警批次寫入、新來源位址、稽核失效退路、
// 每日審閱逾期、AI agent、系統安全告警的目標名稱與去重）。

// ---- 共用替身 ----

// failNotificationInserts 讓 notification_messages 的 INSERT 在 flag 為真時失敗（GORM 層故障注入）。
func failNotificationInserts(t testing.TB, db *gorm.DB, flag *atomic.Bool) {
	t.Helper()
	name := "test:fail_notification_messages"
	if err := db.Callback().Create().Before("gorm:create").Register(name, func(d *gorm.DB) {
		if flag.Load() && d.Statement != nil && d.Statement.Table == "notification_messages" {
			_ = d.AddError(errors.New("injected notification_messages insert failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Callback().Create().Remove(name) })
}

// useSingletonNotifier 把排入介面設為套件單例（產生點經 GetAlertNotifier 取用），測試結束還原。
func useSingletonNotifier(t testing.TB, n *AlertNotifier) {
	t.Helper()
	alertNotifierMu.Lock()
	prev := alertNotifierInstance
	alertNotifierInstance = n
	alertNotifierMu.Unlock()
	t.Cleanup(func() {
		alertNotifierMu.Lock()
		alertNotifierInstance = prev
		alertNotifierMu.Unlock()
	})
}

// sqlRecorder 記錄執行的 SQL 語句（GORM logger）。
type sqlRecorder struct {
	mu    sync.Mutex
	stmts []string
}

func (r *sqlRecorder) LogMode(logger.LogLevel) logger.Interface      { return r }
func (r *sqlRecorder) Info(context.Context, string, ...interface{})  {}
func (r *sqlRecorder) Warn(context.Context, string, ...interface{})  {}
func (r *sqlRecorder) Error(context.Context, string, ...interface{}) {}
func (r *sqlRecorder) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sql, _ := fc()
	r.mu.Lock()
	r.stmts = append(r.stmts, sql)
	r.mu.Unlock()
}

func (r *sqlRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.stmts...)
}

// countingCodec 計數加解密呼叫次數的替身（明文直通）。
type countingCodec struct{ enc, dec atomic.Int64 }

func (c *countingCodec) EncryptFor(_ context.Context, _ crypto.CipherRef, p string) (string, error) {
	c.enc.Add(1)
	return p, nil
}
func (c *countingCodec) DecryptFor(_ context.Context, _ crypto.CipherRef, s string) (string, error) {
	c.dec.Add(1)
	return s, nil
}

func messageParams(t testing.TB, m model.NotificationMessage) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := json.Unmarshal([]byte(m.Params), &out); err != nil {
		t.Fatalf("內容列參數無法解析: %v", err)
	}
	return out
}

// ---- 6.1 指令告警：告警列之後一次批次寫內容 ----

func TestRecordAlertsWritesNotificationBatch(t *testing.T) {
	t.Run("一批三筆告警：內容列一句 INSERT 三列，沒有讀通道也沒有加解密", func(t *testing.T) {
		e := newNDLEnv(t)
		codec := &countingCodec{}
		rec := &sqlRecorder{}
		quiet := e.db.Session(&gorm.Session{Logger: rec})
		n := NewAlertNotifier(quiet, codec)
		useSingletonNotifier(t, n)
		e.channel("ops", "webhook", "https://example.test/h", true, "")
		recorder := NewAlertRecorder(quiet)
		asset := uint(5)
		alerts := []gatewayapi.CommandAlert{
			{RuleName: "r1", Kind: model.AlertKindRule, Actor: gatewayapi.Actor{UserID: 1}, AssetID: &asset, SessionID: 9, Command: "a", Level: "high", OccurredAt: e.clock.now(), Disposition: model.AlertDispositionPending},
			{RuleName: "r2", Kind: model.AlertKindRule, Actor: gatewayapi.Actor{UserID: 1}, AssetID: &asset, SessionID: 9, Command: "b", Level: "medium", OccurredAt: e.clock.now(), Disposition: model.AlertDispositionPending},
			{RuleName: "r3", Kind: model.AlertKindRule, Actor: gatewayapi.Actor{UserID: 1}, AssetID: &asset, SessionID: 9, Command: "c", Level: "low", OccurredAt: e.clock.now(), Disposition: model.AlertDispositionPending},
		}
		if err := recorder.RecordAlerts(context.Background(), alerts); err != nil {
			t.Fatal(err)
		}
		stmts := rec.snapshot()
		inserts := 0
		for _, s := range stmts {
			upper := strings.ToUpper(s)
			if strings.Contains(upper, "NOTIFICATION_CHANNELS") {
				t.Fatalf("產生點不得讀通道: %s", s)
			}
			if strings.HasPrefix(upper, "INSERT") {
				inserts++
			}
		}
		if len(stmts) != 2 || inserts != 2 {
			t.Fatalf("應恰為兩句 INSERT（告警列、內容列），得 %d 句: %v", len(stmts), stmts)
		}
		if !strings.Contains(stmts[1], "notification_messages") {
			t.Fatalf("第二句應寫內容列: %s", stmts[1])
		}
		if codec.enc.Load() != 0 || codec.dec.Load() != 0 {
			t.Fatalf("產生點不得加解密: enc=%d dec=%d", codec.enc.Load(), codec.dec.Load())
		}
		msgs := e.messages()
		if len(msgs) != 3 {
			t.Fatalf("內容列應為 3，得 %d", len(msgs))
		}
		for _, m := range msgs {
			if m.Category != model.NotificationCategoryCommandAlert || m.AlertID == nil || m.State != model.NotificationMessagePending {
				t.Fatalf("內容列欄位不符: %+v", m)
			}
		}
	})

	t.Run("內容列寫入失敗：告警列仍在、回傳 nil，下一輪回報稽核失效", func(t *testing.T) {
		e := newNDLEnv(t)
		useSingletonNotifier(t, e.n)
		var fail atomic.Bool
		fail.Store(true)
		failNotificationInserts(t, e.db, &fail)
		recorder := NewAlertRecorder(e.db)
		err := recorder.RecordAlert(context.Background(), gatewayapi.CommandAlert{RuleName: "r", Kind: model.AlertKindRule,
			Actor: gatewayapi.Actor{UserID: 1}, Command: "x", Level: "high", OccurredAt: e.clock.now(), Disposition: model.AlertDispositionPending, Blocked: true})
		if err != nil {
			t.Fatalf("內容寫不進去不得回錯給呼叫端: %v", err)
		}
		var alerts int64
		e.db.Model(&model.CommandAlert{}).Count(&alerts)
		if alerts != 1 || len(e.messages()) != 0 {
			t.Fatalf("告警列 %d（應 1）內容列 %d（應 0）", alerts, len(e.messages()))
		}
		if events, _, _ := e.rep.state(model.MechanismNotificationDelivery); events != 0 {
			t.Fatal("寫入當下不得回報")
		}
		e.w.RunOnce()
		if events, _, open := e.rep.state(model.MechanismNotificationDelivery); events != 1 || !open {
			t.Fatalf("一輪後應回報 notification_delivery: events=%d open=%v", events, open)
		}
	})

	t.Run("agent 熔斷與系統安全告警的告警列不產生指令告警內容", func(t *testing.T) {
		e := newNDLEnv(t)
		useSingletonNotifier(t, e.n)
		recorder := NewAlertRecorder(e.db)
		for _, kind := range []string{model.AlertKindAgentBreaker, model.AlertKindSystemSecurity} {
			if err := recorder.RecordAlert(context.Background(), gatewayapi.CommandAlert{RuleName: kind, Kind: kind,
				Actor: gatewayapi.Actor{UserID: 1}, Level: "high", OccurredAt: e.clock.now(), Disposition: model.AlertDispositionPending}); err != nil {
				t.Fatal(err)
			}
		}
		if n := len(e.messages()); n != 0 {
			t.Fatalf("不應產生內容列，得 %d", n)
		}
	})
}

// ---- 6.2 新來源位址：交易內以 savepoint 寫內容 ----

func setupSourceIPPipeline(t *testing.T) (*ndlEnv, *SourceIPBaseline) {
	t.Helper()
	e := newNDLEnv(t)
	useSingletonNotifier(t, e.n)
	if err := e.db.Exec(`CREATE TABLE IF NOT EXISTS user_source_ips (user_id INTEGER NOT NULL, client_ip TEXT NOT NULL,
		first_seen_at DATETIME, last_seen_at DATETIME, first_session_at DATETIME, first_session_id INTEGER,
		PRIMARY KEY (user_id, client_ip))`).Error; err != nil {
		t.Fatal(err)
	}
	return e, NewSourceIPBaseline(e.db, NewAlertRecorder(e.db), NewTxSink())
}

func TestSourceIPAlertEnqueuedInTx(t *testing.T) {
	t.Run("內容列寫入失敗：基準與告警列照常提交，建線不受影響", func(t *testing.T) {
		e, b := setupSourceIPPipeline(t)
		var fail atomic.Bool
		fail.Store(true)
		failNotificationInserts(t, e.db, &fail)
		winner, err := b.ObserveSession(context.Background(), 1, "203.0.113.7", 11, nil, e.clock.now())
		if err != nil || !winner {
			t.Fatalf("建線觀察應成功並取得勝者: winner=%v err=%v", winner, err)
		}
		var base, alerts int64
		e.db.Table("user_source_ips").Count(&base)
		e.db.Model(&model.CommandAlert{}).Where("kind = ?", model.AlertKindNewSourceIP).Count(&alerts)
		if base != 1 || alerts != 1 || len(e.messages()) != 0 {
			t.Fatalf("基準 %d 告警 %d（應各 1）內容 %d（應 0）", base, alerts, len(e.messages()))
		}
	})
	t.Run("業務交易回滾時內容列不存在；成功時內容列指向告警列", func(t *testing.T) {
		e, b := setupSourceIPPipeline(t)
		b.afterAlertWrite = func() error { return errors.New("injected rollback") }
		if _, err := b.ObserveSession(context.Background(), 1, "203.0.113.8", 12, nil, e.clock.now()); err == nil {
			t.Fatal("應回錯")
		}
		if n := len(e.messages()); n != 0 {
			t.Fatalf("回滾後內容列應為 0，得 %d", n)
		}
		b.afterAlertWrite = nil
		if winner, err := b.ObserveSession(context.Background(), 1, "203.0.113.8", 13, nil, e.clock.now()); err != nil || !winner {
			t.Fatalf("第二次應成功: %v %v", winner, err)
		}
		msgs := e.messages()
		if len(msgs) != 1 || msgs[0].AlertID == nil || msgs[0].Category != model.NotificationCategoryCommandAlert {
			t.Fatalf("內容列不符: %+v", msgs)
		}
	})
}

// ---- 6.6 稽核失效一族的退路 ----

type auditFailureFixture struct {
	e    *ndlEnv
	svc  *AuditFailureService
	stub *stubSrv
	ch   model.NotificationChannel
}

func newAuditFailureFixture(t *testing.T, respond func(int, http.ResponseWriter, *http.Request)) *auditFailureFixture {
	t.Helper()
	e := newNDLEnv(t)
	if err := e.db.AutoMigrate(&model.AuditFailureEvent{}, &model.SecurityPolicy{}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Create(&model.SecurityPolicy{Key: policy.PolicyFailureAlertEnabled, Value: "true"}).Error; err != nil {
		t.Fatal(err)
	}
	stub := newStubSrv(t, e.clock, respond)
	ch := e.channel("ops", "webhook", stub.srv.URL, true, "")
	svc := &AuditFailureService{db: e.db, policy: policy.NewSecurityPolicyService(e.db)}
	svc.notify = e.n.EnqueueAuditFailureNotice
	e.n.backoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	e.n.sleep = func(time.Duration) {}
	e.w.UseAuditFallback(e.n.AuditFallbackList())
	e.w.reporter = svc
	return &auditFailureFixture{e: e, svc: svc, stub: stub, ch: ch}
}

func (f *auditFailureFixture) failureEvents(mechanism string) int64 {
	var n int64
	f.e.db.Model(&model.AuditFailureEvent{}).Where("mechanism = ?", mechanism).Count(&n)
	return n
}

func (f *auditFailureFixture) failDB() {
	injected := errors.New("injected database unavailable")
	f.e.n.auditHooks.beforeWrite = func(notifycat.Event) error { return injected }
	f.e.n.auditHooks.beforeChannelRead = func() error { return injected }
}

func (f *auditFailureFixture) eventsOf(stub *stubSrv) []string {
	var out []string
	for i := 0; i < stub.count(); i++ {
		var body struct {
			Event  string         `json:"event"`
			Params map[string]any `json:"params"`
		}
		_ = json.Unmarshal(stub.body(i), &body)
		out = append(out, body.Event+"/"+toString(body.Params["mechanism"]))
	}
	return out
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

func TestAuditFailureNoticeFallback(t *testing.T) {
	t.Run("(a) 資料庫可用：一筆內容列、替身收到一次、失效事件只有原本那一筆", func(t *testing.T) {
		f := newAuditFailureFixture(t, nil)
		f.svc.Report(model.MechanismSyslogForward, model.CauseSyslogConnectFailed, nil)
		f.e.n.waitAuditNotices()
		if n := len(f.e.messages()); n != 1 {
			t.Fatalf("內容列應為 1，得 %d", n)
		}
		f.e.w.RunOnce()
		if f.stub.count() != 1 {
			t.Fatalf("替身應收到一次，得 %d", f.stub.count())
		}
		var all int64
		f.e.db.Model(&model.AuditFailureEvent{}).Count(&all)
		if all != 1 {
			t.Fatalf("失效事件應只有原本那一筆，得 %d", all)
		}
	})

	t.Run("(b) 啟動後未產生任何通知：寫入與讀通道都失敗時仍以清單直接送出，且不產生新的失效事件", func(t *testing.T) {
		f := newAuditFailureFixture(t, nil)
		f.e.w.RunOnce() // 啟動後的第一輪：換新退路清單
		f.failDB()
		f.svc.Report(model.MechanismAuditWrite, model.CauseAuditWriteSyncRefused, nil)
		f.e.n.waitAuditNotices()
		if f.stub.count() != 1 {
			t.Fatalf("替身應收到一次（來自啟動時讀到的清單），得 %d", f.stub.count())
		}
		if got := f.eventsOf(f.stub); got[0] != "audit_failure/"+model.MechanismAuditWrite {
			t.Fatalf("送出的不是這則失效通知: %v", got)
		}
		f.e.w.RunOnce()
		if n := f.failureEvents(model.MechanismNotificationDelivery) + f.failureEvents(model.MechanismNotificationDispatch); n != 0 {
			t.Fatalf("不得產生 notification_delivery／notification_dispatch 事件，得 %d", n)
		}
		if n := len(f.e.messages()); n != 0 {
			t.Fatalf("內容列應為 0，得 %d", n)
		}
	})

	t.Run("(c) 通道停用後跑一輪，再觸發同樣情境：該通道收到 0 次", func(t *testing.T) {
		f := newAuditFailureFixture(t, nil)
		f.e.w.RunOnce()
		f.e.db.Model(&model.NotificationChannel{}).Where("id = ?", f.ch.ID).Update("enabled", false)
		f.e.w.RunOnce()
		f.failDB()
		f.svc.Report(model.MechanismAuditWrite, model.CauseAuditWriteSyncRefused, nil)
		f.e.n.waitAuditNotices()
		if f.stub.count() != 0 {
			t.Fatalf("停用的通道不得收到，得 %d", f.stub.count())
		}
	})

	t.Run("(d) 持續失效帶真實起點；補列事件不帶", func(t *testing.T) {
		f := newAuditFailureFixture(t, nil)
		started := time.Date(2026, 11, 1, 3, 4, 5, 0, time.UTC)
		f.e.db.Create(&model.AuditFailureEvent{Mechanism: model.MechanismKEKRetirement, StartedAt: started,
			CauseCode: model.CauseKEKRetirementBacklog})
		f.e.db.Create(&model.AuditFailureEvent{Mechanism: model.MechanismAuditChainStructure, StartedAt: started,
			CauseCode: model.CauseAuditChainStructureInvalid, Details: failureEventBackfillDetails})
		f.svc.NotifyOngoing(notifycat.EventAuditFailureOngoing, map[string]string{"mechanism": model.MechanismKEKRetirement,
			"cause_code": model.CauseKEKRetirementBacklog, "reported_at": started.Add(time.Hour).Format(time.RFC3339)})
		f.svc.NotifyOngoing(notifycat.EventAuditFailureOngoing, map[string]string{"mechanism": model.MechanismAuditChainStructure,
			"cause_code": model.CauseAuditChainStructureInvalid, "reported_at": started.Add(time.Hour).Format(time.RFC3339)})
		f.e.n.waitAuditNotices()
		msgs := f.e.messages()
		if len(msgs) != 2 {
			t.Fatalf("內容列應為 2，得 %d", len(msgs))
		}
		byMech := map[string]map[string]string{}
		for _, m := range msgs {
			p := messageParams(t, m)
			byMech[p["mechanism"]] = p
		}
		if got := byMech[model.MechanismKEKRetirement]["started_at"]; got != started.Format(time.RFC3339) {
			t.Fatalf("持續失效應帶真實起點，得 %q", got)
		}
		if got, ok := byMech[model.MechanismAuditChainStructure]["started_at"]; ok {
			t.Fatalf("補列事件不得帶起點，得 %q", got)
		}
	})

	t.Run("(e) 無自我死鎖：真的服務與入口，寫入成功與失敗各一次都在 1 秒內返回", func(t *testing.T) {
		f := newAuditFailureFixture(t, nil)
		auditFailureMu.Lock()
		prev := auditFailureInstance
		auditFailureInstance = f.svc
		auditFailureMu.Unlock()
		t.Cleanup(func() {
			auditFailureMu.Lock()
			auditFailureInstance = prev
			auditFailureMu.Unlock()
		})
		within := func(name string, fn func()) {
			t.Helper()
			done := make(chan struct{})
			go func() { fn(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatalf("%s 未在 1 秒內返回", name)
			}
		}
		within("Report（寫入成功）", func() { f.svc.Report(model.MechanismSyslogForward, model.CauseSyslogConnectFailed, nil) })
		f.e.n.auditHooks.beforeWrite = func(notifycat.Event) error { return errors.New("injected") }
		within("Report（寫入失敗）", func() { f.svc.Report(model.MechanismAuditWrite, model.CauseAuditWriteSyncRefused, nil) })
		within("Report 另一個機制", func() { f.svc.Report(model.MechanismRecordingProbe, model.CauseSyslogConnectFailed, nil) })
		within("Resolve", func() { f.svc.Resolve(model.MechanismSyslogForward) })
		f.e.n.waitAuditNotices()
	})

	t.Run("(f) 直接送出不拖住鎖：A 的送出掛住時，B 的 Report 在 200 毫秒內返回", func(t *testing.T) {
		release := make(chan struct{})
		f := newAuditFailureFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
			if n == 0 {
				<-release
			}
			w.WriteHeader(http.StatusOK)
		})
		f.e.n.backoff = nil
		f.e.w.RunOnce()
		f.failDB()
		reportedA := make(chan struct{})
		go func() {
			f.svc.Report(model.MechanismAuditWrite, model.CauseAuditWriteSyncRefused, nil)
			close(reportedA)
		}()
		deadline := time.Now().Add(2 * time.Second)
		for f.stub.count() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if f.stub.count() == 0 {
			t.Fatal("A 的直接送出沒有開始")
		}
		start := time.Now()
		f.svc.Report(model.MechanismSyslogForward, model.CauseSyslogConnectFailed, nil)
		if d := time.Since(start); d > 200*time.Millisecond {
			close(release)
			t.Fatalf("B 的 Report 被拖住 %v", d)
		}
		select {
		case <-reportedA:
		default:
			close(release)
			t.Fatal("A 的 Report 在送出掛住期間仍未返回")
		}
		close(release)
		f.e.n.waitAuditNotices()
		got := strings.Join(f.eventsOf(f.stub), ",")
		if !strings.Contains(got, "audit_failure/"+model.MechanismAuditWrite) {
			t.Fatalf("替身最後應收到 A 的通知: %s", got)
		}
	})

	t.Run("(g) goroutine 的 panic 不結束行程，之後的通知照常寫入", func(t *testing.T) {
		f := newAuditFailureFixture(t, nil)
		var buf bytes.Buffer
		prevOut := log.Writer()
		log.SetOutput(&buf)
		t.Cleanup(func() { log.SetOutput(prevOut) })
		var once atomic.Bool
		f.e.n.auditHooks.beforeWrite = func(notifycat.Event) error {
			if once.CompareAndSwap(false, true) {
				panic("injected render panic")
			}
			return nil
		}
		f.svc.Report(model.MechanismAuditWrite, model.CauseAuditWriteSyncRefused, nil)
		f.e.n.waitAuditNotices()
		if !strings.Contains(buf.String(), "panic") {
			t.Fatalf("log 應記下一筆 panic: %s", buf.String())
		}
		f.svc.Report(model.MechanismSyslogForward, model.CauseSyslogConnectFailed, nil)
		f.e.n.waitAuditNotices()
		if n := len(f.e.messages()); n != 1 {
			t.Fatalf("之後的失效通知應照常寫入，內容列 %d", n)
		}
	})
}

// ---- 6.7 每日審閱逾期：寫入成功才推進 ----

func TestDailyReviewOverdueAdvancesOnlyAfterWrite(t *testing.T) {
	const tz = "Asia/Taipei"
	svc, db, _ := setupDailyReviewDB(t)
	if err := db.AutoMigrate(&model.NotificationMessage{}); err != nil {
		t.Fatal(err)
	}
	enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
	signRange(t, svc, tz, "2026-10-01", "2026-10-06")
	n := NewAlertNotifier(db, nil)
	useSingletonNotifier(t, n)
	var fail atomic.Bool
	fail.Store(true)
	failNotificationInserts(t, db, &fail)

	if svc.CheckOverdue(at(t, tz, "2026-10-11", 9, 0, 0).UTC()) {
		t.Fatal("寫不進去時不得回報已送出")
	}
	if svc.reminderSent != "" {
		t.Fatalf("寫不進去時不得推進 reminderSent，得 %q", svc.reminderSent)
	}
	fail.Store(false)
	if !svc.CheckOverdue(at(t, tz, "2026-10-11", 9, 15, 0).UTC()) {
		t.Fatal("下一次檢查應寫入")
	}
	var msgs []model.NotificationMessage
	db.Find(&msgs)
	if len(msgs) != 1 || msgs[0].EventKey != string(notifycat.EventDailyReviewOverdue) {
		t.Fatalf("應有一列逾期提醒，得 %+v", msgs)
	}
	if svc.reminderSent == "" {
		t.Fatal("寫入成功後應推進 reminderSent")
	}
}

// ---- 6.5 AI agent ----

func setupAgentNoticeDB(t *testing.T, db *gorm.DB) *AlertNotifier {
	t.Helper()
	if err := db.AutoMigrate(&model.NotificationMessage{}, &model.NotificationDelivery{}, &model.NotificationChannel{},
		&model.SystemAlertDetail{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '', deleted_at TIMESTAMP)`).Error; err != nil {
		t.Fatal(err)
	}
	n := NewAlertNotifier(db, nil)
	useSingletonNotifier(t, n)
	return n
}

// dispatchAll 跑一輪分派（沒有通道時只解析名稱並標為已分派）。
func dispatchAll(t *testing.T, db *gorm.DB) []model.NotificationMessage {
	t.Helper()
	w := NewSystemAlertOutboxWorker(db, nil)
	w.tee = func(model.CommandAlert) {}
	w.reporter = nopFailureReporter{}
	w.RunOnce()
	var msgs []model.NotificationMessage
	db.Order("id").Find(&msgs)
	return msgs
}

func TestAgentBreakerNoticeInTx(t *testing.T) {
	t.Run("熔斷分派後名稱齊備、次數正確", func(t *testing.T) {
		s := probeSQLite(t)
		setupAgentNoticeDB(t, s.db)
		s.db.Create(&model.User{ID: 1, Username: "owner-login"})
		s.db.Exec(`INSERT INTO assets (id, name) VALUES (1, 'web-01'), (2, 'web-02'), (3, 'db-03')`)
		s.deps.Notify = NotifyAgentOwner
		s.deps.TokenName = func(*gorm.DB, uint) string { return "deploy-token" }
		for _, a := range []uint{1, 2, 3} {
			if _, err := s.RecordDenied(context.Background(), 2, 7, a, "GET /assets/:id"); err != nil {
				t.Fatal(err)
			}
		}
		msgs := dispatchAll(t, s.db)
		if len(msgs) != 1 || msgs[0].EventKey != string(notifycat.EventAgentBreakerTripped) || msgs[0].State != model.NotificationMessageDispatched {
			t.Fatalf("應有一列已分派的熔斷通知: %+v", msgs)
		}
		p := messageParams(t, msgs[0])
		want := map[string]string{"agent_name": "agent", "owner_name": "owner-login", "token_name": "deploy-token",
			"asset_name": "db-03", "distinct_count": "3", "window_minutes": "5", "owner_id": "1", "token_id": "7"}
		for k, v := range want {
			if p[k] != v {
				t.Fatalf("參數 %s=%q，應為 %q（全部 %v）", k, p[k], v, p)
			}
		}
	})
	t.Run("熔斷的內容列寫不進去：探測紀錄、熔斷狀態與告警列照常提交", func(t *testing.T) {
		s := probeSQLite(t)
		setupAgentNoticeDB(t, s.db)
		s.deps.Notify = NotifyAgentOwner
		var fail atomic.Bool
		fail.Store(true)
		failNotificationInserts(t, s.db, &fail)
		var last ProbeBreakerResult
		for _, a := range []uint{1, 2, 3} {
			r, err := s.RecordDenied(context.Background(), 2, 7, a, "GET /assets/:id")
			if err != nil {
				t.Fatal(err)
			}
			last = r
		}
		if !last.Tripped {
			t.Fatal("第三次應熔斷")
		}
		var probes, alerts int64
		s.db.Model(&model.AgentProbeEvent{}).Count(&probes)
		s.db.Model(&model.CommandAlert{}).Where("kind = ?", model.AlertKindAgentBreaker).Count(&alerts)
		var u model.User
		s.db.First(&u, 2)
		if probes != 3 || alerts != 1 || u.BreakerPendingAt == nil {
			t.Fatalf("探測 %d（應 3）告警 %d（應 1）熔斷狀態 %v", probes, alerts, u.BreakerPendingAt)
		}
		var msgs int64
		s.db.Model(&model.NotificationMessage{}).Count(&msgs)
		if msgs != 0 {
			t.Fatalf("內容列應為 0，得 %d", msgs)
		}
	})
}

func agentReportsFixture(t *testing.T) (*AgentTaskReports, *gorm.DB) {
	t.Helper()
	s := probeSQLite(t)
	db := s.db
	setupAgentNoticeDB(t, db)
	if err := db.AutoMigrate(&model.AgentTaskReport{}); err != nil {
		t.Fatal(err)
	}
	db.Create(&model.User{ID: 1, Username: "owner-login"})
	db.Exec(`INSERT INTO assets (id, name) VALUES (4, 'app-04')`)
	task := func(*gorm.DB, uint) (AgentTaskFacts, error) {
		return AgentTaskFacts{ID: 30, RequesterID: 2, ExecutorID: 2, AssetID: 4, AssetCount: 2}, nil
	}
	principal := func(*gorm.DB, uint) (AgentPrincipalFacts, error) {
		return AgentPrincipalFacts{Kind: model.KindAgent, OwnerID: 1}, nil
	}
	return NewAgentTaskReports(db, NewTxSink(), task, principal, NotifyAgentOwner), db
}

func TestAgentTaskReportNoticeInTx(t *testing.T) {
	t.Run("MCP 路徑（Username 為空）分派後 agent 名稱仍是登入帳號", func(t *testing.T) {
		r, db := agentReportsFixture(t)
		if _, err := r.SubmitAndClose(context.Background(), 30, gatewayapi.Actor{UserID: 2}, "done", nil); err != nil {
			t.Fatal(err)
		}
		msgs := dispatchAll(t, db)
		if len(msgs) != 1 {
			t.Fatalf("應有一列，得 %d", len(msgs))
		}
		p := messageParams(t, msgs[0])
		if p["agent_name"] != "agent" || p["owner_name"] != "owner-login" || p["asset_name"] != "app-04" || p["asset_count"] != "2" {
			t.Fatalf("參數不符: %v", p)
		}
		if strings.Contains(msgs[0].Params, "done") {
			t.Fatal("通知不得帶報告內文")
		}
	})
	t.Run("內容列寫不進去：報告照常提交、不回錯", func(t *testing.T) {
		r, db := agentReportsFixture(t)
		var fail atomic.Bool
		fail.Store(true)
		failNotificationInserts(t, db, &fail)
		if _, err := r.SubmitAndClose(context.Background(), 30, gatewayapi.Actor{UserID: 2}, "done", nil); err != nil {
			t.Fatalf("通知寫不進去不得讓提交失敗: %v", err)
		}
		var reports int64
		db.Model(&model.AgentTaskReport{}).Count(&reports)
		if reports != 1 {
			t.Fatalf("報告應已提交，得 %d", reports)
		}
	})
}

// ---- 6.8 系統安全告警的目標名稱與去重 ----

func TestSystemAlertTargetNamesAndDedup(t *testing.T) {
	t.Run("只有識別碼的資產名稱與會話使用者名稱在同一交易查", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		for _, stmt := range []string{
			`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`,
			`CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`,
		} {
			if err := db.Exec(stmt).Error; err != nil {
				t.Fatal(err)
			}
		}
		db.Exec(`INSERT INTO assets (id, name) VALUES (21, 'bastion-21')`)
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY, user_id INTEGER, client_ip TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`).Error; err != nil {
			t.Fatal(err)
		}
		db.Exec(`INSERT INTO sessions (id, user_id) VALUES (77, 31)`)
		db.Exec(`INSERT INTO users (id, username) VALUES (31, 'session-login')`)
		asset := uint(21)
		cases := []struct {
			name string
			ev   port.SystemAlertEvent
			want map[string]string
		}{
			{"主機金鑰不符", port.SystemAlertEvent{Type: port.SystemAlertHostKeyMismatch,
				Target: port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset, ID: "21"}, AssetID: &asset,
				Params: map[string]string{"path": "terminal", "outcome": "refused", "record_source": "own",
					"recorded_fingerprint": "SHA256:a", "observed_fingerprint": "SHA256:b", "observed_algorithm": "ssh-ed25519"}},
				map[string]string{"asset_name": "bastion-21"}},
			{"金鑰記錄變更", port.SystemAlertEvent{Type: port.SystemAlertHostKeyRecordChanged,
				Target: port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset, ID: "21"}, AssetID: &asset,
				Params: map[string]string{"change": "adopted", "previous_fingerprint": "SHA256:a", "adopted_fingerprint": "SHA256:b"}},
				map[string]string{"asset_name": "bastion-21"}},
			{"自訂秘密", port.SystemAlertEvent{Type: port.SystemAlertCustomSecretUsed,
				Target: port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset, ID: "21"}, AssetID: &asset,
				Params: map[string]string{"entry": "change_password"}},
				map[string]string{"asset_name": "bastion-21"}},
			{"未納管特權帳號", port.SystemAlertEvent{Type: port.SystemAlertUnmanagedPrivilegedAccount,
				Target: port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset, ID: "21"}, AssetID: &asset,
				Params: map[string]string{"new_count": "2", "identity_mode": "executor"}},
				map[string]string{"asset_name": "bastion-21"}},
			{"錄影刪除", port.SystemAlertEvent{Type: port.SystemAlertRecordingDeleted,
				Target: port.SystemAlertTarget{Kind: port.SystemAlertTargetSession, ID: "77"}, AssetID: &asset,
				Params: map[string]string{"session_id": "77"}},
				map[string]string{"asset_name": "bastion-21", "session_username": "session-login"}},
		}
		for _, c := range cases {
			c.ev.Actor = port.SystemAlertActor{UserID: 1, Username: "op"}
			var receipt port.SystemAlertReceipt
			if err := db.Transaction(func(tx *gorm.DB) error {
				var err error
				receipt, err = NewSystemAlertSink(nil).(*systemAlertSink).raise(tx, c.ev, nil)
				return err
			}); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			var detail model.SystemAlertDetail
			db.Where("alert_id = ?", receipt.AlertID).First(&detail)
			got := map[string]string{}
			_ = json.Unmarshal([]byte(detail.Params), &got)
			for k, v := range c.want {
				if got[k] != v {
					t.Fatalf("%s: 明細參數 %s=%q，應為 %q（全部 %v）", c.name, k, got[k], v, got)
				}
			}
		}
	})

	t.Run("兩個 slack_app 通道同網址同 token 不同目標時產生兩筆紀錄", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		for _, target := range []string{"C111", "C222"} {
			if err := db.Create(&model.NotificationChannel{Name: "s-" + target, Type: "slack_app", URL: "https://slack.example.test/api/chat.postMessage",
				Secret: "xoxb-same", Target: target, Enabled: true, Language: "zh-TW", MinSeverity: "low"}).Error; err != nil {
				t.Fatal(err)
			}
		}
		var receipt port.SystemAlertReceipt
		if err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			receipt, err = NewSystemAlertSink(nil).(*systemAlertSink).raise(tx, validGrantEvent(), nil)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var rows []model.NotificationDelivery
		db.Where("alert_id = ? AND dest_type = ?", receipt.AlertID, "slack_app").Order("id").Find(&rows)
		if len(rows) != 2 || rows[0].DestTarget == rows[1].DestTarget {
			t.Fatalf("應為兩筆不同目標的紀錄，得 %+v", rows)
		}
	})
}
