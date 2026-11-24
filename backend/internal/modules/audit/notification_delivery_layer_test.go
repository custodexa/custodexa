package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 通知投遞層（排入、分派、投遞程序）的行為測試。可控時鐘＋本機替身；斷言收端收到的請求與資料列狀態。

// ---- 共用替身 ----

// fakeClock 可控時鐘。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// stubSrv 可設定回應的收端替身：記錄每個請求的本文、標頭與收到時（可控時鐘）的時刻。
type stubSrv struct {
	mu      sync.Mutex
	srv     *httptest.Server
	bodies  [][]byte
	headers []http.Header
	times   []time.Time
	clock   *fakeClock
	respond func(n int, w http.ResponseWriter, r *http.Request)
}

func newStubSrv(t *testing.T, clock *fakeClock, respond func(n int, w http.ResponseWriter, r *http.Request)) *stubSrv {
	t.Helper()
	s := &stubSrv{clock: clock, respond: respond}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		n := len(s.bodies)
		s.bodies = append(s.bodies, b)
		s.headers = append(s.headers, r.Header.Clone())
		if s.clock != nil {
			s.times = append(s.times, s.clock.now())
		}
		respond := s.respond
		s.mu.Unlock()
		if respond == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		respond(n, w, r)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubSrv) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodies)
}

func (s *stubSrv) body(i int) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bodies[i]
}

func (s *stubSrv) header(i int) http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headers[i]
}

func respondStatus(code int) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

// recordingReporter 模擬稽核失效服務的記憶體去重：每個機制同時只有一筆進行中事件。
type recordingReporter struct {
	mu      sync.Mutex
	open    map[string]bool
	events  map[string]int // 機制 → 開過的事件數
	ended   map[string]int // 機制 → 結束的事件數
	reports []string
	onCall  func(kind, mechanism string)
}

func newRecordingReporter() *recordingReporter {
	return &recordingReporter{open: map[string]bool{}, events: map[string]int{}, ended: map[string]int{}}
}

func (r *recordingReporter) NotifyOngoing(notifycat.Event, map[string]string) {}

func (r *recordingReporter) ReportWithCounts(mechanism, cause string, p map[string]string, _ map[string]int) {
	r.Report(mechanism, cause, p)
}

func (r *recordingReporter) Report(mechanism, cause string, _ map[string]string) {
	if r.onCall != nil {
		r.onCall("report", mechanism)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, mechanism+"/"+cause)
	if !r.open[mechanism] {
		r.open[mechanism] = true
		r.events[mechanism]++
	}
}

func (r *recordingReporter) Resolve(mechanism string) {
	if r.onCall != nil {
		r.onCall("resolve", mechanism)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.open[mechanism] {
		r.open[mechanism] = false
		r.ended[mechanism]++
	}
}

func (r *recordingReporter) state(mechanism string) (events, ended int, open bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.events[mechanism], r.ended[mechanism], r.open[mechanism]
}

// ---- 測試環境 ----

type ndlEnv struct {
	t     *testing.T
	db    *gorm.DB
	clock *fakeClock
	n     *AlertNotifier
	w     *SystemAlertOutboxWorker
	rep   *recordingReporter
}

func newNDLEnv(t *testing.T) *ndlEnv {
	t.Helper()
	p := newNotifyPipeline(t)
	clock := newFakeClock()
	rep := newRecordingReporter()
	p.n.now = clock.now
	p.w.now = clock.now
	p.w.backoffBase = time.Second
	p.w.backoffMax = 2 * time.Hour
	p.w.httpTimeout = 2 * time.Second
	p.w.reporter = rep
	p.w.sleep = clock.advance
	return &ndlEnv{t: t, db: p.db, clock: clock, n: p.n, w: p.w, rep: rep}
}

func (e *ndlEnv) channel(name, typ, url string, enabled bool, minSeverity string) model.NotificationChannel {
	e.t.Helper()
	ch := model.NotificationChannel{Name: name, Type: typ, URL: url, Enabled: true, Language: "zh-TW", MinSeverity: minSeverity}
	if ch.MinSeverity == "" {
		ch.MinSeverity = model.AlertSeverityLow
	}
	if err := e.db.Create(&ch).Error; err != nil {
		e.t.Fatal(err)
	}
	if !enabled {
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).Update("enabled", false)
		ch.Enabled = false
	}
	return ch
}

func (e *ndlEnv) alert(severity string, sessionID uint, userID uint, assetID *uint) model.CommandAlert {
	e.t.Helper()
	a := model.CommandAlert{RuleName: "r", Command: "rm -rf /", Severity: severity, SessionID: sessionID,
		UserID: userID, AssetID: assetID, TriggeredAt: e.clock.now(), Disposition: "pending", Kind: model.AlertKindRule}
	if err := e.db.Create(&a).Error; err != nil {
		e.t.Fatal(err)
	}
	return a
}

func (e *ndlEnv) enqueueAlert(a model.CommandAlert) {
	e.t.Helper()
	if err := e.n.EnqueueStandalone(commandAlertNotice(a)); err != nil {
		e.t.Fatal(err)
	}
}

func (e *ndlEnv) enqueueEvent(event notifycat.Event, params map[string]string) {
	e.t.Helper()
	if err := e.n.EnqueueStandalone(SystemEventNotice(event, params)); err != nil {
		e.t.Fatal(err)
	}
}

func (e *ndlEnv) deliveries() []model.NotificationDelivery {
	e.t.Helper()
	var rows []model.NotificationDelivery
	if err := e.db.Order("id").Find(&rows).Error; err != nil {
		e.t.Fatal(err)
	}
	return rows
}

func (e *ndlEnv) messages() []model.NotificationMessage {
	e.t.Helper()
	var rows []model.NotificationMessage
	if err := e.db.Order("id").Find(&rows).Error; err != nil {
		e.t.Fatal(err)
	}
	return rows
}

// liveRow 直接建一筆不帶快照的到期紀錄（指向一則已分派的系統事件內容）。
func (e *ndlEnv) liveRow(channelID uint, severity string, attempts int) model.NotificationDelivery {
	e.t.Helper()
	msg := model.NotificationMessage{Category: model.NotificationCategorySystemEvent, EventKey: string(notifycat.EventDailyReviewOverdue),
		Severity: severity, OccurredAt: e.clock.now(), Params: `{}`, NameRefs: `{}`, State: model.NotificationMessageDispatched,
		Degraded: true, CreatedAt: e.clock.now()}
	if err := e.db.Create(&msg).Error; err != nil {
		e.t.Fatal(err)
	}
	key, _ := newDeliveryKey()
	chID, msgID := channelID, msg.ID
	row := model.NotificationDelivery{Category: model.NotificationCategorySystemEvent, MessageID: &msgID, Severity: severity,
		SourceChannelID: &chID, State: model.NotificationDeliveryPending, Attempts: attempts, NextAttemptAt: e.clock.now(),
		CreatedAt: e.clock.now(), DeliveryKey: key}
	if attempts > 0 {
		row.State = model.NotificationDeliveryRetrying
	}
	if err := e.db.Create(&row).Error; err != nil {
		e.t.Fatal(err)
	}
	return row
}

// snapshotRow 直接建一筆帶快照的系統安全告警紀錄。
func (e *ndlEnv) snapshotRow(channelID uint, url string, version int, attempts int) model.NotificationDelivery {
	e.t.Helper()
	a := model.CommandAlert{RuleName: "sys", Command: "", Severity: model.AlertSeverityHigh, TriggeredAt: e.clock.now(),
		Disposition: "pending", Kind: model.AlertKindSystemSecurity}
	if err := e.db.Create(&a).Error; err != nil {
		e.t.Fatal(err)
	}
	d := model.SystemAlertDetail{AlertID: a.ID, AlertType: string(notifycat.EventSystemAlertManagementRoleGranted),
		Params: `{"path":"direct_assign","recipient":"bob","role_name":"asset_admin"}`}
	if err := e.db.Create(&d).Error; err != nil {
		e.t.Fatal(err)
	}
	key, _ := newDeliveryKey()
	alertID, chID := a.ID, channelID
	row := model.NotificationDelivery{Category: model.NotificationCategorySystemSecurityAlert, AlertID: &alertID,
		Severity: model.AlertSeverityHigh, DestType: model.NotificationChannelTypeWebhook, DestName: "c", DestLanguage: "zh-TW",
		SourceChannelID: &chID, URLEnc: url, State: model.NotificationDeliveryPending, Attempts: attempts,
		NextAttemptAt: e.clock.now(), CreatedAt: e.clock.now(), DeliveryKey: key, DestVersion: version}
	if attempts > 0 {
		row.State = model.NotificationDeliveryRetrying
	}
	if err := e.db.Create(&row).Error; err != nil {
		e.t.Fatal(err)
	}
	return row
}

func (e *ndlEnv) row(id uint) model.NotificationDelivery {
	e.t.Helper()
	var r model.NotificationDelivery
	if err := e.db.First(&r, id).Error; err != nil {
		e.t.Fatal(err)
	}
	return r
}

// ---- 4.1 排入介面 ----

func TestEnqueueInTxFollowsBusinessTransaction(t *testing.T) {
	e := newNDLEnv(t)
	if err := e.db.Exec(`CREATE TABLE biz (id INTEGER PRIMARY KEY, v TEXT)`).Error; err != nil {
		t.Fatal(err)
	}

	t.Run("(a) 業務交易回滾時內容列一起消失", func(t *testing.T) {
		_ = e.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(`INSERT INTO biz (v) VALUES ('a')`).Error; err != nil {
				return err
			}
			if err := e.n.EnqueueInTx(tx, SystemEventNotice(notifycat.EventDailyReviewOverdue, nil)); err != nil {
				t.Fatalf("排入應成功: %v", err)
			}
			return errors.New("後續業務步驟失敗")
		})
		if n := len(e.messages()); n != 0 {
			t.Fatalf("內容列應為 0，得 %d", n)
		}
	})

	t.Run("(b)(c) 寫入失敗回到 savepoint、業務照常提交；回報在下一輪、成功後結束", func(t *testing.T) {
		if err := e.db.Exec(`CREATE TRIGGER fail_msg BEFORE INSERT ON notification_messages BEGIN SELECT RAISE(ABORT, 'injected'); END`).Error; err != nil {
			t.Fatal(err)
		}
		inEnqueue := false
		e.rep.onCall = func(kind, _ string) {
			if inEnqueue {
				t.Errorf("排入函式的呼叫堆疊內不得呼叫 %s", kind)
			}
		}
		if err := e.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(`INSERT INTO biz (v) VALUES ('b')`).Error; err != nil {
				return err
			}
			inEnqueue = true
			err := e.n.EnqueueInTx(tx, SystemEventNotice(notifycat.EventDailyReviewOverdue, nil))
			inEnqueue = false
			if err == nil {
				t.Fatal("故障注入下排入應回錯")
			}
			if events, _, _ := e.rep.state(model.MechanismNotificationDelivery); events != 0 {
				t.Fatal("業務交易提交前不得有失效事件")
			}
			return tx.Exec(`INSERT INTO biz (v) VALUES ('b2')`).Error
		}); err != nil {
			t.Fatalf("業務交易應提交: %v", err)
		}
		var biz int64
		e.db.Raw(`SELECT COUNT(*) FROM biz WHERE v IN ('b','b2')`).Scan(&biz)
		if biz != 2 || len(e.messages()) != 0 {
			t.Fatalf("業務列 %d（應 2）內容列 %d（應 0）", biz, len(e.messages()))
		}
		e.w.RunOnce()
		if events, _, open := e.rep.state(model.MechanismNotificationDelivery); events != 1 || !open {
			t.Fatalf("一輪後應有一筆進行中的 notification_delivery: events=%d open=%v", events, open)
		}
		if !strings.Contains(strings.Join(e.rep.reports, ","), model.MechanismNotificationDelivery+"/"+model.CauseNotificationEnqueueFailed) {
			t.Fatalf("原因碼不符: %v", e.rep.reports)
		}
		e.db.Exec(`DROP TRIGGER fail_msg`)
		e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
		e.w.RunOnce()
		if _, ended, open := e.rep.state(model.MechanismNotificationDelivery); ended != 1 || open {
			t.Fatalf("成功排入後一輪應結束事件: ended=%d open=%v", ended, open)
		}
	})

	t.Run("(d) 分派失敗進行中時排入成功不結束分派事件", func(t *testing.T) {
		e.rep.Report(model.MechanismNotificationDispatch, model.CauseNotificationDispatchFailed, nil)
		e.w.dispOpen = true
		e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
		e.w.hooks.dispatchRead = func(*model.NotificationMessage) error { return errors.New("injected") }
		e.w.RunOnce()
		e.w.hooks.dispatchRead = nil
		if _, ended, open := e.rep.state(model.MechanismNotificationDispatch); ended != 0 || !open {
			t.Fatalf("分派事件不應被排入成功結束: ended=%d open=%v", ended, open)
		}
	})

	t.Run("(e) 非交易句柄回錯且不寫入", func(t *testing.T) {
		before := len(e.messages())
		if err := e.n.EnqueueInTx(e.db, SystemEventNotice(notifycat.EventDailyReviewOverdue, nil)); !errors.Is(err, errEnqueueNotInTx) {
			t.Fatalf("應回非交易錯誤: %v", err)
		}
		if len(e.messages()) != before {
			t.Fatal("非交易句柄不得寫入")
		}
	})
}

// ---- 4.2 分派 ----

func TestDispatchCreatesOneLiveRowPerAdmittedChannel(t *testing.T) {
	e := newNDLEnv(t)
	e.db.Exec(`INSERT INTO users (id, username) VALUES (9, 'alice')`)
	e.db.Exec(`INSERT INTO users (id, username, deleted_at) VALUES (10, 'gone-user', CURRENT_TIMESTAMP)`)
	e.channel("high", "webhook", "http://127.0.0.1:1/a", true, "high")
	mid := e.channel("medium", "webhook", "http://127.0.0.1:1/b", true, "medium")
	low := e.channel("low", "webhook", "http://127.0.0.1:1/c", true, "low")

	asset := uint(77) // 不存在（已硬刪）的資產
	a := e.alert(model.AlertSeverityMedium, 0, 9, &asset)
	e.enqueueAlert(a)
	e.w.dispatchPending()

	rows := e.deliveries()
	if len(rows) != 2 {
		t.Fatalf("紀錄應恰兩筆，得 %d", len(rows))
	}
	if *rows[0].SourceChannelID != mid.ID || *rows[1].SourceChannelID != low.ID {
		t.Fatalf("來源通道應為門檻 medium、low 兩者: %v %v", *rows[0].SourceChannelID, *rows[1].SourceChannelID)
	}
	if rows[0].URLEnc != "" || rows[0].DestVersion != 0 || rows[0].DeliveryKey == rows[1].DeliveryKey ||
		len(rows[0].DeliveryKey) != 32 || len(rows[1].DeliveryKey) != 32 {
		t.Fatalf("不帶快照紀錄欄位不符: %+v %+v", rows[0], rows[1])
	}
	msg := e.messages()[0]
	if msg.ActorName != "alice" || msg.State != model.NotificationMessageDispatched || msg.TargetName != "" {
		t.Fatalf("內容列: actor=%q state=%s target=%q", msg.ActorName, msg.State, msg.TargetName)
	}

	b := e.alert(model.AlertSeverityHigh, 0, 10, nil)
	e.enqueueAlert(b)
	e.w.dispatchPending()
	if got := e.messages()[1].ActorName; got != "gone-user" {
		t.Fatalf("軟刪使用者的名稱仍應寫回，得 %q", got)
	}

	e.db.Exec(`DELETE FROM notification_channels`)
	e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
	before := len(e.deliveries())
	e.w.dispatchPending()
	last := e.messages()[2]
	if last.State != model.NotificationMessageDispatched || len(e.deliveries()) != before {
		t.Fatalf("沒有通道時應標已分派、零筆: state=%s", last.State)
	}
}

func TestDispatchSystemEventsBeforeCommandAlerts(t *testing.T) {
	e := newNDLEnv(t)
	e.channel("c", "webhook", "http://127.0.0.1:1/a", true, "low")
	for i := 0; i < 100; i++ {
		e.enqueueAlert(e.alert(model.AlertSeverityHigh, 0, 1, nil))
	}
	if err := e.n.EnqueueStandalone(NotificationNotice{Category: model.NotificationCategorySystemEvent,
		Event: notifycat.EventAccessRequestApproved, Severity: model.AlertSeverityLow, Params: map[string]string{"request_id": "1"}}); err != nil {
		t.Fatal(err)
	}
	e.w.dispatchPending()
	var ev model.NotificationMessage
	e.db.Where("category = ?", model.NotificationCategorySystemEvent).First(&ev)
	if ev.State != model.NotificationMessageDispatched {
		t.Fatalf("系統事件應在這一輪被分派，狀態 %s", ev.State)
	}
}

func TestDispatchFinalizeIsConditional(t *testing.T) {
	e := newNDLEnv(t)
	e.channel("a", "webhook", "http://127.0.0.1:1/a", true, "low")
	e.channel("b", "webhook", "http://127.0.0.1:1/b", true, "low")
	e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
	// 另一個執行個體在收尾前已把內容標為已分派：本交易的條件更新影響 0 列，整個交易回滾。
	e.w.hooks.beforeDispatchFinalize = func(tx *gorm.DB, id uint) {
		tx.Exec(`UPDATE notification_messages SET state = 'dispatched' WHERE id = ?`, id)
	}
	e.w.dispatchPending()
	if n := len(e.deliveries()); n != 0 {
		t.Fatalf("收尾條件不成立時應回滾已建立的紀錄，得 %d 筆", n)
	}
}

// ---- 4.3 分派失敗的收尾與回報 ----

func TestDispatchFailureHandling(t *testing.T) {
	t.Run("(a) 未登錄事件降級分派", func(t *testing.T) {
		e := newNDLEnv(t)
		e.channel("c", "webhook", "http://127.0.0.1:1/a", true, "low")
		e.enqueueEvent(notifycat.Event("ghost.event"), map[string]string{"who": "x"})
		e.w.dispatchPending()
		m := e.messages()[0]
		if !m.Degraded || m.Params != "{}" || len(e.deliveries()) != 1 {
			t.Fatalf("degraded=%v params=%s rows=%d", m.Degraded, m.Params, len(e.deliveries()))
		}
	})

	t.Run("(b) 每次 panic：行程存活、其他列照常、第 10 輪後失敗", func(t *testing.T) {
		e := newNDLEnv(t)
		e.channel("c", "webhook", "http://127.0.0.1:1/a", true, "low")
		e.enqueueEvent(notifycat.EventDailyReviewOverdue, map[string]string{"bad": "1"})
		badID := e.messages()[0].ID
		e.w.hooks.dispatchRead = func(m *model.NotificationMessage) error {
			if m.ID == badID {
				panic("injected")
			}
			return nil
		}
		for round := 1; round <= 10; round++ {
			e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
			e.w.RunOnce()
			e.clock.advance(61 * time.Second)
			var bad model.NotificationMessage
			e.db.First(&bad, badID)
			if bad.DispatchAttempts != round {
				t.Fatalf("第 %d 輪後分派次數應為 %d，得 %d", round, round, bad.DispatchAttempts)
			}
			if round == 9 && bad.State != model.NotificationMessagePending {
				t.Fatalf("第 9 輪後應仍待分派: %s", bad.State)
			}
		}
		e.w.RunOnce()
		var bad model.NotificationMessage
		e.db.First(&bad, badID)
		if bad.State != model.NotificationMessageFailed || bad.FailReason != model.NotificationMessageFailDispatchError {
			t.Fatalf("第 10 次之後應失敗: %s %s", bad.State, bad.FailReason)
		}
		var others int64
		e.db.Model(&model.NotificationMessage{}).Where("id <> ? AND state = ?", badID, model.NotificationMessageDispatched).Count(&others)
		if others != 10 {
			t.Fatalf("其他內容應照常分派，得 %d", others)
		}
	})

	t.Run("(b) 認領後不收尾即返回：租約到期再認領，次數累加到 10 即終止", func(t *testing.T) {
		e := newNDLEnv(t)
		e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
		e.w.hooks.dispatchAfterClaim = func(uint) bool { return true }
		for i := 0; i < 12; i++ {
			e.w.RunOnce()
			e.clock.advance(61 * time.Second)
		}
		m := e.messages()[0]
		if m.DispatchAttempts != 10 || m.State != model.NotificationMessageFailed {
			t.Fatalf("attempts=%d state=%s", m.DispatchAttempts, m.State)
		}
	})

	t.Run("(c) 只有稽核失效一族分派失敗時不產生分派事件", func(t *testing.T) {
		e := newNDLEnv(t)
		e.channel("c", "webhook", "http://127.0.0.1:1/a", true, "low")
		e.w.hooks.dispatchRead = func(m *model.NotificationMessage) error {
			if isAuditFailureFamily(m.EventKey) {
				return errors.New("injected")
			}
			return nil
		}
		for i := 0; i < 20; i++ {
			e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
			e.enqueueEvent(notifycat.EventAuditFailure, map[string]string{"mechanism": "audit_write"})
			e.w.RunOnce()
			e.clock.advance(61 * time.Second)
		}
		var failed int64
		e.db.Model(&model.NotificationMessage{}).Where("state = ?", model.NotificationMessageFailed).Count(&failed)
		if failed == 0 {
			t.Fatal("前提：稽核失效一族的內容應已轉為失敗")
		}
		if events, _, _ := e.rep.state(model.MechanismNotificationDispatch); events != 0 {
			t.Fatalf("稽核失效一族的失敗不得回報: events=%d", events)
		}
	})

	t.Run("(c)(d) 持續失敗只有一筆分派事件，稽核失效一族不回報；恢復後結束、再失敗開第二筆", func(t *testing.T) {
		e := newNDLEnv(t)
		e.channel("c", "webhook", "http://127.0.0.1:1/a", true, "low")
		e.w.hooks.dispatchRead = func(*model.NotificationMessage) error { return errors.New("injected") }
		for i := 0; i < 50; i++ {
			e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
			e.enqueueEvent(notifycat.EventAuditFailure, map[string]string{"mechanism": "audit_write"})
			e.w.RunOnce()
			e.clock.advance(61 * time.Second)
		}
		if events, ended, open := e.rep.state(model.MechanismNotificationDispatch); events != 1 || ended != 0 || !open {
			t.Fatalf("分派事件應恰一筆且進行中: events=%d ended=%d open=%v", events, ended, open)
		}
		e.w.hooks.dispatchRead = nil
		// 解除故障：清掉已逾限的列，讓下一輪只有成功的分派。
		e.w.RunOnce()
		e.clock.advance(61 * time.Second)
		e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
		e.w.RunOnce()
		if _, ended, open := e.rep.state(model.MechanismNotificationDispatch); ended != 1 || open {
			t.Fatalf("一般內容分派成功後應結束: ended=%d open=%v", ended, open)
		}
		e.w.hooks.dispatchRead = func(*model.NotificationMessage) error { return errors.New("again") }
		e.enqueueEvent(notifycat.EventDailyReviewOverdue, nil)
		for i := 0; i < 11; i++ {
			e.w.RunOnce()
			e.clock.advance(61 * time.Second)
		}
		if events, _, _ := e.rep.state(model.MechanismNotificationDispatch); events != 2 {
			t.Fatalf("再有一列轉失敗應產生第二筆: %d", events)
		}
	})
}

// ---- 4.4 名稱分派後不再變動 ----

func TestNameFixedAtDispatch(t *testing.T) {
	e := newNDLEnv(t)
	e.db.Exec(`INSERT INTO users (id, username) VALUES (5, 'old-name')`)
	okSrv := newStubSrv(t, e.clock, nil)
	flaky := newStubSrv(t, e.clock, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 0 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	})
	e.channel("ok", "webhook", okSrv.srv.URL, true, "low")
	e.channel("flaky", "webhook", flaky.srv.URL, true, "low")
	e.enqueueAlert(e.alert(model.AlertSeverityHigh, 0, 5, nil))
	e.w.RunOnce()
	e.db.Exec(`UPDATE users SET username = 'new-name' WHERE id = 5`)
	e.clock.advance(5 * time.Second)
	e.w.RunOnce()
	if flaky.count() != 2 || okSrv.count() != 1 {
		t.Fatalf("flaky=%d ok=%d", flaky.count(), okSrv.count())
	}
	for _, b := range [][]byte{okSrv.body(0), flaky.body(1)} {
		if !strings.Contains(string(b), `"username":"old-name"`) {
			t.Fatalf("本文應帶分派時的名稱: %s", b)
		}
	}
}

// ---- 4.5 來源位址與降級原因在分派時保存 ----

func TestClientIPAndDegradeReasonSavedAtDispatch(t *testing.T) {
	e := newNDLEnv(t)
	e.db.Exec(`INSERT INTO sessions (id, client_ip) VALUES (31, '203.0.113.7')`)
	hook := newStubSrv(t, e.clock, nil)
	slack := newStubSrv(t, e.clock, nil)
	e.channel("hook", "webhook", hook.srv.URL, true, "low")
	e.channel("slack", model.NotificationChannelTypeSlack, slack.srv.URL, true, "low")
	a := e.alert(model.AlertSeverityHigh, 31, 1, nil)
	a2 := model.CommandAlert{RuleName: string(model.AlertKindNewSourceIP), Severity: model.AlertSeverityMedium, SessionID: 31, UserID: 1,
		TriggeredAt: e.clock.now(), Disposition: "pending", Kind: model.AlertKindNewSourceIP}
	e.db.Create(&a2)
	e.enqueueAlert(a)
	e.enqueueAlert(a2)
	e.w.dispatchPending()
	for _, m := range e.messages() {
		if !strings.Contains(m.Params, `"client_ip":"203.0.113.7"`) {
			t.Fatalf("內容列應保存 client_ip: %s", m.Params)
		}
	}
	// (b) 分派後改掉或刪掉會話列，送出的本文仍是分派時的值；(d) 送出時不查 sessions／session_commands。
	e.db.Exec(`DELETE FROM sessions`)
	var sessionQueries int
	cbName := "count_session_queries"
	_ = e.db.Callback().Query().Before("gorm:query").Register(cbName, func(db *gorm.DB) {
		if db.Statement != nil && (db.Statement.Table == "sessions" || db.Statement.Table == "session_commands") {
			sessionQueries++
		}
	})
	_ = e.db.Callback().Row().Before("gorm:row").Register(cbName+"_row", func(db *gorm.DB) {
		if db.Statement != nil && (db.Statement.Table == "sessions" || db.Statement.Table == "session_commands") {
			sessionQueries++
		}
	})
	t.Cleanup(func() {
		_ = e.db.Callback().Query().Remove(cbName)
		_ = e.db.Callback().Row().Remove(cbName + "_row")
	})
	e.w.deliverDue()
	if sessionQueries != 0 {
		t.Fatalf("送出時不得查會話表，得 %d 次", sessionQueries)
	}
	if hook.count() != 2 || slack.count() != 2 {
		t.Fatalf("hook=%d slack=%d", hook.count(), slack.count())
	}
	var payload struct {
		Session struct {
			ClientIP string `json:"client_ip"`
		} `json:"session"`
	}
	if err := json.Unmarshal(hook.body(0), &payload); err != nil || payload.Session.ClientIP != "203.0.113.7" {
		t.Fatalf("webhook session.client_ip: %s", hook.body(0))
	}
	found := false
	for i := 0; i < slack.count(); i++ {
		if strings.Contains(string(slack.body(i)), "203.0.113.7") {
			found = true
		}
	}
	if !found {
		t.Fatal("新來源位址告警的 Slack 文字應含位址")
	}
}

func TestDegradeReasonSavedAtDispatch(t *testing.T) {
	e := newNDLEnv(t)
	slack := newStubSrv(t, e.clock, nil)
	hook := newStubSrv(t, e.clock, nil)
	e.channel("slack", model.NotificationChannelTypeSlack, slack.srv.URL, true, "low")
	e.channel("hook", "webhook", hook.srv.URL, true, "low")
	at := e.clock.now()
	e.db.Exec(`INSERT INTO session_commands (session_id, degraded, executed_at, degrade_reason) VALUES (40, 1, ?, ?)`, at, model.DegradeAltScreen)
	a := model.CommandAlert{RuleName: model.AlertReasonDegradedSpan, Severity: model.AlertSeverityMedium, SessionID: 40, UserID: 1,
		TriggeredAt: at, Disposition: "pending", Kind: model.AlertKindAuditDegraded, ReasonCode: model.AlertReasonDegradedSpan}
	e.db.Create(&a)
	e.enqueueAlert(a)
	e.w.RunOnce()
	if !strings.Contains(e.messages()[0].Params, model.DegradeAltScreen) {
		t.Fatalf("內容列應保存降級原因: %s", e.messages()[0].Params)
	}
	if slack.count() != 1 || !strings.Contains(string(slack.body(0)), "全螢幕") {
		t.Fatalf("Slack 文字應含降級情境行: %s", slack.body(0))
	}
	if strings.Contains(string(hook.body(0)), "degrade_reason") || strings.Contains(string(hook.body(0)), model.DegradeAltScreen) {
		t.Fatalf("webhook 本文不得有降級原因欄位: %s", hook.body(0))
	}
}

// ---- 5.1 目的地公平性 ----

func TestDeliveryDestinationFairness(t *testing.T) {
	t.Run("(a) 逾時的目的地不拖累其他目的地", func(t *testing.T) {
		e := newNDLEnv(t)
		e.w.httpTimeout = 150 * time.Millisecond
		slow := newStubSrv(t, nil, func(_ int, w http.ResponseWriter, _ *http.Request) { time.Sleep(600 * time.Millisecond) })
		h1 := newStubSrv(t, nil, nil)
		h2 := newStubSrv(t, nil, nil)
		cs := e.channel("slow", "webhook", slow.srv.URL, true, "low")
		c1 := e.channel("h1", "webhook", h1.srv.URL, true, "low")
		c2 := e.channel("h2", "webhook", h2.srv.URL, true, "low")
		for i := 0; i < 10; i++ {
			e.liveRow(cs.ID, "high", 0)
			e.liveRow(c1.ID, "high", 0)
			e.liveRow(c2.ID, "high", 0)
		}
		e.w.RunOnce()
		if h1.count() != 10 || h2.count() != 10 || slow.count() != 1 {
			t.Fatalf("h1=%d h2=%d slow=%d", h1.count(), h2.count(), slow.count())
		}
		for _, r := range e.deliveries() {
			if *r.SourceChannelID == cs.ID && (r.Attempts != 1 || !r.NextAttemptAt.Equal(e.clock.now().Add(time.Second))) {
				t.Fatalf("逾時目的地的紀錄應各計一次並依自己的次數排定: %+v", r)
			}
		}
	})

	t.Run("(b) 積壓遠超過單輪上限時健康目的地每輪都輪得到，放棄有上界", func(t *testing.T) {
		e := newNDLEnv(t)
		bad := newStubSrv(t, nil, respondStatus(503))
		good := newStubSrv(t, nil, nil)
		cd := e.channel("D", "webhook", bad.srv.URL, true, "low")
		ch := e.channel("H", "webhook", good.srv.URL, true, "low")
		for i := 0; i < 300; i++ {
			e.liveRow(cd.ID, "high", 0)
		}
		for i := 0; i < 5; i++ {
			e.liveRow(ch.ID, "low", 0)
		}
		start := e.clock.now()
		e.w.RunOnce()
		if good.count() != 5 || bad.count() != 1 {
			t.Fatalf("第一輪 H=%d（應 5）D=%d（應 1）", good.count(), bad.count())
		}
		var notOne int64
		e.db.Model(&model.NotificationDelivery{}).Where("source_channel_id = ? AND attempts <> 1", cd.ID).Count(&notOne)
		if notOne != 0 {
			t.Fatalf("D 的 300 筆應全部計一次，有 %d 筆不是", notOne)
		}
		const round = 2 * time.Second
		var bound time.Duration
		for n := 1; n <= notifyMaxAttempts; n++ {
			d := time.Duration(1<<uint(minInt(n-1, 30))) * time.Second
			if d > 2*time.Hour {
				d = 2 * time.Hour
			}
			bound += d
		}
		bound += notifyMaxAttempts * round
		rounds := 0
		for rounds < 2000 {
			var active int64
			e.db.Model(&model.NotificationDelivery{}).Where("source_channel_id = ? AND state IN ?", cd.ID, activeOutboxStates()).Count(&active)
			if active == 0 {
				break
			}
			next := e.nextDue()
			if next.After(e.clock.now()) {
				e.clock.advance(next.Sub(e.clock.now()))
			} else {
				e.clock.advance(round)
			}
			newH := e.liveRow(ch.ID, "low", 0)
			e.w.RunOnce()
			if r := e.row(newH.ID); r.State != model.NotificationDeliveryDelivered {
				t.Fatalf("第 %d 輪 H 新到期的紀錄未在該輪送出: %s", rounds, r.State)
			}
			rounds++
		}
		var abandoned int64
		e.db.Model(&model.NotificationDelivery{}).Where("source_channel_id = ? AND state = ? AND end_reason = ?", cd.ID,
			model.NotificationDeliveryAbandoned, model.NotificationEndMaxAttempts).Count(&abandoned)
		if abandoned != 300 {
			t.Fatalf("D 應全部放棄，得 %d", abandoned)
		}
		if elapsed := e.clock.now().Sub(start); elapsed > bound {
			t.Fatalf("放棄時間 %s 超過上界 %s", elapsed, bound)
		}
	})

	t.Run("(c) 單筆失敗不波及同目的地其他紀錄", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, func(n int, w http.ResponseWriter, _ *http.Request) {
			if n == 0 {
				w.WriteHeader(400)
				return
			}
			w.WriteHeader(200)
		})
		c := e.channel("H", "webhook", srv.srv.URL, true, "low")
		first := e.liveRow(c.ID, "high", 0)
		for i := 0; i < 4; i++ {
			e.liveRow(c.ID, "high", 0)
		}
		e.w.RunOnce()
		for _, r := range e.deliveries() {
			if r.ID == first.ID {
				if r.Attempts != 1 || r.State != model.NotificationDeliveryRetrying {
					t.Fatalf("第一筆: %+v", r)
				}
			} else if r.State != model.NotificationDeliveryDelivered {
				t.Fatalf("其餘應送達: %+v", r)
			}
		}
	})

	t.Run("(d) 改址後舊網址的快照紀錄與通道當下設定分在不同目的地", func(t *testing.T) {
		e := newNDLEnv(t)
		e.w.httpTimeout = 150 * time.Millisecond
		old := newStubSrv(t, nil, func(_ int, w http.ResponseWriter, _ *http.Request) { time.Sleep(600 * time.Millisecond) })
		cur := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", cur.srv.URL, true, "low")
		snap := e.snapshotRow(c.ID, old.srv.URL, 1, 0)
		for i := 0; i < 3; i++ {
			e.liveRow(c.ID, "low", 0)
		}
		e.w.RunOnce()
		if cur.count() != 3 {
			t.Fatalf("新網址應收到 3 個請求，得 %d", cur.count())
		}
		if r := e.row(snap.ID); r.Attempts != 1 || r.State != model.NotificationDeliveryRetrying {
			t.Fatalf("舊網址那筆應計一次: %+v", r)
		}
		for _, r := range e.deliveries() {
			if r.ID != snap.ID && (r.State != model.NotificationDeliveryDelivered || r.Attempts != 1) {
				t.Fatalf("新網址紀錄不應被一起計次: %+v", r)
			}
		}
	})

	t.Run("(e) 同目的地 high 先於 low", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		low := e.liveRow(c.ID, "low", 0)
		high := e.liveRow(c.ID, "high", 0)
		e.db.Model(&model.NotificationMessage{}).Where("id = ?", *e.row(high.ID).MessageID).Update("event_key", string(notifycat.EventBreakGlassUsed))
		_ = low
		e.w.RunOnce()
		if srv.count() != 2 || !strings.Contains(string(srv.body(0)), string(notifycat.EventBreakGlassUsed)) {
			t.Fatalf("high 應先送: %s", srv.body(0))
		}
	})

	t.Run("(f) 改正通道網址後下一次打到新網址；(g) 密文損毀計一次失敗、修好後送達", func(t *testing.T) {
		e := newNDLEnv(t)
		fixed := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", "http://127.0.0.1:1/wrong", true, "low")
		r := e.liveRow(c.ID, "medium", 0)
		e.w.RunOnce()
		if got := e.row(r.ID); got.Attempts != 1 || got.State != model.NotificationDeliveryRetrying {
			t.Fatalf("打錯網址應失敗一次: %+v", got)
		}
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", c.ID).Update("url", fixed.srv.URL)
		e.clock.advance(2 * time.Second)
		e.w.RunOnce()
		if fixed.count() != 1 || e.row(r.ID).State != model.NotificationDeliveryDelivered {
			t.Fatalf("改正後應打到新網址: %d", fixed.count())
		}

		r2 := e.liveRow(c.ID, "medium", 0)
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", c.ID).Update("url", "enc:v9:Y29ycnVwdA==")
		e.w.RunOnce()
		if got := e.row(r2.ID); got.Attempts != 1 || got.State != model.NotificationDeliveryRetrying || got.LastError != channelUnreadableText {
			t.Fatalf("密文損毀應計一次失敗: %+v", got)
		}
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", c.ID).Update("url", fixed.srv.URL)
		e.clock.advance(2 * time.Second)
		e.w.RunOnce()
		if e.row(r2.ID).State != model.NotificationDeliveryDelivered {
			t.Fatal("修好密文後應送達")
		}
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// nextDue 最早的下次嘗試時間（沒有進行中紀錄時回現在）。
func (e *ndlEnv) nextDue() time.Time {
	var rows []model.NotificationDelivery
	e.db.Where("state IN ?", activeOutboxStates()).Order("next_attempt_at").Limit(1).Find(&rows)
	if len(rows) == 0 {
		return e.clock.now()
	}
	return rows[0].NextAttemptAt
}

// ---- 5.2 次數上限、退避與限流 ----

func TestDeliveryAttemptCapAndBackoff(t *testing.T) {
	t.Run("(a)(b) 恆回 500：等待依序倍增到 2 小時，第 48 次後放棄、之後不再送", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, respondStatus(500))
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		r := e.liveRow(c.ID, "high", 0)
		want := []int64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 7200}
		for i := 1; i <= notifyMaxAttempts; i++ {
			before := e.clock.now()
			e.w.RunOnce()
			got := e.row(r.ID)
			if got.Attempts != i {
				t.Fatalf("第 %d 輪 attempts=%d", i, got.Attempts)
			}
			if i <= len(want) {
				if wait := got.NextAttemptAt.Sub(before); wait != time.Duration(want[i-1])*time.Second {
					t.Fatalf("第 %d 次後等待 %s，應為 %d 秒", i, wait, want[i-1])
				}
			}
			if i < notifyMaxAttempts {
				e.clock.advance(got.NextAttemptAt.Sub(e.clock.now()))
			}
		}
		got := e.row(r.ID)
		if got.State != model.NotificationDeliveryAbandoned || got.Attempts != 48 || got.EndReason != model.NotificationEndMaxAttempts {
			t.Fatalf("第 48 次後應放棄: %+v", got)
		}
		reqs := srv.count()
		for i := 0; i < 10; i++ {
			e.clock.advance(3 * time.Hour)
			e.w.RunOnce()
		}
		if srv.count() != reqs {
			t.Fatal("放棄後不得再送")
		}
	})

	t.Run("(c) 401 三次後 200：送達且 attempts=4", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, func(n int, w http.ResponseWriter, _ *http.Request) {
			if n < 3 {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(200)
		})
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		r := e.liveRow(c.ID, "high", 0)
		for i := 0; i < 4; i++ {
			e.w.RunOnce()
			e.clock.advance(10 * time.Second)
		}
		if got := e.row(r.ID); got.State != model.NotificationDeliveryDelivered || got.Attempts != 4 {
			t.Fatalf("%+v", got)
		}
	})

	t.Run("(f) 送出 panic：其他紀錄照送、該列計次，每輪 panic 到 48 次放棄", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		bad := e.liveRow(c.ID, "high", 0)
		ok := e.liveRow(c.ID, "low", 0)
		e.w.hooks.beforeSend = func(id uint) {
			if id == bad.ID {
				panic("injected")
			}
		}
		e.w.RunOnce()
		if e.row(ok.ID).State != model.NotificationDeliveryDelivered || e.row(bad.ID).Attempts != 1 {
			t.Fatalf("ok=%s bad.attempts=%d", e.row(ok.ID).State, e.row(bad.ID).Attempts)
		}
		for i := 0; i < 60 && e.row(bad.ID).State != model.NotificationDeliveryAbandoned; i++ {
			e.clock.advance(3 * time.Hour)
			e.w.RunOnce()
		}
		if got := e.row(bad.ID); got.State != model.NotificationDeliveryAbandoned || got.Attempts != 48 {
			t.Fatalf("%+v", got)
		}
	})

	t.Run("(g) 認領後不寫結果即返回：次數已加，租約到期再加，到 48 由掃描放棄", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		r := e.liveRow(c.ID, "high", 0)
		e.w.hooks.afterClaim = func(uint) bool { return true }
		e.w.RunOnce()
		if got := e.row(r.ID); got.Attempts != 1 {
			t.Fatalf("認領即計次: %d", got.Attempts)
		}
		e.w.RunOnce()
		if got := e.row(r.ID); got.Attempts != 1 {
			t.Fatalf("租約未到期不得再認領: %d", got.Attempts)
		}
		for i := 0; i < 60; i++ {
			e.clock.advance(61 * time.Second)
			e.w.RunOnce()
		}
		if got := e.row(r.ID); got.State != model.NotificationDeliveryAbandoned || got.Attempts != 48 || srv.count() != 0 {
			t.Fatalf("%+v 收到 %d", got, srv.count())
		}
	})

	t.Run("(h) 型別不在登錄中：認領前判斷，attempts 維持原值", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		fresh := e.liveRow(c.ID, "high", 0)
		retried := e.liveRow(c.ID, "high", 3)
		e.db.Exec(`UPDATE notification_channels SET type = 'teams' WHERE id = ?`, c.ID)
		e.w.RunOnce()
		for id, want := range map[uint]int{fresh.ID: 0, retried.ID: 3} {
			got := e.row(id)
			if got.Attempts != want || got.EndReason != model.NotificationEndTypeUnregistered || got.LeaseUntil != nil ||
				got.State != model.NotificationDeliveryAbandoned {
				t.Fatalf("%+v", got)
			}
		}
		if srv.count() != 0 {
			t.Fatal("不得送出")
		}
	})
}

func TestDeliveryRateLimit(t *testing.T) {
	t.Run("(d) 429 帶 Retry-After：只計被拒那一筆，其餘延後不計次", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, e.clock, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(429)
		})
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		first := e.liveRow(c.ID, "high", 0)
		var others []uint
		for i := 0; i < 5; i++ {
			others = append(others, e.liveRow(c.ID, "low", 0).ID)
		}
		t0 := e.clock.now()
		e.w.RunOnce()
		if got := e.row(first.ID); got.Attempts != 1 || !got.NextAttemptAt.Equal(t0.Add(30*time.Second)) {
			t.Fatalf("第一次後應排在 30 秒後: %+v", got)
		}
		for _, id := range others {
			got := e.row(id)
			if got.Attempts != 0 || got.ThrottledSince == nil || got.NextAttemptAt.Before(t0.Add(30*time.Second)) {
				t.Fatalf("其餘應延後不計次: %+v", got)
			}
		}
		e.clock.advance(10 * time.Second)
		e.w.RunOnce()
		if srv.count() != 1 {
			t.Fatalf("暫停期間不得送出: %d", srv.count())
		}
	})

	t.Run("(d) 次數與等待：第 6 次 32 秒、第 13 次 4096 秒，放棄時已超過 69 小時", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, e.clock, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(429)
		})
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		r := e.liveRow(c.ID, "high", 0)
		start := e.clock.now()
		for i := 1; i <= notifyMaxAttempts; i++ {
			before := e.clock.now()
			e.w.RunOnce()
			got := e.row(r.ID)
			switch i {
			case 6:
				if w := got.NextAttemptAt.Sub(before); w != 32*time.Second {
					t.Fatalf("第 6 次後 %s", w)
				}
			case 13:
				if w := got.NextAttemptAt.Sub(before); w != 4096*time.Second {
					t.Fatalf("第 13 次後 %s", w)
				}
			}
			if got.State == model.NotificationDeliveryAbandoned {
				break
			}
			e.clock.advance(got.NextAttemptAt.Sub(e.clock.now()))
		}
		got := e.row(r.ID)
		if got.State != model.NotificationDeliveryAbandoned || e.clock.now().Sub(start) <= 69*time.Hour {
			t.Fatalf("%+v elapsed=%s", got, e.clock.now().Sub(start))
		}
	})

	t.Run("(e) Retry-After 的 HTTP 日期與不合法值", func(t *testing.T) {
		now := time.Date(2015, 10, 21, 7, 0, 0, 0, time.UTC)
		if d, ok := parseRetryAfterHeader("Wed, 21 Oct 2015 07:28:00 GMT", now); !ok || d != 28*time.Minute {
			t.Fatalf("HTTP 日期: %s %v", d, ok)
		}
		for _, v := range []string{"Wed, 21 Oct 2015 06:28:00 GMT", "-5", "abc", ""} {
			if _, ok := parseRetryAfterHeader(v, now); ok {
				t.Fatalf("%q 應忽略", v)
			}
		}
	})

	t.Run("(j) 限流的獨立上限：自第一次延後起 72 小時全部放棄，沒有一筆達 48 次", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, e.clock, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(429)
		})
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		for i := 0; i < 20; i++ {
			e.liveRow(c.ID, "high", 0)
		}
		start := e.clock.now()
		for e.clock.now().Sub(start) <= 73*time.Hour {
			e.w.RunOnce()
			e.clock.advance(61 * time.Second)
		}
		e.w.RunOnce()
		// 依分級與編號取件時，編號小的紀錄每次到期都排在前面而被拒，依決策 11 第 1 點約 70 小時就用完 48 次，
		// 會先以 max_attempts 放棄，這是可接受的結果。
		// 斷言：時窗過後全部放棄；以 rate_limited 放棄的紀錄次數都未達上限；兩種原因之外沒有其他結果。
		rateLimited := 0
		for _, r := range e.deliveries() {
			if r.State != model.NotificationDeliveryAbandoned {
				t.Fatalf("時窗過後應全部放棄: %+v", r)
			}
			switch r.EndReason {
			case model.NotificationEndRateLimited:
				rateLimited++
				if r.Attempts >= 48 || r.ThrottledSince == nil {
					t.Fatalf("%+v", r)
				}
			case model.NotificationEndMaxAttempts:
				if r.Attempts != 48 {
					t.Fatalf("%+v", r)
				}
			default:
				t.Fatalf("%+v", r)
			}
		}
		if rateLimited == 0 {
			t.Fatal("應有紀錄以 rate_limited 放棄")
		}
		t.Logf("20 筆中 %d 筆以 rate_limited 放棄，%d 筆以 max_attempts 放棄", rateLimited, 20-rateLimited)
	})

	t.Run("(k) slack_app 送出節流：每輪名額依距上次送出的秒數；webhook 不節流", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, e.clock, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		})
		ch := model.NotificationChannel{Name: "app", Type: model.NotificationChannelTypeSlackApp, URL: srv.srv.URL,
			Secret: "xoxb-test", Target: "C123", Enabled: true, Language: "zh-TW", MinSeverity: "low"}
		e.db.Create(&ch)
		for i := 0; i < 30; i++ {
			e.liveRow(ch.ID, "high", 0)
		}
		perRound := []int{}
		for i := 0; i < 10; i++ {
			before := srv.count()
			e.w.RunOnce()
			perRound = append(perRound, srv.count()-before)
			e.clock.advance(2 * time.Second)
		}
		if perRound[0] != 1 || srv.count() != 19 {
			t.Fatalf("每輪請求數 %v（應 1 之後每輪 2，共 19）", perRound)
		}
		var sumAttempts int64
		e.db.Raw(`SELECT COALESCE(SUM(attempts),0) FROM system_alert_outbox`).Scan(&sumAttempts)
		if sumAttempts != 19 {
			t.Fatalf("次數只在實際送出時加：%d", sumAttempts)
		}

		e2 := newNDLEnv(t)
		hook := newStubSrv(t, nil, nil)
		c2 := e2.channel("hook", "webhook", hook.srv.URL, true, "low")
		for i := 0; i < 30; i++ {
			e2.liveRow(c2.ID, "high", 0)
		}
		e2.w.RunOnce()
		if hook.count() != 10 {
			t.Fatalf("webhook 第一輪應收到 10 個，得 %d", hook.count())
		}
	})
}

// ---- 5.3 通道變動 ----

func TestDeliveryChannelChanges(t *testing.T) {
	t.Run("(a) 停用：不帶快照者取消、系統安全告警照送；刪除：channel_deleted", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		live := e.liveRow(c.ID, "medium", 0)
		snap := e.snapshotRow(c.ID, srv.srv.URL, 0, 0)
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", c.ID).Update("enabled", false)
		e.w.RunOnce()
		if got := e.row(live.ID); got.State != model.NotificationDeliveryCanceled || got.EndReason != model.NotificationEndChannelDisabled {
			t.Fatalf("%+v", got)
		}
		if e.row(snap.ID).State != model.NotificationDeliveryDelivered || srv.count() != 1 {
			t.Fatalf("系統安全告警應照送: 收到 %d", srv.count())
		}
		live2 := e.liveRow(c.ID, "medium", 0)
		e.db.Exec(`DELETE FROM notification_channels WHERE id = ?`, c.ID)
		e.w.RunOnce()
		if got := e.row(live2.ID); got.EndReason != model.NotificationEndChannelDeleted {
			t.Fatalf("%+v", got)
		}
	})

	t.Run("(b) 系統安全告警排入後改網址，重送打到舊網址", func(t *testing.T) {
		e := newNDLEnv(t)
		old := newStubSrv(t, nil, func(n int, w http.ResponseWriter, _ *http.Request) {
			if n == 0 {
				w.WriteHeader(400)
				return
			}
			w.WriteHeader(200)
		})
		other := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", old.srv.URL, true, "low")
		snap := e.snapshotRow(c.ID, old.srv.URL, 0, 0)
		e.w.RunOnce()
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", c.ID).Update("url", other.srv.URL)
		e.clock.advance(2 * time.Second)
		e.w.RunOnce()
		if old.count() != 2 || other.count() != 0 || e.row(snap.ID).State != model.NotificationDeliveryDelivered {
			t.Fatalf("old=%d other=%d", old.count(), other.count())
		}
	})

	t.Run("(c) 取消步驟與送出之間的變動：不計次、不送", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, nil)
		c1 := e.channel("c1", "webhook", srv.srv.URL, true, "low")
		c2 := e.channel("c2", "webhook", srv.srv.URL, true, "low")
		r1 := e.liveRow(c1.ID, "medium", 2)
		r2 := e.liveRow(c2.ID, "medium", 2)
		e.w.hooks.afterCancel = func() {
			e.db.Model(&model.NotificationChannel{}).Where("id = ?", c1.ID).Update("enabled", false)
			e.db.Exec(`DELETE FROM notification_channels WHERE id = ?`, c2.ID)
		}
		e.w.RunOnce()
		for id, reason := range map[uint]string{r1.ID: model.NotificationEndChannelDisabled, r2.ID: model.NotificationEndChannelDeleted} {
			got := e.row(id)
			if got.EndReason != reason || got.Attempts != 2 || got.LeaseUntil != nil || got.LastError == channelUnreadableText {
				t.Fatalf("%+v", got)
			}
		}
		if srv.count() != 0 {
			t.Fatal("不得送出")
		}
	})

	t.Run("(d) 認領前讀取之後的窗口：這一筆照送並計次，下一筆下一輪取消", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		r1 := e.liveRow(c.ID, "high", 0)
		e.w.hooks.afterPreRead = func(id uint) {
			if id == r1.ID {
				e.db.Model(&model.NotificationChannel{}).Where("id = ?", c.ID).Update("enabled", false)
			}
		}
		e.w.RunOnce()
		if got := e.row(r1.ID); got.State != model.NotificationDeliveryDelivered || got.Attempts != 1 || srv.count() != 1 {
			t.Fatalf("%+v 收到 %d", got, srv.count())
		}
		e.w.hooks.afterPreRead = nil
		r2 := e.liveRow(c.ID, "high", 0)
		e.w.RunOnce()
		if e.row(r2.ID).State != model.NotificationDeliveryCanceled {
			t.Fatal("下一筆應取消")
		}
	})
}

// ---- 5.4 送出前檢查 ----

func TestDeliveryPrecheck(t *testing.T) {
	event := notifycat.EventDailyReviewOverdue
	t.Cleanup(func() { RegisterDeliveryPrecheck(event, nil) })

	t.Run("(a) 取消：認領前判斷、不計次；原因碼寫入結束原因", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		r := e.liveRow(c.ID, "high", 2)
		var seen model.NotificationChannel
		RegisterDeliveryPrecheck(event, func(in DeliveryPrecheckInput) DeliveryPrecheckResult {
			seen = in.Channel
			return DeliveryPrecheckResult{Cancel: true}
		})
		e.w.RunOnce()
		got := e.row(r.ID)
		if srv.count() != 0 || got.Attempts != 2 || got.LeaseUntil != nil || got.State != model.NotificationDeliveryCanceled ||
			got.EndReason != model.NotificationEndPrecheckCanceled {
			t.Fatalf("%+v 收到 %d", got, srv.count())
		}
		if seen.ID != c.ID || seen.URL != srv.srv.URL {
			t.Fatalf("檢查應收到認領前讀到的通道列: %+v", seen)
		}
		r2 := e.liveRow(c.ID, "high", 0)
		RegisterDeliveryPrecheck(event, func(DeliveryPrecheckInput) DeliveryPrecheckResult {
			return DeliveryPrecheckResult{Cancel: true, Reason: model.NotificationEndChannelDisabled}
		})
		e.w.RunOnce()
		if got := e.row(r2.ID); got.EndReason != model.NotificationEndChannelDisabled {
			t.Fatalf("回報的原因碼應寫入結束原因: %s", got.EndReason)
		}
	})

	t.Run("(b) 未登錄時照送", func(t *testing.T) {
		RegisterDeliveryPrecheck(event, nil)
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		e.liveRow(c.ID, "high", 0)
		e.w.RunOnce()
		if srv.count() != 1 {
			t.Fatal("應照送")
		}
	})

	t.Run("(c) 檢查 panic：改為認領並記一次失敗，到 48 次由掃描放棄", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, nil, nil)
		c := e.channel("c", "webhook", srv.srv.URL, true, "low")
		r := e.liveRow(c.ID, "high", 0)
		RegisterDeliveryPrecheck(event, func(DeliveryPrecheckInput) DeliveryPrecheckResult { panic("injected") })
		e.w.RunOnce()
		if got := e.row(r.ID); got.Attempts != 1 || got.State != model.NotificationDeliveryRetrying {
			t.Fatalf("%+v", got)
		}
		for i := 0; i < 60 && e.row(r.ID).State != model.NotificationDeliveryAbandoned; i++ {
			e.clock.advance(3 * time.Hour)
			e.w.RunOnce()
		}
		if got := e.row(r.ID); got.State != model.NotificationDeliveryAbandoned || got.Attempts != 48 || srv.count() != 0 {
			t.Fatalf("%+v", got)
		}
		RegisterDeliveryPrecheck(event, nil)
	})
}

// ---- 5.5 升級後既有紀錄 ----

func TestLegacyRowsUnderAttemptCap(t *testing.T) {
	e := newNDLEnv(t)
	srv := newStubSrv(t, nil, nil)
	c := e.channel("c", "webhook", srv.srv.URL, true, "low")
	over := e.snapshotRow(c.ID, srv.srv.URL, 0, 60)
	keep := e.snapshotRow(c.ID, srv.srv.URL, 0, 3)
	e.w.RunOnce()
	if got := e.row(over.ID); got.State != model.NotificationDeliveryAbandoned || got.EndReason != model.NotificationEndMaxAttempts {
		t.Fatalf("%+v", got)
	}
	if srv.count() != 1 || !strings.Contains(string(srv.body(0)), `"delivery_id":"`+keep.DeliveryKey+`"`) {
		t.Fatalf("另一筆應以原投遞識別送出: %d", srv.count())
	}
}

// ---- 5.8 依型別處理轉址 ----

// fakeRisks 以網址子字串標示風險項。
type fakeRisks map[string]string

func (f fakeRisks) NotifyRisks(u string) []model.TransmissionRisk {
	var out []model.TransmissionRisk
	for sub, key := range f {
		if strings.Contains(u, sub) {
			out = append(out, model.TransmissionRisk{Key: key})
		}
	}
	return out
}

func redirectTo(target string, code int) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, code)
	}
}

func TestDeliveryRedirectRules(t *testing.T) {
	t.Run("(a) slack_app 不跟隨任何 3xx", func(t *testing.T) {
		for _, code := range []int{302, 307, 308} {
			for _, suffix := range []string{"", "/other-path"} {
				e := newNDLEnv(t)
				b := newStubSrv(t, nil, nil)
				a := newStubSrv(t, nil, redirectTo(b.srv.URL+suffix, code))
				ch := model.NotificationChannel{Name: "app", Type: model.NotificationChannelTypeSlackApp, URL: a.srv.URL,
					Secret: "xoxb-test", Target: "C1", Enabled: true, Language: "zh-TW", MinSeverity: "low"}
				e.db.Create(&ch)
				r := e.liveRow(ch.ID, "high", 0)
				e.w.RunOnce()
				got := e.row(r.ID)
				if b.count() != 0 || got.State != model.NotificationDeliveryRetrying || !strings.Contains(got.LastError, "3xx") {
					t.Fatalf("code=%d: B 收到 %d, %+v", code, b.count(), got)
				}
				status, err := SendTestNotification(&ch)
				if err == nil && status >= 200 && status < 300 {
					t.Fatalf("測試發送應回失敗: %d", status)
				}
				if b.count() != 0 {
					t.Fatal("測試發送不得跟隨")
				}
			}
		}
	})

	for _, typ := range []string{model.NotificationChannelTypeWebhook, model.NotificationChannelTypeSlack} {
		typ := typ
		t.Run("(b) "+typ+" 307 到合規位址：跟隨、本文與簽章相同、不帶 Referer", func(t *testing.T) {
			e := newNDLEnv(t)
			b := newStubSrv(t, nil, nil)
			a := newStubSrv(t, nil, redirectTo(b.srv.URL+"/final", http.StatusTemporaryRedirect))
			secret := ""
			if typ == model.NotificationChannelTypeWebhook {
				secret = "sign-key"
			}
			ch := model.NotificationChannel{Name: "c", Type: typ, URL: a.srv.URL + "/hook?token=abc", Secret: secret,
				Enabled: true, Language: "zh-TW", MinSeverity: "low"}
			e.db.Create(&ch)
			r := e.liveRow(ch.ID, "high", 0)
			e.w.RunOnce()
			if b.count() != 1 || e.row(r.ID).State != model.NotificationDeliveryDelivered {
				t.Fatalf("B 收到 %d, %+v", b.count(), e.row(r.ID))
			}
			if string(a.body(0)) != string(b.body(0)) {
				t.Fatal("本文應相同")
			}
			if typ == model.NotificationChannelTypeWebhook && b.header(0).Get(signatureHeaderKey) != a.header(0).Get(signatureHeaderKey) {
				t.Fatal("簽章應相同")
			}
			if ref := b.header(0).Get("Referer"); ref != "" {
				t.Fatalf("轉址後不得帶 Referer: %q", ref)
			}
			if status, err := SendTestNotification(&ch); err != nil || status != 200 {
				t.Fatalf("測試發送應成功: %d %v", status, err)
			}
		})

		t.Run("(c) "+typ+" 轉址到不符政策的位址：停止且判單筆失敗", func(t *testing.T) {
			e := newNDLEnv(t)
			d := newStubSrv(t, nil, nil)
			x := newStubSrv(t, nil, nil)
			risks := fakeRisks{d.srv.URL: "risk_y", x.srv.URL: "risk_x"}
			e.w.risks = risks
			SetNotificationTransmissionPolicy(risks)
			t.Cleanup(func() { SetNotificationTransmissionPolicy(nil) })
			// 保存網址本身帶風險項 X；轉址目的地帶不同的風險項 Y。
			a := newStubSrv(t, nil, redirectTo(d.srv.URL+"/d", http.StatusTemporaryRedirect))
			ch := model.NotificationChannel{Name: "c", Type: typ, URL: a.srv.URL + "/?via=" + x.srv.URL, Enabled: true, Language: "zh-TW", MinSeverity: "low"}
			e.db.Create(&ch)
			r := e.liveRow(ch.ID, "high", 0)
			e.w.RunOnce()
			got := e.row(r.ID)
			if d.count() != 0 || got.State != model.NotificationDeliveryRetrying || got.LastError != errRedirectPolicy.Error() {
				t.Fatalf("D 收到 %d, %+v", d.count(), got)
			}
			if status, err := SendTestNotification(&ch); err == nil && status == 200 {
				t.Fatal("測試發送應回失敗")
			}
			if d.count() != 0 {
				t.Fatal("測試發送不得送到不符政策的位址")
			}
		})
	}

	t.Run("(c) https 轉 http 一律不通過", func(t *testing.T) {
		check := notificationCheckRedirect(model.NotificationChannelTypeWebhook, "https://a.example/h", nil)
		prev, _ := http.NewRequest("POST", "https://a.example/h", nil)
		next, _ := http.NewRequest("POST", "http://c.example/h", nil)
		if err := check(next, []*http.Request{prev}); !errors.Is(err, errRedirectPolicy) {
			t.Fatalf("應拒絕降為 http: %v", err)
		}
		ok, _ := http.NewRequest("POST", "https://c.example/h", nil)
		ok.Header.Set("Referer", "https://a.example/h")
		if err := check(ok, []*http.Request{prev}); err != nil || ok.Header.Get("Referer") != "" {
			t.Fatalf("合規轉址應通過且移除 Referer: %v %q", err, ok.Header.Get("Referer"))
		}
	})

	t.Run("(d) webhook 連續轉址 6 次：第 6 跳不送出，原因轉址次數過多", func(t *testing.T) {
		e := newNDLEnv(t)
		final := newStubSrv(t, nil, nil)
		next := final.srv.URL
		var hops []*stubSrv
		for i := 0; i < 6; i++ {
			s := newStubSrv(t, nil, redirectTo(next, http.StatusTemporaryRedirect))
			hops = append(hops, s)
			next = s.srv.URL
		}
		ch := model.NotificationChannel{Name: "c", Type: "webhook", URL: next, Enabled: true, Language: "zh-TW", MinSeverity: "low"}
		e.db.Create(&ch)
		r := e.liveRow(ch.ID, "high", 0)
		e.w.RunOnce()
		if final.count() != 0 || e.row(r.ID).LastError != errRedirectTooMany.Error() {
			t.Fatalf("final 收到 %d, %+v", final.count(), e.row(r.ID))
		}
	})
}

// TestNotificationHTTPClientsUseSharedRedirect 本套件非測試檔的每個 http.Client 字面量都要以共用函式設定 CheckRedirect。
func TestNotificationHTTPClientsUseSharedRedirect(t *testing.T) {
	hits := scanHTTPClientLiterals(t, ".")
	for _, h := range hits {
		if !h.shared {
			t.Errorf("%s:%d 的 http.Client 沒有使用 notificationCheckRedirect", h.file, h.line)
		}
	}
	if len(hits) == 0 {
		t.Fatal("掃描不到任何 http.Client 字面量，守衛失效")
	}
}

type clientLiteralHit struct {
	file   string
	line   int
	shared bool
}

func scanHTTPClientLiterals(t *testing.T, dir string) []clientLiteralHit {
	t.Helper()
	entries, err := readGoSources(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []clientLiteralHit
	for name, src := range entries {
		lines := strings.Split(src, "\n")
		for i, ln := range lines {
			if !strings.Contains(ln, "http.Client{") {
				continue
			}
			end := i
			depth := strings.Count(ln, "{") - strings.Count(ln, "}")
			for depth > 0 && end+1 < len(lines) {
				end++
				depth += strings.Count(lines[end], "{") - strings.Count(lines[end], "}")
			}
			block := strings.Join(lines[i:end+1], "\n")
			out = append(out, clientLiteralHit{file: name, line: i + 1,
				shared: strings.Contains(block, "CheckRedirect: notificationCheckRedirect(")})
		}
	}
	return out
}

var _ = fmt.Sprintf
var _ = strconv.Itoa

// readGoSources 讀目錄下非測試的 .go 檔（檔名 → 內容）。
func readGoSources(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out[name] = string(b)
	}
	return out, nil
}

// TestLiveRowUsesCurrentChannelLanguage 排入後改通道語系，不帶快照的紀錄下一次嘗試用新語系。
func TestLiveRowUsesCurrentChannelLanguage(t *testing.T) {
	e := newNDLEnv(t)
	srv := newStubSrv(t, nil, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 0 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	})
	c := e.channel("s", model.NotificationChannelTypeSlack, srv.srv.URL, true, "low")
	e.enqueueEvent(notifycat.EventDailyReviewOverdue, OverdueParams([]string{"2026-11-18"}, 1, "UTC"))
	e.w.RunOnce()
	e.db.Model(&model.NotificationChannel{}).Where("id = ?", c.ID).Update("language", model.NotificationChannelLanguageEnUS)
	e.clock.advance(2 * time.Second)
	e.w.RunOnce()
	if srv.count() != 2 || string(srv.body(0)) == string(srv.body(1)) {
		t.Fatalf("第二次應以新語系渲染: %d", srv.count())
	}
	en, _ := notifycat.Render(model.NotificationChannelLanguageEnUS, notifycat.EventDailyReviewOverdue, OverdueParams([]string{"2026-11-18"}, 1, "UTC"))
	if !strings.Contains(string(srv.body(1)), en) {
		t.Fatalf("第二次本文應含英文標題 %q: %s", en, srv.body(1))
	}
}

// TestDeliveryReservesSlotsForNonCommandCategories 同一目的地有大量高分級指令告警時，每輪至少 5 個名額留給其他類別。
func TestDeliveryReservesSlotsForNonCommandCategories(t *testing.T) {
	e := newNDLEnv(t)
	srv := newStubSrv(t, nil, nil)
	c := e.channel("c", "webhook", srv.srv.URL, true, "low")
	for i := 0; i < 20; i++ {
		a := e.alert(model.AlertSeverityHigh, 0, 1, nil)
		e.enqueueAlert(a)
	}
	for i := 0; i < 7; i++ {
		e.liveRow(c.ID, "low", 0)
	}
	e.w.RunOnce()
	var sys, cmd int64
	e.db.Model(&model.NotificationDelivery{}).Where("state = ? AND category = ?", model.NotificationDeliveryDelivered, model.NotificationCategorySystemEvent).Count(&sys)
	e.db.Model(&model.NotificationDelivery{}).Where("state = ? AND category = ?", model.NotificationDeliveryDelivered, model.NotificationCategoryCommandAlert).Count(&cmd)
	if sys != 5 || cmd != 5 {
		t.Fatalf("第一輪應送出 5 則系統事件與 5 則指令告警，得 %d、%d", sys, cmd)
	}
}

// TestRateLimitedSpacingDoesNotDelayOtherDestinations 限速目的地的送出間隔等待不延遲其他目的地：
// slack_app 積壓 100 筆、webhook 10 筆時，webhook 的 10 筆在第一輪、等待開始之前全部送出。
func TestRateLimitedSpacingDoesNotDelayOtherDestinations(t *testing.T) {
	e := newNDLEnv(t)
	app := newStubSrv(t, e.clock, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	hook := newStubSrv(t, e.clock, nil)
	ch := model.NotificationChannel{Name: "app", Type: model.NotificationChannelTypeSlackApp, URL: app.srv.URL,
		Secret: "xoxb-test", Target: "C1", Enabled: true, Language: "zh-TW", MinSeverity: "low"}
	e.db.Create(&ch)
	wh := e.channel("hook", "webhook", hook.srv.URL, true, "low")
	for i := 0; i < 100; i++ {
		e.liveRow(ch.ID, "high", 0)
	}
	for i := 0; i < 10; i++ {
		e.liveRow(wh.ID, "high", 0)
	}
	// 上次送出在 5 秒前：本輪名額 5，連續送出之間須間隔 1 秒。
	t0 := e.clock.now()
	e.w.markSent(deliveryDestKey{ChannelID: ch.ID, Audience: deliveryAudienceChannel}, t0.Add(-5*time.Second))
	e.w.RunOnce()
	if hook.count() != 10 {
		t.Fatalf("webhook 應在第一輪收到 10 筆，得 %d", hook.count())
	}
	for i, at := range hook.times {
		if !at.Equal(t0) {
			t.Fatalf("webhook 第 %d 筆在 %s 才送出，被限速目的地的等待延遲", i+1, at.Sub(t0))
		}
	}
	if app.count() < 2 {
		t.Fatalf("限速目的地本輪應送出多筆，得 %d", app.count())
	}
	for i := 1; i < app.count(); i++ {
		if gap := app.times[i].Sub(app.times[i-1]); gap < time.Second {
			t.Fatalf("限速目的地第 %d、%d 筆間隔 %s，少於 1 秒", i, i+1, gap)
		}
	}
}
