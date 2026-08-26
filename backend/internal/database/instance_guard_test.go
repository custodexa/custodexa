package database

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"log"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// InstanceGuard 離線測試：
//   - sqlite 分支：第二次取鎖被攔、ack 相符／不符／未使用、釋放後可再取。
//   - fakeLockBackend 驅動 watchdog 狀態機：lost→regained、可重試／永久／未知、
//     overridden→held、競爭指認持鎖者、對等計數、關閉競態、panic 注入、事件緩衝。
//
// 確定性：一律以 CheckNow 驅動，不靠時序競賽；fake 不啟動 watchdog goroutine。
// 不用 t.Parallel：sqlite 分支共用包級 instanceGuardProcessMu，且測試改寫 log 輸出。

// ── 測試替身 ──────────────────────────────────────────────────────────────

type fakeLockBackend struct {
	mu          sync.Mutex
	tryLockFn   func(ctx context.Context) (bool, error)
	isHeldFn    func(ctx context.Context) (bool, error)
	holderFn    func(ctx context.Context) (HolderFingerprint, bool)
	peersFn     func(ctx context.Context) (int, error)
	reconnectFn func(ctx context.Context) error
	conn        bool
	pid         int
	closeCalls  []bool
	reconnects  int
}

func newFakeLockBackend() *fakeLockBackend {
	return &fakeLockBackend{conn: true, pid: 4321}
}

func (f *fakeLockBackend) tryLock(ctx context.Context) (bool, error) {
	if f.tryLockFn != nil {
		return f.tryLockFn(ctx)
	}
	return true, nil
}

func (f *fakeLockBackend) isHeld(ctx context.Context) (bool, error) {
	if f.isHeldFn != nil {
		return f.isHeldFn(ctx)
	}
	return true, nil
}

func (f *fakeLockBackend) holderFingerprint(ctx context.Context) (HolderFingerprint, bool) {
	if f.holderFn != nil {
		return f.holderFn(ctx)
	}
	return degradedFingerprint("no_holder"), false
}

func (f *fakeLockBackend) countPeers(ctx context.Context) (int, error) {
	if f.peersFn != nil {
		return f.peersFn(ctx)
	}
	return 0, nil
}

func (f *fakeLockBackend) sessionPID() int { return f.pid }

func (f *fakeLockBackend) connected() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conn
}

func (f *fakeLockBackend) setConnected(v bool) {
	f.mu.Lock()
	f.conn = v
	f.mu.Unlock()
}

func (f *fakeLockBackend) reconnect(ctx context.Context) error {
	f.mu.Lock()
	f.reconnects++
	f.mu.Unlock()
	if f.reconnectFn != nil {
		if err := f.reconnectFn(ctx); err != nil {
			f.setConnected(false)
			return err
		}
	}
	f.setConnected(true)
	return nil
}

func (f *fakeLockBackend) runsWatchdog() bool { return false }

func (f *fakeLockBackend) close(_ context.Context, unlock bool) {
	f.mu.Lock()
	f.closeCalls = append(f.closeCalls, unlock)
	f.conn = false
	f.mu.Unlock()
}

type eventRecorder struct {
	mu     sync.Mutex
	events []GuardEvent
}

func (r *eventRecorder) sink(ev GuardEvent) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *eventRecorder) all() []GuardEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]GuardEvent, len(r.events))
	copy(out, r.events)
	return out
}

func (r *eventRecorder) names() []string {
	var out []string
	for _, ev := range r.all() {
		out = append(out, ev.Event)
	}
	return out
}

// captureLog 攔截標準 log 輸出（測試結束還原）。
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func countLines(buf *bytes.Buffer, substr string) int {
	return strings.Count(buf.String(), substr)
}

// newHeldFakeGuard 以 fake 後端取鎖成功的守衛（held），sink 已注入。
func newHeldFakeGuard(t *testing.T, fake *fakeLockBackend, opts InstanceGuardOptions) (*InstanceGuard, *eventRecorder) {
	t.Helper()
	opts.backend = fake
	if opts.RetryInterval == 0 {
		opts.RetryInterval = time.Millisecond
	}
	if opts.RetryAttempts == 0 {
		opts.RetryAttempts = 2
	}
	g := NewInstanceGuard(nil, opts)
	rec := &eventRecorder{}
	g.SetEventSink(rec.sink)
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("fake 後端取鎖失敗: %v", err)
	}
	if g.State() != GuardStateHeld {
		t.Fatalf("取鎖後狀態 = %s，want held", g.State())
	}
	t.Cleanup(g.Stop)
	return g, rec
}

func newGuardSQLiteDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("開 sqlite: %v", err)
	}
	return db
}

var codePattern = regexp.MustCompile(`code=([0-9a-f]{12})`)

func fastOpts(ack string) InstanceGuardOptions {
	return InstanceGuardOptions{Ack: ack, RetryInterval: time.Millisecond, RetryAttempts: 2}
}

// ── sqlite 分支：攔下、ack、釋放 ───────────────────────────────────────────

func TestInstanceGuardSecondAcquireBlocked(t *testing.T) {
	db := newGuardSQLiteDB(t)
	a := NewInstanceGuard(db, fastOpts(""))
	if err := a.Acquire(context.Background()); err != nil {
		t.Fatalf("第一個實例取鎖失敗: %v", err)
	}
	t.Cleanup(a.Stop)
	if a.State() != GuardStateHeld {
		t.Fatalf("A 狀態 = %s，want held", a.State())
	}

	b := NewInstanceGuard(db, fastOpts(""))
	rec := &eventRecorder{}
	b.SetEventSink(rec.sink)
	err := b.Acquire(context.Background())
	if err == nil {
		t.Fatal("同一行程第二次取鎖 MUST 被攔下")
	}
	if !errors.Is(err, ErrInstanceGuardBlocked) {
		t.Fatalf("錯誤應可 errors.Is(ErrInstanceGuardBlocked)，實得 %v", err)
	}
	msg := err.Error()
	for _, want := range []string{
		"本版不支援多實例",
		"另一個資料庫工作階段持有",
		"code=",
		"INSTANCE_GUARD_ACK=",
		"先停止它",
		"未由本實例執行 migration 或任何資料寫入",
		"持鎖者變更後失效",
		"application_name=sqlite",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("攔下訊息缺 %q\n%s", want, msg)
		}
	}
	for _, banned := range []string{"password=", "host=", "dbname=", "client_addr"} {
		if strings.Contains(msg, banned) {
			t.Errorf("攔下訊息不得含 %q", banned)
		}
	}
	if b.State() != GuardStateReleased {
		t.Fatalf("被攔下的實例狀態 = %s，want released（不持有任何連線）", b.State())
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("被攔下不應發任何事件，實得 %d", n)
	}

	// 釋放後可再次取得
	a.Stop()
	c := NewInstanceGuard(db, fastOpts(""))
	if err := c.Acquire(context.Background()); err != nil {
		t.Fatalf("A 釋放後新實例應可取鎖: %v", err)
	}
	c.Stop()
}

func TestInstanceGuardAckMatches(t *testing.T) {
	db := newGuardSQLiteDB(t)
	a := NewInstanceGuard(db, fastOpts(""))
	if err := a.Acquire(context.Background()); err != nil {
		t.Fatalf("A 取鎖失敗: %v", err)
	}
	t.Cleanup(a.Stop)

	// 先以無 ack 取得本次衝突的確認碼（照操作者實際會做的事：從訊息抄 code）
	probe := NewInstanceGuard(db, fastOpts(""))
	err := probe.Acquire(context.Background())
	m := codePattern.FindStringSubmatch(err.Error())
	if len(m) != 2 {
		t.Fatalf("訊息中找不到 12 碼確認碼：%v", err)
	}
	code := m[1]

	b := NewInstanceGuard(db, fastOpts(code))
	rec := &eventRecorder{}
	b.SetEventSink(rec.sink)
	if err := b.Acquire(context.Background()); err != nil {
		t.Fatalf("ack 相符 MUST 允許啟動，實得 %v", err)
	}
	t.Cleanup(b.Stop)
	snap := b.Snapshot()
	if snap.State != GuardStateOverridden || snap.Reason != GuardReasonAckStartup {
		t.Fatalf("狀態 = %s/%s，want overridden/ack_startup", snap.State, snap.Reason)
	}
	if snap.Holder == nil || snap.Holder.Code != code || snap.Ack != code {
		t.Fatalf("快照應含持鎖者指紋與 ack：%+v", snap)
	}
	if snap.Since.IsZero() || snap.Instance.Hostname == "" || snap.Instance.PID == 0 || snap.Instance.StartedAt.IsZero() {
		t.Fatalf("快照的 since／instance 三元組不齊：%+v", snap)
	}

	evs := rec.all()
	if len(evs) != 1 || evs[0].Event != GuardEventOverridden {
		t.Fatalf("應恰有一筆 overridden 事件，實得 %v", rec.names())
	}
	ev := evs[0]
	if ev.Reason != GuardReasonAckStartup || ev.Ack != code || ev.Holder == nil || ev.Holder.Code != code ||
		ev.Holder.Source != FingerprintSourceSQLite || ev.Instance.PID == 0 || ev.Instance.Hostname == "" ||
		ev.Instance.StartedAt.IsZero() || ev.At.IsZero() {
		t.Fatalf("overridden 事件欄位不齊：%+v", ev)
	}

	// 原持鎖者結束 → 下一輪重取成功 → held ＋ regained{reason=ack_startup}
	a.Stop()
	time.Sleep(2 * time.Millisecond)
	if st := b.CheckNow(context.Background()); st != GuardStateHeld {
		t.Fatalf("原持鎖者釋放後重取應成功，狀態 = %s", st)
	}
	evs = rec.all()
	if len(evs) != 2 || evs[1].Event != GuardEventRegained || evs[1].Reason != GuardReasonAckStartup {
		t.Fatalf("應新增 regained{reason=ack_startup}，實得 %v", rec.names())
	}
	if evs[1].UnheldForMS <= 0 {
		t.Fatalf("regained 事件應含未持鎖時長，實得 %d ms", evs[1].UnheldForMS)
	}
	if b.Snapshot().Holder != nil {
		t.Fatal("取得鎖後持鎖者指紋應清空")
	}
}

func TestInstanceGuardAckMismatch(t *testing.T) {
	db := newGuardSQLiteDB(t)
	a := NewInstanceGuard(db, fastOpts(""))
	if err := a.Acquire(context.Background()); err != nil {
		t.Fatalf("A 取鎖失敗: %v", err)
	}
	t.Cleanup(a.Stop)

	b := NewInstanceGuard(db, fastOpts("000000000000"))
	rec := &eventRecorder{}
	b.SetEventSink(rec.sink)
	err := b.Acquire(context.Background())
	if !errors.Is(err, ErrInstanceGuardBlocked) {
		t.Fatalf("ack 不符 MUST 視同未帶而攔下，實得 %v", err)
	}
	if !strings.Contains(err.Error(), "持鎖者已變更") {
		t.Fatalf("不符時訊息應加註持鎖者已變更\n%s", err)
	}
	if !strings.Contains(err.Error(), "code=") {
		t.Fatal("不符時訊息仍應含新的確認碼")
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("不符時不得寫 overridden 事件，實得 %d 筆", n)
	}
}

func TestInstanceGuardAckUnusedWithoutConflict(t *testing.T) {
	buf := captureLog(t)
	db := newGuardSQLiteDB(t)
	a := NewInstanceGuard(db, fastOpts("ab12cd34ef56"))
	rec := &eventRecorder{}
	a.SetEventSink(rec.sink)
	if err := a.Acquire(context.Background()); err != nil {
		t.Fatalf("無衝突時有 ack 應正常取鎖: %v", err)
	}
	t.Cleanup(a.Stop)
	if a.State() != GuardStateHeld {
		t.Fatalf("狀態 = %s，want held", a.State())
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("無衝突時不得發 overridden 事件，實得 %d", n)
	}
	if !strings.Contains(buf.String(), "已設定但本次未偵測到衝突") || !strings.Contains(buf.String(), "建議自環境移除") {
		t.Fatalf("應有「已設定未使用、建議移除」的資訊日誌，實得：%s", buf.String())
	}
}

type guardFakeDialector struct {
	gorm.Dialector
	name string
}

func (d guardFakeDialector) Name() string { return d.name }

func TestInstanceGuardUnknownDialectFailClose(t *testing.T) {
	db := newGuardSQLiteDB(t)
	orig := db.Config.Dialector
	db.Config.Dialector = guardFakeDialector{Dialector: orig, name: "mysql"}
	defer func() { db.Config.Dialector = orig }()

	g := NewInstanceGuard(db, fastOpts(""))
	err := g.Acquire(context.Background())
	if err == nil {
		t.Fatal("未知 dialect MUST fail-close")
	}
	if !strings.Contains(err.Error(), "dialect") {
		t.Fatalf("錯誤應指明 dialect 白名單拒絕: %v", err)
	}
	if errors.Is(err, ErrInstanceGuardBlocked) {
		t.Fatal("fail-close 不是「被他人持鎖」，不得混用攔下哨兵")
	}
	// 未靜默退化為行程內鎖：包級互斥未被佔用
	if !instanceGuardProcessMu.tryLock(time.Now()) {
		t.Fatal("未知 dialect 不得佔用行程內互斥")
	}
	instanceGuardProcessMu.unlock()
}

func TestInstanceGuardTryLockResponseFailure(t *testing.T) {
	fake := newFakeLockBackend()
	fake.tryLockFn = func(context.Context) (bool, error) { return false, driver.ErrBadConn }
	g := NewInstanceGuard(nil, InstanceGuardOptions{backend: fake, RetryInterval: time.Millisecond, RetryAttempts: 3})
	err := g.Acquire(context.Background())
	if err == nil || !errors.Is(err, driver.ErrBadConn) {
		t.Fatalf("取鎖回應失敗應回錯（含原因），實得 %v", err)
	}
	if !strings.Contains(err.Error(), "已丟棄該連線") {
		t.Fatalf("錯誤應說明連線已丟棄（不歸池）: %v", err)
	}
	if errors.Is(err, ErrInstanceGuardBlocked) {
		t.Fatal("回應失敗不是攔下")
	}
}

// TestInstanceGuardRetryAbsorbsTransientContention 毫秒級的工作階段收尾競態被有界重試吸收：
// 第一次 try 回 false（前一實例的 EOF 尚未處理完）、第二次即成功 → 不產生攔下警告、狀態 held。
func TestInstanceGuardRetryAbsorbsTransientContention(t *testing.T) {
	buf := captureLog(t)
	fake := newFakeLockBackend()
	calls := 0
	fake.tryLockFn = func(context.Context) (bool, error) {
		calls++
		return calls >= 2, nil
	}
	g := NewInstanceGuard(nil, InstanceGuardOptions{backend: fake, RetryInterval: time.Millisecond, RetryAttempts: 5})
	rec := &eventRecorder{}
	g.SetEventSink(rec.sink)
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("瞬時競態應被重試吸收，實得 %v", err)
	}
	t.Cleanup(g.Stop)
	if g.State() != GuardStateHeld || calls != 2 {
		t.Fatalf("狀態 = %s、try 次數 = %d，want held／2", g.State(), calls)
	}
	if strings.Contains(buf.String(), "CRITICAL") {
		t.Fatalf("重試吸收的競態不得印攔下警告：%s", buf.String())
	}
	if !strings.Contains(buf.String(), "等待既有實例釋放單實例鎖（第 1/5 次") {
		t.Fatalf("重試應記一行等待日誌：%s", buf.String())
	}
	if len(rec.all()) != 0 {
		t.Fatal("正常取鎖不發事件")
	}
}
