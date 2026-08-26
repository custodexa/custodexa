package database

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// watchdog 狀態機的離線測試：以 fakeLockBackend 驅動，
// 一律 CheckNow、不靠時序競賽。替身與 helper 在 instance_guard_test.go。

// ── fakeLockBackend 驅動的狀態機 ──────────────────────────────────────────

func TestInstanceGuardWatchdogLostThenRegained(t *testing.T) {
	buf := captureLog(t)
	fake := newFakeLockBackend()
	g, rec := newHeldFakeGuard(t, fake, InstanceGuardOptions{})

	// 驗證回「未持有」（無錯誤、無他人持鎖）→ lost{unknown}
	fake.isHeldFn = func(context.Context) (bool, error) { return false, nil }
	fake.tryLockFn = func(context.Context) (bool, error) { return false, nil }
	if st := g.CheckNow(context.Background()); st != GuardStateLost {
		t.Fatalf("驗證未持有後狀態 = %s，want lost", st)
	}
	snap := g.Snapshot()
	if snap.LostTotal != 1 || snap.Since.IsZero() {
		t.Fatalf("lost_total = %d / since = %v", snap.LostTotal, snap.Since)
	}
	if names := rec.names(); len(names) != 1 || names[0] != GuardEventLost {
		t.Fatalf("應恰有 lost 事件，實得 %v", names)
	}
	if fake.reconnects != 1 {
		t.Fatalf("失鎖時應丟棄舊連線並重釘一條（reconnect 次數 %d）", fake.reconnects)
	}
	if !strings.Contains(buf.String(), "CRITICAL") || !strings.Contains(buf.String(), "reason=") {
		t.Fatalf("失鎖應有 CRITICAL 日誌含 reason=：%s", buf.String())
	}
	if !strings.Contains(buf.String(), "不阻擋") {
		t.Fatalf("失鎖日誌應明說繼續服務、不阻擋：%s", buf.String())
	}

	// 重取仍失敗（他人持鎖，無指紋）→ 維持 lost，可持續 CheckNow
	for i := 0; i < 3; i++ {
		if st := g.CheckNow(context.Background()); st != GuardStateLost {
			t.Fatalf("第 %d 輪重取失敗後狀態 = %s，want lost", i+1, st)
		}
	}
	if g.Snapshot().LostTotal != 1 {
		t.Fatal("維持 lost 期間不得重複計 lost_total")
	}

	// 重取成功 → held ＋ regained
	time.Sleep(2 * time.Millisecond)
	fake.tryLockFn = func(context.Context) (bool, error) { return true, nil }
	if st := g.CheckNow(context.Background()); st != GuardStateHeld {
		t.Fatalf("重取成功後狀態 = %s，want held", st)
	}
	evs := rec.all()
	if len(evs) != 2 || evs[1].Event != GuardEventRegained {
		t.Fatalf("應新增 regained 事件，實得 %v", rec.names())
	}
	if evs[1].UnheldForMS <= 0 {
		t.Fatalf("regained 應含 unheld_for_ms > 0，實得 %d", evs[1].UnheldForMS)
	}
	if evs[1].LostTotal != 1 {
		t.Fatalf("regained 事件的 lost_total = %d，want 1", evs[1].LostTotal)
	}
	if evs[0].DBSessionPID != 4321 || evs[0].Instance.PID == 0 {
		t.Fatalf("事件應含本實例識別與工作階段 id：%+v", evs[0])
	}
	if g.Snapshot().Reason != GuardReasonNone {
		t.Fatal("回到 held 後 reason 應清空")
	}
}

func TestInstanceGuardWatchdogRetryableKeepsLostAndThrottles(t *testing.T) {
	buf := captureLog(t)
	fake := newFakeLockBackend()
	g, rec := newHeldFakeGuard(t, fake, InstanceGuardOptions{})

	// 驗證查詢逾時（可重試）→ lost{db_unreachable}；重釘也失敗
	fake.isHeldFn = func(context.Context) (bool, error) { return false, context.DeadlineExceeded }
	fake.reconnectFn = func(context.Context) error { return driver.ErrBadConn }
	if st := g.CheckNow(context.Background()); st != GuardStateLost {
		t.Fatalf("狀態 = %s，want lost", st)
	}
	if r := g.Snapshot().Reason; r != GuardReasonDBUnreachable {
		t.Fatalf("reason = %s，want db_unreachable", r)
	}
	if fake.connected() {
		t.Fatal("重釘失敗後應無連線")
	}

	// 連續 N 輪可重試錯誤：維持 lost、行程與守衛皆無退出面（CheckNow 可持續呼叫、Stop 前狀態仍 lost）
	buf.Reset()
	for i := 0; i < 5; i++ {
		if st := g.CheckNow(context.Background()); st != GuardStateLost {
			t.Fatalf("第 %d 輪：狀態 = %s，want lost", i+1, st)
		}
	}
	if n := countLines(buf, "可重試"); n != 1 {
		t.Fatalf("可重試類日誌應節流（每分鐘至多一次），5 輪實得 %d 行：%s", n, buf.String())
	}
	if names := rec.names(); len(names) != 1 || names[0] != GuardEventLost {
		t.Fatalf("可重試失敗期間不得重複發事件，實得 %v", names)
	}
	if g.State() != GuardStateLost {
		t.Fatal("Stop() 前狀態應仍為 lost")
	}

	// 資料庫恢復（不論多久）→ 重釘成功 → 重取成功 → held
	fake.reconnectFn = nil
	fake.tryLockFn = func(context.Context) (bool, error) { return true, nil }
	if st := g.CheckNow(context.Background()); st != GuardStateHeld {
		t.Fatalf("恢復後狀態 = %s，want held", st)
	}
	if names := rec.names(); len(names) != 2 || names[1] != GuardEventRegained {
		t.Fatalf("恢復後應發 regained，實得 %v", names)
	}
	if rec.all()[1].Reason != GuardReasonDBUnreachable {
		t.Fatalf("regained 應帶先前的 reason（db_unreachable），實得 %s", rec.all()[1].Reason)
	}
}

func TestInstanceGuardWatchdogPermanentAndUnknownNotThrottled(t *testing.T) {
	buf := captureLog(t)
	fake := newFakeLockBackend()
	g, _ := newHeldFakeGuard(t, fake, InstanceGuardOptions{})

	fake.isHeldFn = func(context.Context) (bool, error) {
		return false, &pgconn.PgError{Code: "42501", Message: "permission denied"}
	}
	if st := g.CheckNow(context.Background()); st != GuardStateLost {
		t.Fatalf("狀態 = %s，want lost", st)
	}
	if r := g.Snapshot().Reason; r != GuardReasonPermanent {
		t.Fatalf("reason = %s，want permanent", r)
	}

	// 重取時權限不足：每週期 CRITICAL、不節流、不退出
	buf.Reset()
	fake.tryLockFn = func(context.Context) (bool, error) {
		return false, &pgconn.PgError{Code: "42501", Message: "permission denied"}
	}
	for i := 0; i < 3; i++ {
		if st := g.CheckNow(context.Background()); st != GuardStateLost {
			t.Fatalf("狀態 = %s，want lost", st)
		}
	}
	if n := countLines(buf, "reason=permanent"); n != 3 {
		t.Fatalf("永久類每週期都應喊（3 輪 want 3 行），實得 %d：%s", n, buf.String())
	}
	if n := countLines(buf, "CRITICAL"); n != 3 {
		t.Fatalf("永久類應以 CRITICAL 記錄，實得 %d 行", n)
	}

	// 無法歸類 → unknown，同樣不節流
	buf.Reset()
	fake.tryLockFn = func(context.Context) (bool, error) { return false, errors.New("something odd") }
	for i := 0; i < 2; i++ {
		g.CheckNow(context.Background())
	}
	if n := countLines(buf, "reason=unknown"); n != 2 {
		t.Fatalf("未知類每週期都應喊（2 輪 want 2 行），實得 %d：%s", n, buf.String())
	}
	if r := g.Snapshot().Reason; r != GuardReasonUnknown {
		t.Fatalf("reason = %s，want unknown", r)
	}
	// 下一週期照常重試：恢復後回 held
	fake.tryLockFn = func(context.Context) (bool, error) { return true, nil }
	if st := g.CheckNow(context.Background()); st != GuardStateHeld {
		t.Fatalf("恢復後狀態 = %s，want held", st)
	}
}

func TestInstanceGuardWatchdogOverriddenRegains(t *testing.T) {
	fake := newFakeLockBackend()
	holder := fingerprintOf(strPtr("custodexa-instance-guard"), int64Ptr(99), timePtr(time.Now()))
	fake.tryLockFn = func(context.Context) (bool, error) { return false, nil }
	fake.holderFn = func(context.Context) (HolderFingerprint, bool) { return holder, true }
	g := NewInstanceGuard(nil, InstanceGuardOptions{backend: fake, Ack: holder.Code, RetryInterval: time.Millisecond, RetryAttempts: 2})
	rec := &eventRecorder{}
	g.SetEventSink(rec.sink)
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("ack 相符應允許啟動: %v", err)
	}
	t.Cleanup(g.Stop)
	if g.State() != GuardStateOverridden {
		t.Fatalf("狀態 = %s，want overridden", g.State())
	}

	// 仍由他人持有：維持 overridden、不發新事件
	if st := g.CheckNow(context.Background()); st != GuardStateOverridden {
		t.Fatalf("狀態 = %s，want overridden", st)
	}
	if names := rec.names(); len(names) != 1 {
		t.Fatalf("overridden 期間重取失敗不得發事件，實得 %v", names)
	}

	// 取得鎖 → held ＋ regained{reason=ack_startup}
	time.Sleep(2 * time.Millisecond)
	fake.tryLockFn = func(context.Context) (bool, error) { return true, nil }
	if st := g.CheckNow(context.Background()); st != GuardStateHeld {
		t.Fatalf("狀態 = %s，want held", st)
	}
	evs := rec.all()
	if len(evs) != 2 || evs[1].Event != GuardEventRegained || evs[1].Reason != GuardReasonAckStartup || evs[1].UnheldForMS <= 0 {
		t.Fatalf("應發 regained{reason=ack_startup, unheld_for_ms>0}，實得 %+v", evs)
	}
	if evs[0].Holder == nil || evs[0].Holder.Code != holder.Code {
		t.Fatalf("overridden 事件應含持鎖者指紋：%+v", evs[0])
	}
}

func TestInstanceGuardWatchdogContentionIdentifiesHolder(t *testing.T) {
	buf := captureLog(t)
	fake := newFakeLockBackend()
	g, rec := newHeldFakeGuard(t, fake, InstanceGuardOptions{})

	other := fingerprintOf(strPtr("custodexa-instance-guard"), int64Ptr(555), timePtr(time.Now()))
	// 本工作階段被終止（57P01）；重釘後查到他人持鎖 → lost{contention, holder}
	fake.isHeldFn = func(context.Context) (bool, error) {
		return false, &pgconn.PgError{Code: "57P01", Message: "terminating connection due to administrator command"}
	}
	fake.holderFn = func(context.Context) (HolderFingerprint, bool) { return other, true }
	fake.tryLockFn = func(context.Context) (bool, error) { return false, nil }
	if st := g.CheckNow(context.Background()); st != GuardStateLost {
		t.Fatalf("狀態 = %s，want lost", st)
	}
	snap := g.Snapshot()
	if snap.Reason != GuardReasonContention || snap.Holder == nil || snap.Holder.Code != other.Code {
		t.Fatalf("競爭時應指認持鎖者：%+v", snap)
	}
	evs := rec.all()
	if len(evs) != 1 || evs[0].Reason != GuardReasonContention || evs[0].Holder == nil || evs[0].Holder.Code != other.Code {
		t.Fatalf("lost 事件應含 reason=contention 與持鎖者指紋：%+v", evs)
	}
	if !strings.Contains(buf.String(), "code="+other.Code) {
		t.Fatalf("競爭日誌應含持鎖者指紋：%s", buf.String())
	}

	// 持續重試、每週期 CRITICAL、行程未退出
	buf.Reset()
	for i := 0; i < 2; i++ {
		if st := g.CheckNow(context.Background()); st != GuardStateLost {
			t.Fatalf("狀態 = %s，want lost", st)
		}
	}
	if n := countLines(buf, "reason=contention"); n != 2 {
		t.Fatalf("競爭類每週期都應喊，實得 %d 行", n)
	}
	if len(rec.all()) != 1 {
		t.Fatal("競爭期間不得重複發 lost 事件")
	}
}

func TestInstanceGuardPeersCount(t *testing.T) {
	buf := captureLog(t)
	fake := newFakeLockBackend()
	g, rec := newHeldFakeGuard(t, fake, InstanceGuardOptions{})

	fake.peersFn = func(context.Context) (int, error) { return 1, nil }
	if st := g.CheckNow(context.Background()); st != GuardStateHeld {
		t.Fatalf("對等偵測不改狀態，實得 %s", st)
	}
	if p := g.Snapshot().Peers; p != 1 {
		t.Fatalf("peers = %d，want 1", p)
	}
	if len(rec.all()) != 0 {
		t.Fatal("對等偵測不寫事件")
	}
	g.CheckNow(context.Background())
	if n := countLines(buf, "偵測到 1 個其他守衛版實例"); n != 1 {
		t.Fatalf("對等日誌應節流（首次一行），實得 %d 行", n)
	}

	// 查詢失敗維持上一次的值；歸零即歸零
	fake.peersFn = func(context.Context) (int, error) { return 0, errors.New("boom") }
	g.CheckNow(context.Background())
	if p := g.Snapshot().Peers; p != 1 {
		t.Fatalf("查詢失敗時 peers 應維持上一次的值 1，實得 %d", p)
	}
	fake.peersFn = func(context.Context) (int, error) { return 0, nil }
	g.CheckNow(context.Background())
	if p := g.Snapshot().Peers; p != 0 {
		t.Fatalf("peers = %d，want 0", p)
	}
}

func TestInstanceGuardShutdownRaceDiscardsResult(t *testing.T) {
	fake := newFakeLockBackend()
	g, rec := newHeldFakeGuard(t, fake, InstanceGuardOptions{})

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fake.isHeldFn = func(context.Context) (bool, error) {
		once.Do(func() { close(entered) })
		<-release
		return false, nil // Stop() 進行中才回「未持有」
	}

	checkDone := make(chan struct{})
	go func() {
		g.CheckNow(context.Background())
		close(checkDone)
	}()
	<-entered

	stopDone := make(chan struct{})
	go func() {
		g.Stop()
		close(stopDone)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		st := g.State()
		if st == GuardStateStopping || st == GuardStateReleased {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Stop() 未在期限內把狀態標為 stopping")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	<-checkDone
	<-stopDone

	snap := g.Snapshot()
	if snap.State != GuardStateReleased {
		t.Fatalf("終態 = %s，want released", snap.State)
	}
	if snap.LostTotal != 0 {
		t.Fatalf("關閉期間的「未持有」不得計為失鎖，lost_total = %d", snap.LostTotal)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("關閉期間不得發事件，實得 %v", rec.names())
	}
	if fake.reconnects != 0 {
		t.Fatal("關閉期間不得重釘連線／重取")
	}
	if len(fake.closeCalls) != 1 || !fake.closeCalls[0] {
		t.Fatalf("持鎖時關閉應 best-effort 解鎖後釋放連線，實得 %v", fake.closeCalls)
	}
}

func TestInstanceGuardWatchdogPanicKeepsState(t *testing.T) {
	buf := captureLog(t)
	fake := newFakeLockBackend()
	g, rec := newHeldFakeGuard(t, fake, InstanceGuardOptions{})

	fired := 0
	fake.isHeldFn = func(context.Context) (bool, error) {
		fired++
		if fired == 1 {
			panic("injected watchdog panic")
		}
		return true, nil
	}
	if st := g.CheckNow(context.Background()); st != GuardStateHeld {
		t.Fatalf("panic 後狀態 = %s，want held（不變）", st)
	}
	if fired != 1 {
		t.Fatal("注入點未走到：測試沒有證明力")
	}
	if !strings.Contains(buf.String(), "panic 已攔截") {
		t.Fatalf("panic 應被記錄：%s", buf.String())
	}
	// 下一輪照常驗證
	if st := g.CheckNow(context.Background()); st != GuardStateHeld || fired != 2 {
		t.Fatalf("下一輪應照常驗證（fired=%d, state=%s）", fired, st)
	}
	if g.Snapshot().LostTotal != 0 || len(rec.all()) != 0 {
		t.Fatal("panic 不得改變狀態或發事件")
	}
}

func TestInstanceGuardEventBufferFlushOrder(t *testing.T) {
	fake := newFakeLockBackend()
	g := NewInstanceGuard(nil, InstanceGuardOptions{backend: fake, RetryInterval: time.Millisecond, RetryAttempts: 1})
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Stop)

	// sink 注入前發三個事件：lost → regained → lost
	fake.isHeldFn = func(context.Context) (bool, error) { return false, nil }
	fake.tryLockFn = func(context.Context) (bool, error) { return true, nil }
	g.CheckNow(context.Background()) // lost
	g.CheckNow(context.Background()) // regained
	g.CheckNow(context.Background()) // lost

	rec := &eventRecorder{}
	g.SetEventSink(rec.sink)
	names := rec.names()
	want := []string{GuardEventLost, GuardEventRegained, GuardEventLost}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("sink 注入後應依序收到緩衝事件：want %v，got %v", want, names)
	}
	evs := rec.all()
	if evs[0].At.After(evs[1].At) || evs[1].At.After(evs[2].At) {
		t.Fatal("緩衝事件的時間戳應為發生當下（非 flush 當下）且遞增")
	}
	// 注入後的事件直送
	g.CheckNow(context.Background()) // regained
	if n := len(rec.all()); n != 4 {
		t.Fatalf("注入後事件應直送，實得 %d 筆", n)
	}
}

func TestInstanceGuardEventBufferOverflowDropsOldest(t *testing.T) {
	buf := captureLog(t)
	fake := newFakeLockBackend()
	g := NewInstanceGuard(nil, InstanceGuardOptions{backend: fake, RetryInterval: time.Millisecond, RetryAttempts: 1, EventBufferLimit: 2})
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Stop)

	fake.isHeldFn = func(context.Context) (bool, error) { return false, nil }
	fake.tryLockFn = func(context.Context) (bool, error) { return true, nil }
	g.CheckNow(context.Background()) // lost (1)
	g.CheckNow(context.Background()) // regained (2)
	g.CheckNow(context.Background()) // lost (3) → 丟最舊
	if !strings.Contains(buf.String(), "丟棄最舊") {
		t.Fatalf("溢出應記 log：%s", buf.String())
	}

	rec := &eventRecorder{}
	g.SetEventSink(rec.sink)
	evs := rec.all()
	if len(evs) != 2 || evs[0].Event != GuardEventRegained || evs[1].Event != GuardEventLost {
		t.Fatalf("上限 2 時第 3 筆應丟最舊，保留 [regained, lost]，實得 %v", rec.names())
	}
	if evs[0].LostTotal != 1 || evs[1].LostTotal != 2 {
		t.Fatalf("保留的事件應是第 2、3 筆（lost_total 1、2），實得 %d、%d", evs[0].LostTotal, evs[1].LostTotal)
	}
}

func TestInstanceGuardStopIdempotent(t *testing.T) {
	fake := newFakeLockBackend()
	g, _ := newHeldFakeGuard(t, fake, InstanceGuardOptions{})
	g.Stop()
	g.Stop()
	if g.State() != GuardStateReleased {
		t.Fatalf("狀態 = %s，want released", g.State())
	}
	if len(fake.closeCalls) != 1 {
		t.Fatalf("重複 Stop 不得重複釋放連線，實得 %d 次", len(fake.closeCalls))
	}
	// 釋放後 CheckNow 為 no-op：不重取、不改狀態
	fake.tryLockFn = func(context.Context) (bool, error) { t.Fatal("釋放後不得重取"); return true, nil }
	if st := g.CheckNow(context.Background()); st != GuardStateReleased {
		t.Fatalf("釋放後狀態 = %s", st)
	}
}

func strPtr(s string) *string        { return &s }
func int64Ptr(v int64) *int64        { return &v }
func timePtr(v time.Time) *time.Time { return &v }
