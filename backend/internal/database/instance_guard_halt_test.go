package database

import (
	"context"
	"errors"
	"testing"
	"time"
)

// 攔下模式（halted）的行程內行為。
//
// 射程：進入攔下不退出、攔下期不寫任何事件、確認碼與**當下**持鎖者重比、
// 相符即轉 overridden 並帶確認者、鎖先釋放則自動轉 held 且不寫事件。
// 「零資料庫寫入」由 pg-gated 的 TestInstanceGuardHaltedMode（cmd/server）承擔——
// 本檔用的 sqlite 分支是行程內互斥，沒有跨副本語義可證。

// haltWaitResume 等 resume 訊號；逾時即 Fatal（避免測試永久掛住）。
func haltWaitResume(t *testing.T, g *InstanceGuard, d time.Duration) {
	t.Helper()
	select {
	case <-g.Resume():
	case <-time.After(d):
		t.Fatalf("resume 訊號未於 %s 內送達（狀態=%s）", d, g.State())
	}
}

func haltResumeClosed(g *InstanceGuard) bool {
	select {
	case <-g.Resume():
		return true
	default:
		return false
	}
}

// haltedPair 起一個持鎖者 a 與一個被攔下的 b，並回傳 b 看到的持鎖者確認碼。
func haltedPair(t *testing.T) (a, b *InstanceGuard, code string, rec *eventRecorder) {
	t.Helper()
	db := newGuardSQLiteDB(t)
	a = NewInstanceGuard(db, fastOpts(""))
	if err := a.Acquire(context.Background()); err != nil {
		t.Fatalf("A 取鎖失敗: %v", err)
	}
	t.Cleanup(a.Stop)

	b = NewInstanceGuard(db, fastOpts(""))
	rec = &eventRecorder{}
	b.SetEventSink(rec.sink)
	halted, err := b.AcquireOrHalt(context.Background())
	if !halted {
		t.Fatalf("鎖被他人持有且未帶確認碼時 MUST 進入攔下模式，實得 halted=%v err=%v", halted, err)
	}
	if !errors.Is(err, ErrInstanceGuardBlocked) {
		t.Fatalf("攔下時仍應回既有的攔下錯誤（訊息本體是單一事實源），實得 %v", err)
	}
	t.Cleanup(b.Stop)

	snap := b.Snapshot()
	if snap.State != GuardStateHalted {
		t.Fatalf("狀態 = %s，want halted", snap.State)
	}
	if snap.Holder == nil || snap.Holder.Code == "" {
		t.Fatalf("攔下狀態必須帶持鎖者指紋（攔下頁要顯示它）：%+v", snap)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("攔下期 MUST NOT 寫任何守衛事件，實得 %d 筆：%v", n, rec.names())
	}
	if haltResumeClosed(b) {
		t.Fatal("尚未取得鎖也未確認，resume 不得已關閉")
	}
	return a, b, snap.Holder.Code, rec
}

// TestInstanceGuardHaltDoesNotExitAndKeepsRetrying 取鎖失敗即進攔下：
// 不回傳「不可啟動」而是停在 halted，watchdog 仍在跑。
func TestInstanceGuardHaltDoesNotExitAndKeepsRetrying(t *testing.T) {
	_, b, code, rec := haltedPair(t)
	if len(code) != 12 {
		t.Fatalf("確認碼應為 12 碼，實得 %q", code)
	}
	// 鎖仍被持有 → 一輪 watchdog 後仍是 halted，且仍不寫事件
	if st := b.CheckNow(context.Background()); st != GuardStateHalted {
		t.Fatalf("鎖仍被持有時 watchdog 一輪後應維持 halted，實得 %s", st)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("攔下期重取失敗 MUST NOT 寫事件，實得 %v", rec.names())
	}
}

// TestInstanceGuardHaltAutoAcquiresWhenLockReleased 確認前鎖已釋放：
// watchdog 取得鎖即放行啟動，且 MUST NOT 寫 overridden／regained。
func TestInstanceGuardHaltAutoAcquiresWhenLockReleased(t *testing.T) {
	a, b, _, rec := haltedPair(t)

	a.Stop()
	time.Sleep(2 * time.Millisecond)
	if st := b.CheckNow(context.Background()); st != GuardStateHeld {
		t.Fatalf("鎖釋放後 watchdog 應取得鎖，實得 %s", st)
	}
	haltWaitResume(t, b, time.Second)
	if evs := rec.all(); len(evs) != 0 {
		t.Fatalf("攔下期自動取得鎖 MUST NOT 寫任何事件（本實例從未持鎖，regained 不成立），實得 %v", rec.names())
	}
	if snap := b.Snapshot(); snap.Holder != nil || snap.Actor != "" || snap.ActorSource != "" {
		t.Fatalf("自動取得鎖後不得留下持鎖者或確認者：%+v", snap)
	}
}

// TestInstanceGuardPageConfirmOverriddenCarriesActor 三要件相符（碼與當下持鎖者一致）：
// 轉 overridden、寫一筆帶確認者與來源的事件、放行啟動。
func TestInstanceGuardPageConfirmOverriddenCarriesActor(t *testing.T) {
	_, b, code, rec := haltedPair(t)

	// 確認前先累計兩次憑證失敗：它們寫不進審計，只能隨成功後的事件出門
	b.NoteHaltCredentialFailure()
	b.NoteHaltCredentialFailure()

	res := b.ConfirmHalt(context.Background(), code, "alice")
	if res.Outcome != HaltConfirmAccepted {
		t.Fatalf("碼與當下持鎖者相符 MUST 接受，實得 %s", res.Outcome)
	}
	haltWaitResume(t, b, time.Second)

	snap := b.Snapshot()
	if snap.State != GuardStateOverridden || snap.Reason != GuardReasonAckPage {
		t.Fatalf("狀態 = %s/%s，want overridden/ack_page", snap.State, snap.Reason)
	}
	if snap.Actor != "alice" || snap.ActorSource != GuardActorSourcePage {
		t.Fatalf("確認者應為通過驗證的管理員帳號與 page 來源：%+v", snap)
	}

	evs := rec.all()
	if len(evs) != 1 || evs[0].Event != GuardEventOverridden {
		t.Fatalf("應恰有一筆 overridden 事件，實得 %v", rec.names())
	}
	ev := evs[0]
	if ev.Actor != "alice" || ev.ActorSource != GuardActorSourcePage {
		t.Fatalf("overridden 事件的確認者欄不齊：%+v", ev)
	}
	if ev.PageFailedAttempts != 2 {
		t.Fatalf("overridden 事件應帶頁面確認前的失敗次數 2，實得 %d", ev.PageFailedAttempts)
	}
	if ev.Holder == nil || ev.Holder.Code != code {
		t.Fatalf("overridden 事件應帶當下持鎖者指紋：%+v", ev.Holder)
	}
}

// TestInstanceGuardConfirmHaltRejectsStaleCode 重打的碼不等於當下持鎖者：
// 拒絕、回新指紋、維持 halted、MUST NOT 寫 overridden。
func TestInstanceGuardConfirmHaltRejectsStaleCode(t *testing.T) {
	_, b, code, rec := haltedPair(t)

	res := b.ConfirmHalt(context.Background(), "000000000000", "alice")
	if res.Outcome != HaltConfirmHolderChanged {
		t.Fatalf("碼不符 MUST 拒絕並標為持鎖者已變更，實得 %s", res.Outcome)
	}
	if res.Holder == nil || res.Holder.Code != code {
		t.Fatalf("拒絕時 MUST 回當下持鎖者的新指紋與確認碼，實得 %+v", res.Holder)
	}
	if st := b.State(); st != GuardStateHalted {
		t.Fatalf("拒絕後應維持 halted，實得 %s", st)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("碼不符 MUST NOT 寫 overridden 事件，實得 %v", rec.names())
	}
	if haltResumeClosed(b) {
		t.Fatal("碼不符不得放行啟動")
	}
	if snap := b.Snapshot(); snap.Actor != "" || snap.ActorSource != "" {
		t.Fatalf("被拒的確認不得留下確認者：%+v", snap)
	}
}

// TestInstanceGuardConfirmHaltWhenLockAlreadyFree 送出當下鎖已被釋放：
// 直接取得鎖並放行，MUST NOT 寫 overridden（沒有並存，也就沒有要承擔的事）。
func TestInstanceGuardConfirmHaltWhenLockAlreadyFree(t *testing.T) {
	a, b, code, rec := haltedPair(t)
	a.Stop()
	time.Sleep(2 * time.Millisecond)

	res := b.ConfirmHalt(context.Background(), code, "alice")
	if res.Outcome != HaltConfirmAccepted {
		t.Fatalf("鎖已釋放時確認 MUST 被接受，實得 %s", res.Outcome)
	}
	haltWaitResume(t, b, time.Second)
	if st := b.State(); st != GuardStateHeld {
		t.Fatalf("鎖已釋放時應直接轉 held，實得 %s", st)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("鎖已釋放時 MUST NOT 寫 overridden 事件，實得 %v", rec.names())
	}
	if snap := b.Snapshot(); snap.ActorSource != "" {
		t.Fatalf("未經 overridden 的啟動不得記確認者：%+v", snap)
	}
}

// TestInstanceGuardConfirmHaltRejectedWhenNotHalted 非攔下狀態的確認一律拒絕
// （完整路由樹上兩條端點恆註冊，正常服務期必須擋在任何狀態變更之前）。
func TestInstanceGuardConfirmHaltRejectedWhenNotHalted(t *testing.T) {
	db := newGuardSQLiteDB(t)
	g := NewInstanceGuard(db, fastOpts(""))
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("取鎖失敗: %v", err)
	}
	t.Cleanup(g.Stop)
	if st := g.State(); st != GuardStateHeld {
		t.Fatalf("前置條件不成立：狀態 = %s", st)
	}
	res := g.ConfirmHalt(context.Background(), "000000000000", "alice")
	if res.Outcome != HaltConfirmNotHalted {
		t.Fatalf("非攔下狀態 MUST 回 not_halted，實得 %s", res.Outcome)
	}
	if g.State() != GuardStateHeld {
		t.Fatalf("被拒的確認不得改變狀態，實得 %s", g.State())
	}
}

// TestInstanceGuardAcquireOrHaltPropagatesNonBlockedFailures 非「有人持鎖」的失敗不進攔下模式：
// 攔下頁對它們無能為力（頁面能做的只有「確認另一實例已停」），維持既有 fail-close。
func TestInstanceGuardAcquireOrHaltPropagatesNonBlockedFailures(t *testing.T) {
	db := newGuardSQLiteDB(t)
	fake := newFakeLockBackend()
	fake.tryLockFn = func(context.Context) (bool, error) { return false, errors.New("取鎖回應失敗") }
	opts := fastOpts("")
	opts.backend = fake
	g := NewInstanceGuard(db, opts)

	halted, err := g.AcquireOrHalt(context.Background())
	if halted {
		t.Fatal("取鎖回應失敗 MUST NOT 進入攔下模式")
	}
	if err == nil || errors.Is(err, ErrInstanceGuardBlocked) {
		t.Fatalf("應原樣回傳非攔下類的失敗，實得 %v", err)
	}
}

// TestInstanceGuardEnvAckOverriddenCarriesEnvActor 環境變數路徑的確認者標示不變：
// `operator via env`／來源 env。**與頁面路徑各佔一個測試**——兩條路徑共用同一個
// 事件欄位，只驗一條時另一條寫錯（例如把 env 也標成 page）不會有任何訊號。
func TestInstanceGuardEnvAckOverriddenCarriesEnvActor(t *testing.T) {
	db := newGuardSQLiteDB(t)
	a := NewInstanceGuard(db, fastOpts(""))
	if err := a.Acquire(context.Background()); err != nil {
		t.Fatalf("A 取鎖失敗: %v", err)
	}
	t.Cleanup(a.Stop)

	probe := NewInstanceGuard(db, fastOpts(""))
	m := codePattern.FindStringSubmatch(probe.Acquire(context.Background()).Error())
	if len(m) != 2 {
		t.Fatal("訊息中找不到 12 碼確認碼")
	}

	b := NewInstanceGuard(db, fastOpts(m[1]))
	rec := &eventRecorder{}
	b.SetEventSink(rec.sink)
	if err := b.Acquire(context.Background()); err != nil {
		t.Fatalf("ack 相符應允許啟動: %v", err)
	}
	t.Cleanup(b.Stop)

	if snap := b.Snapshot(); snap.Actor != GuardActorEnv || snap.ActorSource != GuardActorSourceEnv {
		t.Fatalf("環境變數路徑的確認者應為 %q／%q，實得 %q／%q",
			GuardActorEnv, GuardActorSourceEnv, snap.Actor, snap.ActorSource)
	}
	evs := rec.all()
	if len(evs) != 1 || evs[0].Actor != GuardActorEnv || evs[0].ActorSource != GuardActorSourceEnv {
		t.Fatalf("overridden 事件的確認者欄不符：%+v", evs)
	}
	if evs[0].PageFailedAttempts != 0 {
		t.Fatalf("環境變數路徑不得帶頁面失敗次數，實得 %d", evs[0].PageFailedAttempts)
	}
}
