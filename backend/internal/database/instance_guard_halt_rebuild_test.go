package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// 攔下模式下釘選連線重建失敗的復原。
//
// 缺陷形態：enterHalted 的重建失敗只留下 backend=nil，而 watchdog 見 nil 即整輪
// 返回、ConfirmHalt 見 nil 即直接拒絕——資料庫恢復之後沒有任何路徑會再試一次，
// 行程永遠卡在攔下模式，只能靠外部重啟。攔下模式的賣點正是「不需要重啟」，
// 所以這不是可以由營運吸收的邊角，而是把該模式的價值整個抵銷掉。
//
// 兩條路徑各釘一條：watchdog 每週期重試（本檔第一個測試）、頁面確認當場重試並在
// 仍失敗時回可分辨的機器碼（第二個）。

// haltedWithBrokenBackend 把一個已在攔下模式的守衛改成「釘選連線建不起來」，
// 並裝上一個先失敗 failures 次、之後成功的重建工廠。回傳實際的重建嘗試次數指標。
func haltedWithBrokenBackend(t *testing.T, g *InstanceGuard, failures int) *int {
	t.Helper()
	g.mu.Lock()
	real := g.backend
	g.backend = nil
	g.mu.Unlock()
	if real == nil {
		t.Fatal("前提不成立：攔下的守衛本應已有釘選連線")
	}
	attempts := 0
	g.opts.backendFactory = func(context.Context) (lockBackend, error) {
		attempts++
		if attempts <= failures {
			return nil, errors.New("資料庫尚未恢復（測試注入）")
		}
		return real, nil
	}
	return &attempts
}

// TestInstanceGuardHaltWatchdogRebuildsBackendThenAcquires 重建先失敗兩次再成功：
// watchdog MUST 續試，重建成功後 MUST 取得鎖並放行啟動（不需重啟行程）。
func TestInstanceGuardHaltWatchdogRebuildsBackendThenAcquires(t *testing.T) {
	buf := captureLog(t)
	a, b, _, rec := haltedPair(t)
	attempts := haltedWithBrokenBackend(t, b, 2)

	// 鎖已釋放：只差重建成功，watchdog 就該接手。
	a.Stop()
	time.Sleep(2 * time.Millisecond)

	// 週期數上限取 30：足以吸收有界退避略過的週期，又不會變成無限迴圈。
	for i := 0; i < 30 && b.State() != GuardStateHeld; i++ {
		b.CheckNow(context.Background())
	}
	if st := b.State(); st != GuardStateHeld {
		t.Fatalf("重建成功後 watchdog 應取得鎖，實得 %s（重建嘗試 %d 次）——"+
			"backend 為 nil 時整輪返回即為永久攔下", st, *attempts)
	}
	if *attempts < 3 {
		t.Fatalf("重建工廠只被呼叫 %d 次：前兩次為注入的失敗，第三次才會成功，"+
			"少於 3 次代表根本沒有重試", *attempts)
	}
	haltWaitResume(t, b, time.Second)
	if evs := rec.all(); len(evs) != 0 {
		t.Fatalf("攔下期自動取得鎖 MUST NOT 寫任何事件，實得 %v", rec.names())
	}
	if s := buf.String(); !strings.Contains(s, "釘選連線重建失敗") || !strings.Contains(s, "釘選連線已重建") {
		t.Fatalf("重建的失敗與成功都應留下日誌（營運要看得出它在重試）：%s", s)
	}
}

// TestInstanceGuardConfirmHaltRetriesRebuildAndReportsUnavailable 頁面確認送出時：
// 連線建不起來 MUST 回 unavailable（可分辨、可重試），MUST NOT 回 not_halted；
// 重建成功後同一個確認 MUST 照常判定。
func TestInstanceGuardConfirmHaltRetriesRebuildAndReportsUnavailable(t *testing.T) {
	_, b, code, _ := haltedPair(t)
	attempts := haltedWithBrokenBackend(t, b, 1)

	res := b.ConfirmHalt(context.Background(), code, "admin")
	if res.Outcome != HaltConfirmUnavailable {
		t.Fatalf("釘選連線建不起來時應回 unavailable，實得 %s——"+
			"回 not_halted 等於告訴操作者「已經啟動了」，他就不會再重試", res.Outcome)
	}
	if *attempts != 1 {
		t.Fatalf("確認送出應當場重試重建一次（不遵守背景退避），實得 %d 次", *attempts)
	}

	// 第二次呼叫：工廠已改為成功，確認應照常走完（碼相符 → 接受）。
	res = b.ConfirmHalt(context.Background(), code, "admin")
	if res.Outcome != HaltConfirmAccepted {
		t.Fatalf("重建成功後確認應照常判定，實得 %s", res.Outcome)
	}
	if b.State() != GuardStateOverridden && b.State() != GuardStateHeld {
		t.Fatalf("確認接受後狀態 = %s", b.State())
	}
}
