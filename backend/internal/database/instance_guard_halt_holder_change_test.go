package database

import (
	"context"
	"testing"
	"time"
)

// 「確認碼與**當下**持鎖者重比」的端到端一格：真的讓持鎖者換人。
//
// 既有的 TestInstanceGuardConfirmHaltRejectsStaleCode 以「打錯的碼」當代理，
// 持鎖者其實從未變更——因此把 ConfirmHalt 的重查換成攔下時快取的指紋（也就是
// 拿掉本條保護），**整包測試照樣綠**。本格補的正是那個訊號：
// A 釋放、C 接手之後，B 拿攔下頁上顯示的舊碼送出，MUST 被拒並收到新碼。

// TestInstanceGuardConfirmHaltComparesAgainstCurrentHolder 持鎖者中途換人：
// 舊碼 MUST NOT 被接受，且回的是新持鎖者的指紋與碼。
func TestInstanceGuardConfirmHaltComparesAgainstCurrentHolder(t *testing.T) {
	a, b, oldCode, rec := haltedPair(t)

	// A 退出、C 接手：sqlite 分支的指紋含持鎖時間，換手即換碼。
	a.Stop()
	time.Sleep(2 * time.Millisecond)
	db := newGuardSQLiteDB(t)
	c := NewInstanceGuard(db, fastOpts(""))
	if err := c.Acquire(context.Background()); err != nil {
		t.Fatalf("C 接手取鎖失敗: %v", err)
	}
	t.Cleanup(c.Stop)

	res := b.ConfirmHalt(context.Background(), oldCode, "alice")
	if res.Outcome != HaltConfirmHolderChanged {
		t.Fatalf("持鎖者已換人時舊碼 MUST 被拒（＝碼與當下持鎖者重比），實得 %s", res.Outcome)
	}
	if res.Holder == nil || res.Holder.Code == "" {
		t.Fatalf("拒絕時 MUST 回當下持鎖者的指紋與碼，實得 %+v", res.Holder)
	}
	if res.Holder.Code == oldCode {
		t.Fatalf("回的仍是換手前的舊碼 %q——重比對象是快取而非當下持鎖者", oldCode)
	}
	if st := b.State(); st != GuardStateHalted {
		t.Fatalf("被拒後應維持 halted，實得 %s", st)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("被拒的確認 MUST NOT 寫任何事件，實得 %v", rec.names())
	}
	if haltResumeClosed(b) {
		t.Fatal("被拒的確認不得放行啟動")
	}

	// 對照組：改打新碼即被接受——證明上面的拒絕不是「什麼碼都拒」。
	res = b.ConfirmHalt(context.Background(), res.Holder.Code, "alice")
	if res.Outcome != HaltConfirmAccepted {
		t.Fatalf("改打當下持鎖者的新碼 MUST 被接受，實得 %s", res.Outcome)
	}
	haltWaitResume(t, b, time.Second)
}
