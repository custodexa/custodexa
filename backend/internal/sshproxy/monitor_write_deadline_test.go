package sshproxy

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 監看廣播寫入逾時（backend-i18n-unification A2）
//
// 契約：慢速或半死的觀察者不得阻塞 room 的廣播——broadcastOutput 由 bridge 的
// 輸出路徑呼叫且持有 r.mu，一個卡住的 ws.WriteMessage 會把被監看會話一起拖住。
// 逾時即移除該觀察者並關其連線（監看是可重連的唯讀職能，掉線屬可接受降級）。
// ---------------------------------------------------------------------------

// setMonitorWriteTimeout 暫時縮短廣播寫入逾時，測試結束還原
func setMonitorWriteTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := monitorWriteTimeout
	monitorWriteTimeout = d
	t.Cleanup(func() { monitorWriteTimeout = prev })
}

// TestMonitorWriteDeadlineEvictsUnwritableObserver 逾時邊界的確定性驗證：
// 逾時窗口已過期時，寫入立即失敗、觀察者被移除，room 仍可服務其餘觀察者
func TestMonitorWriteDeadlineEvictsUnwritableObserver(t *testing.T) {
	hub := NewMonitorHub()
	tap := hub.OpenRoom(10, 80, 24)
	serverWS, clientWS := newWSPair(t)
	if !hub.Join(10, serverWS, ObserverContext{}) {
		t.Fatal("Join 應成功")
	}
	readMessages(t, clientWS, 1) // 消化 join 的 resize

	room := hub.rooms[10]
	if len(room.observers) != 1 {
		t.Fatalf("觀察者數 = %d, want 1", len(room.observers))
	}

	// 逾時窗口設為已過期：底層 net.Conn 的寫入立刻回 deadline exceeded
	setMonitorWriteTimeout(t, -time.Second)
	tap.WriteOutput([]byte("payload"))

	if len(room.observers) != 0 {
		t.Errorf("寫入逾時的觀察者應被移除，實際剩 %d", len(room.observers))
	}
}

// TestMonitorSlowObserverDoesNotBlockBroadcast 真實慢速觀察者（永不讀取，
// TCP 視窗塞滿後寫入阻塞）：廣播必須在逾時內脫身並踢掉該觀察者，
// 不得無限期卡住主路徑
func TestMonitorSlowObserverDoesNotBlockBroadcast(t *testing.T) {
	setMonitorWriteTimeout(t, 100*time.Millisecond)

	hub := NewMonitorHub()
	tap := hub.OpenRoom(11, 80, 24)
	serverWS, _ := newWSPair(t) // client 端刻意不讀取
	if !hub.Join(11, serverWS, ObserverContext{}) {
		t.Fatal("Join 應成功")
	}
	room := hub.rooms[11]

	chunk := make([]byte, 256*1024)
	for i := range chunk {
		chunk[i] = 'x'
	}

	start := time.Now()
	const maxRounds = 64
	rounds := 0
	for ; rounds < maxRounds; rounds++ {
		if len(room.observers) == 0 {
			break
		}
		tap.WriteOutput(chunk)
	}
	elapsed := time.Since(start)

	if len(room.observers) != 0 {
		t.Errorf("慢速觀察者未被移除（%d 輪後仍在），廣播已被拖住", rounds)
	}
	// 上限寬鬆但有意義：無 deadline 時本迴圈會永久卡在第一次阻塞的寫入
	if elapsed > 10*time.Second {
		t.Errorf("廣播耗時 %v 過長——寫入逾時未生效", elapsed)
	}
}
