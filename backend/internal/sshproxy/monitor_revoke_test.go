package sshproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// 監看訂閱的撤銷收線（idp-oidc-integration 1.9a）。
//
// 監看是唯一「不建 session 列、不經連線授權、靠一次角色檢查就長期存活」的能力。
// 按 session 掃描收不到它——被監看的會話可能是別人（甚至本地帳號）建立的，
// 故必須有按觀察者自身脈絡的三個收線途徑。

// dialObserver 建一條連上 hub 的觀察者連線
func dialObserver(t *testing.T, hub *MonitorHub, sessionID uint, obs ObserverContext) (*websocket.Conn, *httptest.Server) {
	t.Helper()
	joined := make(chan bool, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			joined <- false
			return
		}
		joined <- hub.Join(sessionID, ws, obs)
	}))
	client, _, err := websocket.DefaultDialer.Dial("ws"+srv.URL[4:], nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case ok := <-joined:
		if !ok {
			t.Fatal("Join 應成功（room 已開啟）")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Join 逾時")
	}
	t.Cleanup(func() {
		client.Close()
		srv.Close()
	})
	return client, srv
}

// expectClosed 斷言該連線已被伺服端收線。
//
// **逾時不算關閉**：原實作對 ReadMessage 的任何 err 都 return（視為已收線），
// 而讀取逾時本身就是一個 err——於是「訂閱根本沒被收線」的實作照樣全綠，
// 只是每格多花 2 秒。C1 的對抗驗證即在此處失效（拿掉 authenticate 的脈絡寫入後，
// 靠 expectClosed 斷言的那幾格仍然是綠的），故一併收緊
func expectClosed(t *testing.T, ws *websocket.Conn, why string) {
	t.Helper()
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				t.Fatalf("%s：連線在期限內未被收線（讀取逾時而非關閉）", why)
			}
			return // 連線已關閉，符合預期
		}
		// 收線前會先送出一則撤銷訊息，讀到它繼續等關閉
		if len(msg) == 0 {
			t.Fatalf("%s：讀到空訊息", why)
		}
	}
}

// expectAlive 斷言該連線未被收線
func expectAlive(t *testing.T, ws *websocket.Conn, why string) {
	t.Helper()
	_ = ws.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _, err := ws.ReadMessage()
	if err == nil {
		return // 讀到訊息代表連線正常
	}
	if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
		return // 逾時＝沒東西可讀但連線仍在，符合預期
	}
	t.Fatalf("%s：連線不應被收線，實得 %v", why, err)
}

func TestDisconnectByProviderOnlyHitsThatProvider(t *testing.T) {
	hub := NewMonitorHub()
	hub.OpenRoom(1, 80, 24)

	viaAzure, _ := dialObserver(t, hub, 1, ObserverContext{UserID: 10, ProviderID: 7, AuthEpoch: 1})
	viaOkta, _ := dialObserver(t, hub, 1, ObserverContext{UserID: 11, ProviderID: 8, AuthEpoch: 1})
	local, _ := dialObserver(t, hub, 1, ObserverContext{UserID: 12}) // providerID=0

	if n := hub.DisconnectByProvider(7); n != 1 {
		t.Fatalf("收線數 = %d, want 1", n)
	}
	expectClosed(t, viaAzure, "經 provider 7 認證的觀察者")
	expectAlive(t, viaOkta, "經另一 provider 認證的觀察者")
	expectAlive(t, local, "本地登入的觀察者")
}

func TestDisconnectByProviderIgnoresZero(t *testing.T) {
	hub := NewMonitorHub()
	hub.OpenRoom(1, 80, 24)
	local, _ := dialObserver(t, hub, 1, ObserverContext{UserID: 12})

	// providerID=0 是「本地登入」的語義，不是萬用字元。
	// 若被當成萬用字元，任何一次 provider 收線都會誤殺全部本地管理員的監看
	if n := hub.DisconnectByProvider(0); n != 0 {
		t.Fatalf("providerID=0 不得匹配任何人，實得收線 %d", n)
	}
	expectAlive(t, local, "本地觀察者")
}

func TestDisconnectByUserCoversLocalObserver(t *testing.T) {
	hub := NewMonitorHub()
	hub.OpenRoom(1, 80, 24)

	// 本地 admin 的 providerID=0，按 provider 的兩個方法都掃不到。
	// 缺這個途徑，停用一個本地管理員帳號時他正在進行的監看會繼續存活
	local, _ := dialObserver(t, hub, 1, ObserverContext{UserID: 12})
	other, _ := dialObserver(t, hub, 1, ObserverContext{UserID: 13})

	if n := hub.DisconnectByUser(12); n != 1 {
		t.Fatalf("收線數 = %d, want 1", n)
	}
	expectClosed(t, local, "被停用帳號的觀察者")
	expectAlive(t, other, "其他使用者的觀察者")
}

func TestDisconnectByUserAndProviderIsNarrow(t *testing.T) {
	hub := NewMonitorHub()
	hub.OpenRoom(1, 80, 24)

	// 同一人綁兩個 provider：解綁其中一個身分時，只收該身分建立的訂閱
	viaAzure, _ := dialObserver(t, hub, 1, ObserverContext{UserID: 10, ProviderID: 7})
	viaOkta, _ := dialObserver(t, hub, 1, ObserverContext{UserID: 10, ProviderID: 8})
	sameProviderOther, _ := dialObserver(t, hub, 1, ObserverContext{UserID: 11, ProviderID: 7})

	if n := hub.DisconnectByUserAndProvider(10, 7); n != 1 {
		t.Fatalf("收線數 = %d, want 1", n)
	}
	expectClosed(t, viaAzure, "該 (user, provider) 的觀察者")
	expectAlive(t, viaOkta, "同一人經另一 provider 的觀察者")
	expectAlive(t, sameProviderOther, "同 provider 但另一人的觀察者")
}

func TestDisconnectSpansAllRooms(t *testing.T) {
	hub := NewMonitorHub()
	hub.OpenRoom(1, 80, 24)
	hub.OpenRoom(2, 80, 24)

	// 同一人同時監看兩個會話：收線須涵蓋全部 room，
	// 只處理第一個命中的 room 會留下活著的訂閱
	a, _ := dialObserver(t, hub, 1, ObserverContext{UserID: 10, ProviderID: 7})
	b, _ := dialObserver(t, hub, 2, ObserverContext{UserID: 10, ProviderID: 7})

	if n := hub.DisconnectByUser(10); n != 2 {
		t.Fatalf("收線數 = %d, want 2（跨 room）", n)
	}
	expectClosed(t, a, "room 1 的觀察者")
	expectClosed(t, b, "room 2 的觀察者")
}

func TestDisconnectOnEmptyHubIsSafe(t *testing.T) {
	hub := NewMonitorHub()
	if n := hub.DisconnectByUser(1); n != 0 {
		t.Errorf("空 hub 收線數 = %d, want 0", n)
	}
	if n := hub.DisconnectByProvider(1); n != 0 {
		t.Errorf("空 hub 收線數 = %d, want 0", n)
	}
	if n := hub.DisconnectByUserAndProvider(1, 1); n != 0 {
		t.Errorf("空 hub 收線數 = %d, want 0", n)
	}
}
