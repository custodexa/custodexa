package sshproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// newWSPair 建立一對真實的 WebSocket 連線（server 端供 room 寫入、client 端供測試讀取）
func newWSPair(t *testing.T) (server *websocket.Conn, client *websocket.Conn) {
	t.Helper()

	upgrader := websocket.Upgrader{}
	var serverConn *websocket.Conn
	var wg sync.WaitGroup
	wg.Add(1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade 失敗: %v", err)
			return
		}
		serverConn = conn
		wg.Done()
		// 保持 handler 存活直到測試結束
		select {}
	}))
	t.Cleanup(srv.Close)

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial 失敗: %v", err)
	}
	t.Cleanup(func() { clientConn.Close() })

	wg.Wait()
	return serverConn, clientConn
}

// readMessages 從 client 端讀取 n 則訊息
func readMessages(t *testing.T, client *websocket.Conn, n int) []Message {
	t.Helper()

	msgs := make([]Message, 0, n)
	for i := 0; i < n; i++ {
		client.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, raw, err := client.ReadMessage()
		if err != nil {
			t.Fatalf("讀取第 %d 則訊息失敗: %v", i+1, err)
		}
		msg, err := DecodeMessage(raw)
		if err != nil {
			t.Fatalf("解碼失敗: %v", err)
		}
		msgs = append(msgs, msg)
	}
	return msgs
}

func TestMonitorBroadcastReachesObserver(t *testing.T) {
	// Arrange
	hub := NewMonitorHub()
	tap := hub.OpenRoom(1, 120, 30)
	serverWS, clientWS := newWSPair(t)
	if !hub.Join(1, serverWS, ObserverContext{}) {
		t.Fatal("Join 應成功")
	}

	// Act
	tap.WriteOutput([]byte("live-output"))

	// Assert：join 先收 resize，再收即時 data
	msgs := readMessages(t, clientWS, 2)
	if msgs[0].Type != MsgResize {
		t.Errorf("首則訊息 = %s, want resize", msgs[0].Type)
	}
	if msgs[1].Type != MsgData || msgs[1].Data != "live-output" {
		t.Errorf("即時訊息 = %+v, want data live-output", msgs[1])
	}
}

func TestMonitorMidStreamJoinGetsReplay(t *testing.T) {
	// Arrange：先有輸出，觀察者後加入
	hub := NewMonitorHub()
	tap := hub.OpenRoom(2, 80, 24)
	tap.WriteOutput([]byte("earlier-context\r\n"))

	serverWS, clientWS := newWSPair(t)

	// Act
	if !hub.Join(2, serverWS, ObserverContext{}) {
		t.Fatal("Join 應成功")
	}

	// Assert：resize 後緊接 replay 緩衝
	msgs := readMessages(t, clientWS, 2)
	if msgs[1].Type != MsgData || !strings.Contains(msgs[1].Data, "earlier-context") {
		t.Errorf("replay 訊息 = %+v, want 含 earlier-context", msgs[1])
	}
}

func TestMonitorReplayBufferTrimmed(t *testing.T) {
	// Arrange：寫入超過上限的輸出
	hub := NewMonitorHub()
	tap := hub.OpenRoom(3, 80, 24)
	chunk := make([]byte, 8*1024)
	for i := range chunk {
		chunk[i] = 'a'
	}
	for i := 0; i < 10; i++ { // 80KB > 64KB
		tap.WriteOutput(chunk)
	}
	tap.WriteOutput([]byte("TAIL-MARKER"))

	serverWS, clientWS := newWSPair(t)

	// Act
	hub.Join(3, serverWS, ObserverContext{})

	// Assert：replay 不超過上限且尾端內容保留
	msgs := readMessages(t, clientWS, 2)
	if len(msgs[1].Data) > replayBufferMax {
		t.Errorf("replay 長度 %d 超過上限 %d", len(msgs[1].Data), replayBufferMax)
	}
	if !strings.HasSuffix(msgs[1].Data, "TAIL-MARKER") {
		t.Error("replay 應保留尾端內容")
	}
}

func TestMonitorSessionEndNotifiesObserver(t *testing.T) {
	// Arrange
	hub := NewMonitorHub()
	hub.OpenRoom(4, 80, 24)
	serverWS, clientWS := newWSPair(t)
	hub.Join(4, serverWS, ObserverContext{})
	readMessages(t, clientWS, 1) // 消化 join 時的 resize

	// Act
	hub.CloseRoom(4)

	// Assert：收到結束通知後連線關閉
	msgs := readMessages(t, clientWS, 1)
	if msgs[0].Type != MsgError || !strings.Contains(msgs[0].Data, "會話已結束") {
		t.Errorf("結束通知 = %+v", msgs[0])
	}
	clientWS.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := clientWS.ReadMessage(); err == nil {
		t.Error("會話結束後監看連線應關閉")
	}
}

func TestMonitorJoinUnknownSession(t *testing.T) {
	// Arrange
	hub := NewMonitorHub()
	serverWS, _ := newWSPair(t)

	// Act + Assert
	if hub.Join(99, serverWS, ObserverContext{}) {
		t.Error("不存在的會話 Join 應回傳 false")
	}
}

func TestMonitorResizeBroadcast(t *testing.T) {
	// Arrange
	hub := NewMonitorHub()
	tap := hub.OpenRoom(5, 80, 24)
	serverWS, clientWS := newWSPair(t)
	hub.Join(5, serverWS, ObserverContext{})
	readMessages(t, clientWS, 1)

	// Act
	tap.Resize(200, 50)

	// Assert
	msgs := readMessages(t, clientWS, 1)
	payload, err := ParseResizePayload(msgs[0].Data)
	if err != nil || payload.Cols != 200 || payload.Rows != 50 {
		t.Errorf("resize 廣播 = %+v, err=%v", payload, err)
	}
}
