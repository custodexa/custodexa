package sshproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeTerminalConn 供 terminate 競態測試：Read 阻塞至 Close
type fakeTerminalConn struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newFakeTerminalConn() *fakeTerminalConn {
	return &fakeTerminalConn{closed: make(chan struct{})}
}

func (f *fakeTerminalConn) Read(p []byte) (int, error) {
	<-f.closed
	return 0, io.EOF
}

func (f *fakeTerminalConn) Write(p []byte) (int, error) { return len(p), nil }

func (f *fakeTerminalConn) WindowChange(rows, cols int) error { return nil }

func (f *fakeTerminalConn) Close() {
	f.closeOnce.Do(func() { close(f.closed) })
}

// newTestWSPair 建立真實 WS 對（server 端唯讀丟棄）
func newTestWSPair(t *testing.T) (*websocket.Conn, *httptest.Server) {
	t.Helper()
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return ws, srv
}

// TestTerminateConcurrentWithBridgeWrites 核心競態：資料橋接持續寫出的同時
// 管理路徑觸發 terminate——關閉通知與資料寫入必須經同一把 wsWriteMu 串行，
// go test -race 下不得有併發寫（前身 Registry 裸寫 conn 即在此炸）
func TestTerminateConcurrentWithBridgeWrites(t *testing.T) {
	ws, srv := newTestWSPair(t)
	defer srv.Close()

	conn := newFakeTerminalConn()
	b := newBridge(ws, conn, nil, nil, "", 0, 0)

	var wg sync.WaitGroup
	writerDone := make(chan struct{})

	// 模擬 pumpOutput：持續經 bridge 寫鎖寫出資料
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(writerDone)
		for i := 0; i < 500; i++ {
			select {
			case <-b.stopChan:
				return
			default:
			}
			b.writeMessage(MsgData, "output-chunk")
		}
	}()

	// 寫入進行中觸發 terminate（另兩個 goroutine 併發搶，驗證 stopOnce 冪等）
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			time.Sleep(2 * time.Millisecond)
			if err := b.terminate(); err != nil {
				t.Errorf("terminate: %v", err)
			}
		}()
	}

	wg.Wait()
	<-writerDone

	// terminate 後 stopChan 已關、底層 conn 已收
	select {
	case <-b.stopChan:
	default:
		t.Error("terminate 後 stopChan 應已關閉")
	}
	select {
	case <-conn.closed:
	default:
		t.Error("terminate 後 TerminalConn 應已關閉")
	}
}

// TestTerminateIdempotent terminate 重複呼叫安全（stopOnce）
func TestTerminateIdempotent(t *testing.T) {
	ws, srv := newTestWSPair(t)
	defer srv.Close()

	b := newBridge(ws, newFakeTerminalConn(), nil, nil, "", 0, 0)

	if err := b.terminate(); err != nil {
		t.Fatalf("first terminate: %v", err)
	}
	if err := b.terminate(); err != nil {
		t.Fatalf("second terminate: %v", err)
	}
}
