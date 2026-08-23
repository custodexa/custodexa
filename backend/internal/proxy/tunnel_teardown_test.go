package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/pkg/guacamole"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 圖形隧道收線時序的回歸測試。
//
// **為什麼這個檔案存在**：`internal/proxy` 先前對「`Start()` 何時返回」「keepalive」
// 「錄影 rename-stat」三件事零覆蓋——這正是「客戶端送 WS close frame 後隧道要等下一次
// 保活 ping（最長 30 秒）才收線」這個缺陷能長期存活的原因。座架不需要引入任何介面抽象：
// `Connection` 是具體結構、`GuacClient` 是公開欄位，用 `net.Listen` 起一個假 guacd
// 再以 `guacamole.NewClient` 撥上去即可；WS 側沿用 `registry_test.go` 已在用的
// `httptest` + `websocket.Upgrader` 形態。

// ---------------------------------------------------------------------------
// 座架
// ---------------------------------------------------------------------------

// fakeGuacd 假 guacd：接受 TCP 連線後**不回話**，讓 pumpGuacamoleToWebSocket
// 真的阻塞在 ReadInstruction（而不是因為建構失敗提早退出）。
type fakeGuacd struct {
	ln     net.Listener
	connCh chan net.Conn
}

func newFakeGuacd(t *testing.T) *fakeGuacd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "假 guacd 監聽失敗")

	f := &fakeGuacd{ln: ln, connCh: make(chan net.Conn, 4)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.connCh <- c
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

// dial 撥一條連線並組出 proxy.Connection（與 handler 建線後交給 Tunnel 的狀態相同）
func (f *fakeGuacd) dial(t *testing.T) *Connection {
	t.Helper()
	host, portStr, err := net.SplitHostPort(f.ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	gc, err := guacamole.NewClient(host, port)
	require.NoError(t, err, "撥假 guacd 失敗")
	t.Cleanup(func() { _ = gc.Close() })

	return &Connection{ID: "test", Protocol: "rdp", GuacClient: gc, Ready: true}
}

// accepted 取出假 guacd 端已接受的連線（用來從 guacd 側主動斷線）
func (f *fakeGuacd) accepted(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-f.connCh:
		t.Cleanup(func() { _ = c.Close() })
		return c
	case <-time.After(3 * time.Second):
		t.Fatal("假 guacd 未收到連線——座架建構失敗，後續斷言失去前提")
		return nil
	}
}

// wsPair 起一個 httptest WS server 並回傳（伺服端 conn, 客戶端 conn）。
// Tunnel 持伺服端 conn（與正式路徑同向：Tunnel 在後端、瀏覽器在對面），
// 測試持客戶端 conn 扮演瀏覽器。
func wsPair(t *testing.T) (srvConn, cliConn *websocket.Conn) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srvCh := make(chan *websocket.Conn, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("WS 升級失敗: %v", err)
			return
		}
		srvCh <- c
	}))
	t.Cleanup(server.Close)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	cli, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err, "WS 撥號失敗")
	t.Cleanup(func() { _ = cli.Close() })

	select {
	case srvConn = <-srvCh:
	case <-time.After(3 * time.Second):
		t.Fatal("伺服端 WS conn 未就緒")
	}
	t.Cleanup(func() { _ = srvConn.Close() })
	return srvConn, cli
}

// startTunnel 在背景跑 Start()，回傳一個「已返回」通道與取回傳值的函式。
func startTunnel(t *testing.T, tunnel *Tunnel) (<-chan struct{}, func() error) {
	t.Helper()
	done := make(chan struct{})
	var retErr atomic.Value // error（nil 以 sentinel 表示）
	go func() {
		err := tunnel.Start()
		if err != nil {
			retErr.Store(err)
		}
		close(done)
	}()
	t.Cleanup(func() {
		_ = tunnel.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	})
	return done, func() error {
		if v := retErr.Load(); v != nil {
			return v.(error)
		}
		return nil
	}
}

// ---------------------------------------------------------------------------
// 2.1 座架 sanity：無事件時 Start() 不返回
// ---------------------------------------------------------------------------

// TestTunnelStartBlocksWithoutEvents 座架自檢：兩條 pump 都真的掛起來了。
//
// 沒有這條，後面「2 秒內返回」的斷言可能因為座架建構失敗（例如假 guacd 沒接上、
// WS 沒升級成功）而**恆真**——那是最典型的假綠：測試通過但什麼都沒測到。
func TestTunnelStartBlocksWithoutEvents(t *testing.T) {
	guacd := newFakeGuacd(t)
	conn := guacd.dial(t)
	guacd.accepted(t)
	srvWS, _ := wsPair(t)

	tunnel := NewTunnel(srvWS, conn, nil, nil, nil)
	done, _ := startTunnel(t, tunnel)

	select {
	case <-done:
		t.Fatal("Start() 在無任何事件時就返回了——座架沒把兩條 pump 掛起來，" +
			"本檔其餘的「N 秒內返回」斷言全部失去意義")
	case <-time.After(1 * time.Second):
		// 期望：仍在阻塞
	}
}

// ---------------------------------------------------------------------------
// 2.2 正常關閉（WS close frame）立即收線
// ---------------------------------------------------------------------------

// TestTunnelStartReturnsOnClientNormalClose 客戶端送 WS close frame（真實瀏覽器
// 關分頁走的路徑）後，Start() 必須立即返回。
//
// **2 秒的選法**：遠小於 wsPingInterval（30 秒）故修前必逾時——修前
// pumpWebSocketToGuacamole 對正常關閉回 nil 而不進 errChan，另一條 pump 仍阻塞在
// ReadInstruction，唯一的解鎖者是下一次保活 ping 失敗；同時 2 秒遠大於本機收線的實際
// 耗時（毫秒級），不製造 flake。
//
// 突變自檢：拿掉 pumpWebSocketToGuacamole 的 `defer t.Close()` 後本測試必須紅。
func TestTunnelStartReturnsOnClientNormalClose(t *testing.T) {
	guacd := newFakeGuacd(t)
	conn := guacd.dial(t)
	guacd.accepted(t)
	srvWS, cliWS := wsPair(t)

	tunnel := NewTunnel(srvWS, conn, nil, nil, nil)
	done, retErr := startTunnel(t, tunnel)

	// 客戶端送正常關閉訊號
	require.NoError(t, cliWS.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(2*time.Second),
	))

	select {
	case <-done:
		assert.NoError(t, retErr(), "正常關閉不應產生錯誤——end_reason 必須維持 normal")
	case <-time.After(2 * time.Second):
		t.Fatal("Start() 未於 2 秒內返回：正常關閉仍在等保活 ping，" +
			"會話會滯留 active 最長 30 秒")
	}
}

// ---------------------------------------------------------------------------
// 2.3 guacd 側關閉立即收線（「兩條都要加」的守衛）
// ---------------------------------------------------------------------------

// TestTunnelStartReturnsOnGuacdClose guacd 側關閉 TCP 後 Start() 必須立即返回。
//
// 這條打的是 pumpGuacamoleToWebSocket 的對稱缺口：ReadInstruction 出錯且連線已不
// IsConnected 時該 pump 回 nil，若不同時收線，另一條 WS pump 仍阻塞在 ReadMessage，
// 一樣要等保活 ping。只在 WS 側加 `defer t.Close()` 時本測試會紅
//（memory: same-type-different-path——同型缺陷要換條路徑再驗一次）。
func TestTunnelStartReturnsOnGuacdClose(t *testing.T) {
	guacd := newFakeGuacd(t)
	conn := guacd.dial(t)
	guacdSide := guacd.accepted(t)
	srvWS, _ := wsPair(t)

	tunnel := NewTunnel(srvWS, conn, nil, nil, nil)
	done, _ := startTunnel(t, tunnel)

	// 先確認座架真的掛住了（否則下面的「2 秒內返回」可能是本來就會返回）
	select {
	case <-done:
		t.Fatal("Start() 在 guacd 斷線前就返回了——座架失效")
	case <-time.After(200 * time.Millisecond):
	}

	require.NoError(t, guacdSide.Close(), "假 guacd 斷線失敗")

	select {
	case <-done:
		// 期望：立即返回。此路徑 WS 側是被自己的 Close 關掉的，
		// 故 Start() 可能帶回「讀取 WebSocket 失敗」錯誤——時機才是本條要守的東西。
	case <-time.After(2 * time.Second):
		t.Fatal("Start() 未於 2 秒內返回：guacd 側關閉後仍在等保活 ping——" +
			"`defer t.Close()` 只加在 WS 側，同型缺陷留在 guac 側")
	}
}

// ---------------------------------------------------------------------------
// 2.4 keepalive 非退化
// ---------------------------------------------------------------------------

// TestTunnelKeepaliveDefaultsUnchanged 釘住保活參數的產品預設值。
//
// 本 change 讓 keepalive 不再是**正常關閉**的解鎖者，但它仍是**半開連線**
//（網路中斷、兩個方向都沒有任何訊號抵達）的唯一收斂者，不得移除、不得改週期。
//
// 這條同時擋兩種退化：
//   - 有人把 wsPingInterval 調小來「順便讓滯留變短」——那只是縮短一個不該存在的窗，
//     且提高所有連線的控制訊框成本；
//   - 有人為了讓收線測試跑快一點而調小產品預設值，使「為了測試調小」悄悄變成產品行為。
func TestTunnelKeepaliveDefaultsUnchanged(t *testing.T) {
	assert.Equal(t, 30*time.Second, wsPingInterval,
		"wsPingInterval 是半開連線兜底的探測週期，改值須有獨立依據")
	assert.Equal(t, 90*time.Second, wsReadTimeout,
		"wsReadTimeout 是半開連線的最後一道收斂線，改值須有獨立依據")
}

// deadlineRecordingConn 記錄 SetReadDeadline 呼叫的 net.Conn 包裝。
// 用來在不改動產品程式碼、也不等滿 90 秒的前提下，觀測 keepalive 是否仍然
// **武裝了半開連線的兜底**（讀取逾時 ＋ pong 刷新）。
type deadlineRecordingConn struct {
	net.Conn
	deadlines chan time.Time
}

func (c *deadlineRecordingConn) SetReadDeadline(tm time.Time) error {
	select {
	case c.deadlines <- tm:
	default:
	}
	return c.Conn.SetReadDeadline(tm)
}

// TestTunnelKeepaliveArmsReadDeadlineAndPongRefresh keepalive 仍武裝半開兜底。
//
// 斷言兩件事：
//  1. Start() 之後讀取逾時被設到「約 wsReadTimeout 之後」——半開連線的最後收斂線還在；
//  2. 對端送 pong 時該逾時被重新設定——pong handler 還掛著，活著的連線不會被誤殺。
//
// **為什麼不直接測「半開 90 秒後真的收線」**：那需要等滿 wsReadTimeout（90 秒），
// 或把 wsPingInterval／wsReadTimeout 改成可注入變數。後者會動到本 change 明文要求
// 逐字不動的 keepalive 常數宣告，故本檔改為驗「武裝動作仍然發生」——逾時到期後
// net.Conn 會讓 ReadMessage 出錯是標準庫行為，不是本專案的程式碼。
func TestTunnelKeepaliveArmsReadDeadlineAndPongRefresh(t *testing.T) {
	guacd := newFakeGuacd(t)
	conn := guacd.dial(t)
	guacd.accepted(t)

	// 伺服端只負責升級與送 pong（扮演對端）
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	peerCh := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("WS 升級失敗: %v", err)
			return
		}
		peerCh <- c
	}))
	t.Cleanup(server.Close)

	// 自行撥 TCP 並包上記錄器，再交給 gorilla 完成 WS 客戶端握手：
	// 這樣 Tunnel 持有的 websocket.Conn 底層就是可觀測的 net.Conn。
	rawAddr := strings.TrimPrefix(server.URL, "http://")
	raw, err := net.Dial("tcp", rawAddr)
	require.NoError(t, err)
	rec := &deadlineRecordingConn{Conn: raw, deadlines: make(chan time.Time, 16)}
	u, err := url.Parse("ws://" + rawAddr + "/")
	require.NoError(t, err)
	tunnelWS, _, err := websocket.NewClient(rec, u, nil, 1024, 1024)
	require.NoError(t, err, "WS 客戶端握手失敗")
	t.Cleanup(func() { _ = tunnelWS.Close() })

	var peer *websocket.Conn
	select {
	case peer = <-peerCh:
	case <-time.After(3 * time.Second):
		t.Fatal("對端 WS conn 未就緒")
	}
	t.Cleanup(func() { _ = peer.Close() })

	tunnel := NewTunnel(tunnelWS, conn, nil, nil, nil)
	startTunnel(t, tunnel)

	// 1. keepalive 起手即武裝讀取逾時
	var armed time.Time
	select {
	case armed = <-rec.deadlines:
	case <-time.After(2 * time.Second):
		t.Fatal("Start() 後未見 SetReadDeadline——keepalive 沒被啟動，" +
			"半開連線將永不收斂（session-leak 回歸）")
	}
	remaining := time.Until(armed)
	assert.Greater(t, remaining, wsReadTimeout-10*time.Second,
		"讀取逾時被設得比 wsReadTimeout 短很多——兜底窗被悄悄縮小")
	assert.LessOrEqual(t, remaining, wsReadTimeout+time.Second,
		"讀取逾時被設得比 wsReadTimeout 長——兜底窗被悄悄放大")

	// 2. 對端送 pong 時逾時被刷新（pong handler 仍掛著）
	require.NoError(t, peer.WriteControl(websocket.PongMessage, nil, time.Now().Add(2*time.Second)))
	deadline := time.After(3 * time.Second)
	refreshed := false
	for !refreshed {
		select {
		case d := <-rec.deadlines:
			// 排除 pump 讀到訊息後自己刷新的那次（本測試對端不送資料訊框，
			// 故任何後續的 SetReadDeadline 都來自 pong handler）
			if !d.Before(armed) {
				refreshed = true
			}
		case <-deadline:
			t.Fatal("對端送 pong 後未見讀取逾時刷新——pong handler 沒掛上，" +
				"活著但安靜的連線會在 wsReadTimeout 到期時被誤殺")
		}
	}
}
