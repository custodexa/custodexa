package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

// 創建測試用的 WebSocket 服務器和客戶端連線（Tunnel.Disconnect 協議測試用）
func createTestWebSocketConn(t *testing.T) (*websocket.Conn, *httptest.Server) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade: %v", err)
			return
		}
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	}))

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	return conn, server
}

// noopClose 計數用關閉回呼
func noopClose(counter *atomic.Int32) CloseFunc {
	return func() error {
		counter.Add(1)
		return nil
	}
}

// TestNewConnectionRegistry 測試創建連線註冊表
func TestNewConnectionRegistry(t *testing.T) {
	registry := NewConnectionRegistry()
	assert.NotNil(t, registry)
	assert.NotNil(t, registry.connections)
	assert.Equal(t, 0, registry.Count())
}

// TestRegister 測試註冊連線
func TestRegister(t *testing.T) {
	registry := NewConnectionRegistry()
	var n atomic.Int32

	registry.Register(1, noopClose(&n))

	assert.Equal(t, 1, registry.Count())
	assert.True(t, registry.Has(1))
}

// TestRegisterMultiple 測試註冊多個連線
func TestRegisterMultiple(t *testing.T) {
	registry := NewConnectionRegistry()
	var n atomic.Int32

	for i := 1; i <= 3; i++ {
		registry.Register(uint(i), noopClose(&n))
	}

	assert.Equal(t, 3, registry.Count())
	for i := 1; i <= 3; i++ {
		assert.True(t, registry.Has(uint(i)))
	}
}

// TestRegisterOverwrite 測試註冊覆蓋舊回呼（同 sessionID 重複註冊以後者為準）
func TestRegisterOverwrite(t *testing.T) {
	registry := NewConnectionRegistry()
	var first, second atomic.Int32

	registry.Register(1, noopClose(&first))
	assert.Equal(t, 1, registry.Count())

	registry.Register(1, noopClose(&second))
	assert.Equal(t, 1, registry.Count())

	// 關閉時只執行第二個回呼
	assert.NoError(t, registry.Close(1))
	assert.Equal(t, int32(0), first.Load())
	assert.Equal(t, int32(1), second.Load())
}

// TestUnregister 測試註銷連線
func TestUnregister(t *testing.T) {
	registry := NewConnectionRegistry()
	var n atomic.Int32

	registry.Register(1, noopClose(&n))
	assert.Equal(t, 1, registry.Count())

	registry.Unregister(1)
	assert.Equal(t, 0, registry.Count())
	assert.False(t, registry.Has(1))

	// 註銷後 Close 為 no-op（回呼不被呼叫）
	assert.NoError(t, registry.Close(1))
	assert.Equal(t, int32(0), n.Load())
}

// TestUnregisterNotExists 測試註銷不存在的連線
func TestUnregisterNotExists(t *testing.T) {
	registry := NewConnectionRegistry()

	registry.Unregister(999)
	assert.Equal(t, 0, registry.Count())
}

// TestCount 測試計數功能
func TestCount(t *testing.T) {
	registry := NewConnectionRegistry()
	var n atomic.Int32
	assert.Equal(t, 0, registry.Count())

	for i := 1; i <= 5; i++ {
		registry.Register(uint(i), noopClose(&n))
		assert.Equal(t, i, registry.Count())
	}

	for i := 1; i <= 5; i++ {
		registry.Unregister(uint(i))
		assert.Equal(t, 5-i, registry.Count())
	}
}

// TestClose_Success 測試正常關閉連線：回呼被呼叫、項目移除
func TestClose_Success(t *testing.T) {
	registry := NewConnectionRegistry()
	var n atomic.Int32

	registry.Register(1, noopClose(&n))

	err := registry.Close(1)
	assert.NoError(t, err)
	assert.Equal(t, int32(1), n.Load())

	assert.False(t, registry.Has(1))
	assert.Equal(t, 0, registry.Count())
}

// TestClose_NotExists 測試關閉不存在的連線
func TestClose_NotExists(t *testing.T) {
	registry := NewConnectionRegistry()

	err := registry.Close(999)
	assert.NoError(t, err)
}

// TestClose_OnlyOnce 重複 Close 同一 session 回呼至多執行一次（原子取出語義）
func TestClose_OnlyOnce(t *testing.T) {
	registry := NewConnectionRegistry()
	var n atomic.Int32

	registry.Register(1, noopClose(&n))

	assert.NoError(t, registry.Close(1))
	assert.NoError(t, registry.Close(1))
	assert.Equal(t, int32(1), n.Load())
}

// TestClose_ErrorPropagated 回呼錯誤要回傳且項目仍移除（不重試）
func TestClose_ErrorPropagated(t *testing.T) {
	registry := NewConnectionRegistry()
	wantErr := errors.New("close failed")

	registry.Register(1, func() error { return wantErr })

	err := registry.Close(1)
	assert.ErrorIs(t, err, wantErr)
	assert.False(t, registry.Has(1))
}

// TestTunnelDisconnect_SendsGuacDisconnect Tunnel.Disconnect 作為 CloseFunc：
// 前端收到 Guacamole disconnect 指令（圖形通道協議正確性）
func TestTunnelDisconnect_SendsGuacDisconnect(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	msgChan := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade: %v", err)
			return
		}
		defer conn.Close()

		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if messageType == websocket.TextMessage {
				msgChan <- string(message)
			}
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err)

	tunnel := NewTunnel(conn, nil, nil, nil, nil)

	registry := NewConnectionRegistry()
	registry.Register(1, tunnel.Disconnect)

	err = registry.Close(1)
	assert.NoError(t, err)

	select {
	case msg := <-msgChan:
		assert.Equal(t, "10.disconnect;", msg)
	case <-time.After(500 * time.Millisecond):
		t.Error("Timeout waiting for disconnect message")
	}
}

// TestConcurrentRegister 測試並發註冊
func TestConcurrentRegister(t *testing.T) {
	registry := NewConnectionRegistry()
	const numGoroutines = 100
	var n atomic.Int32

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			registry.Register(uint(id), noopClose(&n))
		}(i)
	}

	wg.Wait()

	assert.Equal(t, numGoroutines, registry.Count())
}

// TestConcurrentUnregister 測試並發註銷
func TestConcurrentUnregister(t *testing.T) {
	registry := NewConnectionRegistry()
	const numGoroutines = 100
	var n atomic.Int32

	for i := 0; i < numGoroutines; i++ {
		registry.Register(uint(i), noopClose(&n))
	}
	assert.Equal(t, numGoroutines, registry.Count())

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			registry.Unregister(uint(id))
		}(i)
	}

	wg.Wait()

	assert.Equal(t, 0, registry.Count())
}

// TestConcurrentReadWrite 測試並發讀寫混合操作
func TestConcurrentReadWrite(t *testing.T) {
	registry := NewConnectionRegistry()
	const numOperations = 100
	var n atomic.Int32

	var wg sync.WaitGroup

	for i := 0; i < numOperations; i++ {
		wg.Add(3)

		go func(id int) {
			defer wg.Done()
			registry.Register(uint(id), noopClose(&n))
		}(i)

		go func(id int) {
			defer wg.Done()
			registry.Has(uint(id))
		}(i)

		go func() {
			defer wg.Done()
			registry.Count()
		}()
	}

	wg.Wait()

	t.Logf("Final count: %d", registry.Count())
}

// TestConcurrentClose 並發 Close 全部連線：每個回呼至多一次、不 panic
func TestConcurrentClose(t *testing.T) {
	registry := NewConnectionRegistry()
	const numGoroutines = 50
	var n atomic.Int32

	for i := 0; i < numGoroutines; i++ {
		registry.Register(uint(i), noopClose(&n))
	}
	assert.Equal(t, numGoroutines, registry.Count())

	var wg sync.WaitGroup
	// 每個 session 由兩個 goroutine 競爭 Close，驗證原子取出
	wg.Add(numGoroutines * 2)

	for i := 0; i < numGoroutines; i++ {
		for j := 0; j < 2; j++ {
			go func(id int) {
				defer wg.Done()
				_ = registry.Close(uint(id))
			}(i)
		}
	}

	wg.Wait()

	assert.Equal(t, 0, registry.Count())
	assert.Equal(t, int32(numGoroutines), n.Load(), "每個回呼恰好執行一次")
}

// TestHas 測試存活查詢（session-reconciliation 孤兒偵測的權威訊號）
func TestHas(t *testing.T) {
	registry := NewConnectionRegistry()
	var n atomic.Int32

	assert.False(t, registry.Has(1), "未註冊應回 false")

	registry.Register(1, noopClose(&n))
	assert.True(t, registry.Has(1), "已註冊應回 true")

	registry.Unregister(1)
	assert.False(t, registry.Has(1), "註銷後應回 false")
}

// TestConcurrentHas 並發 Has 與註冊/註銷混合不得 race
func TestConcurrentHas(t *testing.T) {
	registry := NewConnectionRegistry()
	var n atomic.Int32

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(id uint) {
			defer wg.Done()
			registry.Register(id, noopClose(&n))
			registry.Unregister(id)
		}(uint(i))
		go func(id uint) {
			defer wg.Done()
			_ = registry.Has(id)
		}(uint(i))
	}
	wg.Wait()
}
