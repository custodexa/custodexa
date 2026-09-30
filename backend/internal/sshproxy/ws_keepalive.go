package sshproxy

import (
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// 與圖形 tunnel 相同的 WebSocket 存活期限。var 供同套件測試縮短時間；
// 生產流程不修改這兩個值。
var (
	wsKeepalivePingInterval = 30 * time.Second
	wsKeepaliveReadTimeout  = 90 * time.Second
)

// startWSKeepalive 僅對真正的 WebSocket 啟動。行程內傳輸沒有 ping/pong，
// 也不得被 WebSocket 的讀取期限收掉。呼叫端必須從讀取 goroutine 呼叫，
// 因 SetReadDeadline 與 SetPongHandler 都屬 gorilla 的單一 reader 方法。
// 回傳的 touch 在每次 ReadMessage 成功後由同一 reader 呼叫。
func startWSKeepalive(transport Transport, writeMu *sync.Mutex, done <-chan struct{}, onPingFailure func()) func() {
	ws, ok := transport.(*websocket.Conn)
	if !ok {
		return func() {}
	}
	touch := func() {
		_ = ws.SetReadDeadline(time.Now().Add(wsKeepaliveReadTimeout))
	}
	touch()
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(wsKeepaliveReadTimeout))
	})

	go func() {
		ticker := time.NewTicker(wsKeepalivePingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				writeMu.Lock()
				err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
				writeMu.Unlock()
				if err != nil {
					log.Printf("[SSHProxy] WebSocket 保活 ping 失敗: %v", err)
					onPingFailure()
					return
				}
			}
		}
	}()
	return touch
}
