package proxy

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/pkg/guacamole"
)

// 斷線原因（session-timeout 值域，與 sshproxy 一致供審計）
const (
	tunnelEndReasonIdleTimeout = "idle_timeout"
	tunnelEndReasonMaxDuration = "max_duration"
)

// tunnelTimeoutCheckInterval 閒置/時長檢查間隔；斷線精度約此值
const tunnelTimeoutCheckInterval = 15 * time.Second

// defaultTunnelIdleTimeout TimeoutPolicy 未注入時的安全退路（TIMEOUT-3）：
// 與 sshproxy 的 defaultIdleTimeoutMinutes(30) 對齊，避免 RDP/VNC 靜默永不逾時
const defaultTunnelIdleTimeout = 30 * time.Minute

// guacd error instruction 的 status code。兩種逾時**必須用不同碼**
// guacamole-common-js 的 client error handler
// 只讀 args[0]（訊息）與 args[1]（狀態碼），額外參數一律丟棄，因此前端唯一能
// 據以分辨「閒置逾時」與「達會話上限」並各自查譯的欄位就是狀態碼。
const (
	// guacClientTimeoutCode Guacamole status CLIENT_TIMEOUT（0x0308=776）：閒置逾時
	guacClientTimeoutCode = "776"
	// guacSessionClosedCode Guacamole status SESSION_CLOSED（0x020B=523）：
	// 會話達最長時長由伺服端主動結束（非客戶端無回應）
	guacSessionClosedCode = "523"
)

// clientInputOpcodes 計入「使用者活動」的 client→guacd 指令：
// RDP/VNC 畫面更新永遠在動（時鐘/動畫），以輸出計時等於永不逾時，
// 故僅以客戶端輸入事件重置閒置計時；sync/nop 是協議心跳、size 是視窗控制，不算
var clientInputOpcodes = map[string]bool{
	"mouse":     true,
	"key":       true,
	"touch":     true,
	"clipboard": true, // 剪貼簿與檔案傳輸是使用者主動行為
	"file":      true,
	"put":       true, // filesystem 物件上傳（RDP 磁碟／VNC SFTP）：上傳中不誤判閒置
	"blob":      true,
	"pipe":      true,
}

// Tunnel 表示一個 WebSocket 到 Guacamole 的隧道（RDP/VNC 圖形協議專用）。
// 簡化版：只負責純資料轉發，不處理握手；
// SSH 文字流的審計與錄製由 internal/sshproxy 負責
type Tunnel struct {
	ws        *websocket.Conn
	conn      *Connection
	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
	stopChan  chan struct{}
	// 剪貼簿審計旁路（clipboard-audit）；nil 時略過
	sendTap *ClipboardTap
	recvTap *ClipboardTap
	// 檔案上傳審計旁路（vnc-file-transfer）：RDP 磁碟＋VNC SFTP 共用；nil 時略過
	fileTap *FileTap

	// 會話閒置/最大時長：0 = 停用該檢查
	idleTimeout   time.Duration
	maxDuration   time.Duration
	startTime     time.Time
	lastInputNano atomic.Int64
	// endReason 斷線原因（timeout 觸發時設定，正常結束為空）
	endReasonMu sync.Mutex
	endReason   string
}

// NewTunnel 建立新的隧道
func NewTunnel(ws *websocket.Conn, conn *Connection, sendTap, recvTap *ClipboardTap, fileTap *FileTap) *Tunnel {
	t := &Tunnel{
		ws:        ws,
		conn:      conn,
		closed:    false,
		stopChan:  make(chan struct{}),
		sendTap:   sendTap,
		recvTap:   recvTap,
		fileTap:   fileTap,
		startTime: time.Now(),
	}
	t.lastInputNano.Store(time.Now().UnixNano())
	return t
}

// SetTimeouts 設定閒置與最大會話時長（須在 Start 前；0 = 停用該檢查）
func (t *Tunnel) SetTimeouts(idle, max time.Duration) {
	t.idleTimeout = idle
	t.maxDuration = max
}

// EndReason 回傳斷線原因（Start 結束後由 handler 讀取寫入 session；空 = 正常）
func (t *Tunnel) EndReason() string {
	t.endReasonMu.Lock()
	defer t.endReasonMu.Unlock()
	return t.endReason
}

func (t *Tunnel) setEndReason(reason string) {
	t.endReasonMu.Lock()
	defer t.endReasonMu.Unlock()
	if t.endReason == "" {
		t.endReason = reason
	}
}

// Start 啟動隧道的雙向資料轉發
func (t *Tunnel) Start() error {
	log.Println("[Tunnel] 啟動資料轉發...")

	var wg sync.WaitGroup
	wg.Add(2)

	// 錯誤通道
	errChan := make(chan error, 2)

	// WebSocket -> Guacamole
	go func() {
		defer wg.Done()
		if err := t.pumpWebSocketToGuacamole(); err != nil {
			errChan <- fmt.Errorf("WebSocket->Guacamole 錯誤: %w", err)
		}
	}()

	// Guacamole -> WebSocket
	go func() {
		defer wg.Done()
		if err := t.pumpGuacamoleToWebSocket(); err != nil {
			errChan <- fmt.Errorf("Guacamole->WebSocket 錯誤: %w", err)
		}
	}()

	// 等待任一方向出錯或完成
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// WS 層保活（session-leak 修復）：瀏覽器強關/網路中斷留下半開 TCP 時，
	// ping 失敗或 read deadline 超時讓 pump 解鎖，避免會話永久 active
	pingDone := make(chan struct{})
	go t.keepalive(pingDone)

	// 閒置/最大時長監控：僅在啟用任一檢查時啟動
	if t.idleTimeout > 0 || t.maxDuration > 0 {
		go t.pumpTimeout()
	}

	// 收集錯誤：首錯即 Close——關閉 ws/conn 解鎖另一側 pump（否則單側卡死）
	var firstErr error
	for err := range errChan {
		if firstErr == nil {
			firstErr = err
			t.Close()
		}
		log.Printf("[Tunnel] 錯誤: %v", err)
	}
	close(pingDone)

	// 確保關閉
	t.Close()

	log.Println("[Tunnel] 已停止")
	return firstErr
}

// wsReadTimeout 無任何訊息（含 pong）超過此時長視為死連線
const wsReadTimeout = 90 * time.Second

// wsPingInterval 保活 ping 週期
const wsPingInterval = 30 * time.Second

// keepalive 週期送 WS ping；pong 刷新 read deadline（瀏覽器自動回 pong）
func (t *Tunnel) keepalive(done chan struct{}) {
	t.ws.SetReadDeadline(time.Now().Add(wsReadTimeout))
	t.ws.SetPongHandler(func(string) error {
		return t.ws.SetReadDeadline(time.Now().Add(wsReadTimeout))
	})

	ticker := time.NewTicker(wsPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.stopChan:
			return
		case <-ticker.C:
			t.mu.Lock()
			err := t.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
			t.mu.Unlock()
			if err != nil {
				log.Printf("[Tunnel] 保活 ping 失敗，關閉隧道: %v", err)
				t.Close()
				return
			}
		}
	}
}

// pumpTimeout 週期檢查閒置與最大時長，觸發即通知前端、記原因、收線。
// 判定邏輯與 sshproxy.evalTimeout 一致：max 優先於 idle、0=停用該檢查
func (t *Tunnel) pumpTimeout() {
	ticker := time.NewTicker(tunnelTimeoutCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopChan:
			return
		case now := <-ticker.C:
			lastInput := time.Unix(0, t.lastInputNano.Load())
			reason, fire := evalTunnelTimeout(now, t.startTime, lastInput, t.idleTimeout, t.maxDuration)
			if !fire {
				continue
			}
			// 訊息取 apierror registry 的 zh fallback（伺服端不再寫散文，
			// 前端依 status code 查譯，msg 僅為未查譯時的退路）
			code, status := apierror.CodeSessionIdleTimeout, guacClientTimeoutCode
			if reason == tunnelEndReasonMaxDuration {
				code, status = apierror.CodeSessionMaxDuration, guacSessionClosedCode
			}
			msg := ""
			if d, ok := apierror.DescriptorOf(code); ok {
				msg = d.ZhFallback
			}

			// 以 Guacamole error instruction 通知前端斷線原因（onerror 呈現）；
			// 失敗不影響收線——Close 本身就會讓前端斷開
			errInst := &guacamole.Instruction{
				Opcode: "error",
				Args:   []string{msg, status},
			}
			t.mu.Lock()
			_ = t.ws.WriteMessage(websocket.TextMessage, []byte(errInst.Encode()))
			t.mu.Unlock()

			t.setEndReason(reason)
			log.Printf("[Tunnel] 會話超時斷線(%s)", reason)
			t.Close()
			return
		}
	}
}

// evalTunnelTimeout 純判斷：回傳斷線原因與是否觸發（max 優先於 idle；0 = 停用該檢查）。
// 與 sshproxy.evalTimeout 同構——兩 package 語義必須一致（同一政策鍵驅動）
func evalTunnelTimeout(now, start, lastInput time.Time, idle, max time.Duration) (string, bool) {
	if max > 0 && now.Sub(start) > max {
		return tunnelEndReasonMaxDuration, true
	}
	if idle > 0 && now.Sub(lastInput) > idle {
		return tunnelEndReasonIdleTimeout, true
	}
	return "", false
}

// pumpWebSocketToGuacamole 從 WebSocket 讀取並轉發到 Guacamole
func (t *Tunnel) pumpWebSocketToGuacamole() error {
	// 與 sshproxy/bridge.go 的 `defer b.stop` 對稱：
	// 本方向結束即收線，不論回的是錯誤還是 nil。少了這一行，客戶端送 WS close frame
	// 的**正常關閉**路徑會回 nil 而不進 errChan，另一條 pump 仍阻塞在 ReadInstruction，
	// Start() 要等下一次保活 ping 失敗（最長 30 秒）才解鎖。
	// `Close()` 以 `closeOnce` 冪等，故與 `Start()` 的「首錯即 Close」同時發生無害。
	defer t.Close()
	for {
		select {
		case <-t.stopChan:
			return nil
		default:
		}

		// 從 WebSocket 讀取訊息
		_, message, err := t.ws.ReadMessage()
		if err == nil {
			t.ws.SetReadDeadline(time.Now().Add(wsReadTimeout))
		}
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Println("[Tunnel] WebSocket 正常關閉")
				return nil
			}
			return fmt.Errorf("讀取 WebSocket 失敗: %w", err)
		}

		// 跳過空消息（Guacamole.js 會發送空消息作為心跳）
		messageStr := string(message)
		if messageStr == "" || messageStr == ";" {
			log.Printf("[Tunnel] [WS->Guac] 跳過空消息: len=%d, content=[%s]", len(messageStr), messageStr)
			continue
		}

		// 解碼 Guacamole 指令
		instruction, err := guacamole.DecodeInstruction(messageStr)
		if err != nil {
			// **不印原始資料**（guacamole-protocol-conformance task 4.1）：
			// WS→guacd 方向的第一個指令是握手 connect，其 args 含**明文密碼**。
			// 解碼失敗時把 messageStr 印進 log 等於把密碼（及任何畸形輸入）寫進日誌。
			// 只留原因與長度，足以診斷、不洩內容。
			log.Printf("[Tunnel] 解碼指令失敗: %v（原始資料 %d bytes，已去識別不記錄內容）", err, len(messageStr))
			continue
		}

		log.Printf("[Tunnel] [WS->Guac] %s", instruction.Opcode)
		// 客戶端輸入事件重置閒置計時（畫面更新不算活動）
		if clientInputOpcodes[instruction.Opcode] {
			t.lastInputNano.Store(time.Now().UnixNano())
		}
		t.sendTap.Observe(instruction)
		verdict := t.fileTap.Observe(instruction)

		// 資料傳輸管控（data-transfer-control 5.2）：被拒的 stream 其 put／blob／end
		// **一併不轉發**。只擋 put 而放行 blob 等於檔案照樣寫入——這是本組最可能的錯誤。
		// ack 先回送（讓客戶端立即失敗而非無限等待），再丟棄指令
		if verdict.Ack != nil {
			if err := t.writeToClient(verdict.Ack); err != nil {
				return fmt.Errorf("回送串流拒絕 ack 失敗: %w", err)
			}
		}
		if !verdict.Forward {
			log.Printf("[Tunnel] [WS->Guac] %s 遭資料傳輸管控攔下，不轉發", instruction.Opcode)
			continue
		}

		// 直接轉發到 Guacamole（無握手攔截）
		if err := t.conn.WriteInstruction(instruction); err != nil {
			return fmt.Errorf("寫入 Guacamole 失敗: %w", err)
		}
	}
}

// writeToClient 由 WS→guacd 泵回送指令給客戶端（data-transfer-control 5.3）。
//
// 與 pumpGuacamoleToWebSocket 共用同一把 `t.mu`——兩條 goroutine 同時寫同一個
// websocket.Conn 是 gorilla 的並發違規，不加鎖會偶發 panic 或訊框交錯。
func (t *Tunnel) writeToClient(inst *guacamole.Instruction) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	return t.ws.WriteMessage(websocket.TextMessage, []byte(inst.Encode()))
}

// pumpGuacamoleToWebSocket 從 Guacamole 讀取並轉發到 WebSocket
func (t *Tunnel) pumpGuacamoleToWebSocket() error {
	// 與 sshproxy/bridge.go 的 `defer b.stop` 對稱：
	// **兩條 pump 都要加，不是只加 WS 側**——本方向在 `GuacClient == nil ||
	// !IsConnected()` 時同樣回 nil（見下方守衛），是同型的第二個缺口，目標端斷線而
	// backend 尚未自行 Close 時會走到。`Close()` 以 `closeOnce` 冪等，故與 `Start()`
	// 的「首錯即 Close」同時發生無害。
	defer t.Close()
	for {
		select {
		case <-t.stopChan:
			return nil
		default:
		}

		// 從 Guacamole 讀取指令
		instruction, err := t.conn.ReadInstruction()
		if err != nil {
			// GuacClient 在 teardown 競態下可能已為 nil：先守衛再判連線，
			// 否則對 nil *Client 呼叫 IsConnected() 會 nil deref panic 拖垮整個 backend
			if t.conn.GuacClient == nil || !t.conn.GuacClient.IsConnected() {
				log.Println("[Tunnel] Guacamole 連線已關閉")
				return nil
			}
			return fmt.Errorf("讀取 Guacamole 失敗: %w", err)
		}

		log.Printf("[Tunnel] [Guac->WS] %s (args: %d)", instruction.Opcode, len(instruction.Args))
		t.recvTap.Observe(instruction)

		// 編碼並發送到 WebSocket
		encoded := instruction.Encode()
		t.mu.Lock()
		err = t.ws.WriteMessage(websocket.TextMessage, []byte(encoded))
		t.mu.Unlock()

		if err != nil {
			return fmt.Errorf("寫入 WebSocket 失敗: %w", err)
		}
	}
}

// Close 關閉隧道
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		log.Println("[Tunnel] 關閉隧道...")
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()

		close(t.stopChan)

		// 關閉 WebSocket
		if t.ws != nil {
			t.ws.Close()
		}

		// 關閉 Guacamole 連線
		if t.conn != nil {
			t.conn.Close()
		}
	})
	return nil
}

// IsClosed 檢查隧道是否已關閉
func (t *Tunnel) IsClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

// Disconnect 管理端強制收線（Registry CloseFunc）：
// 於本 tunnel 寫鎖內送 Guacamole disconnect 指令通知前端，再走冪等 Close。
// 通知失敗不影響收線——Close 本身就會讓前端斷開
func (t *Tunnel) Disconnect() error {
	t.mu.Lock()
	if !t.closed {
		// 格式: 10.disconnect; (10 是 "disconnect" 的字串長度)
		if err := t.ws.WriteMessage(websocket.TextMessage, []byte("10.disconnect;")); err != nil {
			log.Printf("[Tunnel] 警告: 發送 disconnect 指令失敗: %v", err)
		}
	}
	t.mu.Unlock()
	return t.Close()
}
