package sshproxy

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/notifycat"
)

// 輸出批次 flush 間隔：60ms 是「人眼察覺不到延遲」與「不讓每個 byte 各成一個 WS 封包」的折衷
const outputFlushInterval = 60 * time.Millisecond

// 閒置/時長檢查間隔（session-timeout）：足夠細不浪費，斷線精度約此值
const timeoutCheckInterval = 15 * time.Second

// 斷線原因（session-timeout，session.end_reason 值域）
const (
	endReasonNormal      = "normal"
	endReasonIdleTimeout = "idle_timeout"
	endReasonMaxDuration = "max_duration"
	// endReasonBlockClearFailed 阻斷後清遠端行緩衝失敗而主動收線
	// （backend-i18n-unification A1 fail-close）。經 setEndReason → handler 的
	// CloseWithReason 落 sessions.end_reason，與逾時／強制終止同一條審計軌
	endReasonBlockClearFailed = "block_clear_failed"
)

// outputSink 旁路消費終端輸出（錄製器、審計虛擬螢幕）。
// 旁路失敗不可影響轉發主路徑。
type outputSink interface {
	WriteOutput(p []byte)
}

// inputSink 旁路消費使用者輸入（審計指令重組）
type inputSink interface {
	WriteInput(p []byte)
}

// resizeSink 旁路消費尺寸變更（錄製器尺寸事件、審計螢幕尺寸）
type resizeSink interface {
	Resize(cols, rows int)
}

// bridge 串接 WebSocket（前端 xterm.js）與 SSHConn（遠端 PTY）的雙向轉發
type bridge struct {
	ws             *websocket.Conn
	conn           TerminalConn
	session        *model.Session
	sessionService *session.SessionService
	recordingPath  string
	userID         uint
	assetID        uint

	// wsWriteMu 序列化 WS 寫入：gorilla/websocket 僅允許單一併發 writer
	wsWriteMu sync.Mutex
	stopOnce  sync.Once
	stopChan  chan struct{}

	// blocker 指令阻斷（command-blocking 輪 B）：nil 時直通
	blocker *commandBlocker

	// 會話超時（session-timeout）：0 = 停用該檢查
	idleTimeout    time.Duration
	maxDuration    time.Duration
	checkInterval  time.Duration // 預設 timeoutCheckInterval，測試可縮短
	startTime      time.Time
	lastActiveNano atomic.Int64 // 使用者最後輸入時戳（UnixNano）

	// endReason 斷線原因（session-timeout）：第一個觸發者勝出
	endReasonMu sync.Mutex
	endReason   string

	outputSinks []outputSink
	inputSinks  []inputSink
	resizeSinks []resizeSink
}

func newBridge(
	ws *websocket.Conn,
	conn TerminalConn,
	sess *model.Session,
	sessionService *session.SessionService,
	recordingPath string,
	userID uint,
	assetID uint,
) *bridge {
	b := &bridge{
		ws:             ws,
		conn:           conn,
		session:        sess,
		sessionService: sessionService,
		recordingPath:  recordingPath,
		userID:         userID,
		assetID:        assetID,
		stopChan:       make(chan struct{}),
		checkInterval:  timeoutCheckInterval,
		startTime:      time.Now(),
		endReason:      endReasonNormal,
	}
	b.lastActiveNano.Store(time.Now().UnixNano())
	return b
}

// setTimeouts 設定閒置與最大會話時長（須在 Run 前；0 = 停用該檢查）
func (b *bridge) setTimeouts(idle, max time.Duration) {
	b.idleTimeout = idle
	b.maxDuration = max
}

// touchActive 標記會話活躍（使用者輸入或伺服器下行資料皆算；resize/ping 控制訊號不算）。
// 「伺服器下行輸出也算活躍」是刻意權衡（對抗驗證 TIMEOUT-1，使用者決策方案 B）：
// tail -f/top/journalctl -f 等監看類會話是真實維運需求，人在場盯著日誌流卻無鍵盤輸入，
// 純輸入計 idle 會誤砍。代價是 idle 控制對持續輸出會話失效——由「最長會話時長」
// （session_max_minutes，與 lastActive 無關的絕對封頂）治理長連線，達上限強制中斷。
// 政策頁對「設了閒置逾時但未設最長時長」標風險，提示部署者為監看場景設封頂。
// 對比：RDP/VNC（proxy.Tunnel）以純客戶端輸入 opcode 計 idle——圖形協議畫面永遠在動，
// 以輸出計時等於永不逾時，故兩協議族的 idle 語義本就不同
func (b *bridge) touchActive() {
	b.lastActiveNano.Store(time.Now().UnixNano())
}

// setEndReason 記錄斷線原因（第一個觸發者勝出，正常結束維持 normal）
func (b *bridge) setEndReason(reason string) {
	b.endReasonMu.Lock()
	defer b.endReasonMu.Unlock()
	if b.endReason == endReasonNormal {
		b.endReason = reason
	}
}

// EndReason 回傳斷線原因（Run 結束後由 handler 讀取寫入 session）
func (b *bridge) EndReason() string {
	b.endReasonMu.Lock()
	defer b.endReasonMu.Unlock()
	return b.endReason
}

// attachAudit 掛載審計旁路（須在 Run 前呼叫）
func (b *bridge) attachAudit(tap *auditTap) {
	b.outputSinks = append(b.outputSinks, tap)
	b.inputSinks = append(b.inputSinks, tap)
	b.resizeSinks = append(b.resizeSinks, tap)
}

// attachRecording 掛載錄製旁路（須在 Run 前呼叫）
func (b *bridge) attachRecording(tap *recordingTap) {
	b.outputSinks = append(b.outputSinks, tap)
	b.resizeSinks = append(b.resizeSinks, tap)
}

// attachMonitor 掛載即時監看旁路（須在 Run 前呼叫）
func (b *bridge) attachMonitor(tap *monitorTap) {
	b.outputSinks = append(b.outputSinks, tap)
	b.resizeSinks = append(b.resizeSinks, tap)
}

// attachBlocker 掛載指令阻斷器（須在 Run 前呼叫）
func (b *bridge) attachBlocker(blocker *commandBlocker) {
	b.blocker = blocker
}

// Run 啟動雙向轉發，阻塞直到任一方向結束
func (b *bridge) Run() {
	// connected 帶 session_id（session-stats）：前端據此查詢指標 API
	connectedPayload := `{"session_id":0}`
	if b.session != nil {
		connectedPayload = fmt.Sprintf(`{"session_id":%d}`, b.session.ID)
	}
	b.writeMessage(MsgConnected, connectedPayload)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		b.pumpOutput()
	}()
	go func() {
		defer wg.Done()
		b.pumpInput()
	}()

	// 閒置/時長監控（session-timeout）：僅在啟用任一檢查時啟動
	if b.idleTimeout > 0 || b.maxDuration > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.pumpTimeout()
		}()
	}

	wg.Wait()
}

// pumpTimeout 週期檢查閒置與最大時長，觸發即注入訊息、記原因、收線（session-timeout）
func (b *bridge) pumpTimeout() {
	ticker := time.NewTicker(b.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopChan:
			return
		case now := <-ticker.C:
			idleSince := time.Unix(0, b.lastActiveNano.Load())
			reason, fire := evalTimeout(now, b.startTime, idleSince, b.idleTimeout, b.maxDuration)
			if !fire {
				continue
			}
			// D7：改送碼化 MsgError 幀（原為內嵌 ANSI 紅字的 MsgData）——
			// 文案與紅字樣式改由前端依 code 決定，伺服端不再組終端逸出序列
			code := apierror.CodeSessionIdleTimeout
			if reason == endReasonMaxDuration {
				code = apierror.CodeSessionMaxDuration
			}
			b.writeErrorMessage(code)
			b.setEndReason(reason)
			log.Printf("[SSHProxy] 會話超時斷線(%s): session=%v", reason, b.sessionID())
			b.stop()
			return
		}
	}
}

// evalTimeout 純判斷：回傳斷線原因與是否觸發（max 優先於 idle；0 = 停用該檢查）
func evalTimeout(now, start, lastActive time.Time, idle, max time.Duration) (string, bool) {
	if max > 0 && now.Sub(start) > max {
		return endReasonMaxDuration, true
	}
	if idle > 0 && now.Sub(lastActive) > idle {
		return endReasonIdleTimeout, true
	}
	return "", false
}

// stop 通知雙向 pump 結束並關閉底層連線
func (b *bridge) stop() {
	b.stopOnce.Do(func() {
		close(b.stopChan)
		b.conn.Close()
		b.ws.Close()
	})
}

// terminate 管理端強制收線（Registry CloseFunc，break-glass-revocation F4）：
// 斷線通知走本 bridge 寫鎖與文字訊息協議（前身 Registry 裸寫 guac 指令＝
// 錯協議＋併發寫 panic 風險）；stop 冪等（stopOnce），與自然收線競態安全
func (b *bridge) terminate() error {
	b.writeErrorMessage(apierror.CodeSessionTerminated)
	b.stop()
	return nil
}

// sessionID 供日誌（session 可能 nil）
func (b *bridge) sessionID() uint {
	if b.session != nil {
		return b.session.ID
	}
	return 0
}

// writeMessage 序列化寫出 WS 訊息
func (b *bridge) writeMessage(msgType MessageType, data string) {
	raw, err := EncodeMessage(msgType, data)
	if err != nil {
		log.Printf("[SSHProxy] 訊息編碼失敗: %v", err)
		return
	}
	b.writeRaw(raw)
}

// writeErrorMessage 送出碼化的 MsgError 幀（D7：Data 取 registry zh fallback，
// 前端依 code 查譯）。斷線類注入（逾時／終止／帳號停用）全走本函式
func (b *bridge) writeErrorMessage(code apierror.ErrCode) {
	raw, err := EncodeCodedErrorMessage(code)
	if err != nil {
		log.Printf("[SSHProxy] 錯誤幀編碼失敗: %v", err)
		return
	}
	b.writeRaw(raw)
}

// writeNoticeMessage 送出碼化的 MsgNotice 控制幀（D7：指令阻斷警告）
func (b *bridge) writeNoticeMessage(code apierror.ErrCode, params map[string]string) {
	raw, err := EncodeNoticeMessage(code, params)
	if err != nil {
		log.Printf("[SSHProxy] 通知幀編碼失敗: %v", err)
		return
	}
	b.writeRaw(raw)
}

// blockedMarkerFormat 阻斷標記寫入輸出旁路的終端呈現外殼（A5）：前後各一組 CRLF
// 讓標記獨佔一行，紅字 SGR 於回放時與一般輸出區別。中文本體由
// apierror.CommandBlockedAuditMarker 提供（串流出口的中文一律出自 registry，D7）
const blockedMarkerFormat = "\r\n\x1b[31m%s\x1b[0m\r\n"

// writeBlockedMarkerToSinks 將標準化阻斷標記寫入 outputSinks（錄影／即時監看／
// 審計 tap 三軌，backend-i18n-unification A5）。
//
// 此標記是**審計標準格式**，不是使用者所見渲染的副本：使用者端看到的是同時送出的
// MsgNotice 幀由前端依語系渲染的結果，本標記則是伺服端固定 zh 格式＋機器碼
// `[RULE_COMMAND_BLOCKED]`，供回放與稽核 grep。寫入 sinks 後，錄影回放、即時監看
// 與審計虛擬螢幕三軌都留下阻斷軌跡（原本三軌皆看不到阻斷，僅前端當下閃一則提示）。
//
// 規則名過 notifycat.SanitizeOpaque：AlertRule.Name 僅驗 required，可含 ANSI 逸出
// 序列與控制字元，未淨化即直接寫進錄影與監看者終端＝注入面。
func (b *bridge) writeBlockedMarkerToSinks(ruleName string) {
	marker := fmt.Sprintf(blockedMarkerFormat,
		apierror.CommandBlockedAuditMarker(notifycat.SanitizeOpaque(ruleName)))
	for _, sink := range b.outputSinks {
		sink.WriteOutput([]byte(marker))
	}
}

// writeRaw 在 WS 寫鎖下送出已編碼的幀（gorilla/websocket 僅允許單一併發 writer）
func (b *bridge) writeRaw(raw []byte) {
	b.wsWriteMu.Lock()
	defer b.wsWriteMu.Unlock()
	if err := b.ws.WriteMessage(websocket.TextMessage, raw); err != nil {
		log.Printf("[SSHProxy] WS 寫入失敗: %v", err)
	}
}

// pumpOutput SSH stdout → WS（60ms 批次 flush）＋ 旁路 sinks
func (b *bridge) pumpOutput() {
	defer b.stop()

	type readResult struct {
		data []byte
		err  error
	}
	readChan := make(chan readResult, 16)

	// 獨立 goroutine 讀 SSH stdout：Read 會阻塞，與 flush ticker 解耦
	go func() {
		defer close(readChan)
		for {
			buf := make([]byte, 4096)
			n, err := b.conn.Read(buf)
			if n > 0 {
				readChan <- readResult{data: buf[:n]}
			}
			if err != nil {
				readChan <- readResult{err: err}
				return
			}
		}
	}()

	ticker := time.NewTicker(outputFlushInterval)
	defer ticker.Stop()

	var pending []byte
	flush := func() {
		if len(pending) == 0 {
			return
		}
		b.writeMessage(MsgData, string(pending))
		pending = nil
	}

	for {
		select {
		case <-b.stopChan:
			flush()
			return
		case res, ok := <-readChan:
			if !ok {
				flush()
				return
			}
			if res.err != nil {
				if len(res.data) > 0 {
					pending = append(pending, res.data...)
				}
				flush()
				return
			}
			// 下行資料也算活躍（k8s-exec D8：tail -f/等部署等「有輸出無鍵盤輸入」
			// 的會話不被 idle 誤砍，貼近原生 kubectl；maxDuration 仍為上限 backstop）
			b.touchActive()
			pending = append(pending, res.data...)
			for _, sink := range b.outputSinks {
				sink.WriteOutput(res.data)
			}
		case <-ticker.C:
			flush()
		}
	}
}

// pumpInput WS → SSH stdin，並處理 resize / ping 控制訊息
func (b *bridge) pumpInput() {
	defer b.stop()

	for {
		select {
		case <-b.stopChan:
			return
		default:
		}

		_, raw, err := b.ws.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Println("[SSHProxy] WebSocket 正常關閉")
			}
			return
		}

		msg, err := DecodeMessage(raw)
		if err != nil {
			log.Printf("[SSHProxy] 忽略無效訊息: %v", err)
			continue
		}

		switch msg.Type {
		case MsgData:
			data := []byte(msg.Data)
			// 使用者輸入＝活躍，重置閒置計時（session-timeout；resize/ping 不算）
			b.touchActive()
			if b.blocker != nil {
				if blockedRule := b.blocker.Inspect(data); blockedRule != nil {
					// 阻斷：本段輸入不轉發；送 MsgNotice 控制幀（D7：規則名以
					// params 傳遞、由前端組字與上色）；中斷鍵清遠端行緩衝
					b.writeNoticeMessage(apierror.CodeCommandBlocked,
						map[string]string{"rule": blockedRule.Name})
					b.writeBlockedMarkerToSinks(blockedRule.Name)
					if _, err := b.conn.Write([]byte{0x03}); err != nil { // Ctrl+C 清遠端已鍵入行
						// A1 fail-close：清行失敗＝遠端行緩衝可能殘留被阻斷指令的
						// 前綴，使用者下次按 Enter 就送出殘句——阻斷等於沒發生。
						// 原行為只 log 續跑（fail-open），改為終止會話：先送碼化
						// MsgError 說明原因，再記 end_reason 讓終止落入審計軌
						// 規則名進日誌前淨化（C4）：AlertRule.Name 可含換行／ESC，
						// 未淨化即可在 log 裡偽造整行事件或操縱讀 log 的終端
						log.Printf("[SSHProxy] 阻斷後清行失敗，終止會話: session=%v rule=%q err=%v",
							b.sessionID(), notifycat.SanitizeOpaque(blockedRule.Name), err)
						b.writeErrorMessage(apierror.CodeCommandBlockClearFailed)
						b.setEndReason(endReasonBlockClearFailed)
						return // defer b.stop() 收線
					}
					log.Printf("[SSHProxy] 指令已阻斷: session=%v rule=%q",
						b.sessionID(), notifycat.SanitizeOpaque(blockedRule.Name))
					continue
				}
			}
			if _, err := b.conn.Write(data); err != nil {
				log.Printf("[SSHProxy] 寫入 SSH stdin 失敗: %v", err)
				return
			}
			for _, sink := range b.inputSinks {
				sink.WriteInput(data)
			}
		case MsgResize:
			payload, err := ParseResizePayload(msg.Data)
			if err != nil {
				log.Printf("[SSHProxy] 忽略無效 resize: %v", err)
				continue
			}
			if err := b.conn.WindowChange(payload.Rows, payload.Cols); err != nil {
				log.Printf("[SSHProxy] WindowChange 失敗: %v", err)
			}
			for _, sink := range b.resizeSinks {
				sink.Resize(payload.Cols, payload.Rows)
			}
		case MsgPing:
			b.writeMessage(MsgPong, "")
		default:
			// connected/error/pong 為後端→前端方向，前端送來即忽略
		}
	}
}
