package sshproxy

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
)

// ---------------------------------------------------------------------------
// 阻斷軌跡測試
//
// 一、阻斷標記必須進 outputSinks（錄影／即時監看／審計 tap 三軌），
//     否則阻斷只在使用者當下的分頁閃一則提示，事後回放與稽核完全看不到。
// 二、阻斷後的清行（Ctrl+C）失敗即終止會話，並把原因寫入既有審計軌
//     （sessions.end_reason，經 bridge.EndReason → handler.CloseWithReason）。
// ---------------------------------------------------------------------------

// captureSink 記錄旁路收到的輸出（代錄影／監看／審計 tap 三軌的共同介面）
type captureSink struct {
	mu   sync.Mutex
	data []byte
}

func (s *captureSink) WriteOutput(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = append(s.data, p...)
}

func (s *captureSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.data)
}

// blockingConn 可設定 Ctrl+C 清行失敗的 TerminalConn，並記錄所有寫入
type blockingConn struct {
	*fakeTerminalConn
	clearErr error

	mu     sync.Mutex
	writes [][]byte
}

func newBlockingConn(clearErr error) *blockingConn {
	return &blockingConn{fakeTerminalConn: newFakeTerminalConn(), clearErr: clearErr}
}

func (c *blockingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	cp := append([]byte(nil), p...)
	c.writes = append(c.writes, cp)
	c.mu.Unlock()

	if len(p) == 1 && p[0] == 0x03 && c.clearErr != nil {
		return 0, c.clearErr
	}
	return len(p), nil
}

func (c *blockingConn) written() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	for _, w := range c.writes {
		b.Write(w)
	}
	return b.String()
}

// alwaysBlockMatcher 一律命中指定規則
type alwaysBlockMatcher struct{ rule *model.AlertRule }

func (m *alwaysBlockMatcher) MatchBlock(command, protocol string) (*model.AlertRule, bool) {
	return m.rule, true
}

// startBlockingBridge 建好一條掛了阻斷器與捕捉 sink 的 bridge，回傳
// （bridge、旁路 sink、遠端 conn、測試端 WS client）。db 傳 nil＝阻斷事件不入庫。
func startBlockingBridge(t *testing.T, ruleName string, clearErr error) (
	*bridge, *captureSink, *blockingConn, *websocket.Conn) {
	t.Helper()

	serverWS, clientWS := newWSPair(t)
	conn := newBlockingConn(clearErr)
	b := newBridge(serverWS, conn, nil, nil, "", 0, 0)

	sink := &captureSink{}
	b.outputSinks = append(b.outputSinks, sink)
	b.attachBlocker(newCommandBlocker(
		&alwaysBlockMatcher{rule: &model.AlertRule{Name: ruleName}},
		nil, 1, 2, 3, string(model.ProtocolSSH)))

	go b.pumpInput()
	t.Cleanup(b.stop)
	return b, sink, conn, clientWS
}

// sendInput 由測試端（前端角色）送一段終端輸入
func sendInput(t *testing.T, ws *websocket.Conn, data string) {
	t.Helper()
	raw, err := EncodeMessage(MsgData, data)
	if err != nil {
		t.Fatalf("編碼輸入失敗: %v", err)
	}
	if err := ws.WriteMessage(websocket.TextMessage, raw); err != nil {
		t.Fatalf("送出輸入失敗: %v", err)
	}
}

// readFrames 讀 n 則後端幀。不走 DecodeMessage：MsgNotice 是後端→前端方向，
// DecodeMessage 的白名單刻意不含它
func readFrames(t *testing.T, ws *websocket.Conn, n int) []Message {
	t.Helper()
	out := make([]Message, 0, n)
	for i := 0; i < n; i++ {
		ws.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, raw, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("讀取第 %d 則幀失敗: %v", i+1, err)
		}
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatalf("解析第 %d 則幀失敗: %v", i+1, err)
		}
		out = append(out, msg)
	}
	return out
}

// TestBlockedCommandMarkerReachesOutputSinks 阻斷時標準化標記進三軌旁路，
// 且使用者端照舊收到 MsgNotice（兩者並存，不是二選一）
func TestBlockedCommandMarkerReachesOutputSinks(t *testing.T) {
	const ruleName = "禁止刪根目錄"
	_, sink, conn, clientWS := startBlockingBridge(t, ruleName, nil)

	sendInput(t, clientWS, "rm -rf /\r")

	// 使用者端：碼化 MsgNotice（規則名走 params，前端組字）
	frames := readFrames(t, clientWS, 1)
	if frames[0].Type != MsgNotice || frames[0].Code != string(apierror.CodeCommandBlocked) {
		t.Fatalf("使用者端幀 = %+v, want notice/%s", frames[0], apierror.CodeCommandBlocked)
	}

	// 旁路三軌：標準化阻斷標記（機器碼可 grep ＋ 規則名 ＋ 紅字外殼）
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && sink.String() == "" {
		time.Sleep(5 * time.Millisecond)
	}
	got := sink.String()
	for _, want := range []string{
		"[" + string(apierror.CodeCommandBlocked) + "]", // 可 grep 的機器碼
		ruleName,
		"指令命中阻斷規則",
		"已阻止送往目標主機",
		"\x1b[31m", "\x1b[0m", "\r\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("旁路標記缺 %q，實得 %q", want, got)
		}
	}

	// 主路徑不變：被阻斷的指令沒送到遠端，只送了清行的 Ctrl+C
	if w := conn.written(); strings.Contains(w, "rm -rf /") {
		t.Errorf("被阻斷指令不得送往目標主機，實際寫入 %q", w)
	} else if !strings.Contains(w, "\x03") {
		t.Errorf("應送出 Ctrl+C 清行，實際寫入 %q", w)
	}
}

// TestBlockedMarkerSanitizesRuleName 規則名為 opaque 自由字串：ANSI 逸出序列與
// 控制字元不得原樣進入錄影／監看者終端（注入面）
func TestBlockedMarkerSanitizesRuleName(t *testing.T) {
	_, sink, _, clientWS := startBlockingBridge(t, "邪惡\x1b[2J規則\r\n偽造行", nil)

	sendInput(t, clientWS, "danger\r")
	readFrames(t, clientWS, 1)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && sink.String() == "" {
		time.Sleep(5 * time.Millisecond)
	}
	got := sink.String()
	if strings.Contains(got, "\x1b[2J") {
		t.Errorf("規則名的 ANSI 逸出序列未淨化: %q", got)
	}
	// 標記外殼自帶前後 CRLF，規則名內的換行則須被折掉：總計不得多於 2 個 \n
	if n := strings.Count(got, "\n"); n > 2 {
		t.Errorf("規則名的換行未折平（可偽造額外行）: %d 個換行，%q", n, got)
	}
}

// TestBlockClearFailureTerminatesSession 清行失敗＝遠端行緩衝可能殘留被阻斷
// 指令的前綴，故 fail-close 終止會話；終止原因入既有審計軌（end_reason），
// 使用者端收到碼化 MsgError 說明
func TestBlockClearFailureTerminatesSession(t *testing.T) {
	b, sink, _, clientWS := startBlockingBridge(t, "禁止關機", errors.New("broken pipe"))

	sendInput(t, clientWS, "shutdown -h now\r")

	// 幀序：先 notice（阻斷）後 error（因清行失敗中止）
	frames := readFrames(t, clientWS, 2)
	if frames[0].Type != MsgNotice || frames[0].Code != string(apierror.CodeCommandBlocked) {
		t.Errorf("第一幀 = %+v, want notice/%s", frames[0], apierror.CodeCommandBlocked)
	}
	if frames[1].Type != MsgError || frames[1].Code != string(apierror.CodeCommandBlockClearFailed) {
		t.Fatalf("第二幀 = %+v, want error/%s", frames[1], apierror.CodeCommandBlockClearFailed)
	}
	d, _ := apierror.DescriptorOf(apierror.CodeCommandBlockClearFailed)
	if frames[1].Data != d.ZhFallback {
		t.Errorf("MsgError Data = %q, want registry zh fallback %q", frames[1].Data, d.ZhFallback)
	}

	// 會話確實收線
	select {
	case <-b.stopChan:
	case <-time.After(2 * time.Second):
		t.Fatal("清行失敗後會話應被終止（stopChan 未關閉）")
	}

	// 審計軌：終止原因走既有 end_reason 欄（handler 以 CloseWithReason 落庫）
	if got := b.EndReason(); got != endReasonBlockClearFailed {
		t.Errorf("EndReason = %q, want %q", got, endReasonBlockClearFailed)
	}

	// 阻斷本身仍留在三軌旁路（會話被中止不代表阻斷不必留痕）
	if !strings.Contains(sink.String(), "["+string(apierror.CodeCommandBlocked)+"]") {
		t.Errorf("清行失敗路徑仍須寫入阻斷標記，實得 %q", sink.String())
	}
}

// TestBlockedMarkerFormatIsStable 釘住審計標準格式：錄影是不可變稽核物件，
// 格式漂移會讓既有 grep 規則與回放比對失效
func TestBlockedMarkerFormatIsStable(t *testing.T) {
	got := apierror.CommandBlockedAuditMarker("規則X")
	const want = "[RULE_COMMAND_BLOCKED] 指令命中阻斷規則「規則X」，已阻止送往目標主機"
	if got != want {
		t.Errorf("審計標記格式 = %q, want %q", got, want)
	}
}
