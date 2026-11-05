package sshproxy

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/model"
)

// ksEvent 為測試用的捕捉事件。
type ksEvent struct {
	kind, flags byte
	payload     []byte
}

// ksCapture 滿足 keystrokeAppender，記錄 tap 轉交的事件。
type ksCapture struct {
	mu     sync.Mutex
	events []ksEvent
}

func (c *ksCapture) Append(kind, flags byte, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ksEvent{kind, flags, append([]byte(nil), payload...)})
}

func (c *ksCapture) snapshot() []ksEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ksEvent(nil), c.events...)
}

func (c *ksCapture) count() int { return len(c.snapshot()) }

// 啟動一條掛了阻斷器與鍵盤紀錄 tap 的 bridge。
func startKeystrokeBridge(t *testing.T, clearErr error) (*bridge, *ksCapture, *blockingConn, *websocket.Conn) {
	t.Helper()
	serverWS, clientWS := newWSPair(t)
	conn := newBlockingConn(clearErr)
	b := newBridge(serverWS, conn, nil, nil, "", 0, 0)
	cap := &ksCapture{}
	b.attachKeystroke(newKeystrokeTap(cap))
	b.attachBlocker(newCommandBlocker(
		&alwaysBlockMatcher{rule: &model.AlertRule{Name: "r"}}, nil, 1, 2, 3, string(model.ProtocolSSH)))
	go b.pumpInput()
	t.Cleanup(b.stop)
	return b, cap, conn, clientWS
}

func TestKeystrokeBridgeTapOnlyInInputDirection(t *testing.T) {
	b := &bridge{}
	b.attachKeystroke(newKeystrokeTap(&ksCapture{}))
	require.Len(t, b.inputSinks, 1)
	require.Len(t, b.blockedSinks, 1)
	require.Len(t, b.platformSinks, 1)
	require.Empty(t, b.outputSinks, "keystroke tap must not be an output sink")
	require.Empty(t, b.resizeSinks, "keystroke tap must not be a resize sink")
}

func TestKeystrokeBridgeForwardedInputRecordedWithoutFlag(t *testing.T) {
	serverWS, clientWS := newWSPair(t)
	conn := newBlockingConn(nil)
	b := newBridge(serverWS, conn, nil, nil, "", 0, 0)
	cap := &ksCapture{}
	b.attachKeystroke(newKeystrokeTap(cap))
	go b.pumpInput()
	t.Cleanup(b.stop)

	sendInput(t, clientWS, "ls -l\r")
	sendInput(t, clientWS, "\x03\x1b[A\x00\xff")
	require.Eventually(t, func() bool { return cap.count() == 2 }, 2*time.Second, time.Millisecond)
	evs := cap.snapshot()
	require.Equal(t, []byte("ls -l\r"), evs[0].payload)
	require.Equal(t, byte(0), evs[0].flags)
	require.Equal(t, format.KindBytes, evs[0].kind)
	require.Equal(t, byte(0), evs[1].flags, "a 0x03 typed by the user is user input, not platform")
}

// 逐字鍵入：已轉送字元無旗標，最後一塊含送出鍵帶 blocked，其後平台的 0x03 帶 platform。
func TestKeystrokeBlockTypedThenEnter(t *testing.T) {
	_, cap, conn, client := startKeystrokeBridge(t, nil)
	for _, part := range []string{"ssh", " 10.0.0.9", "\r"} {
		sendInput(t, client, part)
	}
	require.Eventually(t, func() bool { return cap.count() == 4 }, 2*time.Second, time.Millisecond)
	evs := cap.snapshot()
	require.Equal(t, "ssh", string(evs[0].payload))
	require.Equal(t, byte(0), evs[0].flags)
	require.Equal(t, " 10.0.0.9", string(evs[1].payload))
	require.Equal(t, byte(0), evs[1].flags)
	require.Equal(t, "\r", string(evs[2].payload))
	require.Equal(t, format.FlagBlocked, evs[2].flags)
	require.Equal(t, []byte{0x03}, evs[3].payload)
	require.Equal(t, format.FlagPlatform, evs[3].flags)
	// 被阻斷的那一塊確實沒有轉送
	require.NotContains(t, conn.written(), "\r")
}

// 整行貼上：整行加換行是一筆 blocked，其後是平台的 0x03。
func TestKeystrokeBlockPastedLine(t *testing.T) {
	_, cap, conn, client := startKeystrokeBridge(t, nil)
	sendInput(t, client, "rm -rf /tmp/x\r")
	require.Eventually(t, func() bool { return cap.count() == 2 }, 2*time.Second, time.Millisecond)
	evs := cap.snapshot()
	require.Equal(t, "rm -rf /tmp/x\r", string(evs[0].payload))
	require.Equal(t, format.FlagBlocked, evs[0].flags)
	require.Equal(t, []byte{0x03}, evs[1].payload)
	require.Equal(t, format.FlagPlatform, evs[1].flags)
	require.NotContains(t, conn.written(), "rm -rf")
}

// 平台的 0x03 寫入失敗時不入紀錄；被阻斷的那一塊仍記為 blocked。
func TestKeystrokeBlockPlatformWriteFailureNotRecorded(t *testing.T) {
	_, cap, _, client := startKeystrokeBridge(t, errors.New("clear failed"))
	sendInput(t, client, "rm -rf /\r")
	require.Eventually(t, func() bool { return cap.count() >= 1 }, 2*time.Second, time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	evs := cap.snapshot()
	require.Len(t, evs, 1)
	require.Equal(t, format.FlagBlocked, evs[0].flags)
}

type failingDataConn struct{ *blockingConn }

func (c *failingDataConn) Write(p []byte) (int, error) { return 0, errors.New("write failed") }

// 寫入失敗的輸入不入紀錄（沒有轉送出去）。
func TestKeystrokeBridgeWriteFailureInputNotRecorded(t *testing.T) {
	serverWS, clientWS := newWSPair(t)
	conn := &failingDataConn{newBlockingConn(nil)}
	b := newBridge(serverWS, conn, nil, nil, "", 0, 0)
	cap := &ksCapture{}
	b.attachKeystroke(newKeystrokeTap(cap))
	go b.pumpInput()
	t.Cleanup(b.stop)
	sendInput(t, clientWS, "secret-looking-input\r")
	time.Sleep(100 * time.Millisecond)
	require.Zero(t, cap.count())
}

// 既有阻斷標記行為不因鍵盤紀錄旁路而改變。
func TestKeystrokeBlockDoesNotChangeBlockerMarkers(t *testing.T) {
	b, cap, _, client := startKeystrokeBridge(t, nil)
	sink := &captureSink{}
	b.outputSinks = append(b.outputSinks, sink)
	sendInput(t, client, "ssh 10.0.0.9\r")
	require.Eventually(t, func() bool { return cap.count() == 2 }, 2*time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return bytes.Contains([]byte(sink.String()), []byte("RULE_COMMAND_BLOCKED")) },
		2*time.Second, time.Millisecond)
}
