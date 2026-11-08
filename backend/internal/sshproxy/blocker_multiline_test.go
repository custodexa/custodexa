package sshproxy

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
)

// containsMatcher 只在整行含 needle 時命中；prefix 為 true 時改為前綴比對。
type containsMatcher struct {
	needle string
	prefix bool
}

func (m *containsMatcher) MatchBlock(command, protocol string) (*model.AlertRule, bool) {
	hit := strings.Contains(command, m.needle)
	if m.prefix {
		hit = strings.HasPrefix(command, m.needle)
	}
	if hit {
		return &model.AlertRule{Name: "multi"}, true
	}
	return nil, false
}

func startMultiLineBridge(t *testing.T, m blockMatcher) (*blockingConn, *captureSink, func(string)) {
	t.Helper()
	serverWS, clientWS := newWSPair(t)
	conn := newBlockingConn(nil)
	b := newBridge(serverWS, conn, nil, nil, "", 0, 0)
	sink := &captureSink{}
	b.outputSinks = append(b.outputSinks, sink)
	b.attachBlocker(newCommandBlocker(m, nil, 1, 2, 3, string(model.ProtocolSSH)))
	go b.pumpInput()
	t.Cleanup(b.stop)
	return conn, sink, func(s string) { sendInput(t, clientWS, s) }
}

func waitBlocked(t *testing.T, sink *captureSink) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(sink.String(), "RULE_COMMAND_BLOCKED") }, 2*time.Second, 5*time.Millisecond, "blocked 標記未出現")
}

func waitWritten(t *testing.T, conn *blockingConn, want string) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(conn.written(), want) }, 2*time.Second, 5*time.Millisecond, "目標未收到預期內容: %q", want)
}

// 單幀多行：第一行不命中、第二行命中，整幀不得送達目標。
func TestBlockerMultiLineSingleFrame(t *testing.T) {
	conn, sink, send := startMultiLineBridge(t, &containsMatcher{needle: "cat /etc/os-release"})
	send("true\ncat /etc/os-release\n")
	waitBlocked(t, sink)
	require.NotContains(t, conn.written(), "cat /etc/os-release")
	require.NotContains(t, conn.written(), "true")
}

// 括號貼上：首行命中，標記不得使整段被當成無法判讀。
func TestBlockerMultiLineBracketedPaste(t *testing.T) {
	conn, sink, send := startMultiLineBridge(t, &containsMatcher{needle: "cat /etc/os-release"})
	send("\x1b[200~cat /etc/os-release\ntrue\n\x1b[201~")
	waitBlocked(t, sink)
	require.NotContains(t, conn.written(), "cat /etc/os-release")
}

// 括號貼上標記被拆在兩個輸入幀之間時同樣透明。
func TestBlockerMultiLineBracketedPasteSplitMarker(t *testing.T) {
	conn, sink, send := startMultiLineBridge(t, &containsMatcher{needle: "cat /etc/os-release"})
	send("\x1b[20")
	send("0~cat /etc/os-release\n")
	waitBlocked(t, sink)
	require.NotContains(t, conn.written(), "cat /etc/os-release")
}

// 殘段跨幀：第一幀含完整的安全行與一段未提交的殘段，第二幀補齊後命中。
func TestBlockerMultiLineTailAcrossFrames(t *testing.T) {
	conn, sink, send := startMultiLineBridge(t, &containsMatcher{needle: "cat /etc/os-release"})
	send("true\ncat /etc/os-")
	send("release\n")
	waitBlocked(t, sink)
	require.NotContains(t, conn.written(), "cat /etc/os-release", "目標不得收到接續後命中規則的完整命令")
}

// 回歸：單行跨幀。
func TestBlockerMultiLineSingleLineAcrossFrames(t *testing.T) {
	conn, sink, send := startMultiLineBridge(t, &containsMatcher{needle: "cat /etc/os-release"})
	send("cat /etc/os-")
	send("release\n")
	waitBlocked(t, sink)
	require.NotContains(t, conn.written(), "cat /etc/os-release")
}

// 被阻斷幀的殘段不得接續到下一幀。
func TestBlockerMultiLineBlockedTailDiscarded(t *testing.T) {
	conn, sink, send := startMultiLineBridge(t, &containsMatcher{needle: "cat", prefix: true})
	send("cat /blocked\ntrue ")
	waitBlocked(t, sink)
	first := strings.Count(sink.String(), "RULE_COMMAND_BLOCKED")
	send("cat /blocked\n")
	require.Eventually(t, func() bool { return strings.Count(sink.String(), "RULE_COMMAND_BLOCKED") > first }, 2*time.Second, 5*time.Millisecond, "第二幀未被阻斷")
	require.NotContains(t, conn.written(), "cat")
}

// 不命中的多行貼上整段照常送達。
func TestBlockerMultiLineNonMatchingPasteForwarded(t *testing.T) {
	conn, sink, send := startMultiLineBridge(t, &containsMatcher{needle: "cat /etc/os-release"})
	send("echo a\necho b\necho c\n")
	waitWritten(t, conn, "echo a\necho b\necho c\n")
	require.NotContains(t, sink.String(), "RULE_COMMAND_BLOCKED")
}

// 通知碼：單行命中沿用單行通知；一幀含多行（或命中行之後另有殘段）時改用整段未送出的通知，
// 兩者的錄影標記相同且都帶規則名。
func TestBlockerNoticeCodeSingleVersusMultiLine(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  apierror.ErrCode
	}{
		{"單行命中", "cat /etc/os-release\r", apierror.CodeCommandBlocked},
		{"多行其中一行命中", "true\ncat /etc/os-release\ntrue\n", apierror.CodeCommandBlockedMultiLine},
		{"命中行之後另有未提交殘段", "cat /etc/os-release\ntrue ", apierror.CodeCommandBlockedMultiLine},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serverWS, clientWS := newWSPair(t)
			conn := newBlockingConn(nil)
			b := newBridge(serverWS, conn, nil, nil, "", 0, 0)
			sink := &captureSink{}
			b.outputSinks = append(b.outputSinks, sink)
			b.attachBlocker(newCommandBlocker(&containsMatcher{needle: "cat /etc/os-release"}, nil, 1, 2, 3, string(model.ProtocolSSH)))
			go b.pumpInput()
			t.Cleanup(b.stop)
			sendInput(t, clientWS, tc.input)
			frames := readFrames(t, clientWS, 1)
			require.Equal(t, MsgNotice, frames[0].Type)
			require.Equal(t, string(tc.want), frames[0].Code)
			require.Equal(t, "multi", frames[0].Params["rule"])
			waitBlocked(t, sink)
			require.NotContains(t, conn.written(), "true")
		})
	}
}
