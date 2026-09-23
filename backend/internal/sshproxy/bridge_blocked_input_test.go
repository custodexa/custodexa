package sshproxy

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sensitivescan"
	"github.com/glebarez/sqlite"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestBlockedAgentInputRecordedAndRedacted(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.AlertRule{}))
	require.NoError(t, db.Create(&model.AlertRule{Name: "card", Pattern: sensitivescan.CardPattern, Direction: model.DirectionOutput, Enabled: true, Action: "alert"}).Error)
	matcher := audit.InitAlertMatcher(db, nil)
	require.NoError(t, matcher.LoadRules())
	t.Cleanup(func() { audit.InitAlertMatcher(nil, nil); raw, _ := db.DB(); raw.Close() })
	for _, tc := range []struct{ name, input, want string }{
		{"plain", "ssh 10.0.0.9", "  > ssh 10.0.0.9\r\n"},
		{"sensitive", "echo 4111111111111111", "  > echo [REDACTED]\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := NewInProcessTransportPair()
			conn := newBlockingConn(nil)
			b := newBridge(server, conn, nil, nil, "", 0, 0)
			sink := &captureSink{}
			b.outputSinks = []outputSink{sink}
			b.attachBlocker(newCommandBlocker(&alwaysBlockMatcher{rule: &model.AlertRule{Name: "test"}}, nil, 1, 2, 3, "ssh"))
			go b.pumpInput()
			t.Cleanup(b.stop)
			// The recorded input must be the assembled line, not merely the Enter frame.
			for _, part := range []string{tc.input[:3], tc.input[3:] + "\r"} {
				raw, err := EncodeMessage(MsgData, part)
				require.NoError(t, err)
				require.NoError(t, client.WriteMessage(websocket.TextMessage, raw))
			}
			require.Eventually(t, func() bool { return containsBlockedLine(sink.String(), tc.want) }, time.Second, time.Millisecond)
			require.NotContains(t, sink.String(), "4111111111111111")
			require.NotContains(t, conn.written(), tc.input)
		})
	}
}
func containsBlockedLine(actual, want string) bool { return strings.Contains(actual, want) }

func TestBlockedHumanMarkerUnchanged(t *testing.T) {
	_, sink, _, client := startBlockingBridge(t, "rule", nil)
	sendInput(t, client, "ssh 10.0.0.9\r")
	readFrames(t, client, 1)
	require.Eventually(t, func() bool { return strings.Contains(sink.String(), "RULE_COMMAND_BLOCKED") }, time.Second, time.Millisecond)
	require.NotContains(t, sink.String(), "  > ")
	require.NotContains(t, sink.String(), "ssh 10.0.0.9")
}

func TestBlockedAgentInputRulesUnavailable(t *testing.T) {
	audit.InitAlertMatcher(nil, nil)
	b := &bridge{blocker: &commandBlocker{protocol: "ssh"}}
	require.Equal(t, "[REDACTION_UNAVAILABLE]", b.redactBlockedInput("4111111111111111"))
}

func TestBlockedMarkerSanitizesRecordedInput(t *testing.T) {
	sink := &captureSink{}
	b := &bridge{outputSinks: []outputSink{sink}}
	b.writeBlockedMarkerToSinks("rule", "ssh host\x1b[2J\rforged\x7f")
	recorded := sink.String()
	require.Contains(t, recorded, "RULE_COMMAND_BLOCKED")
	lineStart := strings.Index(recorded, "  > ")
	require.NotEqual(t, -1, lineStart)
	inputLine := strings.TrimSuffix(recorded[lineStart:], "\r\n")
	for i := 0; i < len(inputLine); i++ {
		require.Truef(t, inputLine[i] >= 0x20 && inputLine[i] != 0x7f, "control byte at offset %d: %#x", i, inputLine[i])
	}
	require.NotContains(t, inputLine, "[2J")
}
