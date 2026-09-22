package agentmcp

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func terminalFixture(t *testing.T, respond func(string, int) string) (*ownedSession, *atomic.Int64, *sshproxy.InProcessTransport) {
	t.Helper()
	server, client := sshproxy.NewInProcessTransportPair()
	done := make(chan struct{})
	e := newOwnedSession(sessionOwner{}, &sshproxy.InProcessSession{Transport: client, Session: &model.Session{Protocol: model.ProtocolSSH}, Done: done})
	var bytes atomic.Int64
	go e.read()
	go func() {
		defer close(done)
		n := 0
		for {
			_, raw, err := server.ReadMessage()
			if err != nil {
				return
			}
			var msg map[string]any
			_ = json.Unmarshal(raw, &msg)
			data, _ := msg["data"].(string)
			bytes.Add(int64(len(data)))
			n++
			out := respond(data, n)
			if out != "" {
				frame, _ := sshproxy.EncodeMessage(sshproxy.MsgData, out)
				_ = server.WriteMessage(1, frame)
			}
		}
	}()
	t.Cleanup(func() { client.Close(); <-done; <-e.ended })
	return e, &bytes, server
}
func op(t *testing.T, e *ownedSession, name string, a any) *mcp.CallToolResult {
	t.Helper()
	b, err := json.Marshal(a)
	require.NoError(t, err)
	return e.operation(context.Background(), name, b, time.Now)
}
func TestToolRunCommandStates(t *testing.T) {
	for _, state := range []string{"completed", "timed_out", "needs_input", "blocked", "unknown"} {
		t.Run(state, func(t *testing.T) {
			command := "echo test"
			if state == "completed" {
				command = "missing-command"
			}
			var e *ownedSession
			var server *sshproxy.InProcessTransport
			e, _, server = terminalFixture(t, func(data string, n int) string {
				require.Equal(t, command+"\r", data)
				switch state {
				case "completed":
					return "sh: missing-command: not found\r\nuser$ "
				case "needs_input":
					return "Password:"
				case "blocked":
					raw, _ := sshproxy.EncodeNoticeMessage("RULE_COMMAND_BLOCKED", nil)
					_ = server.WriteMessage(1, raw)
				case "unknown":
					_ = server.WriteMessage(1, []byte("malformed"))
				}
				return ""
			})
			r := op(t, e, "run_command", map[string]any{"command": command + "\n", "timeout_seconds": 1})
			v := object(t, r)
			require.Equal(t, state, v["status"], resultText(r))
			if state == "completed" {
				require.Contains(t, v["output"], "sh: missing-command: not found")
			}
			if state == "timed_out" {
				require.ElementsMatch(t, []string{"status", "output", "call_id", "notices"}, keys(v))
			}
			if state == "blocked" {
				require.Equal(t, "RULE_COMMAND_BLOCKED", v["code"])
			}
		})
	}
}
func keys(v map[string]any) []string {
	r := []string{}
	for k := range v {
		r = append(r, k)
	}
	return r
}
func TestToolRunCommandStaleOutput(t *testing.T) {
	e, writes, server := terminalFixture(t, func(_ string, n int) string {
		if n == 1 {
			return "late-start"
		}
		return "new-only\nuser$ "
	})
	r := op(t, e, "run_command", map[string]any{"command": "slow", "timeout_seconds": 1})
	v := object(t, r)
	require.Equal(t, "timed_out", v["status"])
	first := v["call_id"]
	before := writes.Load()
	r = op(t, e, "run_command", map[string]any{"command": "next"})
	v = object(t, r)
	require.Equal(t, "running", v["status"])
	require.Equal(t, first, v["stale_output"].(map[string]any)["call_id"])
	require.Equal(t, before, writes.Load())
	raw, _ := sshproxy.EncodeMessage(sshproxy.MsgData, "late-end\nuser$ ")
	require.NoError(t, server.WriteMessage(1, raw))
	require.Eventually(t, func() bool { text, _, _, _ := e.snapshot(0); return prompt(text) }, time.Second, time.Millisecond)
	r = op(t, e, "run_command", map[string]any{"command": "next"})
	v = object(t, r)
	require.Equal(t, "completed", v["status"])
	require.NotContains(t, v, "stale_output")
	require.NotContains(t, v["output"], "late-end")
}
func TestToolRunCommandIdempotency(t *testing.T) {
	e, writes, _ := terminalFixture(t, func(_ string, _ int) string { return "answer\nuser$ " })
	now := time.Now()
	clock := func() time.Time { return now }
	raw := json.RawMessage(`{"command":"echo answer","idempotency_key":"key"}`)
	first := e.operation(context.Background(), "run_command", raw, clock)
	before := writes.Load()
	second := e.operation(context.Background(), "run_command", raw, clock)
	require.Equal(t, resultText(first), resultText(second))
	require.Equal(t, before, writes.Load())
	now = now.Add(61 * time.Second)
	e.operation(context.Background(), "run_command", raw, clock)
	require.Greater(t, writes.Load(), before)
	before = writes.Load()
	op(t, e, "run_command", map[string]any{"command": "echo answer"})
	op(t, e, "run_command", map[string]any{"command": "echo answer"})
	require.Equal(t, before+int64(2*len("echo answer\r")), writes.Load())
}
func TestToolSendKeys(t *testing.T) {
	e, writes, _ := terminalFixture(t, func(_ string, _ int) string { return "user$ " })
	r := op(t, e, "send_keys", map[string]any{"key": "ctrl-z"})
	require.True(t, r.IsError)
	require.Zero(t, writes.Load())
	for _, key := range []string{"ctrl-c", "ctrl-d", "enter"} {
		r = op(t, e, "send_keys", map[string]any{"key": key})
		require.Equal(t, true, object(t, r)["reset"])
	}
	require.EqualValues(t, 3, writes.Load())
}
func TestNeedsInputReset(t *testing.T) {
	e, writes, _ := terminalFixture(t, func(data string, _ int) string {
		switch data {
		case "sudo test\r":
			return "Password:"
		case "\x03":
			return "\nuser$ "
		default:
			return "own-output\nuser$ "
		}
	})
	r := op(t, e, "run_command", map[string]any{"command": "sudo test", "timeout_seconds": 1})
	require.Equal(t, "needs_input", object(t, r)["status"])
	require.EqualValues(t, len("sudo test\r"), writes.Load())
	before := writes.Load()
	time.Sleep(60 * time.Millisecond)
	require.Equal(t, before, writes.Load(), "no automatic reset bytes")
	r = op(t, e, "send_keys", map[string]any{"key": "ctrl-c"})
	require.Equal(t, true, object(t, r)["reset"])
	r = op(t, e, "run_command", map[string]any{"command": "echo own-output"})
	require.Contains(t, object(t, r)["output"], "own-output")
	require.NotContains(t, object(t, r)["output"], "Password:")
}
func TestToolReadScreenTranscript(t *testing.T) {
	e, _, server := terminalFixture(t, func(string, int) string { return "" })
	raw, _ := sshproxy.EncodeMessage(sshproxy.MsgData, "old\n\x1b[2J\x1b[Hnew\nlast")
	require.NoError(t, server.WriteMessage(1, raw))
	require.Eventually(t, func() bool { text, _, _, _ := e.snapshot(0); return len(text) > 0 }, time.Second, time.Millisecond)
	v := object(t, op(t, e, "read_screen", map[string]any{"lines": 10}))
	require.Equal(t, []any{"old", "new", "last"}, v["lines"])
}
func TestToolQueryTimeoutAndShape(t *testing.T) {
	for _, seconds := range []int{0, 999} {
		t.Run(string(rune('a'+seconds)), func(t *testing.T) {
			server, client := sshproxy.NewInProcessTransportPair()
			done := make(chan struct{})
			e := newOwnedSession(sessionOwner{}, &sshproxy.InProcessSession{Transport: client, Session: &model.Session{Protocol: model.ProtocolPostgres}, Done: done})
			go e.read()
			t.Cleanup(func() { client.Close(); <-e.ended })
			seen := make(chan map[string]any, 1)
			go func() {
				_, raw, _ := server.ReadMessage()
				var m map[string]any
				_ = json.Unmarshal(raw, &m)
				seen <- m
				_ = server.WriteMessage(1, []byte(`{"type":"result","event_id":"event","seq":1,"status":"ok","sets":[{"columns":["x"],"rows":[[1]]}],"rows_affected":1,"duration_ms":2,"truncated":false}`))
			}()
			r := op(t, e, "query", map[string]any{"sql": "select 1", "timeout_seconds": seconds})
			require.EqualValues(t, 60, (<-seen)["timeout_seconds"])
			v := object(t, r)
			result := v
			require.Equal(t, "ok", result["status"])
			require.Contains(t, result, "sets")
			require.Equal(t, "event", result["event_id"])
		})
	}
}
