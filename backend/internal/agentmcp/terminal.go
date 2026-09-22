package agentmcp

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type cachedCommand struct {
	at     time.Time
	result *mcp.CallToolResult
}
type ownedSession struct {
	owner      sessionOwner
	connection *sshproxy.InProcessSession
	op         sync.Mutex
	mu         sync.Mutex
	output     string
	base       int64
	notice     string
	malformed  bool
	notify     chan struct{}
	replies    chan map[string]any
	ended      chan struct{}
	stale      string
	staleStart int64
	cache      map[string]cachedCommand
}

func newOwnedSession(o sessionOwner, c *sshproxy.InProcessSession) *ownedSession {
	return &ownedSession{owner: o, connection: c, notify: make(chan struct{}, 1), replies: make(chan map[string]any, 128), ended: make(chan struct{}), cache: map[string]cachedCommand{}}
}
func (e *ownedSession) terminated() bool {
	select {
	case <-e.connection.Done:
		return true
	case <-e.ended:
		return true
	default:
		return false
	}
}
func (e *ownedSession) read() {
	defer close(e.ended)
	for {
		_, raw, err := e.connection.Transport.ReadMessage()
		if err != nil {
			return
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			e.mu.Lock()
			e.malformed = true
			e.mu.Unlock()
			continue
		}
		typ, _ := m["type"].(string)
		switch typ {
		case "data":
			data, _ := m["data"].(string)
			e.mu.Lock()
			e.output += data
			if len(e.output) > 1<<20 {
				cut := len(e.output) - (1 << 20)
				e.base += int64(cut)
				e.output = e.output[cut:]
			}
			e.mu.Unlock()
		case "notice", "error":
			code, _ := m["code"].(string)
			e.mu.Lock()
			e.notice = code
			e.mu.Unlock()
			fallthrough
		case "ready", "result", "unit_started", "closed":
			select {
			case e.replies <- m:
			default:
				e.connection.Transport.Close()
				return
			}
		}
		select {
		case e.notify <- struct{}{}:
		default:
		}
	}
}
func (e *ownedSession) snapshot(start int64) (string, int64, string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	index := start - e.base
	if index < 0 {
		index = 0
	}
	if index > int64(len(e.output)) {
		index = int64(len(e.output))
	}
	return e.output[index:], e.base + int64(len(e.output)), e.notice, e.malformed || start < e.base
}
func cleanOutput(s string) string {
	// Remove CSI, OSC and single-character ESC sequences, preserving transcript order.
	s = regexp.MustCompile(`\x1b\][^\x07]*(?:\x07|\x1b\\)`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]`).ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 32 && r != 127 {
			return r
		}
		return -1
	}, s)
}
func prompt(s string) bool {
	lines := strings.Split(cleanOutput(s), "\n")
	tail := lines[len(lines)-1]
	return regexp.MustCompile(`[#$>%] ?$`).MatchString(tail)
}
func inputPrompt(s string) bool {
	s = strings.ToLower(strings.TrimSpace(cleanOutput(s)))
	return strings.HasSuffix(s, "password:") || strings.HasSuffix(s, "password: ") || strings.HasSuffix(s, "[y/n]") || strings.HasSuffix(s, "(yes/no)?")
}
func (e *ownedSession) write(data string) error {
	raw, _ := sshproxy.EncodeMessage(sshproxy.MsgData, data)
	return e.connection.Transport.WriteMessage(1, raw)
}
func (e *ownedSession) operation(ctx context.Context, name string, raw json.RawMessage, now func() time.Time) *mcp.CallToolResult {
	e.op.Lock()
	defer e.op.Unlock()
	if ctx.Err() != nil {
		e.connection.Transport.Close()
		return terminatedResult()
	}
	if e.terminated() {
		return terminatedResult()
	}
	var a struct {
		Command     string `json:"command"`
		Key         string `json:"key"`
		Lines       int    `json:"lines"`
		Seconds     int    `json:"timeout_seconds"`
		Idempotency string `json:"idempotency_key"`
		SQL         string `json:"sql"`
	}
	if json.Unmarshal(raw, &a) != nil {
		return codeResult("VALIDATION_BAD_REQUEST")
	}
	console := dbconsole.Protocol(e.connection.Session.Protocol).Supported()
	switch name {
	case "read_screen":
		text, _, _, _ := e.snapshot(0)
		lines := strings.Split(cleanOutput(text), "\n")
		n := a.Lines
		if n <= 0 {
			n = 50
		}
		if n > 1000 {
			n = 1000
		}
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
		return jsonResult(map[string]any{"lines": lines})
	case "query":
		if !console {
			return codeResult("VALIDATION_BAD_REQUEST")
		}
		return e.query(ctx, a.SQL, a.Seconds)
	case "send_keys":
		if console {
			return codeResult("VALIDATION_BAD_REQUEST")
		}
		key := ""
		switch a.Key {
		case "ctrl-c":
			key = "\x03"
		case "ctrl-d":
			key = "\x04"
		case "enter":
			key = "\r"
		default:
			return codeResult("VALIDATION_BAD_REQUEST")
		}
		_, start, _, _ := e.snapshot(0)
		if e.write(key) != nil {
			return terminatedResult()
		}
		result := e.collect(ctx, start, 2*time.Second, "")
		var value map[string]any
		_ = json.Unmarshal([]byte(resultText(result)), &value)
		if value["status"] == "completed" {
			e.stale = ""
			value["reset"] = true
			value["next_action"] = "run_command"
			return jsonResult(value)
		}
		return result
	case "run_command":
		if console || a.Command == "" {
			return codeResult("VALIDATION_BAD_REQUEST")
		}
		for k, v := range e.cache {
			if now().Sub(v.at) >= 60*time.Second {
				delete(e.cache, k)
			}
		}
		if a.Idempotency != "" {
			if v, ok := e.cache[a.Idempotency]; ok {
				return v.result
			}
		}
		if a.Idempotency != "" && len(e.cache) >= 128 {
			return codeResult("RULE_MCP_IDEMPOTENCY_CAPACITY")
		}
		_, start, _, _ := e.snapshot(0)
		stale := e.stale
		if stale != "" {
			previous, _, _, _ := e.snapshot(e.staleStart)
			if prompt(previous) {
				e.stale = ""
				stale = ""
			} else {
				r := jsonResult(map[string]any{"status": "running", "output": cleanOutput(previous), "stale_output": map[string]any{"call_id": stale}, "notices": []any{}, "dispatched": false, "next_action": "observe_or_send_keys"})
				if a.Idempotency != "" {
					e.cache[a.Idempotency] = cachedCommand{at: now(), result: r}
				}
				return r
			}
		}
		e.mu.Lock()
		e.notice = ""
		e.mu.Unlock()
		if err := e.write(strings.TrimRight(a.Command, "\r\n") + "\r"); err != nil {
			return terminatedResult()
		}
		seconds := a.Seconds
		if seconds <= 0 {
			seconds = 30
		}
		if seconds > 300 {
			seconds = 300
		}
		callID := uuid.NewString()
		result := e.collect(ctx, start, time.Duration(seconds)*time.Second, stale)
		var v map[string]any
		_ = json.Unmarshal([]byte(resultText(result)), &v)
		if v["status"] == "timed_out" || v["status"] == "needs_input" {
			e.stale = callID
			e.staleStart = start
		}
		v["call_id"] = callID
		isError := result.IsError
		result = jsonResult(v)
		result.IsError = isError
		if a.Idempotency != "" {

			e.cache[a.Idempotency] = cachedCommand{at: now(), result: result}
		}
		return result
	default:
		return codeResult("VALIDATION_BAD_REQUEST")
	}
}
func (e *ownedSession) collect(ctx context.Context, start int64, timeout time.Duration, stale string) *mcp.CallToolResult {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	settle := time.NewTicker(25 * time.Millisecond)
	defer settle.Stop()
	lastSize := int64(-1)
	stable := 0
	finish := func(status, text, code string) *mcp.CallToolResult {
		v := map[string]any{"status": status, "output": cleanOutput(text), "notices": []any{}}
		if code != "" {
			v["notices"] = []any{map[string]any{"code": code}}
		}
		if code != "" {
			v["code"] = code
		}
		if stale != "" {
			v["stale_output"] = map[string]any{"call_id": stale}
		}
		if status == "needs_input" {
			v["recovery"] = map[string]any{"tool": "send_keys", "key": "ctrl-c", "automatic": false}
		}
		return jsonResult(v)
	}
	for {
		select {
		case <-ctx.Done():
			e.connection.Transport.Close()
			return terminatedResult()
		case <-e.ended:
			return terminatedResult()
		case <-timer.C:
			text, _, code, unknown := e.snapshot(start)
			if unknown {
				return finish("unknown", text, code)
			}
			if inputPrompt(text) {
				return finish("needs_input", text, "")
			}
			return finish("timed_out", text, "")
		case <-settle.C:
			text, size, code, unknown := e.snapshot(start)
			if code == "COMMAND_BLOCKED" || code == "RULE_COMMAND_BLOCKED" {
				return finish("blocked", text, code)
			}
			if unknown {
				return finish("unknown", text, code)
			}
			if size == lastSize {
				stable++
			} else {
				stable = 0
				lastSize = size
			}
			if len(text) > 0 && prompt(text) && stable >= 2 {
				return finish("completed", text, "")
			}
		}
	}
}
func (e *ownedSession) query(ctx context.Context, sql string, seconds int) *mcp.CallToolResult {
	if strings.TrimSpace(sql) == "" {
		return codeResult("VALIDATION_BAD_REQUEST")
	}
	if seconds <= 0 {
		seconds = 60
	}
	limit := int(dbconsole.StatementTimeout.Seconds())
	if seconds > limit {
		seconds = limit
	}
	raw, _ := json.Marshal(map[string]any{"type": "query", "sql": sql, "timeout_seconds": seconds})
	if e.connection.Transport.WriteMessage(1, raw) != nil {
		return terminatedResult()
	}
	results := []map[string]any{}
	batchCount := 1
	for {
		select {
		case <-ctx.Done():
			e.connection.Transport.Close()
			return terminatedResult()
		case <-e.ended:
			return terminatedResult()
		case msg := <-e.replies:
			switch msg["type"] {
			case "unit_started":
				if n, ok := msg["batch_count"].(float64); ok {
					batchCount = int(n)
				}
			case "error":
				r := jsonResult(msg)
				r.IsError = true
				return r
			case "result":
				results = append(results, msg)
				if len(results) >= batchCount {
					if len(results) == 1 {
						msg["timeout_seconds"] = seconds
						return jsonResult(msg)
					}
					return jsonResult(map[string]any{"results": results, "timeout_seconds": seconds})
				}
			}
		}
	}
}
