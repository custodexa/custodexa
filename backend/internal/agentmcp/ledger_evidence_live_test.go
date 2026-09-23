package agentmcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// Full MCP HTTP -> SSH bridge -> cast recording, against the compose SSH target.
func TestMCPBlockedLedgerAndRecordingEvidence(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.db.Create(&model.AlertRule{Name: "lateral test", Pattern: `^ssh 10\.0\.0\.9$`, Action: "block", Enabled: true, Severity: "high", Direction: model.DirectionInput}).Error)
	require.NoError(t, audit.GetAlertMatcher().LoadRules())
	r := gin.New()
	r.POST("/api/v1/mcp", middleware.AuthMiddleware(f.h.ssh.AuthService), f.h.Handle)
	srv := httptest.NewServer(r)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "ledger-evidence", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/api/v1/mcp", HTTPClient: &http.Client{Transport: bearerTransport{f.token}}}, nil)
	require.NoError(t, err)
	defer cs.Close()
	call := func(name string, args map[string]any) *mcp.CallToolResult {
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		require.NoError(t, err)
		return result
	}
	opened := call("open_session", map[string]any{"asset_id": f.asset, "account_id": f.account, "request_id": f.task})
	require.False(t, opened.IsError, resultText(opened))
	handle := object(t, opened)["session_handle"].(string)
	var sess model.Session
	require.NoError(t, f.db.First(&sess).Error)
	f.h.mu.Lock()
	entry := f.h.sessions[handle]
	f.h.mu.Unlock()
	require.Eventually(t, func() bool { text, _, _, _ := entry.snapshot(0); return prompt(text) }, 3*time.Second, 10*time.Millisecond)
	result := call("run_command", map[string]any{"session_handle": handle, "command": "ssh 10.0.0.9", "timeout_seconds": 3})
	require.Equal(t, "blocked", object(t, result)["status"])
	closed := call("close_session", map[string]any{"session_handle": handle})
	require.False(t, closed.IsError, resultText(closed))
	var row model.AgentToolCall
	require.NoError(t, f.db.Where("tool=?", "run_command").First(&row).Error)
	require.Equal(t, model.ToolCallDenied, row.Decision)
	require.Contains(t, row.ArgsRedacted, "ssh 10.0.0.9")
	require.NotContains(t, row.ArgsRedacted, handle)
	require.True(t, row.ArgsRetained)
	require.NoError(t, f.db.First(&sess, sess.ID).Error)
	recording, err := os.ReadFile(sess.RecordingPath)
	require.NoError(t, err)
	var playback strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(recording))
	scanner.Scan() // cast header
	for scanner.Scan() {
		var frame []json.RawMessage
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &frame))
		var text string
		require.NoError(t, json.Unmarshal(frame[2], &text))
		playback.WriteString(text)
	}
	require.NoError(t, scanner.Err())
	require.Contains(t, playback.String(), "> ssh 10.0.0.9")
	var n int64
	require.NoError(t, f.db.Model(&model.SessionCommand{}).Where("session_id=? AND command=?", sess.ID, "ssh 10.0.0.9").Count(&n).Error)
	require.Zero(t, n)
	if dir := os.Getenv("LEDGER_EVIDENCE_DIR"); dir != "" {
		require.NoError(t, os.MkdirAll(dir, 0755))
		path := filepath.Join(dir, "blocked-agent.cast")
		require.NoError(t, os.WriteFile(path, recording, 0600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "blocked-agent-playback.txt"), []byte(playback.String()), 0600))
		t.Logf("MCP HTTP real SSH: session=%d ledger=%d decision=%s recording=%s marker=> ssh 10.0.0.9", sess.ID, row.ID, row.Decision, path)
	}
}
