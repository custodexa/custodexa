package agentmcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// TestAgentLedgerEvidenceE2E runs the real MCP HTTP client against the dev SSH target.
// The local HTTP server uses the production handlers and an isolated SQLite test DB.
func TestAgentLedgerEvidenceE2E(t *testing.T) {
	// Env-gated like the PG parity tests: skip without the dev SSH credential,
	// but REQUIRE_INTEGRATION=1 turns the skip into a failure so CI cannot lose it silently.
	if os.Getenv("LEDGER_E2E_SSH_PASSWORD") == "" {
		if os.Getenv("REQUIRE_INTEGRATION") == "1" {
			t.Fatal("LEDGER_E2E_SSH_PASSWORD must be set when REQUIRE_INTEGRATION=1")
		}
		t.Skip("LEDGER_E2E_SSH_PASSWORD not set; dev SSH credential must arrive through the environment")
	}
	f := newFixture(t)
	require.NoError(t, f.db.Migrator().DropTable(&model.CommandAlert{}))
	// SQLite DATETIME makes the API projection scannable, as in setupAlertDB.
	require.NoError(t, f.db.Exec(`CREATE TABLE command_alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER, rule_name TEXT NOT NULL,
 session_id INTEGER NOT NULL, user_id INTEGER NOT NULL, asset_id INTEGER,
 command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
 reviewed_by INTEGER, reviewed_at DATETIME, disposition TEXT NOT NULL DEFAULT 'pending',
 note TEXT NOT NULL DEFAULT '', blocked BOOLEAN NOT NULL DEFAULT 0,
 kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT '')`).Error)
	require.NoError(t, f.db.Create(&model.AlertRule{Name: "e2e lateral", Pattern: `^ssh 10\.0\.0\.9$`, Action: "block", Enabled: true, Severity: "high", Direction: model.DirectionInput}).Error)
	addMaskRule(t, f)

	policies := policy.NewSecurityPolicyService(f.db)
	reporter := audit.NewSensitiveRevealService(policies, audit.NewAlertRecorder(f.db), nil)
	var agent, owner model.User
	require.NoError(t, f.db.First(&agent, f.agent).Error)
	require.NotNil(t, agent.OwnerUserID)
	require.NoError(t, f.db.First(&owner, *agent.OwnerUserID).Error)
	jwt, err := crypto.NewJWTManager("mcp-test-secret", time.Hour).GenerateToken(owner.ID, owner.Username, "", model.RoleAuditor, crypto.AuthContext{})
	require.NoError(t, err)
	var token model.AgentToken
	require.NoError(t, f.db.Where("user_id = ?", f.agent).First(&token).Error)
	tokenSvc := identity.NewAgentTokenService(f.db, audit.NewTxSink())
	t.Cleanup(func() {
		_, _ = policies.Update(policy.PolicyAlertOnSensitiveReveal, "false", "e2e-cleanup")
		_ = tokenSvc.Revoke(f.agent, token.ID, "e2e-cleanup", gatewayapi.Actor{UserID: owner.ID, Username: owner.Username})
	})

	router := gin.New()
	router.Use(middleware.AgentRouteAllowlist(f.h.ssh.AuthService))
	root := router.Group("/api/v1")
	router.POST("/api/v1/mcp", middleware.AuthMiddleware(f.h.ssh.AuthService), f.h.Handle)
	api.NewCommandAlertHandler(audit.NewCommandAlertService(f.db)).RegisterRoutes(root, f.h.ssh.AuthService)
	argsHandler := api.NewAuditIntegrityHandler(f.db, nil)
	argsHandler.SetToolCallArguments(audit.NewToolCallArgumentsService(f.db, f.h.ledgerCodec, audit.NewTxSink(), nil), reporter)
	argsHandler.RegisterRoutes(root, f.h.ssh.AuthService)
	srv := httptest.NewServer(router)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "ledger-be4-e2e", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/api/v1/mcp", HTTPClient: &http.Client{Transport: bearerTransport{f.token}}}, nil)
	require.NoError(t, err)
	defer cs.Close()
	call := func(name string, args map[string]any) map[string]any {
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		require.NoError(t, err)
		return object(t, result)
	}
	get := func(path string) (int, map[string]any) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+jwt)
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		var body map[string]any
		require.NoError(t, json.NewDecoder(res.Body).Decode(&body))
		return res.StatusCode, body
	}
	countAudit := func() int64 {
		var n int64
		require.NoError(t, f.db.Model(&model.AuditLog{}).Where("action = ?", model.ActionAgentToolCallArgsViewed).Count(&n).Error)
		return n
	}
	countReveal := func() int64 {
		var n int64
		require.NoError(t, f.db.Model(&model.CommandAlert{}).Where("kind = ?", model.AlertKindSensitiveReveal).Count(&n).Error)
		return n
	}
	lines := []string{
		"# Agent 工具呼叫稽核鏈端對端驗證紀錄", "",
		"執行環境：backend dev 容器內真 MCP HTTP client；SSH 對端為 dev compose ssh-test:2222。HTTP 端點由同容器 httptest server 註冊正式 handler，使用隔離測試資料庫。", "",
		"```sh", "e2e_ssh_password=$(docker compose exec -T ssh-test printenv USER_PASSWORD)", "docker compose exec -T -e LEDGER_E2E_SSH_PASSWORD=\"$e2e_ssh_password\" -e LEDGER_E2E_DIR=/app/tmp/agent-ledger-e2e backend go test ./internal/agentmcp -run '^TestAgentLedgerEvidenceE2E$' -count=1 -v", "```", "",
	}
	note := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	opened := call("open_session", map[string]any{"asset_id": f.asset, "account_id": f.account, "request_id": f.task})
	handle, ok := opened["session_handle"].(string)
	require.True(t, ok)
	var sess model.Session
	require.NoError(t, f.db.First(&sess).Error)
	note("- `MCP call_tool open_session {asset_id:%d,account_id:%d,request_id:%d}` → session_id=%d, handle 已交給同一 MCP 連線。", f.asset, f.account, f.task, sess.ID)
	f.h.mu.Lock()
	entry := f.h.sessions[handle]
	f.h.mu.Unlock()
	require.NotNil(t, entry)
	require.Eventually(t, func() bool { text, _, _, _ := entry.snapshot(0); return prompt(text) }, 3*time.Second, 10*time.Millisecond)
	blocked := call("run_command", map[string]any{"session_handle": handle, "command": "ssh 10.0.0.9", "timeout_seconds": 3})
	require.Equal(t, "blocked", blocked["status"])
	note("- `MCP call_tool run_command {command:\"ssh 10.0.0.9\",timeout_seconds:3}` → status=%v。", blocked["status"])
	var blockedRow model.AgentToolCall
	require.NoError(t, f.db.Where("tool = ? AND decision = ?", "run_command", model.ToolCallDenied).First(&blockedRow).Error)
	var blockedArgs map[string]any
	require.NoError(t, json.Unmarshal([]byte(blockedRow.ArgsRedacted), &blockedArgs))
	require.Equal(t, "ssh 10.0.0.9", blockedArgs["command"])
	require.True(t, blockedRow.ArgsRetained)
	note("- `SELECT id,decision,args_redacted,args_retained FROM agent_tool_calls WHERE id=%d` → id=%d, decision=%s, args_redacted.command=%q, args_retained=%t。", blockedRow.ID, blockedRow.ID, blockedRow.Decision, blockedArgs["command"], blockedRow.ArgsRetained)
	var blockedAlert struct {
		ID        uint
		SessionID uint
		Blocked   bool
		RuleName  string
		Command   string
	}
	require.Eventually(t, func() bool {
		return f.db.Table("command_alerts").Select("id,session_id,blocked,rule_name,command").Where("blocked = ? AND session_id = ?", true, sess.ID).Take(&blockedAlert).Error == nil
	}, 2*time.Second, 20*time.Millisecond)
	require.True(t, blockedAlert.Blocked)
	note("- `SELECT id,session_id,blocked,rule_name,command FROM command_alerts WHERE blocked=true AND session_id=%d` → id=%d, session_id=%d, blocked=%t, rule_name=%q, command=%q。", sess.ID, blockedAlert.ID, blockedAlert.SessionID, blockedAlert.Blocked, blockedAlert.RuleName, blockedAlert.Command)
	path := fmt.Sprintf("/api/v1/command-alerts?session_id=%d&blocked=true", sess.ID)
	status, body := get(path)
	require.Equal(t, 200, status, body)
	data, ok := body["data"].([]any)
	require.True(t, ok)
	require.Len(t, data, 1)
	alert := data[0].(map[string]any)
	require.EqualValues(t, blockedAlert.ID, alert["id"])
	for _, key := range []string{"session_id", "blocked", "rule_name", "command", "triggered_at"} {
		require.Contains(t, alert, key)
	}
	note("- `GET %s` → HTTP %d, total=%v, data[0].id=%v, session_id=%v, blocked=%v, rule_name=%q, command=%q, triggered_at=%v。", path, status, body["total"], alert["id"], alert["session_id"], alert["blocked"], alert["rule_name"], alert["command"], alert["triggered_at"])

	echoed := call("run_command", map[string]any{"session_handle": handle, "command": "echo 4111111111111111", "timeout_seconds": 3})
	note("- `MCP call_tool run_command {command:\"echo 4111111111111111\",timeout_seconds:3}` → status=%v。", echoed["status"])
	var cardRow model.AgentToolCall
	require.NoError(t, f.db.Where("tool = ? AND args_sealed IS NOT NULL", "run_command").Order("id DESC").First(&cardRow).Error)
	var cardArgs map[string]any
	require.NoError(t, json.Unmarshal([]byte(cardRow.ArgsRedacted), &cardArgs))
	command, ok := cardArgs["command"].(string)
	require.True(t, ok)
	require.Contains(t, command, "[REDACTED]")
	require.NotContains(t, command, "4111111111111111")
	require.GreaterOrEqual(t, cardRow.MaskedCount, 1)
	require.NotEmpty(t, cardRow.ArgsSealed)
	note("- `SELECT id,args_redacted,masked_count,args_sealed FROM agent_tool_calls WHERE id=%d` → id=%d, args_redacted.command=%q, masked_count=%d, args_sealed_nonempty=%t。", cardRow.ID, cardRow.ID, command, cardRow.MaskedCount, len(cardRow.ArgsSealed) > 0)
	closed := call("close_session", map[string]any{"session_handle": handle})
	note("- `MCP call_tool close_session` → status=%v。", closed["status"])
	require.NoError(t, f.db.First(&sess, sess.ID).Error)
	recording, err := os.ReadFile(sess.RecordingPath)
	require.NoError(t, err)
	var playback strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(recording))
	scanner.Scan()
	for scanner.Scan() {
		var frame []json.RawMessage
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &frame))
		var value string
		require.NoError(t, json.Unmarshal(frame[2], &value))
		playback.WriteString(value)
	}
	require.NoError(t, scanner.Err())
	require.Contains(t, playback.String(), "[RULE_COMMAND_BLOCKED]")
	require.Contains(t, playback.String(), "> ssh 10.0.0.9")
	note("- `grep -nE 'RULE_COMMAND_BLOCKED|> ssh 10.0.0.9' blocked-agent-playback.txt` → 含 `[RULE_COMMAND_BLOCKED]` 與 `> ssh 10.0.0.9`；原錄影=%s，證據副本=blocked-agent.cast。", filepath.Base(sess.RecordingPath))

	argumentsURL := fmt.Sprintf("/api/v1/agent-tool-calls/%d/arguments?reason=e2e", cardRow.ID)
	require.Zero(t, countAudit())
	status, body = get(argumentsURL)
	require.Equal(t, 200, status, body)
	revealed := body["data"].(map[string]any)["arguments"].(map[string]any)
	require.Equal(t, "echo 4111111111111111", revealed["command"])
	require.EqualValues(t, 1, countAudit())
	note("- `GET %s` → HTTP %d, data.arguments.command=%q；`SELECT count(*) FROM audit_logs WHERE action='agent_tool_call_args_viewed'` → %d。", argumentsURL, status, revealed["command"], countAudit())
	require.Zero(t, countReveal())
	updated, err := policies.Update(policy.PolicyAlertOnSensitiveReveal, "true", "e2e")
	require.NoError(t, err)
	require.True(t, policies.GetBool(policy.PolicyAlertOnSensitiveReveal))
	note("- `SecurityPolicyService.Update(alert_on_sensitive_reveal,true)` → previous_value=%q, current_value=true。", updated)
	status, body = get(argumentsURL)
	require.Equal(t, 200, status, body)
	require.Equal(t, "echo 4111111111111111", body["data"].(map[string]any)["arguments"].(map[string]any)["command"])
	require.EqualValues(t, 2, countAudit())
	require.EqualValues(t, 1, countReveal())
	var revealAlert struct {
		ID        uint
		Kind      string
		Command   string
		Note      string
		SessionID uint
	}
	require.NoError(t, f.db.Table("command_alerts").Select("id,kind,command,note,session_id").Where("kind = ?", model.AlertKindSensitiveReveal).Take(&revealAlert).Error)
	require.Empty(t, revealAlert.Command)
	require.Contains(t, revealAlert.Note, `"reason":"e2e"`)
	require.NotContains(t, revealAlert.Note, "4111111111111111")
	note("- `GET %s`（政策 true）→ HTTP %d, audit_view_count=%d；`SELECT id,kind,command,note,session_id FROM command_alerts WHERE kind='sensitive_reveal'` → id=%d, kind=%s, command=%q, session_id=%d, note=%s。", argumentsURL, status, countAudit(), revealAlert.ID, revealAlert.Kind, revealAlert.Command, revealAlert.SessionID, revealAlert.Note)
	updated, err = policies.Update(policy.PolicyAlertOnSensitiveReveal, "false", "e2e")
	require.NoError(t, err)
	require.False(t, policies.GetBool(policy.PolicyAlertOnSensitiveReveal))
	note("- `SecurityPolicyService.Update(alert_on_sensitive_reveal,false)` → previous_value=%q, current_value=false。", updated)
	status, body = get(argumentsURL)
	require.Equal(t, 200, status, body)
	require.EqualValues(t, 3, countAudit())
	require.EqualValues(t, 1, countReveal())
	note("- `GET %s`（政策 false）→ HTTP %d, audit_view_count=%d, sensitive_reveal_count=%d（未新增）。", argumentsURL, status, countAudit(), countReveal())
	require.NoError(t, tokenSvc.Revoke(f.agent, token.ID, "e2e completed", gatewayapi.Actor{UserID: owner.ID, Username: owner.Username}))
	require.NoError(t, f.db.First(&token, token.ID).Error)
	require.NotNil(t, token.RevokedAt)
	note("- `AgentTokenService.Revoke(user_id=%d,token_id=%d)` → revoked_at=%s。", f.agent, token.ID, token.RevokedAt.UTC().Format(time.RFC3339))
	note("- 本次識別：session_id=%d；blocked_ledger_id=%d；card_ledger_id=%d；blocked_alert_id=%d；sensitive_reveal_alert_id=%d。", sess.ID, blockedRow.ID, cardRow.ID, blockedAlert.ID, revealAlert.ID)

	if dir := os.Getenv("LEDGER_E2E_DIR"); dir != "" {
		require.NoError(t, os.MkdirAll(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "e2e-log.md"), []byte(strings.Join(lines, "\n")+"\n"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "blocked-agent.cast"), recording, 0600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "blocked-agent-playback.txt"), []byte(playback.String()), 0600))
	}
	t.Logf("e2e passed: session=%d blocked_ledger=%d card_ledger=%d blocked_alert=%d reveal_alert=%d", sess.ID, blockedRow.ID, cardRow.ID, blockedAlert.ID, revealAlert.ID)
}
