package agentmcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestToolCallLedgerEntryRejections(t *testing.T) {
	for _, tc := range []struct {
		name, tool string
		args       map[string]any
	}{{"missing_task", "open_session", map[string]any{"asset_id": 1}}, {"missing_handle", "run_command", map[string]any{"session_handle": "missing", "command": "echo no"}}, {"nonexistent_task", "open_session", map[string]any{"asset_id": 1, "request_id": 999}}, {"foreign_task", "open_session", map[string]any{"asset_id": 1, "request_id": 2}}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.name == "foreign_task" {
				other := model.AccessRequest{RequesterID: 1, AssetID: f.asset, Status: model.AccessRequestPending, Reason: "other", RequestedDurationMinutes: 10, PendingExpiresAt: time.Now().Add(time.Hour)}
				require.NoError(t, f.db.Create(&other).Error)
			}
			router := gin.New()
			router.Use(middleware.AuditLogMiddleware(f.h.ssh.AuditService))
			router.POST("/api/v1/mcp", middleware.AuthMiddleware(f.h.ssh.AuthService), f.h.Handle)
			body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tc.tool, "arguments": tc.args}})
			q := httptest.NewRequest("POST", "/api/v1/mcp", bytes.NewReader(body))
			q.Header.Set("Authorization", "Bearer "+f.token)
			q.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, q)
			require.Equal(t, 200, w.Code)
			require.Contains(t, w.Body.String(), "isError")
			require.NoError(t, f.h.ssh.AuditService.Shutdown(context.Background()))
			var n int64
			f.db.Model(&model.AgentToolCall{}).Count(&n)
			require.Zero(t, n)
			var rows []model.AuditLog
			require.NoError(t, f.db.Where("resource=? AND path=?", model.ResourceAgentToolCall, "/api/v1/mcp").Find(&rows).Error)
			require.Len(t, rows, 1)
			require.Equal(t, f.agent, rows[0].UserID)
			require.False(t, rows[0].CreatedAt.IsZero())
			var details map[string]any
			require.NoError(t, json.Unmarshal([]byte(rows[0].Details), &details))
			require.Equal(t, tc.tool, details["tool"])
			require.NotEmpty(t, details["denial_code"])
			require.NotEmpty(t, details["occurred_at"])
			if tc.tool == "open_session" {
				var denies []model.AuditLog
				f.db.Where("details LIKE ?", "%mcp%").Find(&denies)
				require.GreaterOrEqual(t, len(denies), 1)
			}
		})
	}
}

type failingLedger struct {
	toolLedger
	begin, complete bool
	inspect         func(*model.AgentToolCall)
}

func (l failingLedger) Begin(ctx context.Context, in audit.AgentToolCallInput) (*model.AgentToolCall, error) {
	if l.begin {
		return nil, errors.New("injected ledger outage")
	}
	r, e := l.toolLedger.Begin(ctx, in)
	if e == nil && l.inspect != nil {
		l.inspect(r)
	}
	return r, e
}
func (l failingLedger) Complete(ctx context.Context, id uint, in audit.AgentToolCallResult) (*model.AgentToolCall, error) {
	if l.complete {
		return nil, context.Canceled
	}
	return l.toolLedger.Complete(ctx, id, in)
}
func TestToolCallLedgerSuccessAndDenial(t *testing.T) {
	f := newFixture(t)
	r := f.invoke(t, "list_assets", map[string]any{})
	require.False(t, r.IsError, resultText(r))
	require.NoError(t, f.db.Model(&model.AccessRequestItem{}).Where("id=?", f.item).Update("revoked_at", time.Now()).Error)
	r = f.invoke(t, "open_session", map[string]any{"asset_id": f.asset, "account_id": f.account, "request_id": f.task, "password": "DO_NOT_STORE", "connect_token": "DO_NOT_STORE"})
	require.True(t, r.IsError)
	var rows []model.AgentToolCall
	require.NoError(t, f.db.Order("id").Find(&rows).Error)
	require.Len(t, rows, 2)
	require.Equal(t, model.ToolCallAllowed, rows[0].Decision)
	require.Equal(t, model.ToolCallDenied, rows[1].Decision)
	require.NotEmpty(t, rows[1].DenialCode)
	require.NotContains(t, rows[1].ArgsRedacted, "DO_NOT_STORE")
	require.True(t, audit.GetAuditIntegrity().VerifyToolCall(&rows[1]))
}
func TestToolCallLedgerWriteFailure(t *testing.T) {
	f := newFixture(t)
	f.h.ledger = failingLedger{toolLedger: f.h.ledger, begin: true}
	r := f.invoke(t, "open_session", map[string]any{"asset_id": f.asset, "request_id": f.task})
	require.Equal(t, "INTERNAL_TOOL_LEDGER", object(t, r)["code"])
	var n int64
	f.db.Model(&model.Session{}).Count(&n)
	require.Zero(t, n)
}
func TestLedgerPendingBeforeDispatch(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete_same_row", true: "result_interrupted"}[interrupt], func(t *testing.T) {
			f := newFixture(t)
			var id uint
			f.h.ledger = failingLedger{toolLedger: f.h.ledger, complete: interrupt, inspect: func(row *model.AgentToolCall) {
				id = row.ID
				var saved model.AgentToolCall
				require.NoError(t, f.db.First(&saved, id).Error)
				require.Equal(t, model.ToolCallPending, saved.Decision)
				var n int64
				f.db.Model(&model.Session{}).Count(&n)
				require.Zero(t, n)
			}}
			r := f.invoke(t, "open_session", map[string]any{"asset_id": f.asset, "account_id": f.account, "request_id": f.task})
			var rows []model.AgentToolCall
			f.db.Find(&rows)
			require.Len(t, rows, 1)
			require.Equal(t, id, rows[0].ID)
			f.h.mu.Lock()
			entries := []*ownedSession{}
			for _, e := range f.h.sessions {
				entries = append(entries, e)
			}
			f.h.mu.Unlock()
			for _, e := range entries {
				e.connection.Transport.Close()
				<-e.connection.Done
			}
			if interrupt {
				require.Equal(t, model.ToolCallPending, rows[0].Decision)
				require.True(t, r.IsError)
			} else {
				require.False(t, r.IsError)
				require.Equal(t, model.ToolCallAllowed, rows[0].Decision)
				sum := sha256.Sum256([]byte(resultText(r)))
				require.Equal(t, hex.EncodeToString(sum[:]), rows[0].ResultDigest)
			}
		})
	}
}
func TestOutputMaskingAgentOnly(t *testing.T) {
	f := newFixture(t)
	addMaskRule(t, f)
	handle, e := f.open(t)
	require.Eventually(t, func() bool { text, _, _, _ := e.snapshot(0); return prompt(text) }, 3*time.Second, 10*time.Millisecond)
	r := f.invoke(t, "run_command", map[string]any{"session_handle": handle, "command": "printf '4111111111111111\\n'", "timeout_seconds": 3})
	require.False(t, r.IsError, resultText(r))
	require.NotContains(t, resultText(r), "4111111111111111")
	require.Contains(t, resultText(r), "REDACTED")
	var row model.AgentToolCall
	require.NoError(t, f.db.Where("tool=?", "run_command").First(&row).Error)
	require.Greater(t, row.MaskedCount, 0)
	require.NotContains(t, row.ResultExcerpt, "4111111111111111")
	sum := sha256.Sum256([]byte(resultText(r)))
	require.Equal(t, hex.EncodeToString(sum[:]), row.ResultDigest)
	require.True(t, audit.GetAuditIntegrity().VerifyToolCall(&row))
	r = f.invoke(t, "read_screen", map[string]any{"session_handle": handle})
	require.NotContains(t, resultText(r), "4111111111111111")
	f.invoke(t, "close_session", map[string]any{"session_handle": handle})
	var sess model.Session
	require.NoError(t, f.db.First(&sess, e.connection.Session.ID).Error)
	raw, err := os.ReadFile(sess.RecordingPath)
	require.NoError(t, err)
	require.Contains(t, string(raw), "4111111111111111")
	var commands []struct{ Command string }
	require.NoError(t, f.db.Model(&model.SessionCommand{}).Select("command").Where("session_id=?", sess.ID).Find(&commands).Error)
	require.NotEmpty(t, commands)
	encoded, _ := json.Marshal(commands)
	require.Contains(t, string(encoded), "4111111111111111")
	r = f.invoke(t, "close_task", map[string]any{"request_id": f.task, "report": "found 4111111111111111"})
	require.False(t, r.IsError, resultText(r))
	require.NotContains(t, resultText(r), "4111111111111111")
	var report model.AgentTaskReport
	require.NoError(t, f.db.First(&report).Error)
	require.NotContains(t, report.Body, "4111111111111111")
	row = model.AgentToolCall{}
	require.NoError(t, f.db.Where("tool=?", "close_task").First(&row).Error)
	require.Equal(t, 2, row.MaskedCount)
}

func TestToolCallLedgerMaskedCountIsSigned(t *testing.T) {
	f := newFixture(t)
	ledger := f.h.ledger
	row, err := ledger.Begin(context.Background(), audit.AgentToolCallInput{PrincipalKind: model.KindAgent, UserID: f.agent, AgentTokenID: f.owner(t).Token, OwnerUserID: 1, Tool: "list_assets", Args: map[string]any{}})
	require.NoError(t, err)
	_, err = ledger.Complete(context.Background(), row.ID, audit.AgentToolCallResult{Decision: model.ToolCallAllowed, RedactedOutput: "safe", MaskedCount: -1})
	require.Error(t, err)
	row, err = ledger.Complete(context.Background(), row.ID, audit.AgentToolCallResult{Decision: model.ToolCallAllowed, RedactedOutput: "safe", MaskedCount: 3})
	require.NoError(t, err)
	require.True(t, audit.GetAuditIntegrity().VerifyToolCall(row))
	row.MaskedCount = 2
	require.False(t, audit.GetAuditIntegrity().VerifyToolCall(row))
}
func TestOutputMaskingStructuredQuery(t *testing.T) {
	f := newFixture(t)
	addMaskRule(t, f)
	input := map[string]any{"results": []any{map[string]any{"sets": []any{map[string]any{"rows": []any{[]any{"4111111111111111", nil, 3.0}}}}}}}
	masked, count, err := redactValue(input, "postgres")
	require.NoError(t, err)
	require.Equal(t, 1, count)
	raw, err := json.Marshal(masked)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "4111111111111111")
	require.Contains(t, string(raw), "REDACTED")
	original, _ := json.Marshal(input)
	require.Contains(t, string(original), "4111111111111111")
}

func TestOutputMaskingPreservesProtocolStructure(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.db.Create(&model.AlertRule{Name: "broad custom", Pattern: ".+", Direction: model.DirectionOutput, Action: "alert", Enabled: true}).Error)
	require.NoError(t, audit.GetAlertMatcher().LoadRules())
	v, n, err := redactResult("run_command", map[string]any{"status": "completed", "output": "secret", "call_id": "opaque", "code": "RULE_COMMAND_BLOCKED"}, "ssh")
	require.NoError(t, err)
	m := v.(map[string]any)
	require.Equal(t, "completed", m["status"])
	require.Equal(t, "opaque", m["call_id"])
	require.Equal(t, "RULE_COMMAND_BLOCKED", m["code"])
	require.NotEqual(t, "secret", m["output"])
	require.Equal(t, 1, n)
	v, n, err = redactResult("query", map[string]any{"status": "ok", "sets": []any{map[string]any{"rows": []any{[]any{"private"}}, "row_count": 1}}}, "postgres")
	require.NoError(t, err)
	require.Equal(t, "ok", v.(map[string]any)["status"])
	require.Equal(t, 1, n)
}

func TestToolCloseTaskReportAndClosureAtomic(t *testing.T) {
	f := newFixture(t)
	_, err := f.h.reports.SubmitAndClose(context.Background(), f.task, gatewayapi.Actor{UserID: f.agent}, "report", func(*gorm.DB, uint, time.Time) error { return errors.New("injected close write failure") })
	require.Error(t, err)
	var n int64
	require.NoError(t, f.db.Model(&model.AgentTaskReport{}).Count(&n).Error)
	require.Zero(t, n)
	var task model.AccessRequest
	require.NoError(t, f.db.First(&task, f.task).Error)
	require.Nil(t, task.ClosedAt)
}
