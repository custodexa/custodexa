package agentmcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func TestAgentSessionTerminationOnRevoke(t *testing.T) {
	for _, trigger := range []string{"token_revoke", "token_suspend", "principal_disable", "owner_disable", "request_revoke", "token_expiry", "item_expiry", "task_close"} {
		t.Run(trigger, func(t *testing.T) {
			f := newFixture(t)
			handle, e := f.open(t)
			require.Eventually(t, func() bool { text, _, _, _ := e.snapshot(0); return prompt(text) }, 3*time.Second, 10*time.Millisecond)
			outcome := make(chan *mcp.CallToolResult, 1)
			go func() {
				outcome <- f.invoke(t, "run_command", map[string]any{"session_handle": handle, "command": "sleep 30", "timeout_seconds": 60})
			}()
			require.Eventually(t, func() bool { text, _, _, _ := e.snapshot(0); return containsText(text, "sleep 30") }, time.Second, 10*time.Millisecond)
			pending := pendingCommandLedger(t, f, e.connection.Session.ID)
			token := f.owner(t).Token
			svc := identity.NewAgentTokenService(f.db, audit.NewTxSink())
			svc.SetSessionTerminator(f.h.ssh.SessionService)
			switch trigger {
			case "token_revoke":
				require.NoError(t, svc.Revoke(f.agent, token, "test", gatewayapi.Actor{UserID: 1}))
			case "token_suspend":
				require.NoError(t, svc.Suspend(f.agent, token, "test", gatewayapi.Actor{UserID: 1}))
			case "principal_disable", "owner_disable":
				users := identity.NewUserService(f.db, nil)
				users.SetAgentTokenService(svc)
				users.SetSessionTerminator(f.h.ssh.SessionService)
				id := f.agent
				if trigger == "owner_disable" {
					id = 1
				}
				require.NoError(t, users.UpdateStatus(id, false))
			case "request_revoke":
				_, err := f.h.requests.Revoke(1, true, "owner", f.task, "test")
				require.NoError(t, err)
			case "token_expiry":
				require.NoError(t, f.db.Model(&model.AgentToken{}).Where("id=?", token).Update("expires_at", time.Now().Add(-time.Second)).Error)
			case "item_expiry":
				require.NoError(t, f.db.Model(&model.AccessRequestItem{}).Where("id=?", f.item).Update("approved_date_start", time.Now().Add(-2*time.Hour)).Error)
			case "task_close":
				r := f.invoke(t, "close_task", map[string]any{"request_id": f.task, "report": "done"})
				require.False(t, r.IsError, resultText(r))
			}
			select {
			case r := <-outcome:
				require.Equal(t, "terminated", object(t, r)["status"])
				assertTerminatedLedger(t, f, pending.ID, r)
			case <-time.After(3 * time.Second):
				t.Fatal("in-flight command not terminated")
			}
			select {
			case <-e.connection.Done:
			case <-time.After(3 * time.Second):
				t.Fatal("upstream not closed")
			}
			require.Error(t, e.connection.Transport.WriteMessage(1, []byte("no")))
			r := e.operation(context.Background(), "read_screen", json.RawMessage(`{}`), time.Now)
			require.Equal(t, "terminated", object(t, r)["status"])
			var sess model.Session
			require.NoError(t, f.db.First(&sess, e.connection.Session.ID).Error)
			require.NotEqual(t, model.SessionStatusActive, sess.Status)
			require.NotNil(t, sess.EndTime)
			require.True(t, sess.HasRecording)
		})
	}
}
func containsText(s, part string) bool {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
func TestAgentSessionIdleLeaseNoOrphanOnDisconnect(t *testing.T) {
	f := newFixture(t)
	f.h = newHandler(f.h.ssh, 200*time.Millisecond)
	router := gin.New()
	router.POST("/api/v1/mcp", middleware.AuthMiddleware(f.h.ssh.AuthService), f.h.Handle)
	srv := httptest.NewServer(router)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "disconnect", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/api/v1/mcp", HTTPClient: &http.Client{Transport: bearerTransport{f.token}}}, nil)
	require.NoError(t, err)
	r, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "open_session", Arguments: map[string]any{"asset_id": f.asset, "account_id": f.account, "request_id": f.task}})
	require.NoError(t, err)
	require.False(t, r.IsError, resultText(r))
	handle := object(t, r)["session_handle"].(string)
	r, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "run_command", Arguments: map[string]any{"session_handle": handle, "command": "echo settlement", "timeout_seconds": 2}})
	require.NoError(t, err)
	require.False(t, r.IsError)
	_ = cs.Close() // POST-only transport detects a silent departure by SDK idle lease.
	require.Eventually(t, func() bool {
		var n int64
		f.db.Model(&model.Session{}).Where("status=?", model.SessionStatusActive).Count(&n)
		return n == 0
	}, 3*time.Second, 10*time.Millisecond)
	var sess model.Session
	require.Eventually(t, func() bool { f.db.First(&sess); return sess.HasRecording }, time.Second, 10*time.Millisecond)
	raw, err := os.ReadFile(sess.RecordingPath)
	require.NoError(t, err)
	require.Contains(t, string(raw), "settlement")
	var n int64
	f.db.Model(&model.SessionCommand{}).Where("session_id=?", sess.ID).Count(&n)
	require.Positive(t, n)
}

func TestAgentSessionRevokedTokenRejectedAtHTTP(t *testing.T) {
	f := newFixture(t)
	svc := identity.NewAgentTokenService(f.db, audit.NewTxSink())
	require.NoError(t, svc.Revoke(f.agent, f.owner(t).Token, "test", gatewayapi.Actor{UserID: 1}))
	router := gin.New()
	router.POST("/api/v1/mcp", middleware.AuthMiddleware(f.h.ssh.AuthService), f.h.Handle)
	q := httptest.NewRequest("POST", "/api/v1/mcp", nil)
	q.Header.Set("Authorization", "Bearer "+f.token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, q)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "AUTH_AGENT_TOKEN_INVALID")
	require.NotContains(t, w.Body.String(), "AUTH_AGENT_TOKEN_REVOKED")
}

// These assertions concern the persisted h.execute row, not a transport-only result.
func pendingCommandLedger(t *testing.T, f *fixture, sessionID uint) model.AgentToolCall {
	t.Helper()
	var row model.AgentToolCall
	require.NoError(t, f.db.Where("tool=? AND session_id=?", "run_command", sessionID).First(&row).Error)
	require.Equal(t, model.ToolCallPending, row.Decision)
	require.Equal(t, f.agent, row.UserID)
	require.Equal(t, f.owner(t).Token, row.AgentTokenID)
	require.NotNil(t, row.AccessRequestID)
	require.Equal(t, f.task, *row.AccessRequestID)
	require.NotNil(t, row.SessionID)
	require.Equal(t, sessionID, *row.SessionID)
	require.EqualValues(t, 1, row.OwnerUserID)
	require.Empty(t, row.ResultStatus)
	require.Empty(t, row.ResultDigest)
	require.Empty(t, row.ResultExcerpt)
	require.True(t, audit.GetAuditIntegrity().VerifyToolCall(&row))
	return row
}
func assertTerminatedLedger(t *testing.T, f *fixture, id uint, result *mcp.CallToolResult) {
	t.Helper()
	var row model.AgentToolCall
	require.NoError(t, f.db.First(&row, id).Error)
	require.Equal(t, model.ToolCallDenied, row.Decision)
	require.Equal(t, "terminated", row.ResultStatus)
	require.Equal(t, "RULE_SESSION_TERMINATED", row.DenialCode)
	require.Equal(t, f.agent, row.UserID)
	require.Equal(t, f.owner(t).Token, row.AgentTokenID)
	require.Equal(t, f.task, *row.AccessRequestID)
	require.NotNil(t, row.SessionID)
	sum := sha256.Sum256([]byte(resultText(result)))
	require.Equal(t, hex.EncodeToString(sum[:]), row.ResultDigest)
	require.Contains(t, row.ResultExcerpt, `"status":"terminated"`)
	require.True(t, audit.GetAuditIntegrity().VerifyToolCall(&row))
}

func TestAgentSessionNoOrphanOnDisconnect(t *testing.T) {
	f := newFixture(t)
	router := gin.New()
	router.POST("/api/v1/mcp", middleware.AuthMiddleware(f.h.ssh.AuthService), f.h.Handle)
	srv := httptest.NewServer(router)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "inflight-disconnect", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/api/v1/mcp", HTTPClient: &http.Client{Transport: bearerTransport{f.token}}}, nil)
	require.NoError(t, err)
	defer cs.Close()
	r, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "open_session", Arguments: map[string]any{"asset_id": f.asset, "account_id": f.account, "request_id": f.task}})
	require.NoError(t, err)
	require.False(t, r.IsError, resultText(r))
	handle := object(t, r)["session_handle"].(string)
	f.h.mu.Lock()
	e := f.h.sessions[handle]
	f.h.mu.Unlock()
	require.NotNil(t, e)
	t.Cleanup(func() { e.connection.Transport.Close(); <-e.connection.Done })
	require.Eventually(t, func() bool { text, _, _, _ := e.snapshot(0); return prompt(text) }, 3*time.Second, 10*time.Millisecond)
	callCtx, disconnect := context.WithCancel(ctx)
	outcome := make(chan error, 1)
	go func() {
		_, err := cs.CallTool(callCtx, &mcp.CallToolParams{Name: "run_command", Arguments: map[string]any{"session_handle": handle, "command": "echo settlement; sleep 30", "timeout_seconds": 60}})
		outcome <- err
	}()
	require.Eventually(t, func() bool { text, _, _, _ := e.snapshot(0); return containsText(text, "sleep 30") }, time.Second, 10*time.Millisecond)
	pending := pendingCommandLedger(t, f, e.connection.Session.ID)
	disconnect() // Cancel the active HTTP request while run_command is still in flight.
	require.Error(t, <-outcome)
	_ = cs.Close()
	select {
	case <-e.connection.Done:
	case <-time.After(3 * time.Second):
		t.Fatal("disconnected in-flight session was orphaned")
	}
	var row model.AgentToolCall
	require.NoError(t, f.db.First(&row, pending.ID).Error)
	require.Equal(t, model.ToolCallPending, row.Decision)
	require.Empty(t, row.ResultStatus)
	require.Empty(t, row.ResultDigest)
	require.Empty(t, row.ResultExcerpt)
	require.Empty(t, row.DenialCode)
	require.Equal(t, pending.UserID, row.UserID)
	require.Equal(t, pending.AgentTokenID, row.AgentTokenID)
	require.Equal(t, pending.AccessRequestID, row.AccessRequestID)
	require.Equal(t, pending.SessionID, row.SessionID)
	require.True(t, audit.GetAuditIntegrity().VerifyToolCall(&row))
	var sess model.Session
	require.NoError(t, f.db.First(&sess, e.connection.Session.ID).Error)
	require.NotEqual(t, model.SessionStatusActive, sess.Status)
	require.NotNil(t, sess.EndTime)
	require.True(t, sess.HasRecording)
	raw, err := os.ReadFile(sess.RecordingPath)
	require.NoError(t, err)
	require.Contains(t, string(raw), "settlement")
	var n int64
	require.NoError(t, f.db.Model(&model.SessionCommand{}).Where("session_id=?", sess.ID).Count(&n).Error)
	require.EqualValues(t, 1, n)
}
