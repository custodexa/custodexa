package agentmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/notifycat"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func TestUnlistedAssetOpenIsIndistinguishable(t *testing.T) {
	f := newFixture(t)
	tokens := identity.NewAgentTokenService(f.db, audit.NewTxSink())
	breaker := audit.NewProbeBreaker(f.db, audit.NewTxSink(), audit.NewAlertRecorder(f.db), audit.ProbeBreakerDependencies{LockPrincipal: identity.LockProbePrincipal, Classify: authz.ClassifyAgentProbe, Trip: tokens.TripProbeBreakerInTx, Finish: func(id uint) { tokens.FinishProbeBreaker(id) }, Notify: func(uint, notifycat.Event, map[string]string) { t.Error("unexpected breaker trip") }, Limits: func() (int, int) { return 10, 300 }})
	f.h.ssh.AuthorizationService.SetAgentProbeRecorder(func(ctx context.Context, u, k, a uint, endpoint string) error {
		_, err := breaker.RecordDenied(ctx, u, k, a, endpoint)
		require.NoError(t, err)
		return err
	})
	hidden := model.Asset{Name: "hidden", Protocol: model.ProtocolSSH, Host: "ssh-test", Port: 2222, Active: true, CreatedBy: 1}
	require.NoError(t, f.db.Create(&hidden).Error)
	listed := object(t, f.invoke(t, "list_assets", map[string]any{}))["assets"].([]any)
	require.NotEmpty(t, listed)
	for _, v := range listed {
		require.NotEqualValues(t, hidden.ID, v.(map[string]any)["asset_id"])
	}
	// A nil issuer is a tripwire: any attempted grant issuance panics instead of
	// hiding a transient grant that was immediately redeemed. Both calls must
	// return normally before reaching the issuer.
	f.h.ssh.ConnectTokens = nil
	for _, id := range []uint{hidden.ID, hidden.ID + 1000} {
		r := f.invoke(t, "open_session", map[string]any{"asset_id": id, "request_id": f.task})
		require.True(t, r.IsError)
		require.Equal(t, "NOTFOUND_ASSET", object(t, r)["code"])
		var count int64
		require.NoError(t, f.db.Model(&model.Session{}).Count(&count).Error)
		require.Zero(t, count)
		require.Nil(t, f.h.ssh.ConnectTokens, "no grant issuer was invoked or installed")
	}
}

func TestToolSchemasRejectSecretProperties(t *testing.T) {
	tools := listedTools(t)
	require.Len(t, tools, 10)
	forbidden := []string{"password", "passwd", "secret", "token", "credential", "private_key", "privatekey", "api_key", "apikey", "authorization", "bearer"}
	var walk func(map[string]any, string)
	walk = func(node map[string]any, path string) {
		if node["type"] == "object" {
			require.Equal(t, false, node["additionalProperties"], path+" must reject unknown fields")
			props, ok := node["properties"].(map[string]any)
			require.True(t, ok, path)
			for name, raw := range props {
				for _, word := range forbidden {
					require.NotContains(t, strings.ToLower(name), word, path+"."+name)
				}
				child, ok := raw.(map[string]any)
				require.True(t, ok, path+"."+name)
				walk(child, path+"."+name)
			}
		}
		if item, ok := node["items"].(map[string]any); ok {
			walk(item, path+"[]")
		}
	}
	for _, tool := range tools {
		raw, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)
		var schema map[string]any
		require.NoError(t, json.Unmarshal(raw, &schema))
		walk(schema, tool.Name)
	}
}

func TestHumanWSAndMCPSessionEvidenceParity(t *testing.T) {
	f := newFixture(t)
	human := uint(1)
	require.NoError(t, f.db.Create(&model.AssetAuthorization{UserID: &human, AssetID: &f.asset, Permission: model.PermissionConnect, GrantedBy: human, Accounts: model.AccountScope{"testuser"}}).Error)
	jwt, err := crypto.NewJWTManager("mcp-test-secret", time.Hour).GenerateToken(human, "mcp-owner", "", model.RoleUser, crypto.AuthContext{})
	require.NoError(t, err)
	router := gin.New()
	router.POST("/api/v1/connect-tokens", middleware.AuthMiddleware(f.h.ssh.AuthService), f.h.ssh.HandleCreateConnectToken)
	router.GET("/api/v1/ssh", f.h.ssh.HandleSSH)
	router.POST("/api/v1/mcp", middleware.AuthMiddleware(f.h.ssh.AuthService), f.h.Handle)
	srv := httptest.NewServer(router)
	defer srv.Close()
	body, err := json.Marshal(map[string]any{"asset_id": f.asset, "account_id": f.account})
	require.NoError(t, err)
	req, err := http.NewRequest("POST", srv.URL+"/api/v1/connect-tokens", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	var grant map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&grant))
	resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode, grant)
	ticket, ok := grant["connect_token"].(string)
	require.True(t, ok, grant)
	ws, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/api/v1/ssh?connect_token="+ticket+"&cols=80&rows=24", nil)
	require.NoError(t, err)
	require.Equal(t, 101, resp.StatusCode)
	defer ws.Close()
	readPrompt := func() string {
		require.NoError(t, ws.SetReadDeadline(time.Now().Add(5*time.Second)))
		var output strings.Builder
		for {
			_, raw, err := ws.ReadMessage()
			require.NoError(t, err)
			var msg struct {
				Type string `json:"type"`
				Data string `json:"data"`
			}
			require.NoError(t, json.Unmarshal(raw, &msg))
			if msg.Type == "data" {
				output.WriteString(msg.Data)
				if prompt(output.String()) {
					return output.String()
				}
			}
		}
	}
	readPrompt()
	const command = "printf 'parity-evidence\\n'"
	frame, err := sshproxy.EncodeMessage(sshproxy.MsgData, command+"\r")
	require.NoError(t, err)
	require.NoError(t, ws.WriteMessage(websocket.TextMessage, frame))
	require.Contains(t, readPrompt(), "parity-evidence")
	require.NoError(t, ws.Close())
	var humanSession model.Session
	require.Eventually(t, func() bool {
		return f.db.Where("user_id=?", human).First(&humanSession).Error == nil && humanSession.EndTime != nil && humanSession.HasRecording
	}, 3*time.Second, 10*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "evidence-parity", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/api/v1/mcp", HTTPClient: &http.Client{Transport: bearerTransport{f.token}}}, nil)
	require.NoError(t, err)
	defer cs.Close()
	opened, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "open_session", Arguments: map[string]any{"asset_id": f.asset, "account_id": f.account, "request_id": f.task}})
	require.NoError(t, err)
	require.False(t, opened.IsError, resultText(opened))
	handle := object(t, opened)["session_handle"].(string)
	f.h.mu.Lock()
	e := f.h.sessions[handle]
	f.h.mu.Unlock()
	require.NotNil(t, e)
	t.Cleanup(func() { e.connection.Transport.Close(); <-e.connection.Done })
	require.Eventually(t, func() bool { text, _, _, _ := e.snapshot(0); return prompt(text) }, 3*time.Second, 10*time.Millisecond)
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "run_command", Arguments: map[string]any{"session_handle": handle, "command": command, "timeout_seconds": 3}})
	require.NoError(t, err)
	require.False(t, result.IsError, resultText(result))
	require.Equal(t, "completed", object(t, result)["status"])
	require.Contains(t, object(t, result)["output"], "parity-evidence")
	closed, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "close_session", Arguments: map[string]any{"session_handle": handle}})
	require.NoError(t, err)
	require.False(t, closed.IsError)
	var agentSession model.Session
	require.NoError(t, f.db.First(&agentSession, e.connection.Session.ID).Error)
	for _, sess := range []model.Session{humanSession, agentSession} {
		require.NotNil(t, sess.EndTime)
		require.True(t, sess.HasRecording)
		require.NotEqual(t, model.SessionStatusActive, sess.Status)
		raw, err := os.ReadFile(sess.RecordingPath)
		require.NoError(t, err)
		require.Contains(t, string(raw), "parity-evidence")
		// The product command-log table is session_commands (SessionCommand).
		var commands []struct{ Command string }
		require.NoError(t, f.db.Model(&model.SessionCommand{}).Select("command").Where("session_id=?", sess.ID).Find(&commands).Error)
		require.Len(t, commands, 1)
		require.Equal(t, command, commands[0].Command)
	}
	require.Equal(t, human, humanSession.UserID)
	require.Equal(t, f.agent, agentSession.UserID)
	require.Nil(t, humanSession.AgentTokenID)
	require.Equal(t, f.owner(t).Token, *agentSession.AgentTokenID)
	require.Nil(t, humanSession.AccessRequestID)
	require.Equal(t, f.task, *agentSession.AccessRequestID)
	require.Equal(t, model.KindAgent, *agentSession.ActorKind)
	require.Equal(t, human, *agentSession.OwnerUserID)
	require.Equal(t, humanSession.Protocol, agentSession.Protocol)
	require.Equal(t, humanSession.AccountID, agentSession.AccountID)
	require.Equal(t, humanSession.AssetID, agentSession.AssetID)
	shapes := []map[string]any{}
	for _, sess := range []model.Session{humanSession, agentSession} {
		raw, err := json.Marshal(sess)
		require.NoError(t, err)
		var shape map[string]any
		require.NoError(t, json.Unmarshal(raw, &shape))
		// Only actor/provenance fields may differ in presence (omitempty) or value.
		for _, key := range []string{"user_id", "actor_kind", "owner_user_id", "agent_token_id", "access_request_id", "on_behalf_of_user_id"} {
			delete(shape, key)
		}
		shapes = append(shapes, shape)
	}
	require.ElementsMatch(t, keys(shapes[0]), keys(shapes[1]))
}
