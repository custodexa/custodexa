package agentmcp

import (
	"context"
	"encoding/json"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	q := r.Clone(r.Context())
	q.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(q)
}
func TestMCPHTTPCallsOpenAndCloseSession(t *testing.T) {
	f := newFixture(t)
	r := gin.New()
	r.POST("/api/v1/mcp", middleware.AuthMiddleware(f.h.ssh.AuthService), f.h.Handle)
	srv := httptest.NewServer(r)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "integration", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/api/v1/mcp", HTTPClient: &http.Client{Transport: bearerTransport{f.token}}}, nil)
	require.NoError(t, err)
	defer cs.Close()
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "open_session", Arguments: map[string]any{"asset_id": f.asset, "account_id": f.account, "request_id": f.task, "user_id": 1, "principal_kind": "human"}})
	require.NoError(t, err)
	require.False(t, result.IsError, "%+v", result.Content)
	var output struct {
		Handle string `json:"session_handle"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &output))
	require.NotEmpty(t, output.Handle)
	var sess model.Session
	require.NoError(t, f.db.First(&sess).Error)
	require.Equal(t, f.agent, sess.UserID)
	require.NotNil(t, sess.ActorKind)
	require.Equal(t, model.KindAgent, *sess.ActorKind)
	result, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "close_session", Arguments: map[string]any{"session_handle": output.Handle}})
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.NoError(t, f.db.First(&sess, sess.ID).Error)
	require.Equal(t, model.SessionStatusClosed, sess.Status)
	require.True(t, sess.HasRecording)
}
