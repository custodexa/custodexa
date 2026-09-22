package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/agentmcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func TestStdioHelper(t *testing.T) {
	if os.Getenv("CUSTODEXA_STDIO_HELPER") != "1" {
		return
	}
	main()
	os.Exit(0)
}
func TestStdioClientToolParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	remote := agentmcp.NewServer(func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"status":"unknown","output":"same","masked_count":2}`}}, StructuredContent: map[string]any{"tool": req.Params.Name, "status": "unknown"}, IsError: req.Params.Name == "close_session"}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return remote }, &mcp.StreamableHTTPOptions{JSONResponse: true})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer parity-token" {
			http.Error(w, "no token", 401)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer srv.Close()
	direct, err := mcp.NewClient(&mcp.Implementation{Name: "direct", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: bearerTransport{"parity-token", http.DefaultTransport}}, DisableStandaloneSSE: true}, nil)
	require.NoError(t, err)
	defer direct.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestStdioHelper$")
	cmd.Env = append(os.Environ(), "CUSTODEXA_STDIO_HELPER=1", "CUSTODEXA_MCP_URL="+srv.URL, "CUSTODEXA_AGENT_TOKEN=parity-token")
	stdio, err := mcp.NewClient(&mcp.Implementation{Name: "stdio", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, &mcp.ClientSessionOptions{ProtocolVersion: direct.InitializeResult().ProtocolVersion})
	require.NoError(t, err)
	defer stdio.Close()
	a, err := direct.ListTools(ctx, nil)
	require.NoError(t, err)
	b, err := stdio.ListTools(ctx, nil)
	require.NoError(t, err)
	require.Len(t, a.Tools, 10)
	aj, _ := json.Marshal(a.Tools)
	bj, _ := json.Marshal(b.Tools)
	require.JSONEq(t, string(aj), string(bj))
	for _, tool := range a.Tools {
		args := map[string]any{"request_id": 1, "asset_id": 1, "items": []any{map[string]any{"asset_id": 1, "accounts": []string{"test"}}}, "reason": "parity", "duration_minutes": 1, "session_handle": "h", "command": "echo x", "key": "enter", "sql": "select 1", "report": "done"}
		// Use only fields in this tool's closed schema, retaining complete result parity.
		schemaBytes, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)
		var schema struct {
			Properties map[string]any `json:"properties"`
		}
		require.NoError(t, json.Unmarshal(schemaBytes, &schema))
		for key := range args {
			if _, ok := schema.Properties[key]; !ok {
				delete(args, key)
			}
		}
		x, err := direct.CallTool(ctx, &mcp.CallToolParams{Name: tool.Name, Arguments: args})
		require.NoError(t, err)
		require.Equal(t, tool.Name == "close_session", x.IsError, tool.Name)
		y, err := stdio.CallTool(ctx, &mcp.CallToolParams{Name: tool.Name, Arguments: args})
		require.NoError(t, err)
		xj, _ := json.Marshal(x)
		yj, _ := json.Marshal(y)
		require.JSONEq(t, string(xj), string(yj), tool.Name)
	}
}
