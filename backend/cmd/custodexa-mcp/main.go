// custodexa-mcp relays stdio tools to the Custodexa HTTP service.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	q := r.Clone(r.Context())
	q.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(q)
}

func relay(ctx context.Context, endpoint, token string, transport mcp.Transport) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("CUSTODEXA_MCP_URL must be an HTTP(S) endpoint without credentials, query or fragment")
	}
	if token == "" {
		return errors.New("CUSTODEXA_AGENT_TOKEN is required")
	}
	hc := &http.Client{Transport: bearerTransport{token, http.DefaultTransport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	upstream, err := mcp.NewClient(&mcp.Implementation{Name: "custodexa-mcp", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: hc, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return fmt.Errorf("connect to MCP service: %w", err)
	}
	defer upstream.Close()
	server := mcp.NewServer(&mcp.Implementation{Name: "custodexa-mcp", Version: "1"}, nil)
	for tool, err := range upstream.Tools(ctx, nil) {
		if err != nil {
			return fmt.Errorf("list remote tools: %w", err)
		}
		server.AddTool(tool, func(callCtx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// Each transport negotiates its own protocol; forward cancellation, not downstream session context.
			requestCtx, cancel := context.WithCancel(ctx)
			stop := context.AfterFunc(callCtx, cancel)
			defer stop()
			defer cancel()
			return upstream.CallTool(requestCtx, &mcp.CallToolParams{Name: req.Params.Name, Arguments: req.Params.Arguments})
		})
	}
	return server.Run(ctx, transport)
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	endpoint := strings.TrimSpace(os.Getenv("CUSTODEXA_MCP_URL"))
	if endpoint == "" {
		endpoint = "http://localhost:8080/api/v1/mcp"
	}
	if err := relay(ctx, endpoint, os.Getenv("CUSTODEXA_AGENT_TOKEN"), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
