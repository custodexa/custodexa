package main

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentTokenForbiddenNonMCPConnectionRoutes(t *testing.T) {
	router, token, _, _ := mcpEndpointFixture(t)
	for _, tc := range []struct{ method, path string }{{"POST", "/api/v1/connect-tokens"}, {"GET", "/api/v1/ssh"}, {"GET", "/api/v1/db-console"}, {"GET", "/api/v1/connect"}} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
			var body map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			require.Equal(t, "AUTH_AGENT_FORBIDDEN_ROUTE", body["code"])
		})
	}
}
