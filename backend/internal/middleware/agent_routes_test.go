package middleware

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentRouteAllowlist(t *testing.T) {
	f := newAgentAuthFixture(t)
	r := gin.New()
	r.Use(AuditLogMiddleware(newAnonAuditService()), AgentRouteAllowlist(f.auth))
	r.GET("/api/v1/assets", AuthMiddleware(f.auth), func(c *gin.Context) { c.Status(200) })
	r.DELETE("/api/v1/users/:id", func(c *gin.Context) { c.Status(204) })
	r.GET("/future-unregistered", func(c *gin.Context) { c.Status(200) })
	request := func(method, path, token string) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, path, nil)
		q.RemoteAddr = "192.0.2.8:8000"
		q.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		return w
	}
	if w := request("GET", "/api/v1/assets", f.token.Token); w.Code != 200 {
		t.Fatalf("allowed: %d %s", w.Code, w.Body)
	}
	var body string
	for _, path := range []string{"/api/v1/users/1", "/api/v1/users/999999"} {
		t.Run(path, func(t *testing.T) {
			w := request("DELETE", path, f.token.Token)
			if w.Code != 403 || !strings.Contains(w.Body.String(), "AUTH_AGENT_FORBIDDEN_ROUTE") {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if body != "" && body != w.Body.String() {
				t.Fatal("resource existence oracle")
			}
			body = w.Body.String()
		})
	}
	if w := request("GET", "/future-unregistered", f.token.Token); w.Code != 403 {
		t.Fatal("unregistered route opened")
	}
	if w := request("DELETE", "/api/v1/users/1", f.humanToken(t)); w.Code != 204 {
		t.Fatal("human no-op changed")
	}
	var rows []model.AuditLog
	if err := f.db.Where("user_id = ? AND status_code = ?", f.agent.ID, 403).Find(&rows).Error; err != nil || len(rows) != 3 {
		t.Fatalf("denial audit: %d %v", len(rows), err)
	}
	for _, row := range rows {
		if strings.Contains(row.Details, f.token.Token) || strings.Contains(row.Details, f.token.TokenHash) {
			t.Fatal("secret in audit")
		}
	}
}
