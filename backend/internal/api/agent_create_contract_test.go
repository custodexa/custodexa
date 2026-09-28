package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// agentCreatePayloadFixture is the exact body the admin UI sends when creating
// an agent principal. The same file is read by the frontend contract spec
// (frontend/src/components/agent/__tests__/AgentPrincipalForm.contract.spec.js),
// which asserts that the form + API client produce this body verbatim. A
// change to the UI payload therefore fails there until this file is updated,
// and updating this file re-runs the backend acceptance below.
const agentCreatePayloadFixture = "agent_create_payload.json"

func loadAgentCreatePayload(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", agentCreatePayloadFixture))
	if err != nil {
		t.Fatalf("read shared fixture: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("parse shared fixture: %v", err)
	}
	// An empty or reshaped fixture would make every case below pass vacuously.
	if payload["kind"] != model.KindAgent || payload["username"] == nil || payload["owner_user_id"] == nil {
		t.Fatalf("shared fixture lost its agent-create shape: %s", raw)
	}
	return payload
}

func postUserJSON(t *testing.T, router *gin.Engine, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/users", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	return w
}

func clonePayload(src map[string]any, overrides map[string]any, drop ...string) map[string]any {
	out := make(map[string]any, len(src)+len(overrides))
	for k, v := range src {
		out[k] = v
	}
	for _, k := range drop {
		delete(out, k)
	}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

func agentContractEnv(t *testing.T) (*gorm.DB, *gin.Engine, *model.User) {
	t.Helper()
	db, h, owner, _ := principalAPIEnv(t)
	// Human creation writes the initial password into history (positive control).
	if err := db.AutoMigrate(&model.PasswordHistory{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.Role{Name: model.RoleUser}).Error; err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/users", h.Create)
	return db, router, owner
}

func storedEmail(t *testing.T, db *gorm.DB, username string) (*string, bool) {
	t.Helper()
	var u model.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		return nil, false
	}
	return u.Email, true
}

// TestCreateAgentWithUIPayload: the admin UI body (no email) creates the agent
// and the absent email is stored as NULL, not an empty string.
func TestCreateAgentWithUIPayload(t *testing.T) {
	db, router, owner := agentContractEnv(t)
	payload := clonePayload(loadAgentCreatePayload(t), map[string]any{"owner_user_id": owner.ID})

	w := postUserJSON(t, router, payload)
	if w.Code != 201 {
		t.Fatalf("UI payload rejected: status=%d body=%s", w.Code, w.Body)
	}
	email, ok := storedEmail(t, db, payload["username"].(string))
	if !ok {
		t.Fatal("agent row not created")
	}
	want, hasEmail := payload["email"].(string)
	switch {
	case !hasEmail && email != nil:
		t.Fatalf("absent email stored as %q, want NULL", *email)
	case hasEmail && (email == nil || *email != want):
		t.Fatalf("stored email=%v want %q", email, want)
	}
}

// TestCreateTwoEmaillessAgents: NULL emails must not collide on the email
// unique index; an empty-string email would.
func TestCreateTwoEmaillessAgents(t *testing.T) {
	db, router, owner := agentContractEnv(t)
	base := loadAgentCreatePayload(t)
	for i, extra := range []map[string]any{{}, {"email": ""}} {
		name := fmt.Sprintf("emailless-agent-%d", i)
		payload := clonePayload(base, map[string]any{"owner_user_id": owner.ID, "username": name}, "email")
		for k, v := range extra {
			payload[k] = v
		}
		w := postUserJSON(t, router, payload)
		if w.Code != 201 {
			t.Fatalf("agent %d: status=%d body=%s", i, w.Code, w.Body)
		}
		email, ok := storedEmail(t, db, name)
		if !ok {
			t.Fatalf("agent %d not created", i)
		}
		if email != nil {
			t.Fatalf("agent %d email=%q, want NULL", i, *email)
		}
	}
}

// TestCreateUserEmailRulesStillEnforced: exempting agents must not loosen the
// human rule, nor skip format validation when an agent does send an email.
func TestCreateUserEmailRulesStillEnforced(t *testing.T) {
	db, router, owner := agentContractEnv(t)
	base := loadAgentCreatePayload(t)
	// Positive control: the same human body plus a valid email is accepted, so
	// the 400s below come from the email rule and not from password or roles.
	if w := postUserJSON(t, router, map[string]any{"username": "human-with-email", "password": "Password123456", "email": "human@example.test", "roles": []string{"user"}}); w.Code != 201 {
		t.Fatalf("control human rejected: status=%d body=%s", w.Code, w.Body)
	}
	cases := []struct {
		name string
		body map[string]any
	}{
		{"human without email", map[string]any{"username": "human-no-email", "password": "Password123456", "roles": []string{"user"}}},
		{"human with explicit kind, no email", map[string]any{"username": "human-kind-no-email", "kind": "human", "password": "Password123456", "roles": []string{"user"}}},
		{"human with empty email", map[string]any{"username": "human-empty-email", "password": "Password123456", "email": "", "roles": []string{"user"}}},
		{"agent with malformed email", clonePayload(base, map[string]any{"owner_user_id": owner.ID, "username": "agent-bad-email", "email": "not-an-email"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := postUserJSON(t, router, tc.body)
			if w.Code != 400 {
				t.Fatalf("status=%d want 400 body=%s", w.Code, w.Body)
			}
			if _, ok := storedEmail(t, db, tc.body["username"].(string)); ok {
				t.Fatal("rejected request created a row")
			}
		})
	}
}
