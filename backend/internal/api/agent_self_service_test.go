package api

import (
	"encoding/json"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMyAgents(t *testing.T) {
	db, h, owner, _ := principalAPIEnv(t)
	if err := db.AutoMigrate(&model.SecurityPolicy{}); err != nil {
		t.Fatal(err)
	}
	policies := policy.NewSecurityPolicyService(db)
	other := model.User{Username: "other", Password: "!", Kind: model.KindHuman, Active: true}
	if err := db.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	hidden := model.User{Username: "hidden-agent", Password: "!", Kind: model.KindAgent, OwnerUserID: &other.ID, Active: true}
	if err := db.Create(&hidden).Error; err != nil {
		t.Fatal(err)
	}
	auth := identity.NewAuthService("self-service-test", time.Hour)
	auth.SetEpochGateDB(db)
	r := gin.New()
	r.Use(middleware.AgentRouteAllowlist(auth))
	h.RegisterRoutes(r.Group("/api/v1"), auth)
	jwt, err := crypto.NewJWTManager("self-service-test", time.Hour).GenerateToken(owner.ID, owner.Username, "", model.RoleUser, crypto.AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, token, body string) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, "/api/v1/my/agents", strings.NewReader(body))
		q.Header.Set("Content-Type", "application/json")
		if token != "" {
			q.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		return w
	}
	for _, method := range []string{"GET", "POST"} {
		if w := request(method, "", `{}`); w.Code != 401 {
			t.Fatalf("unauth %s: %d %s", method, w.Code, w.Body)
		}
		if w := request(method, jwt, `{}`); w.Code != 403 || !strings.Contains(w.Body.String(), "RULE_AGENT_SELF_CREATE_DISABLED") {
			t.Fatalf("disabled %s: %d %s", method, w.Code, w.Body)
		}
	}
	if _, err := policies.Update(policy.PolicyAgentSelfCreateEnabled, "true", "test"); err != nil {
		t.Fatal(err)
	}
	w := request("POST", jwt, `{"username":"my-created-agent","purpose":"nightly report","owner_user_id":999,"kind":"human","password":"attacker-secret","roles":["admin"]}`)
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var response struct{ Data model.User }
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.OwnerUserID == nil || *response.Data.OwnerUserID != owner.ID || response.Data.Kind != model.KindAgent || len(response.Data.Roles) != 0 {
		t.Fatal("body changed owner/kind/roles")
	}
	var saved model.User
	db.First(&saved, response.Data.ID)
	if saved.Password != "!" || saved.FullName != "" || saved.LocalDisplayName != nil {
		t.Fatal("body persisted credentials/purpose")
	}
	w = request("GET", jwt, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), hidden.Username) || !strings.Contains(w.Body.String(), saved.Username) || strings.Contains(w.Body.String(), "nightly report") {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if _, err := policies.Update(policy.PolicyAgentSelfCreateMaxPerOwner, "1", "test"); err != nil {
		t.Fatal(err)
	}
	if w := request("POST", jwt, `{"username":"over-quota","purpose":"test"}`); w.Code != 403 || !strings.Contains(w.Body.String(), "RULE_AGENT_SELF_CREATE_LIMIT") {
		t.Fatalf("quota %d %s", w.Code, w.Body)
	}
}
func TestAgentForbiddenMyAgents(t *testing.T) {
	db, h, owner, agent := principalAPIEnv(t)
	if err := db.AutoMigrate(&model.AgentToken{}, &model.SecurityPolicy{}); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.NewSecurityPolicyService(db).Update(policy.PolicyAgentSelfCreateEnabled, "true", "test"); err != nil {
		t.Fatal(err)
	}
	token, err := identity.NewAgentTokenService(db, audit.NewTxSink()).Create(agent.ID, identity.CreateAgentTokenRequest{Name: "forbidden-self", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	auth := identity.NewAuthService("self-agent", time.Hour)
	auth.SetEpochGateDB(db)
	r := gin.New()
	r.Use(middleware.AgentRouteAllowlist(auth))
	h.RegisterRoutes(r.Group("/api/v1"), auth)
	var before, after int64
	db.Model(&model.User{}).Count(&before)
	for _, method := range []string{"GET", "POST"} {
		q := httptest.NewRequest(method, "/api/v1/my/agents", strings.NewReader(`{"username":"nested-agent","purpose":"test"}`))
		q.Header.Set("Authorization", "Bearer "+token.Token)
		q.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		if w.Code != 403 || !strings.Contains(w.Body.String(), "AUTH_AGENT_FORBIDDEN_ROUTE") {
			t.Fatalf("%s: %d %s", method, w.Code, w.Body)
		}
	}
	db.Model(&model.User{}).Count(&after)
	if before != after {
		t.Fatal("agent request wrote user")
	}
}

// Exercise the real policy PUT handler, service and synchronous audit sink.
// Non-text policy changes keep policy/old/new in error_msg, not details.
func TestAgentSelfServicePolicyChangeAudit(t *testing.T) {
	env := newPolicyTestEnv(t)
	// The shared fixture registers read/preview endpoints only; add the real
	// update handler here without changing any existing fixture or assertion.
	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})
	handler := NewSecurityPolicyHandler(env.service, auditSvc, policy.NewComplianceService(env.service, env.repo), env.repo)
	env.router.PUT("/api/v1/security-policies", middleware.RequireRole(model.RoleAdmin), handler.Update)

	if env.service.GetBool(policy.PolicyAgentSelfCreateEnabled) || env.service.GetInt(policy.PolicyAgentSelfCreateMaxPerOwner) != 3 {
		t.Fatal("unexpected self-service factory defaults")
	}
	w := env.do(t, "PUT", "/api/v1/security-policies", model.RoleAdmin, map[string]any{
		"policies": map[string]string{
			policy.PolicyAgentSelfCreateEnabled:     "true",
			policy.PolicyAgentSelfCreateMaxPerOwner: "5",
		},
	})
	if w.Code != 200 {
		t.Fatalf("policy update HTTP=%d body=%s", w.Code, w.Body)
	}
	if !env.service.GetBool(policy.PolicyAgentSelfCreateEnabled) || env.service.GetInt(policy.PolicyAgentSelfCreateMaxPerOwner) != 5 {
		t.Fatal("successful policy update did not take effect")
	}
	var rows []model.AuditLog
	if err := env.db.Where("resource = ?", model.ResourceSecurityPolicy).Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want one persisted audit row per changed key, got %d", len(rows))
	}
	want := map[string]bool{
		"policy=agent_self_create_enabled old=false new=true": true,
		"policy=agent_self_create_max_per_owner old=3 new=5":  true,
	}
	for _, row := range rows {
		if !want[row.ErrorMsg] {
			t.Fatalf("unexpected or duplicate policy audit key/old/new: %q", row.ErrorMsg)
		}
		delete(want, row.ErrorMsg)
		if row.Action != model.ActionUpdate || row.Status != model.StatusSuccess || row.UserID != 1 || row.Username != "tester-admin" || row.Method != "PUT" || row.Path != "/api/v1/security-policies" || row.StatusCode != 200 || row.Details != "" {
			t.Fatalf("policy audit shape mismatch: %+v", row)
		}
		t.Logf("persisted audit: resource=%s action=%s error_msg=%q details=%q", row.Resource, row.Action, row.ErrorMsg, row.Details)
	}
	if len(want) != 0 {
		t.Fatalf("missing policy change audits: %v", want)
	}
}
