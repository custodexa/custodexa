package api

import (
	"fmt"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentForbiddenSurfaces(t *testing.T) {
	db, _, owner, agent := principalAPIEnv(t)
	if err := db.AutoMigrate(&model.AgentToken{}); err != nil {
		t.Fatal(err)
	}
	svc := identity.NewAgentTokenService(db, audit.NewTxSink())
	token, err := svc.Create(agent.ID, identity.CreateAgentTokenRequest{Name: "surfaces", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	auth := identity.NewAuthService("surfaces", time.Hour)
	auth.SetEpochGateDB(db)
	surfaces := []struct{ method, path string }{{"POST", "/api/v1/access-requests/break-glass"}, {"POST", "/api/v1/auth/change-password"}, {"POST", "/api/v1/policy-groups"}, {"POST", "/api/v1/authorizations"}, {"POST", "/api/v1/users"}, {"POST", "/api/v1/user-groups"}, {"POST", "/api/v1/users/:id/agent-tokens"}, {"POST", "/api/v1/connect-tokens"}, {"GET", "/api/v1/ssh"}, {"GET", "/api/v1/db-console"}, {"GET", "/api/v1/connect"}}
	r := gin.New()
	r.Use(middleware.AgentRouteAllowlist(auth))
	for _, tc := range surfaces {
		r.Handle(tc.method, tc.path, func(c *gin.Context) { t.Error("forbidden handler reached"); c.Status(200) })
	}
	for _, tc := range surfaces {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			q := httptest.NewRequest(tc.method, strings.ReplaceAll(tc.path, ":id", fmt.Sprint(agent.ID)), nil)
			q.Header.Set("Authorization", "Bearer "+token.Token)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, q)
			if w.Code != 403 || !strings.Contains(w.Body.String(), "AUTH_AGENT_FORBIDDEN_ROUTE") {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
}

type agentE2ERegistry struct{ closed map[uint]bool }

func (r *agentE2ERegistry) Close(id uint) error { r.closed[id] = true; return nil }
func TestAgentPrincipalEndToEnd(t *testing.T) {
	for _, event := range []string{"revoke", "owner inactive", "owner epoch"} {
		t.Run(event, func(t *testing.T) {
			db, h, owner, agent := principalAPIEnv(t)
			if err := db.AutoMigrate(&model.AgentToken{}, &model.Session{}, &model.RefreshToken{}, &model.AccessRequest{}, &model.AccessRequestItem{}); err != nil {
				t.Fatal(err)
			}
			old := database.DB
			database.DB = db
			t.Cleanup(func() { database.DB = old })
			registry := &agentE2ERegistry{closed: map[uint]bool{}}
			sessions := session.NewSessionService(registry)
			sessions.SetAuditSink(audit.NewTxSink())
			sessions.SetAgentActorSource(func(tx *gorm.DB, row *model.Session) error {
				if err := identity.BindAgentSessionPrincipal(tx, row); err != nil {
					return err
				}
				return authz.BindAgentSessionTask(tx, row)
			})
			task := model.AccessRequest{RequesterID: owner.ID, ExecutorUserID: &agent.ID, AssetID: 1, Reason: "fixture", RequestedDurationMinutes: 30, Status: model.AccessRequestPending, PendingExpiresAt: time.Now().Add(time.Hour)}
			if err := db.Create(&task).Error; err != nil {
				t.Fatal(err)
			}
			tokens := identity.NewAgentTokenService(db, audit.NewTxSink())
			tokens.SetSessionTerminator(sessions)
			h.SetAgentTokenService(tokens)
			users := identity.NewUserService(db, nil)
			users.SetAgentTokenService(tokens)
			users.SetSessionTerminator(sessions)
			auth := identity.NewAuthService("e2e-agent", time.Hour)
			auth.SetEpochGateDB(db)
			token, err := tokens.Create(agent.ID, identity.CreateAgentTokenRequest{Name: "e2e", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
			if err != nil {
				t.Fatal(err)
			}
			r := gin.New()
			r.Use(middleware.AgentRouteAllowlist(auth))
			r.GET("/api/v1/assets", middleware.AuthMiddleware(auth), func(c *gin.Context) { c.JSON(200, gin.H{"data": []any{}}) })
			for _, p := range []string{"/api/v1/ssh", "/api/v1/db-console", "/api/v1/connect"} {
				r.GET(p, func(c *gin.Context) { t.Error("connection handler reached") })
			}
			r.POST("/api/v1/connect-tokens", func(c *gin.Context) { t.Error("grant handler reached") })
			request := func(method, path string) *httptest.ResponseRecorder {
				q := httptest.NewRequest(method, path, nil)
				q.Header.Set("Authorization", "Bearer "+token.Token)
				w := httptest.NewRecorder()
				r.ServeHTTP(w, q)
				return w
			}
			for _, p := range []string{"/api/v1/ssh", "/api/v1/db-console", "/api/v1/connect", "/api/v1/connect-tokens"} {
				method := "GET"
				if strings.HasSuffix(p, "tokens") {
					method = "POST"
				}
				if w := request(method, p); w.Code != 403 {
					t.Fatalf("bypass: %d", w.Code)
				}
			}
			if w := request("GET", "/api/v1/assets"); w.Code != 200 {
				t.Fatalf("allowed: %d %s", w.Code, w.Body)
			}
			row := model.Session{AccessRequestID: &task.ID, UserID: agent.ID, AgentTokenID: &token.ID, Protocol: model.ProtocolSSH}
			if err := sessions.Create(&row); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			switch event {
			case "revoke":
				err = tokens.Revoke(agent.ID, token.ID, "e2e", gatewayapi.Actor{UserID: owner.ID})
			case "owner inactive":
				err = users.UpdateStatus(owner.ID, false)
			case "owner epoch":
				link := model.UserExternalIdentity{UserID: owner.ID, ProviderID: 1, Issuer: "https://id.example.test", ClientID: "app", Subject: "human"}
				if e := db.Create(&link).Error; e != nil {
					t.Fatal(e)
				}
				err = users.UnbindExternalIdentity(owner.ID, link.ID, identity.IdentityAdminActor{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(started) > 3*time.Second {
				t.Fatal("termination exceeded target")
			}
			var saved model.Session
			if err := db.First(&saved, row.ID).Error; err != nil || saved.Status != model.SessionStatusDisconnected || !registry.closed[row.ID] {
				t.Fatalf("not physically closed: %+v %v", saved, err)
			}
			if w := request("GET", "/api/v1/assets"); w.Code != 401 || !strings.Contains(w.Body.String(), "AUTH_AGENT_TOKEN_INVALID") {
				t.Fatalf("invalid token accepted after %s: %d %s", event, w.Code, w.Body)
			}
			action := model.ActionAgentTokenRevoked
			if event != "revoke" {
				action = model.ActionAgentTokenSuspended
			}
			for _, a := range []model.AuditAction{model.ActionCreate, action, model.ActionAgentSessionsTerminated} {
				var n int64
				if err := db.Model(&model.AuditLog{}).Where("resource = ? AND action = ?", model.ResourceAgentToken, a).Count(&n).Error; err != nil || n < 1 {
					t.Fatalf("missing audit %s: %v", a, err)
				}
			}
		})
	}
}
