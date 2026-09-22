package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func validateAgentRouteRegistration(routes []goldenRoute) error {
	for _, r := range routes {
		if _, known := middleware.AgentRouteDecision(r.Method, r.Path); !known {
			return fmt.Errorf("unregistered: %s %s", r.Method, r.Path)
		}
	}
	return nil
}
func TestAgentAllowlistCoversAllRoutes(t *testing.T) {
	for _, state := range []string{"dev-auditoff", "dev-auditon", "release-auditoff", "release-auditon"} {
		t.Run(state, func(t *testing.T) {
			g := loadGolden(t, state)
			expected := map[string]bool{
				"POST /api/v1/mcp":                        true,
				"GET /api/v1/access-requests/:id/reports": true, "POST /api/v1/access-requests/:id/reports": true,
				"GET /api/v1/assets": true, "GET /api/v1/assets/tags": true, "GET /api/v1/assets/:id": true, "GET /api/v1/assets/:id/accounts": true, "GET /api/v1/assets/:id/k8s/pods": true,
				"GET /api/v1/access-requests/mine": true, "GET /api/v1/access-requests/mine/tickets": true, "POST /api/v1/access-requests": true, "POST /api/v1/access-requests/:id/cancel": true, "GET /api/v1/my/connections": true,
			}
			for _, route := range g.Routes {
				allowed, _ := middleware.AgentRouteDecision(route.Method, route.Path)
				if allowed != expected[route.Method+" "+route.Path] {
					t.Fatalf("contract category drift: %s %s", route.Method, route.Path)
				}
			}

			if err := validateAgentRouteRegistration(g.Routes); err != nil {
				t.Fatal(err)
			}
			fake := append(append([]goldenRoute{}, g.Routes...), goldenRoute{Method: "POST", Path: "/api/v1/future-unregistered"})
			if err := validateAgentRouteRegistration(fake); err == nil {
				t.Fatal("fake unregistered route must fail guard")
			}
			mode := "debug"
			if strings.HasPrefix(state, "release") {
				mode = "release"
			}
			_, chains := buildRouter(t, mode, strings.HasSuffix(state, "auditon"))
			for key, chain := range chains {
				found := false
				for _, entry := range chain {
					if strings.Contains(entry, "AgentRouteAllowlist") {
						found = true
					}
				}
				if !found {
					t.Fatalf("global agent gate absent: %v", key)
				}
			}
		})
	}
	for _, r := range []goldenRoute{{Method: "POST", Path: "/api/v1/connect-tokens"}, {Method: "GET", Path: "/api/v1/ssh"}, {Method: "GET", Path: "/api/v1/db-console"}, {Method: "GET", Path: "/api/v1/connect"}} {
		if allowed, known := middleware.AgentRouteDecision(r.Method, r.Path); allowed || !known {
			t.Fatalf("connection bypass: %+v", r)
		}
	}
}

// Exercise the real read/submit handlers after bearer authentication and the
// allowlist, so an unconditional 200 stub cannot satisfy the positive scenario.
func TestAgentAllowlistPositiveAssetsAndOwnRequests(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	previousDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previousDB })
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.AgentToken{}, &model.AuditLog{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{}, &model.AssetAuthorization{}, &model.ApproverScope{}, &model.AccessRequest{}, &model.AccessRequestItem{}, &model.AgentVisibilityExposure{}, &model.AccessRequestApproval{}, &model.AssetAccount{}, &model.Credential{}, &model.SecurityPolicy{}); err != nil {
		t.Fatal(err)
	}
	owner := model.User{Username: "positive-owner", Password: "!", Kind: model.KindHuman, Active: true}
	if err := db.Create(&owner).Error; err != nil {
		t.Fatal(err)
	}
	agent := model.User{Username: "positive-agent", Password: "!", Kind: model.KindAgent, OwnerUserID: &owner.ID, Active: true}
	if err := db.Create(&agent).Error; err != nil {
		t.Fatal(err)
	}
	segment := model.AccessPolicyApproval
	visible := model.Asset{Name: "agent-visible", Protocol: model.ProtocolSSH, Host: "192.0.2.10", Port: 22, Active: true, AccessPolicy: &segment}
	if err := db.Create(&visible).Error; err != nil {
		t.Fatal(err)
	}
	credential := model.Credential{Scope: model.CredentialScopeDedicated, Username: "app", SecretType: model.ChangeSecretTypePassword, AuthMethod: "password", ProtocolFamily: model.ProtocolFamilySSH}
	if err := db.Create(&credential).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.AssetAccount{AssetID: visible.ID, Username: "app", CredentialID: credential.ID, IsDefault: true}).Error; err != nil {
		t.Fatal(err)
	}
	grant := model.AssetAuthorization{UserID: &agent.ID, AssetID: &visible.ID, Permission: model.PermissionView, GrantedBy: owner.ID}
	if err := db.Create(&grant).Error; err != nil {
		t.Fatal(err)
	}
	tokens := identity.NewAgentTokenService(db, audit.NewTxSink())
	token, err := tokens.Create(agent.ID, identity.CreateAgentTokenRequest{Name: "positive", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	auth := identity.NewAuthService("agent-positive-test", time.Hour)
	auth.SetEpochGateDB(db)
	assets := api.NewAssetHandler(nil, authz.NewAssetAuthorizationService(db), nil)
	policies := policy.NewSecurityPolicyService(db)
	requestService := authz.NewAccessRequestService(db, policies, policy.NewAccessPolicyService(db, policies, nil), nil, nil)
	requestService.SetAccountPresenceSource(asset.RequestAccountPresent)
	requests := api.NewAccessRequestHandler(requestService, nil, db)
	r := gin.New()
	r.Use(middleware.AgentRouteAllowlist(auth))
	r.GET("/api/v1/assets", middleware.AuthMiddleware(auth), assets.List)
	requests.RegisterRoutes(r.Group("/api/v1"), auth)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, path, strings.NewReader(body))
		q.Header.Set("Authorization", "Bearer "+token.Token)
		q.Header.Set("Content-Type", "application/json")
		q.RemoteAddr = "192.0.2.8:8000"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		return w
	}
	t.Run("visible_assets_200", func(t *testing.T) {
		w := call("GET", "/api/v1/assets", "")
		if w.Code != 200 {
			t.Fatalf("assets: %d %s", w.Code, w.Body)
		}
		var body struct {
			Data []struct {
				ID uint `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data) != 1 || body.Data[0].ID != visible.ID {
			t.Fatal("visible asset missing")
		}
	})
	// The allowlist test reads only the ownership fields; item snapshots are API objects.
	type requestResponse struct {
		ID          uint `json:"id"`
		RequesterID uint `json:"requester_id"`
	}
	t.Run("create_without_accounts_400", func(t *testing.T) {
		w := call("POST", "/api/v1/access-requests", fmt.Sprintf(`{"asset_id":%d,"reason":"agent missing accounts","duration_minutes":5}`, visible.ID))
		if w.Code != 400 || !strings.Contains(w.Body.String(), "VALIDATION_AGENT_ACCOUNTS_REQUIRED") {
			t.Fatalf("create without accounts: %d %s", w.Code, w.Body)
		}
	})
	var requestID uint
	t.Run("create_request_201", func(t *testing.T) {
		w := call("POST", "/api/v1/access-requests", fmt.Sprintf(`{"asset_id":%d,"reason":"agent positive scenario","duration_minutes":5,"accounts":["app"]}`, visible.ID))
		if w.Code != 201 {
			t.Fatalf("create: %d %s", w.Code, w.Body)
		}
		var body requestResponse
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		requestID = body.ID
		if requestID == 0 || body.RequesterID != agent.ID {
			t.Fatal("agent request not created")
		}
	})
	t.Run("own_requests_200", func(t *testing.T) {
		w := call("GET", "/api/v1/access-requests/mine", "")
		if w.Code != 200 {
			t.Fatalf("mine: %d %s", w.Code, w.Body)
		}
		var body struct {
			Data []requestResponse `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data) != 1 || body.Data[0].ID != requestID || body.Data[0].RequesterID != agent.ID {
			t.Fatal("own request missing")
		}
	})
}
