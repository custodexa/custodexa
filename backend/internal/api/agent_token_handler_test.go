package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
)

func TestAgentTokenEndpointsAuthz(t *testing.T) {
	for _, actor := range []string{"owner", "admin", "third party"} {
		t.Run(actor, func(t *testing.T) {
			db, h, owner, agent := principalAPIEnv(t)
			if err := db.AutoMigrate(&model.AgentToken{}); err != nil {
				t.Fatal(err)
			}
			service := identity.NewAgentTokenService(db, audit.NewTxSink())
			h.SetAgentTokenService(service)
			auth := identity.NewAuthService("agent-endpoint-test", time.Hour)
			auth.SetEpochGateDB(db)
			r := gin.New()
			h.RegisterRoutes(r.Group("/api/v1"), auth)
			uid := owner.ID
			role := model.RoleUser
			if actor != "owner" {
				other := model.User{Username: actor, Password: "!", Kind: model.KindHuman, Active: true}
				if err := db.Create(&other).Error; err != nil {
					t.Fatal(err)
				}
				uid = other.ID
			}
			if actor == "admin" {
				role = model.RoleAdmin
			}
			jwt, err := crypto.NewJWTManager("agent-endpoint-test", time.Hour).GenerateToken(uid, actor, "", role, crypto.AuthContext{})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := service.Create(agent.ID, identity.CreateAgentTokenRequest{Name: "seed", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
			if err != nil {
				t.Fatal(err)
			}
			base := fmt.Sprintf("/api/v1/users/%d/agent-tokens", agent.ID)
			createBody, _ := json.Marshal(identity.CreateAgentTokenRequest{Name: "new", ExpiresAt: time.Now().Add(time.Hour)})
			for _, tc := range []struct {
				method, path, body string
				status             int
			}{{"POST", base, string(createBody), 201}, {"GET", base, "", 200}, {"DELETE", fmt.Sprintf("%s/%d", base, seed.ID), `{"note":"done"}`, 204}} {
				req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+jwt)
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				want := tc.status
				if actor == "third party" {
					want = 403
				}
				if w.Code != want {
					t.Fatalf("%s: %d %s", tc.method, w.Code, w.Body)
				}
				if tc.method == "GET" && actor != "third party" {
					if strings.Contains(w.Body.String(), seed.Token) || strings.Contains(w.Body.String(), seed.TokenHash) || strings.Contains(w.Body.String(), `"token"`) {
						t.Fatal("list exposed token")
					}
					// 建立者以帳號名投影，抽屜不能只寫「建立者 #1」
					if !strings.Contains(w.Body.String(), fmt.Sprintf(`"created_by_username":%q`, owner.Username)) {
						t.Fatalf("list missing creator name: %s", w.Body)
					}
				}
			}
		})
	}
}
func TestAgentTokenRejectedOnHumanPaths(t *testing.T) {
	db, _, owner, agent := principalAPIEnv(t)
	if err := db.AutoMigrate(&model.AgentToken{}, &model.RefreshToken{}); err != nil {
		t.Fatal(err)
	}
	service := identity.NewAgentTokenService(db, audit.NewTxSink())
	token, err := service.Create(agent.ID, identity.CreateAgentTokenRequest{Name: "human-path-test", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	auth := identity.NewAuthService("human-path-test", time.Hour)
	auth.SetEpochGateDB(db)
	h := NewAuthHandler(auth, nil)
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"), auth)
	for _, path := range []string{"login", "refresh", "change-password", "mfa/verify", "mfa/enroll/setup", "mfa/enroll/confirm", "mfa/setup", "mfa/enable", "mfa/disable"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/auth/"+path, strings.NewReader(`{"username":"human","password":"Password12345"}`))
			req.Header.Set("Authorization", "Bearer "+token.Token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != 403 || !strings.Contains(w.Body.String(), "AUTH_AGENT_FORBIDDEN_ROUTE") {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("agent received cookie")
			}
		})
	}
	var count int64
	if err := db.Model(&model.RefreshToken{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("refresh issued: %d %v", count, err)
	}
}
