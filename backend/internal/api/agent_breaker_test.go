package api

import (
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBreakerRelease(t *testing.T) {
	for _, who := range []string{"owner", "admin", "other"} {
		t.Run(who, func(t *testing.T) {
			db, h, owner, agent := principalAPIEnv(t)
			db.AutoMigrate(&model.AgentToken{})
			svc := identity.NewAgentTokenService(db, audit.NewTxSink())
			h.SetAgentTokenService(svc)
			token, err := svc.Create(agent.ID, identity.CreateAgentTokenRequest{Name: "seed", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			db.Model(&model.User{}).Where("id=?", agent.ID).Update("breaker_pending_at", now)
			db.Model(&model.AgentToken{}).Where("id=?", token.ID).Update("suspended_at", now)
			uid := owner.ID
			role := model.RoleUser
			if who != "owner" {
				u := model.User{Username: who, Kind: model.KindHuman, Active: true}
				db.Create(&u)
				uid = u.ID
			}
			if who == "admin" {
				role = model.RoleAdmin
			}
			auth := identity.NewAuthService("breaker-test", time.Hour)
			auth.SetEpochGateDB(db)
			r := gin.New()
			h.RegisterRoutes(r.Group("/api/v1"), auth)
			jwt, err := crypto.NewJWTManager("breaker-test", time.Hour).GenerateToken(uid, who, "", role, crypto.AuthContext{})
			if err != nil {
				t.Fatal(err)
			}
			for _, body := range []string{`{"reason":""}`, `{"reason":"reviewed"}`} {
				req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/users/%d/agent-breaker/release", agent.ID), strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+jwt)
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				want := 204
				if body == `{"reason":""}` {
					want = 400
				}
				if who == "other" {
					want = 403
				}
				if w.Code != want {
					t.Fatal(w.Code, w.Body.String(), want)
				}
			}
			var fresh model.User
			db.First(&fresh, agent.ID)
			if (fresh.BreakerPendingAt == nil) != (who != "other") {
				t.Fatal(fresh.BreakerPendingAt)
			}
			if who != "other" {
				// 已無待處置熔斷再 release：409 且用熔斷專屬碼，不借申請單的狀態碼
				req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/users/%d/agent-breaker/release", agent.ID), strings.NewReader(`{"reason":"again"}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+jwt)
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				if w.Code != 409 || !strings.Contains(w.Body.String(), "CONFLICT_AGENT_BREAKER_NOT_PENDING") {
					t.Fatal("not pending", w.Code, w.Body.String())
				}
			}
			var saved model.AgentToken
			db.First(&saved, token.ID)
			if saved.SuspendedAt == nil {
				t.Fatal("release reenabled token")
			}
			var logs []model.AuditLog
			db.Where("resource=? AND resource_id=?", model.ResourceUser, agent.ID).Find(&logs)
			found := false
			for _, row := range logs {
				if strings.Contains(row.Details, "agent_breaker_released") {
					found = true
					if !strings.Contains(row.Details, "reviewed") {
						t.Fatal(row.Details)
					}
				}
			}
			if found != (who != "other") {
				t.Fatal("release audit", found)
			}
		})
	}
}
func TestBreakerPendingToken(t *testing.T) {
	db, h, owner, agent := principalAPIEnv(t)
	db.AutoMigrate(&model.AgentToken{})
	h.SetAgentTokenService(identity.NewAgentTokenService(db, audit.NewTxSink()))
	db.Model(&model.User{}).Where("id=?", agent.ID).Update("breaker_pending_at", time.Now())
	auth := identity.NewAuthService("breaker-test", time.Hour)
	auth.SetEpochGateDB(db)
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"), auth)
	jwt, _ := crypto.NewJWTManager("breaker-test", time.Hour).GenerateToken(owner.ID, "owner", "", model.RoleUser, crypto.AuthContext{})
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/users/%d/agent-tokens", agent.ID), strings.NewReader(fmt.Sprintf(`{"name":"blocked","expires_at":%q}`, time.Now().Add(time.Hour).Format(time.RFC3339))))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "RULE_AGENT_BREAKER_PENDING") {
		t.Fatal(w.Code, w.Body.String())
	}
}
