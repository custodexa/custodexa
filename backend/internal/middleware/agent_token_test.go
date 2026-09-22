package middleware

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type agentAuthFixture struct {
	db           *gorm.DB
	auth         *identity.AuthService
	tokens       *identity.AgentTokenService
	owner, agent model.User
	token        *identity.CreatedAgentToken
}

func newAgentAuthFixture(t *testing.T) *agentAuthFixture {
	t.Helper()
	db := installAnonAuditDB(t)
	if err := db.AutoMigrate(&model.User{}, &model.AgentToken{}); err != nil {
		t.Fatal(err)
	}
	f := &agentAuthFixture{db: db, auth: identity.NewAuthService(anonTestJWTSecret, time.Hour), tokens: identity.NewAgentTokenService(db, audit.NewTxSink())}
	f.auth.SetEpochGateDB(db)
	f.owner = model.User{Username: "owner", Password: "!", Kind: model.KindHuman, Active: true}
	if err := db.Create(&f.owner).Error; err != nil {
		t.Fatal(err)
	}
	f.agent = model.User{Username: "worker", Password: "!", Kind: model.KindAgent, OwnerUserID: &f.owner.ID, Active: true}
	if err := db.Create(&f.agent).Error; err != nil {
		t.Fatal(err)
	}
	var err error
	f.token, err = f.tokens.Create(f.agent.ID, identity.CreateAgentTokenRequest{Name: "test", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: f.owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *agentAuthFixture) router(handler gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(AuditLogMiddleware(newAnonAuditService()))
	r.GET("/assets", AuthMiddleware(f.auth), handler)
	return r
}
func agentRequest(r *gin.Engine, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/assets", nil)
	req.RemoteAddr = "192.0.2.8:8080"
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
func (f *agentAuthFixture) humanToken(t *testing.T) string {
	t.Helper()
	token, err := crypto.NewJWTManager(anonTestJWTSecret, time.Hour).GenerateToken(f.owner.ID, f.owner.Username, "owner@example.com", model.RoleAdmin, crypto.AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func TestAuthMiddlewareAgentTokenDispatch(t *testing.T) {
	f := newAgentAuthFixture(t)
	r := f.router(func(c *gin.Context) { c.Status(204) })
	for _, token := range []string{f.token.Token, f.humanToken(t)} {
		if w := agentRequest(r, token); w.Code != 204 {
			t.Fatalf("valid dispatch: %d %s", w.Code, w.Body)
		}
	}
	for _, token := range []string{"cxa_invalid", "invalid-jwt"} {
		w := agentRequest(r, token)
		want := apierror.CodeTokenInvalid
		if strings.HasPrefix(token, "cxa_") {
			want = apierror.CodeAuthAgentTokenInvalid
		}
		if w.Code != 401 || !strings.Contains(w.Body.String(), string(want)) {
			t.Fatalf("dispatch: %d %s", w.Code, w.Body)
		}
	}
}
func TestAgentTokenAuthConditions(t *testing.T) {
	var commonBody string
	reasons := map[string]string{}
	for _, which := range []string{"missing", "expired", "revoked", "suspended", "agent inactive", "owner inactive", "owner epoch", "outside CIDR", "empty CIDR"} {
		t.Run(which, func(t *testing.T) {
			f := newAgentAuthFixture(t)
			token := f.token.Token
			var err error
			switch which {
			case "missing":
				token = "cxa_nonexistent"
			case "expired":
				err = f.db.Model(&f.token.AgentToken).Update("expires_at", time.Now().Add(-time.Minute)).Error
			case "revoked":
				err = f.tokens.Revoke(f.agent.ID, f.token.ID, "test", gatewayapi.Actor{UserID: f.owner.ID})
			case "suspended":
				err = f.tokens.Suspend(f.agent.ID, f.token.ID, "test", gatewayapi.Actor{UserID: f.owner.ID})
			case "agent inactive":
				err = f.db.Model(&f.agent).Update("active", false).Error
			case "owner inactive":
				err = f.db.Model(&f.owner).Update("active", false).Error
			case "owner epoch":
				err = identity.BumpCredentialEpoch(f.db, f.owner.ID, "external_identity_unbound")
				var owner model.User
				if e := f.db.First(&owner, f.owner.ID).Error; e != nil || !owner.Active || owner.CredentialEpoch == 0 {
					t.Fatal("epoch counterexample invalid")
				}
			case "outside CIDR":
				err = f.db.Model(&f.agent).Update("allowed_cidrs", "198.51.100.0/24").Error
			}
			if err != nil {
				t.Fatal(err)
			}
			// Count actual auth SELECTs after setup; rejection audit inserts are separate.
			queries := 0
			f.db.Callback().Query().Before("gorm:query").Register("count_agent_auth", func(tx *gorm.DB) {
				if tx.Statement.Table == "t" || (tx.Statement.TableExpr != nil && strings.Contains(tx.Statement.TableExpr.SQL, "agent_tokens")) {
					queries++
				}
			})
			w := agentRequest(f.router(func(c *gin.Context) { c.Status(204) }), token)
			f.db.Callback().Query().Remove("count_agent_auth")
			if queries != 1 {
				t.Fatalf("auth fact queries=%d", queries)
			}
			if which == "empty CIDR" {
				if w.Code != 204 {
					t.Fatalf("empty CIDR: %s", w.Body)
				}
				return
			}
			if w.Code != 401 || !strings.Contains(w.Body.String(), string(apierror.CodeAuthAgentTokenInvalid)) {
				t.Fatalf("reject=%d %s", w.Code, w.Body)
			}
			if commonBody == "" {
				commonBody = w.Body.String()
			} else if w.Body.String() != commonBody {
				t.Fatal("distinguishable rejection body")
			}
			var row model.AuditLog
			if err := f.db.Where("status_code = ?", 401).Last(&row).Error; err != nil {
				t.Fatal(err)
			}
			reasons[which] = row.Details
		})
	}
	if !strings.Contains(reasons["revoked"], string(apierror.CodeAuthAgentTokenRevoked)) || !strings.Contains(reasons["suspended"], string(apierror.CodeAuthAgentTokenSuspended)) || reasons["revoked"] == reasons["suspended"] {
		t.Fatal("audit reasons did not distinguish revoke/suspend")
	}
}
func TestPrincipalKindContext(t *testing.T) {
	f := newAgentAuthFixture(t)
	for _, kind := range []string{model.KindHuman, model.KindAgent} {
		t.Run(kind, func(t *testing.T) {
			r := f.router(func(c *gin.Context) {
				got, ok := GetPrincipalKind(c)
				if !ok || got != kind {
					t.Errorf("kind=%s exists=%v", got, ok)
				}
				id, exists := GetAgentTokenID(c)
				if kind == model.KindAgent {
					uid, _ := GetCurrentUserID(c)
					if !exists || id != f.token.ID || uid != f.agent.ID || c.GetString("role") != model.RoleUser {
						t.Error("agent context")
					}
				} else if exists {
					t.Error("human has agent token ID")
				}
				c.Status(204)
			})
			token := f.token.Token
			if kind == model.KindHuman {
				token = f.humanToken(t)
			}
			if w := agentRequest(r, token); w.Code != 204 {
				t.Fatal(w.Body)
			}
		})
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if kind, ok := GetPrincipalKind(c); ok || kind == model.KindHuman {
		t.Fatal("missing became human")
	}
	if _, ok := GetAgentTokenID(c); ok {
		t.Fatal("missing token ID exists")
	}
}
func TestAgentTokenLastUsedThrottle(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "throttled", true: "write failure"}[fail], func(t *testing.T) {
			f := newAgentAuthFixture(t)
			writes := 0
			f.db.Callback().Update().Before("gorm:update").Register("count_last_used", func(tx *gorm.DB) {
				if tx.Statement.Table == "agent_tokens" {
					writes++
					if fail {
						tx.AddError(errors.New("telemetry unavailable"))
					}
				}
			})
			r := f.router(func(c *gin.Context) { c.Status(204) })
			for i := 0; i < 5; i++ {
				if w := agentRequest(r, f.token.Token); w.Code != 204 {
					t.Fatalf("telemetry denied auth: %s", w.Body)
				}
			}
			if writes == 0 {
				t.Fatal("last_used fault/measurement hook never fired")
			}
			if !fail && writes != 1 {
				t.Fatalf("writes=%d for 5 requests", writes)
			}
			f.db.Callback().Update().Remove("count_last_used")
			if !fail {
				var stored model.AgentToken
				if err := f.db.First(&stored, f.token.ID).Error; err != nil || stored.LastUsedAt == nil {
					t.Fatal("last_used missing")
				}
			}
		})
	}
}
