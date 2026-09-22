package main

import (
	"context"
	"github.com/custodexa/backend/internal/agentmcp"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mcpEndpointFixture(t *testing.T) (*gin.Engine, string, string, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old; sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}, &model.AgentToken{}, &model.AuditLog{}, &model.Session{}))
	owner := model.User{Username: "mcp-owner", Password: "!", Kind: model.KindHuman, Active: true}
	require.NoError(t, db.Create(&owner).Error)
	agent := model.User{Username: "mcp-agent", Password: "!", Kind: model.KindAgent, OwnerUserID: &owner.ID, Active: true}
	require.NoError(t, db.Create(&agent).Error)
	issued, err := identity.NewAgentTokenService(db, audit.NewTxSink()).Create(agent.ID, identity.CreateAgentTokenRequest{Name: "mcp", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: owner.ID})
	require.NoError(t, err)
	human, err := crypto.NewJWTManager("mcp-endpoint-secret", time.Hour).GenerateToken(owner.ID, owner.Username, "", model.RoleUser, crypto.AuthContext{})
	require.NoError(t, err)
	d := testDeps(false, false)
	d.authService = identity.NewAuthService("mcp-endpoint-secret", time.Hour)
	d.authService.SetEpochGateDB(db)
	d.mcp = agentmcp.NewHandler(nil)
	r := gin.New()
	registerRoutes(r, d)
	return r, issued.Token, human, db
}
func TestMCPEndpointRejectsHumanJWT(t *testing.T) {
	r, _, jwt, db := mcpEndpointFixture(t)
	for _, mode := range []string{"bearer", "cookie"} {
		t.Run(mode, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			req.Header.Set("Content-Type", "application/json")
			if mode == "bearer" {
				req.Header.Set("Authorization", "Bearer "+jwt)
			} else {
				req.AddCookie(&http.Cookie{Name: "token", Value: jwt})
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			require.Equal(t, 401, w.Code)
			require.Contains(t, w.Body.String(), `"code"`)
			var count int64
			require.NoError(t, db.Model(&model.Session{}).Count(&count).Error)
			require.Zero(t, count)
		})
	}
}

type mcpBearerTransport struct{ token string }

func (b mcpBearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	q := r.Clone(r.Context())
	q.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(q)
}
func TestMCPEndpointAcceptsAgentToken(t *testing.T) {
	r, token, _, _ := mcpEndpointFixture(t)
	srv := httptest.NewServer(r)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "endpoint-test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/api/v1/mcp", HTTPClient: &http.Client{Transport: mcpBearerTransport{token}}}, nil)
	require.NoError(t, err)
	defer cs.Close()
	result, err := cs.ListTools(ctx, nil)
	require.NoError(t, err)
	require.Len(t, result.Tools, 10)
}
