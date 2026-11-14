package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
)

// API token 全域閘門接在正式的路由註冊函式上：公開路由、WebSocket 入口、需登入路由與查無的路徑都經過閘門；
// 封印期的回應由封印閘決定；無效 token 回 401；有效 token 打登錄為開放的路由時由閘門放行（之後照端點本身的權限判定），
// 打不開放、未登錄或查無的路由回 403。

const apiTokenGateStableName = "github.com/custodexa/backend/internal/middleware.(*apiTokenGate).Handle-fm"

type apiTokenGateEvents struct{}

func (apiTokenGateEvents) APITokenCreated(*gorm.DB, identity.APITokenCreatedEvent) error { return nil }
func (apiTokenGateEvents) APITokenRevoked(*gorm.DB, identity.APITokenRevokedEvent) error { return nil }

type apiTokenRouteFixture struct {
	db      *gorm.DB
	deps    routeDeps
	token   string
	revoked string
	human   string
}

func newAPITokenRouteFixture(t *testing.T) *apiTokenRouteFixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old; _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.AuditLog{}, &model.UserGroup{}, &model.AssetGroup{},
		&model.AssetAuthorization{}, &model.RolePermission{}, &model.APIToken{}, &model.APITokenRole{}))
	require.NoError(t, db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}))
	k := model.BuiltinIdentityAdmin
	role := model.Role{Name: "identity_admin", BuiltinKey: &k, DefinitionVersion: 1}
	require.NoError(t, db.Create(&role).Error)
	owner := model.User{Username: "token-owner", Password: "!", Kind: model.KindHuman, Active: true}
	require.NoError(t, db.Create(&owner).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: owner.ID, RoleID: role.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)

	tokens := identity.NewAPITokenService(db, apiTokenGateEvents{})
	op := identity.Operator{UserID: owner.ID, Username: owner.Username,
		Principal: authz.NewPrincipal(owner.ID, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)}
	valid, err := tokens.Create(op, identity.CreateAPITokenInput{Name: "terraform", RoleIDs: []uint{role.ID}, NeverExpires: true})
	require.NoError(t, err)
	gone, err := tokens.Create(op, identity.CreateAPITokenInput{Name: "gone", RoleIDs: []uint{role.ID}, NeverExpires: true})
	require.NoError(t, err)
	require.NoError(t, tokens.RevokeOwn(op, gone.View.ID, ""))
	human, err := crypto.NewJWTManager("api-token-gate-secret", time.Hour).GenerateToken(owner.ID, owner.Username, "", model.RoleUser, crypto.AuthContext{})
	require.NoError(t, err)

	d := testDeps(false, false)
	d.authService = identity.NewAuthService("api-token-gate-secret", time.Hour)
	d.authService.SetEpochGateDB(db)
	return &apiTokenRouteFixture{db: db, deps: d, token: valid.Token, revoked: gone.Token, human: human}
}

func (f *apiTokenRouteFixture) router(sealed bool) *gin.Engine {
	d := f.deps
	if sealed {
		d.sealGate = sealGateMiddleware(func() bool { return false })
	}
	r := gin.New()
	registerRoutes(r, d)
	return r
}

func apiTokenRouteCall(r *gin.Engine, method, path, token string) *httptest.ResponseRecorder {
	q := httptest.NewRequest(method, path, nil)
	q.RemoteAddr = "192.0.2.8:8000"
	if token != "" {
		q.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, q)
	return w
}

// apiTokenGateProbePaths 三類路由各取代表，外加查無的路徑；open 為路由範圍登錄的開放與否。
var apiTokenGateProbePaths = []struct {
	class, method, path string
	open                bool
}{
	{"公開路由", "GET", "/api/v1/ping", false},
	{"公開路由", "GET", "/health", false},
	{"WebSocket 入口", "GET", "/api/v1/ssh", false},
	{"WebSocket 入口", "GET", "/api/v1/connect", false},
	{"需登入路由（不開放）", "POST", "/api/v1/connect-tokens", false},
	{"需登入路由（開放）", "GET", "/api/v1/assets", true},
	{"查無的路由", "GET", "/api/v1/no-such-route", false},
}

// TestAPITokenGateOnProductionRoutes 以正式的路由註冊函式建鏈：有效 token 打不開放的路由（公開路由、WebSocket 入口、
// 需登入而不開放者）與查無的路徑皆回 403，打開放的路由由閘門放行（回應不是路由範圍拒絕，也不是未認證）；
// 無效與已撤銷的 token 皆回同一個 401；人類工作階段與不帶憑證的請求不受影響。
func TestAPITokenGateOnProductionRoutes(t *testing.T) {
	f := newAPITokenRouteFixture(t)
	r := f.router(false)
	for _, p := range apiTokenGateProbePaths {
		t.Run(p.class+" "+p.method+" "+p.path, func(t *testing.T) {
			allowed, registered := middleware.APITokenRouteDecision(p.method, p.path)
			if p.path != "/api/v1/no-such-route" {
				require.True(t, registered, "探針路由須已登錄")
			}
			require.Equal(t, p.open, allowed, "探針與登錄的開放與否不一致")
			w := apiTokenRouteCall(r, p.method, p.path, f.token)
			if p.open {
				assert.NotContains(t, w.Body.String(), "AUTH_API_TOKEN_FORBIDDEN_ROUTE", "開放路由不應被閘門拒絕")
				assert.NotEqual(t, 401, w.Code, w.Body.String())
			} else {
				assert.Equal(t, 403, w.Code, w.Body.String())
				assert.Contains(t, w.Body.String(), "AUTH_API_TOKEN_FORBIDDEN_ROUTE")
			}
			for _, bad := range []string{f.revoked, identity.APITokenPrefix + "unknown"} {
				w := apiTokenRouteCall(r, p.method, p.path, bad)
				assert.Equal(t, 401, w.Code, w.Body.String())
				assert.Contains(t, w.Body.String(), "AUTH_TOKEN_INVALID")
			}
		})
	}
	// 開放路由放行後由端點本身的權限判定：所屬帳號只持有帳號管理角色，讀資產清單因缺資產檢視能力被拒，
	// 拒絕來自端點的權限檢查而不是路由範圍（正向的放行另由逐端點對照測試涵蓋）。
	w := apiTokenRouteCall(r, "GET", "/api/v1/assets", f.token)
	assert.Equal(t, 403, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "AUTH_PERMISSION_DENIED")
	// 人類工作階段與不帶憑證：公開路由照常
	for _, token := range []string{"", f.human} {
		w := apiTokenRouteCall(r, "GET", "/api/v1/ping", token)
		assert.Equal(t, 200, w.Code, "human/anonymous ping: %s", w.Body)
	}
	// 帶 API token 前綴的請求不落入人類 JWT 的驗證路徑
	assert.NotContains(t, apiTokenRouteCall(r, "GET", "/api/v1/assets", f.token).Body.String(), "AUTH_TOKEN_MISSING")
}

// TestAPITokenGateSealedResponseDecidedBySealGate 封印期非白名單路由的回應由封印閘決定，不論 token 是否有效。
func TestAPITokenGateSealedResponseDecidedBySealGate(t *testing.T) {
	f := newAPITokenRouteFixture(t)
	r := f.router(true)
	for _, p := range apiTokenGateProbePaths {
		if sealGateWhitelist[[2]string{p.method, p.path}] {
			continue
		}
		for _, token := range []string{f.token, f.revoked, ""} {
			w := apiTokenRouteCall(r, p.method, p.path, token)
			assert.Equal(t, 503, w.Code, "%s %s: %s", p.method, p.path, w.Body)
			assert.Contains(t, w.Body.String(), "SEAL_SERVICE_SEALED")
		}
	}
	// 白名單路由在封印期仍經過 API token 閘門
	w := apiTokenRouteCall(r, "GET", "/health", f.token)
	assert.Equal(t, 403, w.Code, w.Body.String())
}

// TestAPITokenGateRegisteredRightAfterAgentGateOnEveryRoute 四種組態下每一條路由的鏈都含 API token 閘門，
// 且緊接在 agent 閘門之後（之前只有封印閘、計量、CORS、稽核）。
func TestAPITokenGateRegisteredRightAfterAgentGateOnEveryRoute(t *testing.T) {
	for _, c := range []struct {
		mode  string
		audit bool
	}{{gin.DebugMode, true}, {gin.DebugMode, false}, {gin.ReleaseMode, true}, {gin.ReleaseMode, false}} {
		_, chains := buildRouter(t, c.mode, c.audit)
		require.NotEmpty(t, chains)
		for key, chain := range chains {
			agentAt, gateAt := -1, -1
			for i, n := range chain {
				switch {
				case strings.Contains(n, "AgentRouteAllowlist"):
					agentAt = i
				case n == apiTokenGateStableName:
					gateAt = i
				}
			}
			if gateAt < 0 || agentAt < 0 || gateAt != agentAt+1 {
				t.Fatalf("%s %v: API token 閘門須緊接 agent 閘門之後：%s", c.mode, key, strings.Join(chain, " → "))
			}
			if strings.Contains(strings.Join(chain[:agentAt], "|"), "AuthMiddleware") {
				t.Fatalf("%v: 認證中介層出現在閘門之前", key)
			}
		}
	}
}

// roleWriterSession 角色定義寫入的請求脈絡：人類工作階段標示加該帳號的請求主體（寫入交易內以帳號當下的指派重解）。
// 角色定義寫入沒有系統路徑，缺請求主體一律拒絕。
func roleWriterSession(ctx context.Context, userID uint) context.Context {
	p := authz.NewPrincipal(userID, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)
	return authz.ContextWithPrincipal(model.WithRequestCredential(ctx, model.RequestCredentialHumanSession), p)
}
