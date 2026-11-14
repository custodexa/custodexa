package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// API token 的全域閘門：辨識、認證一次、建立帶限定的請求主體；失敗即 401；路由範圍預設拒絕。

type nopTokenEvents struct{}

func (nopTokenEvents) APITokenCreated(*gorm.DB, identity.APITokenCreatedEvent) error { return nil }
func (nopTokenEvents) APITokenRevoked(*gorm.DB, identity.APITokenRevokedEvent) error { return nil }

type apiTokenGateFixture struct {
	*agentAuthFixture
	tokens   *identity.APITokenService
	ida, sec model.Role
	plain    string
	tokenID  uint
}

func newAPITokenGateFixture(t *testing.T) *apiTokenGateFixture {
	t.Helper()
	f := &apiTokenGateFixture{agentAuthFixture: newAgentAuthFixture(t)}
	if err := f.db.AutoMigrate(&model.APIToken{}, &model.APITokenRole{}, &model.AssetGroup{}, &model.AssetAuthorization{}, &model.RolePermission{}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		role *model.Role
		name string
		key  string
	}{{&f.ida, "identity_admin", model.BuiltinIdentityAdmin}, {&f.sec, "security_admin", model.BuiltinSecurityAdmin}} {
		k := r.key
		*r.role = model.Role{Name: r.name, BuiltinKey: &k, DefinitionVersion: 1}
		if err := f.db.Create(r.role).Error; err != nil {
			t.Fatal(err)
		}
		if err := f.db.Create(&model.UserRole{UserID: f.owner.ID, RoleID: r.role.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
			t.Fatal(err)
		}
	}
	f.tokens = identity.NewAPITokenService(f.db, nopTokenEvents{})
	op := identity.Operator{UserID: f.owner.ID, Username: f.owner.Username,
		Principal: authz.NewPrincipal(f.owner.ID, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)}
	created, err := f.tokens.Create(op, identity.CreateAPITokenInput{Name: "terraform", RoleIDs: []uint{f.ida.ID}, NeverExpires: true})
	if err != nil {
		t.Fatal(err)
	}
	f.plain, f.tokenID = created.Token, created.View.ID
	return f
}

func allowAllAPITokenRoutes(string, string) (bool, bool) { return true, true }

// gateRouter 審計 → agent 閘門 → API token 閘門 → 路由，與正式鏈同序。
func (f *apiTokenGateFixture) gateRouter(decide APITokenRouteDecider, observe func(*gin.Context)) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Next()
		if observe != nil {
			observe(c) // 鏈結束後檢視脈絡（含被閘門中止的請求）
		}
	})
	r.Use(AuditLogMiddleware(newAnonAuditService()), AgentRouteAllowlist(f.auth), (&apiTokenGate{auth: f.auth, decide: decide}).Handle)
	r.GET("/api/v1/assets", AuthMiddleware(f.auth), func(c *gin.Context) { c.Status(200) })
	r.GET("/api/v1/ping", func(c *gin.Context) { c.Status(200) })
	return r
}

func bearerRequest(r *gin.Engine, method, path, token string) *httptest.ResponseRecorder {
	q := httptest.NewRequest(method, path, nil)
	q.RemoteAddr = "192.0.2.8:8000"
	if token != "" {
		q.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, q)
	return w
}

// TestAPITokenGateAuthenticatesAndAuthMiddlewareReusesPrincipal 閘門建立帶限定的請求主體並設定 token 識別與名稱；
// 之後的認證中介層沿用、不重驗。認證中介層本身不驗 API token：沒有經過閘門的 API token 請求一律 401。
func TestAPITokenGateAuthenticatesAndAuthMiddlewareReusesPrincipal(t *testing.T) {
	f := newAPITokenGateFixture(t)
	var seen *gin.Context
	r := f.gateRouter(allowAllAPITokenRoutes, func(c *gin.Context) { seen = c })
	if w := bearerRequest(r, "GET", "/api/v1/assets", f.plain); w.Code != 200 {
		t.Fatalf("valid token: %d %s", w.Code, w.Body)
	}
	if kind, ok := GetRequestCredential(seen); !ok || kind != model.RequestCredentialAPIToken {
		t.Fatalf("request credential: %v %v", kind, ok)
	}
	if id, ok := GetAPITokenID(seen); !ok || id != f.tokenID {
		t.Fatalf("token id: %v %v", id, ok)
	}
	if name, ok := GetAPITokenName(seen); !ok || name != "terraform" {
		t.Fatalf("token name: %q %v", name, ok)
	}
	if uid, ok := GetCurrentUserID(seen); !ok || uid != f.owner.ID {
		t.Fatal("operator is the owner")
	}
	ctxPrincipal := authz.PrincipalFromContext(seen.Request.Context())
	if ctxPrincipal == nil || ctxPrincipal.Facts.RoleFilter == nil || ctxPrincipal.Facts.AuthMethod != identity.APITokenAuthMethod {
		t.Fatalf("request context principal must carry the role filter: %+v", ctxPrincipal)
	}
	if got := ctxPrincipal.Facts.RoleFilter.RoleIDs(); len(got) != 1 || got[0] != f.ida.ID {
		t.Fatalf("filter: %v", got)
	}
	if ctxPrincipal.HasBuiltin(model.BuiltinSecurityAdmin) {
		t.Fatal("role held by the owner but not granted to the token leaked into the principal")
	}
	if ref, ok := model.APITokenRefFrom(seen.Request.Context()); !ok || ref.ID != f.tokenID || ref.Name != "terraform" {
		t.Fatalf("api token ref: %+v %v", ref, ok)
	}

	// 沒有閘門：認證中介層不落入 JWT 驗證，也不自行認證 API token
	bare := gin.New()
	bare.GET("/api/v1/assets", AuthMiddleware(f.auth), func(c *gin.Context) { c.Status(200) })
	if w := bearerRequest(bare, "GET", "/api/v1/assets", f.plain); w.Code != 401 || !strings.Contains(w.Body.String(), "AUTH_TOKEN_INVALID") {
		t.Fatalf("api token without gate: %d %s", w.Code, w.Body)
	}
}

// TestAPITokenGateInvalidTokenReturns401WithoutIdentity 無效、已撤銷、帳號停用的 token 回同一個 401，
// 失敗時 gin 脈絡與 request context 都不留下任何身分。
func TestAPITokenGateInvalidTokenReturns401WithoutIdentity(t *testing.T) {
	f := newAPITokenGateFixture(t)
	var seen *gin.Context
	r := f.gateRouter(allowAllAPITokenRoutes, func(c *gin.Context) { seen = c })
	op := identity.Operator{UserID: f.owner.ID, Username: f.owner.Username,
		Principal: authz.NewPrincipal(f.owner.ID, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)}
	revoked, err := f.tokens.Create(op, identity.CreateAPITokenInput{Name: "revoked", RoleIDs: []uint{f.ida.ID}, NeverExpires: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.tokens.RevokeOwn(op, revoked.View.ID, ""); err != nil {
		t.Fatal(err)
	}
	var body string
	for _, tc := range []struct{ name, token, path string }{
		{"unknown", identity.APITokenPrefix + "nope", "/api/v1/assets"},
		{"revoked", revoked.Token, "/api/v1/assets"},
		{"revoked-public", revoked.Token, "/api/v1/ping"},
		{"revoked-unknown-path", revoked.Token, "/api/v1/no-such-route"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := bearerRequest(r, "GET", tc.path, tc.token)
			if w.Code != 401 || !strings.Contains(w.Body.String(), "AUTH_TOKEN_INVALID") {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if body != "" && body != w.Body.String() {
				t.Fatal("rejection bodies differ: the reason leaks to the caller")
			}
			body = w.Body.String()
			for _, key := range []string{"userID", "username", "principal_kind", apiTokenIDContextKey, apiTokenNameContextKey, requestCredentialContextKey, "authContext"} {
				if _, exists := seen.Get(key); exists {
					t.Fatalf("identity key %q left on a rejected request", key)
				}
			}
			if PrincipalFrom(seen) != nil || authz.PrincipalFromContext(seen.Request.Context()) != nil {
				t.Fatal("principal left on a rejected request")
			}
			if _, ok := model.RequestCredentialFrom(seen.Request.Context()); ok {
				t.Fatal("request credential left in request context")
			}
		})
	}
	if err := f.db.Model(&model.User{}).Where("id = ?", f.owner.ID).Update("active", false).Error; err != nil {
		t.Fatal(err)
	}
	if w := bearerRequest(r, "GET", "/api/v1/assets", f.plain); w.Code != 401 || w.Body.String() != body {
		t.Fatalf("disabled owner: %d %s", w.Code, w.Body)
	}
}

// TestAPITokenGateFollowsRouteRegistry 正式的路由範圍判定依登錄：登錄為開放的路由放行；登錄為不開放的路由
// （含公開路由）與查無的路徑，有效 token 皆回 403。
func TestAPITokenGateFollowsRouteRegistry(t *testing.T) {
	f := newAPITokenGateFixture(t)
	r := f.gateRouter(APITokenRouteDecision, nil)
	if w := bearerRequest(r, "GET", "/api/v1/assets", f.plain); w.Code != 200 {
		t.Fatalf("/api/v1/assets（登錄為開放）: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/api/v1/ping", "/api/v1/no-such-route"} {
		w := bearerRequest(r, "GET", path, f.plain)
		if w.Code != 403 || !strings.Contains(w.Body.String(), "AUTH_API_TOKEN_FORBIDDEN_ROUTE") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	if allowed, registered := APITokenRouteDecision("GET", "/api/v1/assets"); !allowed || !registered {
		t.Fatal("GET /api/v1/assets 應登錄為開放")
	}
	if allowed, registered := APITokenRouteDecision("GET", "/api/v1/ping"); allowed || !registered {
		t.Fatal("GET /api/v1/ping 應登錄為不開放")
	}
	if allowed, _ := APITokenRouteDecision("GET", ""); allowed {
		t.Fatal("unmatched route must be denied")
	}
	// 判定函式缺漏時同樣拒絕
	nilDecider := f.gateRouter(nil, nil)
	if w := bearerRequest(nilDecider, "GET", "/api/v1/ping", f.plain); w.Code != 403 {
		t.Fatalf("nil decider: %d", w.Code)
	}
}

// TestAPITokenGateHumanSessionUnchanged 人類工作階段經過閘門的行為與沒有閘門時相同。
func TestAPITokenGateHumanSessionUnchanged(t *testing.T) {
	f := newAPITokenGateFixture(t)
	jwt := f.humanToken(t)
	observeKind := func(dst *model.RequestCredential) func(*gin.Context) {
		return func(c *gin.Context) { *dst, _ = GetRequestCredential(c) }
	}
	var withGate, without model.RequestCredential
	gated := f.gateRouter(APITokenRouteDecision, observeKind(&withGate))
	plain := gin.New()
	plain.Use(func(c *gin.Context) { c.Next(); observeKind(&without)(c) })
	plain.Use(AuditLogMiddleware(newAnonAuditService()), AgentRouteAllowlist(f.auth))
	plain.GET("/api/v1/assets", AuthMiddleware(f.auth), func(c *gin.Context) { c.Status(200) })
	plain.GET("/api/v1/ping", func(c *gin.Context) { c.Status(200) })
	for _, tc := range []struct{ path, token string }{
		{"/api/v1/assets", jwt}, {"/api/v1/ping", jwt}, {"/api/v1/assets", ""}, {"/api/v1/assets", "not-a-jwt"}, {"/api/v1/no-such-route", jwt},
	} {
		a, b := bearerRequest(gated, "GET", tc.path, tc.token), bearerRequest(plain, "GET", tc.path, tc.token)
		if a.Code != b.Code || a.Body.String() != b.Body.String() {
			t.Fatalf("%s token=%v: with gate %d %s, without %d %s", tc.path, tc.token != "", a.Code, a.Body, b.Code, b.Body)
		}
		if withGate != without {
			t.Fatalf("%s: credential kind changed %q vs %q", tc.path, withGate, without)
		}
	}
}

// TestAPITokenGateAgentKeyUnchanged agent 鑰匙仍由 agent 閘門認證與判定範圍，API token 閘門不介入。
func TestAPITokenGateAgentKeyUnchanged(t *testing.T) {
	f := newAPITokenGateFixture(t)
	var kind model.RequestCredential
	r := f.gateRouter(func(string, string) (bool, bool) {
		t.Fatal("agent request must not reach the API token route decision")
		return false, false
	}, func(c *gin.Context) { kind, _ = GetRequestCredential(c) })
	r.DELETE("/api/v1/users/:id", func(c *gin.Context) { c.Status(204) })
	if w := bearerRequest(r, "GET", "/api/v1/assets", f.token.Token); w.Code != 200 {
		t.Fatalf("agent allowed route: %d %s", w.Code, w.Body)
	}
	if kind != model.RequestCredentialAgentKey {
		t.Fatalf("kind %q", kind)
	}
	if w := bearerRequest(r, "DELETE", "/api/v1/users/1", f.token.Token); w.Code != 403 || !strings.Contains(w.Body.String(), "AUTH_AGENT_FORBIDDEN_ROUTE") {
		t.Fatalf("agent forbidden route: %d %s", w.Code, w.Body)
	}
}

// TestAPITokenWithAllRolesRevokedPassesAuthWithEmptyCapabilities 授權角色全數收回時認證通過，
// 但主體帶非 nil 的空限定：沒有任何能力（含零角色帳號的基本能力），不退回不限定。
func TestAPITokenWithAllRolesRevokedPassesAuthWithEmptyCapabilities(t *testing.T) {
	f := newAPITokenGateFixture(t)
	var seen *gin.Context
	r := f.gateRouter(allowAllAPITokenRoutes, func(c *gin.Context) { seen = c })
	if err := f.db.Where("user_id = ?", f.owner.ID).Delete(&model.UserRole{}).Error; err != nil {
		t.Fatal(err)
	}
	if w := bearerRequest(r, "GET", "/api/v1/assets", f.plain); w.Code != 200 {
		t.Fatalf("roles revoked still authenticates: %d %s", w.Code, w.Body)
	}
	p := PrincipalFrom(seen)
	if p == nil || p.Facts.RoleFilter == nil {
		t.Fatal("filter must stay non-nil")
	}
	if p.Has(authz.PermAssetView) || len(p.Capabilities()) != 0 {
		t.Fatalf("empty intersection must have no capability: %v", p.Capabilities())
	}
	// 授權角色列遺失（空集合）同樣是非 nil 的空限定
	if err := f.db.Where("api_token_id = ?", f.tokenID).Delete(&model.APITokenRole{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(&model.UserRole{UserID: f.owner.ID, RoleID: f.ida.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
		t.Fatal(err)
	}
	if w := bearerRequest(r, "GET", "/api/v1/assets", f.plain); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	if p := PrincipalFrom(seen); p == nil || p.Facts.RoleFilter == nil || len(p.Capabilities()) != 0 {
		t.Fatal("token with no granted role rows must not fall back to the unrestricted principal")
	}
}
