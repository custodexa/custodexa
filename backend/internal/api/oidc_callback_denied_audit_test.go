package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// callback 在身分提供者認證成功之後的兩種拒絕：帳號已停用、帳號已被刪除（僅預綁模式）。
//
// 兩者都要走完授權碼交換與 id_token 驗證才到得了，故本檔接一個最小的假身分提供者
// （discovery、JWKS、token 三個端點）。驗的是 handler 這一側：導回登入頁的 slug
// 可行動，且 service 交回的意向真的落成帶請求脈絡的列。

// callbackIdP 最小假身分提供者：只認預先登錄的授權碼，以固定金鑰簽 id_token
type callbackIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	codes  map[string]string
}

func newCallbackIdP(t *testing.T) *callbackIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("產生金鑰: %v", err)
	}
	f := &callbackIdP{key: key, codes: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/auth",
			"token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		idToken, ok := f.codes[r.PostFormValue("code")]
		delete(f.codes, r.PostFormValue("code"))
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "a", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken,
		})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// stage 登錄授權碼與其 id_token（模擬使用者已在身分提供者完成認證）
func (f *callbackIdP) stage(t *testing.T, code, clientID, subject, nonce string) {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": f.server.URL, "sub": subject, "aud": clientID, "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"preferred_username": "sso-user",
	})
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatalf("簽 id_token: %v", err)
	}
	f.mu.Lock()
	f.codes[code] = signed
	f.mu.Unlock()
}

type callbackDeniedEnv struct {
	*oidcAuditEnv
	idp *callbackIdP
}

// setupCallbackDeniedEnv 僅預綁 provider（issuer 指向假身分提供者）＋一個已綁定 sub-1 的帳號
func setupCallbackDeniedEnv(t *testing.T) *callbackDeniedEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	idp := newCallbackIdP(t)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.RefreshToken{},
		&model.SecurityPolicy{}, &model.PasswordHistory{}, &model.OIDCProvider{},
		&model.UserExternalIdentity{}, &model.OIDCFlowState{}, &model.OIDCLoginTicket{},
		&model.GroupRoleMapping{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.UserRole{}); err != nil {
		t.Fatalf("user_roles: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	auth := identity.NewAuthService("oidc-callback-secret", 15*time.Minute)
	auth.SetSecurityPolicies(policy.NewSecurityPolicyService(db))
	egress := &identity.OIDCEgressPolicy{AllowInsecureHosts: []string{"127.0.0.1"}}
	providers := identity.NewOIDCProviderService(db, nil, egress, nil, "https://bastion.example.com")
	login := identity.NewOIDCLoginService(db, providers, identity.NewOIDCDiscoveryService(egress), auth, nil)
	auditService := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	h := NewOIDCHandler(providers, login, "https://bastion.example.com", auditService)
	h.SetSourcePolicyReader(unrestrictedSourcePolicy())

	p := &model.OIDCProvider{
		Name: "corp-idp", Issuer: idp.server.URL, ClientID: "cid-1",
		Scopes: "openid profile email", AdmissionMode: model.AdmissionPreboundOnly,
		Enabled: true, AuthEpoch: 3,
	}
	if err := db.Create(p).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).Update("enabled", true).Error; err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	u := &model.User{
		Username: "sso-user", Password: "x", Active: true,
		ProvisioningOrigin: model.AuthSourceOIDC, ExternalCredential: true, CredentialEpoch: 2,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&model.UserExternalIdentity{
		UserID: u.ID, ProviderID: p.ID, Issuer: p.Issuer, ClientID: p.ClientID, Subject: "sub-1",
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	if err := db.Exec("DELETE FROM audit_logs").Error; err != nil {
		t.Fatalf("清空 seed 期審計列: %v", err)
	}
	return &callbackDeniedEnv{
		oidcAuditEnv: &oidcAuditEnv{h: h, db: db, provider: p, user: u},
		idp:          idp,
	}
}

// callback 落一個合法的流程狀態並以已登錄的授權碼打 callback，回傳導向位址
func (e *callbackDeniedEnv) callback(t *testing.T, state, subject string) string {
	t.Helper()
	flow := model.OIDCFlowState{
		State: state, Nonce: "nonce-" + state, PKCEVerifier: "verifier",
		ProviderID: e.provider.ID, AuthEpoch: e.provider.AuthEpoch,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := e.db.Create(&flow).Error; err != nil {
		t.Fatalf("seed flow: %v", err)
	}
	e.idp.stage(t, "code-"+state, e.provider.ClientID, subject, flow.Nonce)

	r := gin.New()
	r.GET("/api/v1/auth/oidc/callback", e.h.Callback)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/oidc/callback?state="+state+"&code=code-"+state, nil)
	req.RemoteAddr = oidcAuditRemoteAddr
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("callback 應 302 導回，實得 %d", w.Code)
	}
	return w.Header().Get("Location")
}

// rowsByEvent 取 details.event 相符的審計列
func rowsByEvent(t *testing.T, rows []model.AuditLog, event string) []model.AuditLog {
	t.Helper()
	var out []model.AuditLog
	for _, row := range rows {
		var d map[string]any
		if err := json.Unmarshal([]byte(row.Details), &d); err != nil {
			t.Fatalf("Details 應為合法 JSON，實得 %q: %v", row.Details, err)
		}
		if d["event"] == event {
			out = append(out, row)
		}
	}
	return out
}

// TestOIDCCallbackInactiveUserDenied 停用帳號經 callback 被拒：導回 oidc_user_inactive，
// 落一筆 auth／denied 且帶請求脈絡與帳號的列
func TestOIDCCallbackInactiveUserDenied(t *testing.T) {
	env := setupCallbackDeniedEnv(t)
	if err := env.db.Model(&model.User{}).Where("id = ?", env.user.ID).
		Update("active", false).Error; err != nil {
		t.Fatalf("停用帳號: %v", err)
	}

	loc := env.callback(t, "state-inactive", "sub-1")
	if !strings.HasSuffix(loc, "/login#sso_error=oidc_user_inactive") {
		t.Fatalf("應導回 #sso_error=oidc_user_inactive，實得 %s", loc)
	}
	rows := rowsByEvent(t, env.rows(t), "oidc_user_inactive")
	if len(rows) != 1 {
		t.Fatalf("應恰一筆停用拒絕列，實得 %d（全部 %+v）", len(rows), env.rows(t))
	}
	row := rows[0]
	if row.Action != model.ActionLogin || row.Resource != model.ResourceAuth || row.Status != model.StatusDenied {
		t.Errorf("應為 login／auth／denied，實得 %q／%q／%q", row.Action, row.Resource, row.Status)
	}
	if row.UserID != env.user.ID || row.Username != env.user.Username {
		t.Errorf("列的帳號應為 %d/%s，實得 %d/%s", env.user.ID, env.user.Username, row.UserID, row.Username)
	}
	if !strings.Contains(row.Details, `"provider_name":"corp-idp"`) {
		t.Errorf("Details 應帶 provider，實得 %s", row.Details)
	}
	assertRequestContext(t, row, "/api/v1/auth/oidc/callback", http.StatusFound)
}

// TestOIDCCallbackPreboundDeletedAccount 僅預綁模式、帳號已刪除（綁定未作廢，升級前狀態）：
// 導回 oidc_account_removed，落作廢列與拒絕列
func TestOIDCCallbackPreboundDeletedAccount(t *testing.T) {
	env := setupCallbackDeniedEnv(t)
	if err := env.db.Exec("UPDATE users SET deleted_at = ? WHERE id = ?", time.Now(), env.user.ID).Error; err != nil {
		t.Fatalf("直寫軟刪帳號: %v", err)
	}

	loc := env.callback(t, "state-removed", "sub-1")
	if !strings.HasSuffix(loc, "/login#sso_error=oidc_account_removed") {
		t.Fatalf("應導回 #sso_error=oidc_account_removed，實得 %s", loc)
	}
	all := env.rows(t)
	revoked := rowsByEvent(t, all, "oidc_identity_orphan_revoked")
	if len(revoked) != 1 {
		t.Fatalf("應恰一筆作廢列，實得 %d（全部 %+v）", len(revoked), all)
	}
	if r := revoked[0]; r.Action != model.ActionDelete || r.Resource != model.ResourceUser ||
		r.Status != model.StatusSuccess || r.ResourceID == nil || *r.ResourceID != env.user.ID ||
		!strings.Contains(r.Details, `"subject":"sub-1"`) ||
		!strings.Contains(r.Details, `"previous_username":"sso-user"`) {
		t.Errorf("作廢列欄位不符: %+v", r)
	}
	denied := rowsByEvent(t, all, "oidc_account_removed")
	if len(denied) != 1 {
		t.Fatalf("應恰一筆帳號已刪除拒絕列，實得 %d", len(denied))
	}
	row := denied[0]
	if row.Action != model.ActionLogin || row.Resource != model.ResourceAuth || row.Status != model.StatusDenied {
		t.Errorf("應為 login／auth／denied，實得 %q／%q／%q", row.Action, row.Resource, row.Status)
	}
	assertRequestContext(t, row, "/api/v1/auth/oidc/callback", http.StatusFound)
	assertRequestContext(t, revoked[0], "/api/v1/auth/oidc/callback", http.StatusFound)
}
