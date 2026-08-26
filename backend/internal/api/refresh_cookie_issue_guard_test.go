package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 守衛 G1：
// **六個**發放 refresh 憑證的端點全部以 httpOnly cookie 下發，且回應 body 無明文。
//
// # 為什麼需要一張表而不是一兩格
//
// 發放路徑有六條，不是兩條。漏掉任何一條不會有任何既有測試轉紅、不會有錯誤訊息，
// 只會讓該登入路徑的會話在 access token 到期（15 分鐘）後靜默斷掉——而人工測試
// 在 15 分鐘內看不出任何異常。六條路徑如下：
//
//	1. POST /api/v1/auth/login              一階段登入
//	2. POST /api/v1/auth/mfa/verify         MFA 第二階段
//	3. POST /api/v1/auth/mfa/enroll/confirm 強制註冊完成
//	4. POST /api/v1/auth/change-password    改密換發
//	5. POST /api/v1/auth/oidc/exchange      **巢狀 {"login": {...}} 回應，六者中最易漏**
//	6. POST /api/v1/auth/refresh            輪替後的新憑證
//
// # 每格斷言兩件事
//
//	(a) 回應含 Set-Cookie，且 HttpOnly／SameSite=Strict／Path=/api/v1/auth/ 三屬性齊。
//	(b) 回應 body **全文**不含該次發放的憑證明文（明文即 cookie 值本身）。
//	    「全文」是刻意的：OIDC 的巢狀回應曾是最容易漏掉的形狀。
//
// # 白名單的殘餘風險（已知並接受）
//
// 表是白名單：第 7 個發放端點若未入表，本守衛不會自動抓到。緩解有二——
// 發放唯一入口 `issueRefreshToken` → `buildLoginResponse`／`IssueSessionResponse`
// 的收斂結構未變（新端點必經此二函式），且 `json:"-"` 使「漏下 cookie」成為
// 15 分鐘內必然發生的吵鬧失敗，而非靜默回退到 localStorage。
//
// # 突變自檢
//
// 拿掉任一端點的 `h.refreshCookies.SetFromLogin(c, resp)`（或 Refresh 的 `Set`）
// ⇒ 對應那一格轉紅，其餘五格全綠。把 `LoginResponse.RefreshToken` 的 tag 由
// `json:"-"` 改回 `json:"refresh_token,omitempty"` ⇒ 五格的 (b) 斷言同時轉紅。

const (
	refreshCookieGuardSecret   = "refresh-cookie-guard-secret"
	refreshCookieGuardPassword = "C00kie-Guard!pw"
	refreshCookieGuardNewPw    = "C00kie-Guard!pw2"
	// refreshCookieGuardTOTPPeriod TOTP 時間窗長（與 identity 的 totpPeriod 一致）
	refreshCookieGuardTOTPPeriod = 30 * time.Second
)

type refreshCookieEnv struct {
	h        *AuthHandler
	oidc     *OIDCHandler
	auth     *identity.AuthService
	policies *policy.SecurityPolicyService
	db       *gorm.DB
	user     *model.User
	provider *model.OIDCProvider
	// totpSecret 測試自行產碼用的 TOTP 明文 secret
	totpSecret string
}

// setupRefreshCookieEnv 真 handler ＋ 真 service ＋ 真 sqlite。
//
// **不注入自訂的 cookie writer**：走 NewAuthHandler／NewOIDCHandler 的正式建構路徑，
// 使「建構時忘了備妥 writer」也會在此浮現。Secure 旗標不在本檔的斷言範圍
// （它由部署組態推導，見 config 的推導測試）。
func setupRefreshCookieEnv(t *testing.T) *refreshCookieEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1) // ff51836 的「單獨跑綠、整包跑紅」防護
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.RefreshToken{},
		&model.SecurityPolicy{}, &model.PasswordHistory{}, &model.OIDCProvider{},
		&model.UserExternalIdentity{}, &model.OIDCFlowState{}, &model.OIDCLoginTicket{},
		&model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS user_roles (
		user_id INTEGER NOT NULL, role_id INTEGER NOT NULL)`).Error; err != nil {
		t.Fatalf("user_roles: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	policies := policy.NewSecurityPolicyService(db)
	auth, err := identity.NewAuthServiceWithMFA(refreshCookieGuardSecret, 15*time.Minute,
		aesColumnCodec(t, make([]byte, 32)))
	if err != nil {
		t.Fatalf("NewAuthServiceWithMFA: %v", err)
	}
	auth.SetSecurityPolicies(policies)
	auth.SetEpochGateDB(db)

	users := identity.NewUserService(db, authz.NewAssetAuthorizationService(db))
	users.SetSecurityPolicies(policies)

	h := NewAuthHandler(auth, nil)
	h.SetSourcePolicyReader(unrestrictedSourcePolicy())
	h.SetUserService(users)

	providers := identity.NewOIDCProviderService(db, nil, nil, nil, "https://bastion.example.com")
	login := identity.NewOIDCLoginService(db, providers, nil, auth, nil)
	oidcHandler := NewOIDCHandler(providers, login, "https://bastion.example.com", nil)
	oidcHandler.SetSourcePolicyReader(unrestrictedSourcePolicy())

	p := &model.OIDCProvider{
		Name: "corp-idp", Issuer: "https://idp.example.com", ClientID: "cid",
		Scopes: "openid profile email", AdmissionMode: model.AdmissionPreboundOnly,
		Enabled: true, AuthEpoch: 3,
	}
	if err := db.Create(p).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).
		Update("enabled", true).Error; err != nil {
		t.Fatalf("set enabled: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(refreshCookieGuardPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	u := &model.User{
		Username: "cookie-subject", Password: string(hash), Active: true,
		ProvisioningOrigin: model.AuthSourceLocal, CredentialEpoch: 2,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&model.UserExternalIdentity{
		UserID: u.ID, ProviderID: p.ID,
		Issuer: "https://idp.example.com", ClientID: "cid", Subject: "sub-cookie",
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	return &refreshCookieEnv{
		h: h, oidc: oidcHandler, auth: auth, policies: policies,
		db: db, user: u, provider: p,
	}
}

// post 打單一端點（不掛任何中介層：本檔驗的是 handler 自身的回應形狀）
func (e *refreshCookieEnv) post(t *testing.T, path string, handler gin.HandlerFunc,
	payload any, bearer string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.POST(path, handler)

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	req.RemoteAddr = "203.0.113.5:41000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// enableTOTP 讓測試使用者完成 TOTP 綁定（走服務層真流程，不手工塞欄位）
func (e *refreshCookieEnv) enableTOTP(t *testing.T) {
	t.Helper()
	setup, err := e.auth.GenerateMFASetup(e.user.ID)
	if err != nil {
		t.Fatalf("GenerateMFASetup: %v", err)
	}
	// 綁定碼取**前一個時間窗**：與後續驗證碼不同，否則 MFA 重放防護會擋下驗證
	code, err := totp.GenerateCode(setup.Secret, time.Now().Add(-refreshCookieGuardTOTPPeriod))
	if err != nil {
		t.Fatalf("TOTP code: %v", err)
	}
	if err := e.auth.EnableMFA(e.user.ID, code); err != nil {
		t.Fatalf("EnableMFA: %v", err)
	}
	e.user.TOTPEnabled = true
	e.totpSecret = setup.Secret
}

// issueTicket 落一張合法的 OIDC 交棒憑證（世代取自現況）
func (e *refreshCookieEnv) issueTicket(t *testing.T) string {
	t.Helper()
	plain := "ticket-" + hex.EncodeToString([]byte("cookie-guard-seed"))
	sum := sha256.Sum256([]byte(plain))
	ticket := model.OIDCLoginTicket{
		TokenHash: hex.EncodeToString(sum[:]), UserID: e.user.ID, ProviderID: e.provider.ID,
		AuthEpoch: e.provider.AuthEpoch, CredEpoch: e.user.CredentialEpoch,
		AuthMethod: crypto.AuthMethodOIDC,
		ExpiresAt:  time.Now().Add(time.Minute),
	}
	if err := e.db.Create(&ticket).Error; err != nil {
		t.Fatalf("seed ticket: %v", err)
	}
	return plain
}

// findRefreshCookie 自回應取出 refresh cookie；不存在回 nil
func findRefreshCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, ck := range (&http.Response{Header: w.Header()}).Cookies() {
		if ck.Name == RefreshCookieName {
			return ck
		}
	}
	return nil
}

// assertIssuedViaCookie G1 的兩條斷言（屬性齊 ＋ body 無明文）
func assertIssuedViaCookie(t *testing.T, endpoint string, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("%s 應回 200，實得 %d：body=%s", endpoint, w.Code, w.Body.String())
	}
	ck := findRefreshCookie(w)
	if ck == nil {
		t.Fatalf("%s 沒有下發 %s cookie——該登入路徑的會話會在 access token 到期後靜默斷掉，"+
			"而人工測試 15 分鐘內看不出來。Set-Cookie=%q",
			endpoint, RefreshCookieName, w.Header().Values("Set-Cookie"))
	}
	if ck.Value == "" {
		t.Errorf("%s 下發的 cookie 值為空", endpoint)
	}
	if !ck.HttpOnly {
		t.Errorf("%s 的 cookie 未標 HttpOnly——script 讀得到即可被 XSS 外帶，"+
			"這是本 change 的唯一目的", endpoint)
	}
	if ck.SameSite != http.SameSiteStrictMode {
		t.Errorf("%s 的 cookie SameSite = %v, want Strict（跨站請求一律不得攜帶）",
			endpoint, ck.SameSite)
	}
	if ck.Path != RefreshCookiePath {
		t.Errorf("%s 的 cookie Path = %q, want %q", endpoint, ck.Path, RefreshCookiePath)
	}
	if ck.MaxAge <= 0 {
		t.Errorf("%s 的 cookie Max-Age = %d，發放時應為正值（<=0 是「刪除」或「不帶屬性」語義）",
			endpoint, ck.MaxAge)
	}

	body := w.Body.String()
	if strings.Contains(body, ck.Value) {
		t.Errorf("%s 的回應 body 含 refresh 憑證明文——遷移只做了一半，前端照樣讀得到。body=%s",
			endpoint, body)
	}
	if strings.Contains(body, `"refresh_token"`) {
		t.Errorf("%s 的回應 body 仍有 refresh_token 欄位。body=%s", endpoint, body)
	}
}

// --- 表：六個發放端點 ---

func TestAllRefreshIssuingEndpointsSetCookie(t *testing.T) {
	cases := []struct {
		name string
		exec func(t *testing.T) *httptest.ResponseRecorder
	}{
		{"1/6 POST /api/v1/auth/login", execIssueLogin},
		{"2/6 POST /api/v1/auth/mfa/verify", execIssueMFAVerify},
		{"3/6 POST /api/v1/auth/mfa/enroll/confirm", execIssueMFAEnrollConfirm},
		{"4/6 POST /api/v1/auth/change-password", execIssueChangePassword},
		{"5/6 POST /api/v1/auth/oidc/exchange", execIssueOIDCExchange},
		{"6/6 POST /api/v1/auth/refresh", execIssueRefreshRotation},
	}
	if len(cases) != 6 {
		t.Fatalf("表長度 = %d，決策 3 的發放端點清單為 6 個——表與清單脫節即漏報", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertIssuedViaCookie(t, tc.name, tc.exec(t))
		})
	}
}

func execIssueLogin(t *testing.T) *httptest.ResponseRecorder {
	e := setupRefreshCookieEnv(t)
	return e.post(t, "/api/v1/auth/login", e.h.Login, map[string]string{
		"username": e.user.Username, "password": refreshCookieGuardPassword,
	}, "")
}

func execIssueMFAVerify(t *testing.T) *httptest.ResponseRecorder {
	e := setupRefreshCookieEnv(t)
	e.enableTOTP(t)

	first, err := e.auth.Login(&identity.LoginRequest{
		Username: e.user.Username, Password: refreshCookieGuardPassword})
	if err != nil {
		t.Fatalf("第一階段登入: %v", err)
	}
	if !first.MFARequired || first.PendingToken == "" {
		t.Fatalf("前提不成立：應進入 MFA 第二階段，實得 %+v", first)
	}
	code, err := totp.GenerateCode(e.totpSecret, time.Now())
	if err != nil {
		t.Fatalf("TOTP code: %v", err)
	}
	return e.post(t, "/api/v1/auth/mfa/verify", e.h.MFAVerify, map[string]string{
		"pending_token": first.PendingToken, "code": code,
	}, "")
}

func execIssueMFAEnrollConfirm(t *testing.T) *httptest.ResponseRecorder {
	e := setupRefreshCookieEnv(t)
	e.policies.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin")

	first, err := e.auth.Login(&identity.LoginRequest{
		Username: e.user.Username, Password: refreshCookieGuardPassword})
	if err != nil {
		t.Fatalf("登入: %v", err)
	}
	if !first.MFAEnrollmentRequired || first.EnrollmentToken == "" {
		t.Fatalf("前提不成立：應進入強制註冊流程，實得 %+v", first)
	}
	setup, err := e.auth.EnrollmentSetup(first.EnrollmentToken)
	if err != nil {
		t.Fatalf("EnrollmentSetup: %v", err)
	}
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("TOTP code: %v", err)
	}
	return e.post(t, "/api/v1/auth/mfa/enroll/confirm", e.h.MFAEnrollConfirm,
		map[string]string{"code": code}, first.EnrollmentToken)
}

func execIssueChangePassword(t *testing.T) *httptest.ResponseRecorder {
	e := setupRefreshCookieEnv(t)
	session, err := e.auth.Login(&identity.LoginRequest{
		Username: e.user.Username, Password: refreshCookieGuardPassword})
	if err != nil {
		t.Fatalf("登入: %v", err)
	}
	if session.Token == "" {
		t.Fatalf("前提不成立：登入未取得正式 token，實得 %+v", session)
	}
	return e.post(t, "/api/v1/auth/change-password", e.h.ChangePassword, map[string]string{
		"old_password": refreshCookieGuardPassword, "new_password": refreshCookieGuardNewPw,
	}, session.Token)
}

func execIssueOIDCExchange(t *testing.T) *httptest.ResponseRecorder {
	e := setupRefreshCookieEnv(t)
	ticket := e.issueTicket(t)
	return e.post(t, "/api/v1/auth/oidc/exchange", e.oidc.Exchange,
		map[string]string{"ticket": ticket}, "")
}

func execIssueRefreshRotation(t *testing.T) *httptest.ResponseRecorder {
	e := setupRefreshCookieEnv(t)
	first := e.post(t, "/api/v1/auth/login", e.h.Login, map[string]string{
		"username": e.user.Username, "password": refreshCookieGuardPassword,
	}, "")
	ck := findRefreshCookie(first)
	if ck == nil {
		t.Fatal("前提不成立：登入未下發 refresh cookie，輪替無從測起")
	}
	return e.post(t, "/api/v1/auth/refresh", e.h.Refresh, map[string]string{}, "",
		&http.Cookie{Name: RefreshCookieName, Value: ck.Value})
}

// --- 反向斷言：尚待驗證的分支不得下發 ---

// TestOIDCExchangeMFAPendingIssuesNoRefreshCookie MFA 第一階段尚未發出正式會話，
// 此刻下 cookie 等於在第二因子完成前就交出一枚可換發任意次 access token 的長效憑證。
//
// 這一格同時是 SetFromLogin「判準取憑證有無、不是分支清單」的守衛：
// 改成無條件下發即紅。
func TestOIDCExchangeMFAPendingIssuesNoRefreshCookie(t *testing.T) {
	e := setupRefreshCookieEnv(t)
	e.enableTOTP(t)
	ticket := e.issueTicket(t)

	w := e.post(t, "/api/v1/auth/oidc/exchange", e.oidc.Exchange,
		map[string]string{"ticket": ticket}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("exchange 應回 200（MFA 第一階段），實得 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "mfa_required") {
		t.Fatalf("前提不成立：回應不是 MFA 待驗證分支，body=%s", w.Body.String())
	}
	if ck := findRefreshCookie(w); ck != nil {
		t.Errorf("MFA 待驗證分支下發了 refresh cookie（值長度 %d）——"+
			"第二因子尚未通過即交出長效憑證", len(ck.Value))
	}
}

// TestLoginGateBranchesIssueNoRefreshCookie 本地登入的強制註冊分支同樣不得下發。
// 與 OIDC 分支分開一格：兩條路徑各有自己的 handler，一起綠不代表兩邊都對
func TestLoginGateBranchesIssueNoRefreshCookie(t *testing.T) {
	e := setupRefreshCookieEnv(t)
	e.policies.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin")

	w := e.post(t, "/api/v1/auth/login", e.h.Login, map[string]string{
		"username": e.user.Username, "password": refreshCookieGuardPassword,
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("登入應回 200（強制註冊分支），實得 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "mfa_enrollment_required") {
		t.Fatalf("前提不成立：回應不是強制註冊分支，body=%s", w.Body.String())
	}
	if ck := findRefreshCookie(w); ck != nil {
		t.Errorf("強制註冊分支下發了 refresh cookie（值長度 %d）", len(ck.Value))
	}
}
