package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 本地登入與 MFA 完成路徑的兩條留痕紀律（audit-coverage-closure 批 7＋2.9）。
//
// # 缺陷一：來源位址可被偽造（B 類，實測列 id 23057）
//
// 修法前 `auth_handler.go`／`auth_mfa_handler.go` 的審計列以 `c.ClientIP()` 取來源
// 位址。gin 未呼叫 `SetTrustedProxies` 時**信任任意轉送標頭**，故任何人只要對公開的
// `/auth/login` 送一個 `X-Forwarded-For`，他那筆登入列的 `client_ip` 就是他挑的值。
// 零權限、零前置條件，偽造的正是稽核事後追人唯一的線索。OIDC 路徑已於批 2 修正
// （`oidc_handler.go` 的 `auditSourceIP`），本地登入是更常用的那條路。
//
// # 缺陷二：MFA 完成路徑未標 provider（A 類）
//
// spec `oidc-auth`「登入 gate chain 匯流」要求登入審計標註認證方式**與 provider**，
// 且於 MFA 完成路徑一併保留。修法前該路徑只寫 `error_msg="source=oidc"`，無
// `provider_id`／`provider_name`、無 Details——而 SSO＋MFA 使用者的**唯一**正式會話
// 成功列就是這一筆，多 provider 部署下稽核答不出「他從哪個身分來源進來」。
// 資料本就在手上（`auth_mfa_service.go` 的 `resp.AuthProviderID`）。
//
// # 突變自檢（tasks 7.5／2.9）
//
//	`h.auditSourceIP(c)` 改回 `c.ClientIP()` ⇒ 前三個測試轉紅，provider 測試不受影響。
//	拿掉 `auditMFALoginSuccess` 的 provider Details ⇒ 只有 provider 測試轉紅。
//	兩者互不掩蓋。

const (
	authSrcSecret     = "auth-source-ip-audit-secret"
	authSrcPassword   = "S0urce-Audit!pw"
	authSrcRemoteAddr = "192.0.2.10:54321" // socket 對端（唯一可信的事實）
	authSrcPeer       = "192.0.2.10"
	authSrcForged     = "198.51.100.77" // 攻擊者自選的來源
	// totpTestPeriod TOTP 時間窗長（與 identity 的 totpPeriod 一致）
	totpTestPeriod = 30 * time.Second
)

// authSrcForgedHeaders 六種轉送標頭全指向偽造位址。
//
// 逐一列出而非只送 `X-Forwarded-For`：gin 的可信代理解析會依序看多個標頭，
// 只擋一個等於留下五條同效路徑
var authSrcForgedHeaders = map[string]string{
	"X-Forwarded-For":  authSrcForged,
	"X-Real-IP":        authSrcForged,
	"Forwarded":        "for=" + authSrcForged,
	"True-Client-IP":   authSrcForged,
	"CF-Connecting-IP": authSrcForged,
	"X-Client-IP":      authSrcForged,
}

type authSrcEnv struct {
	h    *AuthHandler
	auth *identity.AuthService
	db   *gorm.DB
	uid  uint
	pid  uint
	// totpSecret MFA 使用者的 TOTP 明文 secret（測試自行產碼用）
	totpSecret string
}

// setupAuthSourceEnv 真 handler ＋ 真 audit service ＋ 真 sqlite（同步寫入，
// 每一次紅都是真的缺列而非「等不到」）
func setupAuthSourceEnv(t *testing.T) *authSrcEnv {
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
		&model.UserExternalIdentity{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	policies := policy.NewSecurityPolicyService(db)
	auth, err := identity.NewAuthServiceWithMFA(authSrcSecret, 15*time.Minute,
		aesColumnCodec(t, make([]byte, 32)))
	if err != nil {
		t.Fatalf("NewAuthServiceWithMFA: %v", err)
	}
	auth.SetSecurityPolicies(policies)
	auth.SetEpochGateDB(db)

	auditService := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	h := NewAuthHandler(auth, auditService)

	p := model.OIDCProvider{
		Name: "corp-idp", Issuer: "https://idp.example.com", ClientID: "cid",
		Enabled: true, AuthEpoch: 2, // 非零起始：驗世代現查而非填零值
	}
	if err := db.Create(&p).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(authSrcPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u := &model.User{Username: "source-subject", Password: string(hashed), Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&model.UserExternalIdentity{
		UserID: u.ID, ProviderID: p.ID,
		Issuer: "https://idp.example.com", ClientID: "cid", Subject: "sub-source",
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	env := &authSrcEnv{h: h, auth: auth, db: db, uid: u.ID, pid: p.ID}
	env.clearAudit(t)
	return env
}

func (e *authSrcEnv) clearAudit(t *testing.T) {
	t.Helper()
	if err := e.db.Exec("DELETE FROM audit_logs").Error; err != nil {
		t.Fatalf("清空審計列: %v", err)
	}
}

func (e *authSrcEnv) rows(t *testing.T) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatalf("讀審計列: %v", err)
	}
	return rows
}

// enableTOTP 讓測試使用者完成 TOTP 綁定（走服務層真流程，不手工塞欄位）
func (e *authSrcEnv) enableTOTP(t *testing.T) {
	t.Helper()
	setup, err := e.auth.GenerateMFASetup(e.uid)
	if err != nil {
		t.Fatalf("GenerateMFASetup: %v", err)
	}
	// 綁定用碼取**前一個時間窗**：與後續驗證碼不同，否則 MFA 重放防護會擋下驗證
	code, err := totp.GenerateCode(setup.Secret, time.Now().Add(-totpTestPeriod))
	if err != nil {
		t.Fatalf("TOTP code: %v", err)
	}
	if err := e.auth.EnableMFA(e.uid, code); err != nil {
		t.Fatalf("EnableMFA: %v", err)
	}
	e.totpSecret = setup.Secret
	e.clearAudit(t)
}

// oidcPendingToken 以外部身分（OIDC）走到 MFA 第二階段，取得 pending token
func (e *authSrcEnv) oidcPendingToken(t *testing.T) string {
	t.Helper()
	var u model.User
	if err := e.db.First(&u, e.uid).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	var p model.OIDCProvider
	if err := e.db.First(&p, e.pid).Error; err != nil {
		t.Fatalf("load provider: %v", err)
	}
	resp, err := e.auth.LoginWithExternalIdentity(&u, crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: p.ID,
		AuthEpoch: p.AuthEpoch, CredEpoch: u.CredentialEpoch,
	})
	if err != nil {
		t.Fatalf("LoginWithExternalIdentity: %v", err)
	}
	if !resp.MFARequired || resp.PendingToken == "" {
		t.Fatalf("應進入 MFA 第二階段，實得 MFARequired=%v", resp.MFARequired)
	}
	e.clearAudit(t)
	return resp.PendingToken
}

// post 打端點並帶上全部六種偽造轉送標頭（withHeaders=false 時不帶，作對照）
func (e *authSrcEnv) post(t *testing.T, path string, handler gin.HandlerFunc,
	payload any, withHeaders bool) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.POST(path, handler)
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if withHeaders {
		for k, v := range authSrcForgedHeaders {
			req.Header.Set(k, v)
		}
	}
	req.RemoteAddr = authSrcRemoteAddr
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// postWithCookie 同 post，但憑證以 refresh cookie 攜帶（刷新端點的唯一取值來源），
// 一樣帶上全部六種偽造轉送標頭
func (e *authSrcEnv) postWithCookie(t *testing.T, path string, handler gin.HandlerFunc,
	refreshPlain string) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.POST(path, handler)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range authSrcForgedHeaders {
		req.Header.Set(k, v)
	}
	req.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: refreshPlain})
	req.RemoteAddr = authSrcRemoteAddr
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// assertPeerIP 逐列斷言來源位址為連線對端，且不含任何偽造值
func assertPeerIP(t *testing.T, rows []model.AuditLog) {
	t.Helper()
	if len(rows) == 0 {
		t.Fatal("應至少產生一筆審計列（否則本測試守不到任何東西）")
	}
	for _, r := range rows {
		if r.ClientIP == authSrcForged {
			t.Errorf("列 action=%s status=%s 的 client_ip 落地為**攻擊者指定**的 %s——"+
				"轉送標頭被採信，稽核追人會追到他挑的位址", r.Action, r.Status, r.ClientIP)
			continue
		}
		if r.ClientIP != authSrcPeer {
			t.Errorf("列 action=%s status=%s 的 client_ip = %q，應為連線對端 %s",
				r.Action, r.Status, r.ClientIP, authSrcPeer)
		}
	}
}

// TestLoginAuditIgnoresForwardedHeadersWhenProxyUntrusted 未設可信代理時，
// 本地登入的成功列與失敗列一律取連線對端
func TestLoginAuditIgnoresForwardedHeadersWhenProxyUntrusted(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantCode int
	}{
		{"登入成功", authSrcPassword, http.StatusOK},
		{"登入失敗", "wrong-password", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := setupAuthSourceEnv(t)
			w := env.post(t, "/auth/login", env.h.Login,
				map[string]string{"username": "source-subject", "password": tc.password}, true)
			if w.Code != tc.wantCode {
				t.Fatalf("狀態碼 %d，預期 %d", w.Code, tc.wantCode)
			}
			assertPeerIP(t, env.rows(t))
		})
	}
}

// TestRefreshAuditIgnoresForwardedHeaders 刷新端點同屬公開端點，同一條紀律
func TestRefreshAuditIgnoresForwardedHeaders(t *testing.T) {
	env := setupAuthSourceEnv(t)
	resp, err := env.auth.Login(&identity.LoginRequest{
		Username: "source-subject", Password: authSrcPassword})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	env.clearAudit(t)

	// 憑證以 httpOnly cookie 攜帶（refresh-token-httponly-cookie）：
	// 本格驗的是來源位址紀律，與憑證的載體無關
	w := env.postWithCookie(t, "/auth/refresh", env.h.Refresh, resp.RefreshToken)
	if w.Code != http.StatusOK {
		t.Fatalf("刷新應成功，實得 %d：%s", w.Code, w.Body.String())
	}
	assertPeerIP(t, env.rows(t))
}

// TestMFAVerifyAuditIgnoresForwardedHeaders MFA 完成路徑（正式會話的成功列由此寫出）
func TestMFAVerifyAuditIgnoresForwardedHeaders(t *testing.T) {
	env := setupAuthSourceEnv(t)
	env.enableTOTP(t)
	token := env.oidcPendingToken(t)

	code, err := totp.GenerateCode(env.totpSecret, time.Now())
	if err != nil {
		t.Fatalf("TOTP code: %v", err)
	}
	w := env.post(t, "/auth/mfa/verify", env.h.MFAVerify,
		map[string]string{"pending_token": token, "code": code}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("MFA 驗證應成功，實得 %d：%s", w.Code, w.Body.String())
	}
	assertPeerIP(t, env.rows(t))
}

// TestTrustedProxyConfiguredEnablesForwardedHeader 可信代理**已顯式約定**時才採信
// 轉送標頭——7.3 的設定路徑存在性：預設不採信，要採信必須部署方顯式宣告
// `TRUSTED_PROXIES`（非法即拒絕啟動，見 cmd/server/stage1.go）。
//
// 沒有這一格，「一律取 socket 對端」與「正確實作」在測試上不可區分，
// 代理後部署的真實來源位址會被靜默壓成代理的位址而無人察覺
func TestTrustedProxyConfiguredEnablesForwardedHeader(t *testing.T) {
	env := setupAuthSourceEnv(t)
	env.h.trustProxy = true

	w := env.post(t, "/auth/login", env.h.Login,
		map[string]string{"username": "source-subject", "password": authSrcPassword}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("登入應成功，實得 %d", w.Code)
	}
	rows := env.rows(t)
	if len(rows) == 0 {
		t.Fatal("應產生登入審計列")
	}
	for _, r := range rows {
		if r.ClientIP != authSrcForged {
			t.Errorf("已約定可信代理時應採信轉送標頭，client_ip = %q，預期 %s",
				r.ClientIP, authSrcForged)
		}
	}
}

// TestMFACompletionAuditCarriesProvider MFA 完成路徑的成功列必須答得出
// 「經哪個 provider 認證」（spec oidc-auth「登入 gate chain 匯流」）。
//
// 形態與 OIDC 直登成功列一致（`oidc_handler.go` 的 auditOIDCLogin）：
// Details 帶 provider_id／provider_name／auth_method，ErrorMsg 附註 source=oidc
func TestMFACompletionAuditCarriesProvider(t *testing.T) {
	env := setupAuthSourceEnv(t)
	env.enableTOTP(t)
	token := env.oidcPendingToken(t)

	code, err := totp.GenerateCode(env.totpSecret, time.Now())
	if err != nil {
		t.Fatalf("TOTP code: %v", err)
	}
	w := env.post(t, "/auth/mfa/verify", env.h.MFAVerify,
		map[string]string{"pending_token": token, "code": code}, false)
	if w.Code != http.StatusOK {
		t.Fatalf("MFA 驗證應成功，實得 %d：%s", w.Code, w.Body.String())
	}

	rows := env.rows(t)
	var success *model.AuditLog
	for i := range rows {
		if rows[i].Action == model.ActionLogin && rows[i].Status == model.StatusSuccess {
			success = &rows[i]
		}
	}
	if success == nil {
		t.Fatalf("MFA 完成應寫出一筆登入成功列，實得 %d 筆列", len(rows))
	}
	if !strings.Contains(success.ErrorMsg, "source="+crypto.AuthMethodOIDC) {
		t.Errorf("成功列應附註認證方式，error_msg = %q", success.ErrorMsg)
	}
	if success.Details == "" {
		t.Fatal("成功列無 Details——provider 無處可查（2.9 的缺陷原貌）")
	}
	var d struct {
		ProviderID   uint   `json:"provider_id"`
		ProviderName string `json:"provider_name"`
		AuthMethod   string `json:"auth_method"`
	}
	if err := json.Unmarshal([]byte(success.Details), &d); err != nil {
		t.Fatalf("Details 非合法 JSON（%q）: %v", success.Details, err)
	}
	if d.ProviderID != env.pid {
		t.Errorf("details.provider_id = %d，預期 %d", d.ProviderID, env.pid)
	}
	if d.ProviderName != "corp-idp" {
		t.Errorf("details.provider_name = %q，預期 corp-idp——"+
			"provider 可被改名或刪除，只留 ID 事後未必查得回身分來源", d.ProviderName)
	}
	if d.AuthMethod != crypto.AuthMethodOIDC {
		t.Errorf("details.auth_method = %q，預期 %s", d.AuthMethod, crypto.AuthMethodOIDC)
	}
}

// TestLocalLoginAuditKeepsNoProviderDetails 反向斷言：本地密碼登入不得被標成
// 有 provider——否則「標註」變成無差別附加，稽核無法用它分流
func TestLocalLoginAuditKeepsNoProviderDetails(t *testing.T) {
	env := setupAuthSourceEnv(t)
	env.enableTOTP(t)

	resp, err := env.auth.Login(&identity.LoginRequest{
		Username: "source-subject", Password: authSrcPassword})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !resp.MFARequired {
		t.Fatal("已綁 TOTP 的本地登入應進入 MFA 第二階段")
	}
	env.clearAudit(t)

	code, err := totp.GenerateCode(env.totpSecret, time.Now())
	if err != nil {
		t.Fatalf("TOTP code: %v", err)
	}
	w := env.post(t, "/auth/mfa/verify", env.h.MFAVerify,
		map[string]string{"pending_token": resp.PendingToken, "code": code}, false)
	if w.Code != http.StatusOK {
		t.Fatalf("MFA 驗證應成功，實得 %d：%s", w.Code, w.Body.String())
	}
	for _, r := range env.rows(t) {
		if r.Action == model.ActionLogin && r.Status == model.StatusSuccess && r.Details != "" {
			t.Errorf("本地登入的成功列不應帶 provider Details，實得 %q", r.Details)
		}
	}
}
