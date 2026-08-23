package identity_test

// identity 測試夾具的複本：OIDC 生命週期環境。理由見 identity_fixtures_test.go 檔頭。

import (
	"context"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"net/url"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// OIDC 全鏈路測試環境（共用）。
//
// 與 oidc_flow_test.go 的 setupOIDCEnv 的差別只有兩點，但兩點都是這三項任務的前提：
//
//	MFA 能力  auth 以 identity.NewAuthServiceWithMFA 建構——沒有 mfaCrypto 就簽不出可完成的
//	          pending／enrollment token，「MFA 完成點的世代閘」只能驗到錯誤訊息形狀。
//	fake IdP  provider 的 issuer 指向 fake IdP，使 begin → callback 這一段（七個
//	          驗證點的第一點：flow state）能真的跑完，而不是只斷言到內部函式。

// oidcLifecycleEnv 一組互相接得起來的服務（共用同一個 sqlite :memory:）
type oidcLifecycleEnv struct {
	login     *identity.OIDCLoginService
	providers *identity.OIDCProviderService
	auth      *identity.AuthService
	policies  *policy.SecurityPolicyService
	idp       *fakeIdP
	provider  *model.OIDCProvider
	db        *gorm.DB
}

func setupOIDCLifecycleEnv(t *testing.T) *oidcLifecycleEnv {
	t.Helper()
	// 沿用既有 fixture 的 migration、身分域唯一索引與 database.DB 置換；
	// 其回傳的 login 服務（非 MFA auth）在此不採用
	_, providers, db := setupOIDCEnv(t)

	policies := policy.NewSecurityPolicyService(db)
	auth, err := identity.NewAuthServiceWithMFA("test-secret", 15*time.Minute, aesColumnCodec(t, testMFAKey))
	if err != nil {
		t.Fatalf("identity.NewAuthServiceWithMFA: %v", err)
	}
	auth.SetSecurityPolicies(policies)

	idp := newFakeIdP(t)
	login := identity.NewOIDCLoginService(db, providers, identity.NewOIDCDiscoveryService(testEgress()), auth, nil)
	login.SetAuditSinkForTest(newRecordingAudit())

	p := seedProvider(t, db, func(p *model.OIDCProvider) {
		p.Issuer = idp.issuer
		p.ClientID = "test-client"
		p.AdmissionMode = model.AdmissionJITWithRules
		p.AdmissionRules = `{"hd":["corp.example"]}`
	})

	return &oidcLifecycleEnv{
		login: login, providers: providers, auth: auth, policies: policies,
		idp: idp, provider: p, db: db,
	}
}

// seedIdentityUser 建立「已與本 provider 綁定外部身分」的使用者。
// 身分列以三元組落庫（非 provider_id），與 production 的查找鍵一致
func (e *oidcLifecycleEnv) seedIdentityUser(t *testing.T, username, subject string,
	mutate func(*model.User)) *model.User {
	t.Helper()
	u := &model.User{
		Username: username, Password: "x", Active: true,
		ProvisioningOrigin: model.AuthSourceOIDC, ExternalCredential: true,
	}
	if mutate != nil {
		mutate(u)
	}
	if err := e.db.Create(u).Error; err != nil {
		t.Fatalf("建立使用者 %s: %v", username, err)
	}
	if err := e.db.Create(&model.UserExternalIdentity{
		UserID: u.ID, ProviderID: e.provider.ID,
		Issuer: e.provider.Issuer, ClientID: e.provider.ClientID, Subject: subject,
	}).Error; err != nil {
		t.Fatalf("建立外部身分 %s: %v", subject, err)
	}
	return u
}

// seedMFAIdentityUser 同上並啟用 TOTP（secret 以測試金鑰加密，與 production 同一 AAD 參照）
func (e *oidcLifecycleEnv) seedMFAIdentityUser(t *testing.T, username, subject string) *model.User {
	t.Helper()
	enc := encryptTestSecret(t, e.auth)
	return e.seedIdentityUser(t, username, subject, func(u *model.User) {
		u.TOTPSecretEnc = enc
		u.TOTPEnabled = true
	})
}

// seedLocalUser 純本地密碼帳號（provider 停用時的對照組：不得被牽連）
func (e *oidcLifecycleEnv) seedLocalUser(t *testing.T, username, password string,
	mutate func(*model.User)) *model.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	now := time.Now()
	u := &model.User{
		Username: username, Password: string(hash), Active: true,
		ProvisioningOrigin: model.AuthSourceLocal, PasswordChangedAt: &now,
	}
	if mutate != nil {
		mutate(u)
	}
	if err := e.db.Create(u).Error; err != nil {
		t.Fatalf("建立本地使用者 %s: %v", username, err)
	}
	return u
}

// oidcCtxFor 本次以 OIDC 認證的脈絡（世代現查，與 production 的 buildAuthContext 同源）
func (e *oidcLifecycleEnv) oidcCtxFor(user *model.User) crypto.AuthContext {
	return e.auth.BuildAuthContextForTest(user, crypto.AuthMethodOIDC, e.provider.ID)
}

// setProviderEnabled 經管理服務停用／啟用（走完整失效流程，不直接改欄位——
// 直接 UPDATE enabled 不會推進 auth_epoch，整組測試會因前提不成立而失去意義）
func (e *oidcLifecycleEnv) setProviderEnabled(t *testing.T, enabled bool) {
	t.Helper()
	if _, err := e.providers.Update(e.provider.ID, &identity.OIDCProviderRequest{
		Enabled: boolPtr(enabled)}); err != nil {
		t.Fatalf("設定 provider enabled=%v: %v", enabled, err)
	}
}

// providerAuthEpoch 目前的 provider 世代（Unscoped，軟刪後仍可觀測）
func (e *oidcLifecycleEnv) providerAuthEpoch(t *testing.T) int {
	t.Helper()
	return reloadProvider(t, e.db, e.provider.ID).AuthEpoch
}

// expectFlowChallenge 指定 fake IdP 於 /token 配對的 PKCE challenge，並清除
// 先前累積的配對失敗旗標。
//
// **為什麼必須有這個 helper**：fakeIdP 的 expectedChallenge 是單槽且 pkceMismatch
// 具黏性。一個測試若先後發起兩次流程，後發起者會覆寫 challenge，先發起的那個
// callback 即使走到 IdP 也必然因 PKCE 不符而失敗——於是「provider 停用後 callback
// 被拒」會因為錯誤的理由變綠（守衛假綠）。逐次校準 challenge 之後，拿掉世代閘
// 這條斷言才會真的轉紅
func expectFlowChallenge(idp *fakeIdP, challenge string) {
	idp.mu.Lock()
	idp.expectedChallenge = challenge
	idp.pkceMismatch = false
	idp.mu.Unlock()
}

// beginFlowWithChallenge 同 beginFlow，但額外回傳授權請求送出的 code_challenge，
// 供稍後（可能已有其他流程覆寫過 IdP 期望值時）重新校準
func beginFlowWithChallenge(t *testing.T, login *identity.OIDCLoginService, p *model.OIDCProvider,
	browserSecret string) (state, nonce, challenge string) {
	t.Helper()
	res, err := login.Begin(context.Background(), p.ID, sha256Hex(browserSecret), "/dashboard")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	u, err := url.Parse(res.AuthorizationURL)
	if err != nil {
		t.Fatalf("解析授權 URL: %v", err)
	}
	q := u.Query()
	state, nonce, challenge = q.Get("state"), q.Get("nonce"), q.Get("code_challenge")
	if state == "" || nonce == "" || challenge == "" {
		t.Fatalf("授權 URL 應帶 state／nonce／code_challenge，實得 %s", res.AuthorizationURL)
	}
	return state, nonce, challenge
}

// boolPtr 取位址小工具（原件隨 change_secret_plan_service_test.go
// 遷入 asset 包，跨包取不到；逐字複製一份）。
func boolPtr(b bool) *bool { return &b }
