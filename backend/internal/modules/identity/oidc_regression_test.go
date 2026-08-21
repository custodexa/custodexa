package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// OIDC 引入後的既有登入鏈路回歸（idp-oidc-integration tasks 2.9）。
//
// 本檔守的是「新機制不得誤傷舊路徑」與「新舊身分域不得互穿」四件事：
//
//	(1) LDAP 登入全鏈路（含 MFA 兩階段）不被世代閘／credential_epoch 誤傷；
//	(2) 本地帳號的密碼 gate、失敗計數與鎖定行為與引入前一致；
//	(3) 外部帳號無法設密碼、無法走本地登入；
//	(4) **OIDC 帳號不可被同名目錄憑證登入**——身分域隔離的跨目錄版本。
//
// 與既有測試的分工：auth_service_ldap_test.go 以 sqlmock 驗證 LDAP 分流的
// **查詢序列**；本檔改用真實 sqlite 走完整鏈路，才驗得到「token 內的認證脈絡」
// 與「世代閘實際比對結果」這類 sqlmock 看不到的性質。

// --- fixture ---

// regressionEnv 真實 sqlite 的完整登入環境（AuthService 走全域 database.DB）
type regressionEnv struct {
	auth     *AuthService
	users    *UserService
	policies *policy.SecurityPolicyService
	db       *gorm.DB
}

// setupRegressionEnv 單連線 :memory:（ff51836：連線池放行第二條即出現
// 「建了資料卻查不到」的假紅）。含 audit_logs——外部帳號本地登入嘗試的審計
// 若因缺表而寫入失敗只會留日誌，斷言「有落審計」需要真的有這張表
func setupRegressionEnv(t *testing.T) *regressionEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{},
		&model.PasswordHistory{}, &model.RefreshToken{}, &model.AuditLog{},
		&model.OIDCProvider{}, &model.UserExternalIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS user_roles (
		user_id INTEGER NOT NULL, role_id INTEGER NOT NULL)`).Error; err != nil {
		t.Fatalf("user_roles: %v", err)
	}
	for _, name := range []string{model.RoleAdmin, model.RoleUser} {
		if err := db.Create(&model.Role{Name: name}).Error; err != nil {
			t.Fatalf("seed role %s: %v", name, err)
		}
	}

	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	// MFA 版建構：LDAP＋MFA 全鏈路需要能解密 TOTP secret
	auth, err := NewAuthServiceWithMFA("test-secret", 15*time.Minute, aesColumnCodec(t, testMFAKey))
	if err != nil {
		t.Fatalf("NewAuthServiceWithMFA: %v", err)
	}
	policies := policy.NewSecurityPolicyService(db)
	auth.SetSecurityPolicies(policies)
	users := NewUserService(db, authz.NewAssetAuthorizationService(db))
	users.SetSecurityPolicies(policies)
	return &regressionEnv{auth: auth, users: users, policies: policies, db: db}
}

// seedRegressionUser 依 adminSpec 的三訊號建帳號，並可指定密碼與 TOTP
func seedRegressionUser(t *testing.T, env *regressionEnv, username, password string,
	mutate func(*model.User)) *model.User {
	t.Helper()
	hash := ""
	if password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		hash = string(h)
	}
	u := &model.User{
		Username: username, Password: hash, Active: true,
		ProvisioningOrigin: model.AuthSourceLocal,
	}
	if mutate != nil {
		mutate(u)
	}
	if err := env.db.Create(u).Error; err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	var role model.Role
	if err := env.db.Where("name = ?", model.RoleUser).First(&role).Error; err != nil {
		t.Fatalf("load user role: %v", err)
	}
	if err := env.db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
		u.ID, role.ID).Error; err != nil {
		t.Fatalf("attach role: %v", err)
	}
	return u
}

// claimsOf 解析已簽發 token，取回認證脈絡（token 內容才是世代閘實際比對的輸入）
func claimsOf(t *testing.T, auth *AuthService, token string) *crypto.Claims {
	t.Helper()
	claims, err := auth.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	return claims
}

// countAuditEvent 統計 audit_logs 內含指定 event 的筆數
func countAuditEvent(t *testing.T, db *gorm.DB, event string) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AuditLog{}).
		Where("details LIKE ?", `%"event":"`+event+`"%`).Count(&n).Error; err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

// enrollTOTP 讓既有帳號成為 MFA 帳號（secret 以測試金鑰加密，模擬綁定完成的狀態）
func enrollTOTP(t *testing.T, env *regressionEnv, userID uint) {
	t.Helper()
	if err := env.db.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
		"totp_secret_enc": encryptTestSecret(t, env.auth),
		"totp_enabled":    true,
	}).Error; err != nil {
		t.Fatalf("enroll totp: %v", err)
	}
}

// --- (1) LDAP 登入全鏈路 ---

// TestRegressionLDAPFirstLoginChainIntact（2.9）首次 LDAP 登入的完整鏈路：
// 供應影子帳號 → 發正式 token → token 帶 ldap 脈絡且 provider 為零值。
//
// 「provider 為零值」是本測試的重點：LDAP 不隸屬任何 OIDC provider，若供應或
// 簽發路徑誤填 provider_id，該 token 會被世代閘以「provider 查無/停用」拒絕，
// 使全體 LDAP 使用者在下一次請求即掉線
func TestRegressionLDAPFirstLoginChainIntact(t *testing.T) {
	env := setupRegressionEnv(t)
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{
		Username: "dir-alice", Email: "dir-alice@corp.example", FullName: "Dir Alice"}}
	env.auth.SetLDAPResolver(staticLDAPResolver(fake))

	resp, err := env.auth.Login(&LoginRequest{Username: "dir-alice", Password: "dirpass"})
	if err != nil {
		t.Fatalf("LDAP 首登應成功: %v", err)
	}
	if resp.Token == "" || resp.RefreshToken == "" {
		t.Fatal("應同時核發 access 與 refresh（無 refresh 的會話 15 分後必斷）")
	}
	if resp.AuthSource != model.AuthSourceLDAP {
		t.Fatalf("auth_source = %q, want ldap", resp.AuthSource)
	}
	if fake.calls != 1 {
		t.Fatalf("目錄呼叫次數 = %d, want 1", fake.calls)
	}

	var shadow model.User
	if err := env.db.Where("username = ?", "dir-alice").First(&shadow).Error; err != nil {
		t.Fatalf("影子帳號應已供應: %v", err)
	}
	if !shadow.IsLDAP || shadow.ProvisioningOrigin != model.AuthSourceLDAP || !shadow.ExternalCredential {
		t.Fatalf("影子帳號身分欄位 = (is_ldap=%v, origin=%q, ext_cred=%v)，want (true, ldap, true)",
			shadow.IsLDAP, shadow.ProvisioningOrigin, shadow.ExternalCredential)
	}
	if !shadow.IsExternal() {
		t.Fatal("LDAP 帳號的 IsExternal() 語義應為外部（密碼類 gate 的總開關）")
	}

	claims := claimsOf(t, env.auth, resp.Token)
	if claims.EffectiveMethod() != crypto.AuthMethodLDAP {
		t.Fatalf("auth_method = %q, want ldap", claims.EffectiveMethod())
	}
	if claims.ProviderID != 0 {
		t.Fatalf("provider_id = %d, want 0（LDAP 不隸屬任何 OIDC provider）", claims.ProviderID)
	}
	if claims.CredEpoch != shadow.CredentialEpoch {
		t.Fatalf("cred_epoch = %d, want %d（簽發時現查）", claims.CredEpoch, shadow.CredentialEpoch)
	}
	// 世代閘實地比對：這是每個請求都會走的判定，過不了即等於登入無效
	if err := epochGateForTest.VerifyCredentialGeneration(claims.AuthContext, &shadow); err != nil {
		t.Fatalf("LDAP token 應通過世代閘: %v", err)
	}
}

// TestRegressionLDAPLoginWithMFAChainIntact（2.9）LDAP＋MFA 兩階段全鏈路：
// 第一階段只發 pending、第二階段發正式 token，且脈絡自 pending 正確繼承。
//
// 一併驗證密碼類 gate 不誤傷：政策設為「密碼 90 天到期」且該帳號
// password_changed_at 為 NULL（本地帳號在此條件下必被導向強制改密），
// LDAP 帳號的密碼由目錄管理，不得被導向一個它永遠走不完的改密流程
func TestRegressionLDAPLoginWithMFAChainIntact(t *testing.T) {
	env := setupRegressionEnv(t)
	env.policies.Update(policy.PolicyPasswordMaxAgeDays, "90", "admin")
	env.policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin")

	user := seedRegressionUser(t, env, "dir-mfa", "", func(u *model.User) {
		u.Password = "irrelevant-directory-side"
		u.IsLDAP = true
		u.ProvisioningOrigin = model.AuthSourceLDAP
		u.ExternalCredential = true
	})
	enrollTOTP(t, env, user.ID)
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{Username: "dir-mfa"}}
	env.auth.SetLDAPResolver(staticLDAPResolver(fake))

	first, err := env.auth.Login(&LoginRequest{Username: "dir-mfa", Password: "dirpass"})
	if err != nil {
		t.Fatalf("LDAP 第一階段應成功: %v", err)
	}
	if !first.MFARequired || first.PendingToken == "" {
		t.Fatalf("應進入 MFA 第二階段，got mfa_required=%v pending=%q",
			first.MFARequired, first.PendingToken)
	}
	if first.Token != "" {
		t.Fatal("MFA 第一階段不得核發正式 token")
	}
	if first.AuthSource != model.AuthSourceLDAP {
		t.Fatalf("第一階段 auth_source = %q, want ldap", first.AuthSource)
	}
	pending := claimsOf(t, env.auth, first.PendingToken)
	if pending.Scope != crypto.ScopeMFAPending || pending.EffectiveMethod() != crypto.AuthMethodLDAP {
		t.Fatalf("pending token = (scope=%q, method=%q), want (mfa_pending, ldap)",
			pending.Scope, pending.EffectiveMethod())
	}

	second, err := env.auth.VerifyMFALogin(&MFAVerifyRequest{
		PendingToken: first.PendingToken, Code: validTestCode(t)})
	if err != nil {
		t.Fatalf("LDAP 帳號的 MFA 第二階段應成功: %v", err)
	}
	if second.Token == "" {
		t.Fatal("第二階段應核發正式 token")
	}
	if second.PasswordChangeRequired {
		t.Fatal("LDAP 帳號不得被密碼有效期 gate 導向改密（密碼由目錄管理）")
	}
	final := claimsOf(t, env.auth, second.Token)
	if final.EffectiveMethod() != crypto.AuthMethodLDAP || final.ProviderID != 0 {
		t.Fatalf("正式 token 脈絡 = (method=%q, provider=%d), want (ldap, 0)",
			final.EffectiveMethod(), final.ProviderID)
	}
	reloaded := reloadUser(t, env.db, user.ID)
	if final.CredEpoch != reloaded.CredentialEpoch {
		t.Fatalf("cred_epoch = %d, want %d（換發一律現查、不繼承）",
			final.CredEpoch, reloaded.CredentialEpoch)
	}
	if reloaded.FailedLoginAttempts != 0 || reloaded.LockedUntil != nil {
		t.Fatal("全過後計數應歸零")
	}
}

// TestRegressionLDAPSessionImmuneToProviderRevocation（2.9）LDAP 既簽會話
// 不受任何 OIDC provider 的停用／世代推進影響。
//
// provider 停用會推進 auth_epoch 並使該 provider 的既簽憑證全滅；若 LDAP token
// 也被牽連，「停用一個 OIDC provider」就會順手把全體目錄使用者踢下線
func TestRegressionLDAPSessionImmuneToProviderRevocation(t *testing.T) {
	env := setupRegressionEnv(t)
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{Username: "dir-bob"}}
	env.auth.SetLDAPResolver(staticLDAPResolver(fake))
	resp, err := env.auth.Login(&LoginRequest{Username: "dir-bob", Password: "dirpass"})
	if err != nil {
		t.Fatalf("LDAP 登入: %v", err)
	}
	claims := claimsOf(t, env.auth, resp.Token)

	// 事後才出現的 provider，並且停用＋推進世代
	p := seedProvider(t, env.db, nil)
	if err := env.db.Model(p).Updates(map[string]any{"enabled": false, "auth_epoch": 99}).Error; err != nil {
		t.Fatalf("停用 provider: %v", err)
	}

	if err := epochGateForTest.VerifyCredentialGenerationByUserID(claims.AuthContext, claims.UserID); err != nil {
		t.Fatalf("LDAP 會話不應受 provider 停用影響: %v", err)
	}
	// 再登入一次同樣不受影響（現查路徑也要乾淨）
	if _, err := env.auth.Login(&LoginRequest{Username: "dir-bob", Password: "dirpass"}); err != nil {
		t.Fatalf("provider 停用後 LDAP 仍應可登入: %v", err)
	}
}

// --- (2) 本地帳號密碼 gate 照舊 ---

// TestRegressionLocalPasswordGateAndLockoutUnchanged（2.9）本地帳號在 OIDC
// 機制齊備（provider 啟用、同系統存在 OIDC 帳號）的環境下，密碼驗證、失敗
// 計數與鎖定行為與引入前完全一致，且 OIDC 帳號的計數不被牽動
func TestRegressionLocalPasswordGateAndLockoutUnchanged(t *testing.T) {
	env := setupRegressionEnv(t)
	env.policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin")
	p := seedProvider(t, env.db, nil)
	oidcUser := seedRegressionUser(t, env, "sso-user", "unused", func(u *model.User) {
		u.ProvisioningOrigin = model.AuthSourceOIDC
		u.ExternalCredential = true
	})
	seedIdentity(t, env.db, oidcUser, p, "sub-sso")
	local := seedRegressionUser(t, env, "local-user", "right-pass-1", nil)

	for i := 0; i < 2; i++ {
		if _, err := env.auth.Login(&LoginRequest{Username: "local-user", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("第 %d 次失敗 = %v, want ErrInvalidCredentials", i+1, err)
		}
	}
	if got := reloadUser(t, env.db, local.ID).FailedLoginAttempts; got != 2 {
		t.Fatalf("失敗計數 = %d, want 2", got)
	}
	if _, err := env.auth.Login(&LoginRequest{Username: "local-user", Password: "wrong"}); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("達門檻 = %v, want ErrAccountLocked", err)
	}
	if _, err := env.auth.Login(&LoginRequest{Username: "local-user", Password: "right-pass-1"}); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("鎖定中正確密碼 = %v, want ErrAccountLocked", err)
	}

	// 解鎖後正常登入，且 token 脈絡為本地密碼（密碼類 gate 的適用前提）
	if err := env.users.Unlock(local.ID); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	resp, err := env.auth.Login(&LoginRequest{Username: "local-user", Password: "right-pass-1"})
	if err != nil {
		t.Fatalf("解鎖後登入應成功: %v", err)
	}
	claims := claimsOf(t, env.auth, resp.Token)
	if claims.EffectiveMethod() != crypto.AuthMethodLocalPassword || claims.ProviderID != 0 {
		t.Fatalf("本地登入脈絡 = (method=%q, provider=%d), want (local_password, 0)",
			claims.EffectiveMethod(), claims.ProviderID)
	}
	if got := reloadUser(t, env.db, oidcUser.ID).FailedLoginAttempts; got != 0 {
		t.Fatalf("OIDC 帳號的計數不應被本地帳號的失敗牽動，got %d", got)
	}
}

// TestRegressionLocalMustChangeGateStillFires（2.9）本地帳號的強制改密 gate
// 照舊生效——「密碼 gate 依本次登入方式判定」的改寫不得讓本地路徑一併鬆掉
func TestRegressionLocalMustChangeGateStillFires(t *testing.T) {
	env := setupRegressionEnv(t)
	user := seedRegressionUser(t, env, "local-user", "right-pass-1", nil)
	if err := env.db.Model(&model.User{}).Where("id = ?", user.ID).
		Update("must_change_password", true).Error; err != nil {
		t.Fatalf("seed must_change: %v", err)
	}

	resp, err := env.auth.Login(&LoginRequest{Username: "local-user", Password: "right-pass-1"})
	if err != nil {
		t.Fatalf("登入: %v", err)
	}
	if !resp.PasswordChangeRequired || resp.ChangeToken == "" {
		t.Fatalf("本地帳號應被導向強制改密，got required=%v token=%q",
			resp.PasswordChangeRequired, resp.ChangeToken)
	}
	if resp.Token != "" {
		t.Fatal("強制改密時不得核發正式 token")
	}
}

// --- (3) 外部帳號無法設密碼／本地登入 ---

// TestRegressionExternalAccountsCannotHoldLocalPassword（2.9）OIDC 與 LDAP
// 兩類外部帳號，admin 重設與自助改密兩條路徑皆須拒絕。
//
// 既有覆蓋：auth_service_ldap_test.go:228 已驗 LDAP 帳號的 admin 重設；
// 此處補 OIDC 帳號與自助改密路徑，並斷言密碼雜湊零變動
func TestRegressionExternalAccountsCannotHoldLocalPassword(t *testing.T) {
	env := setupRegressionEnv(t)
	cases := map[string]func(*model.User){
		"OIDC 帳號": func(u *model.User) {
			u.ProvisioningOrigin = model.AuthSourceOIDC
			u.ExternalCredential = true
		},
		"LDAP 影子帳號": func(u *model.User) {
			u.IsLDAP = true
			u.ProvisioningOrigin = model.AuthSourceLDAP
			u.ExternalCredential = true
		},
		"僅外部登入（來源仍是 local）": func(u *model.User) {
			u.ExternalCredential = true
		},
	}
	i := 0
	for name, mutate := range cases {
		i++
		username := "ext-" + string(rune('a'+i))
		user := seedRegressionUser(t, env, username, "placeholder-pass", mutate)
		before := reloadUser(t, env.db, user.ID).Password

		if err := env.users.ChangePassword(user.ID, "new-password-9"); !errors.Is(err, ErrExternalUserPassword) {
			t.Errorf("%s admin 重設 = %v, want ErrExternalUserPassword", name, err)
		}
		if err := env.users.SelfChangePassword(user.ID, "placeholder-pass", "new-password-9"); !errors.Is(err, ErrExternalUserPassword) {
			t.Errorf("%s 自助改密 = %v, want ErrExternalUserPassword", name, err)
		}
		if after := reloadUser(t, env.db, user.ID).Password; after != before {
			t.Errorf("%s 密碼雜湊不得變動", name)
		}
	}
}

// --- (4) OIDC 帳號不可被同名目錄憑證登入 ---

// TestRegressionOIDCAccountNotLoginableByDirectoryCredentials（2.9）身分域隔離
// 的跨目錄版本：地端 LDAP 與 OIDC 並存的部署中，目錄側出現同名帳號時，
// 以該目錄憑證登入**不得**落到 OIDC 帳號上。
//
// 攻擊面：目錄管理員（或任何能在目錄完成 bind 的人）可為自己建一個與 OIDC
// 帳號同名的目錄帳號。若分派寫成「非 is_ldap 即走本地、其餘走目錄」，OIDC
// 帳號會落入目錄分支，而 authenticateLDAP 對已存在帳號直接 resolved = existing
// ——目錄側 bind 成功即取得該 OIDC 帳號的正式會話，且因 authMethod=ldap 而
// 連密碼 gate 都不套用。
//
// 斷言取「目錄根本沒被呼叫」而非只看回傳錯誤：後者在「有打目錄但目錄剛好拒絕」
// 時也會成立，測不出分派本身是否正確
func TestRegressionOIDCAccountNotLoginableByDirectoryCredentials(t *testing.T) {
	env := setupRegressionEnv(t)
	p := seedProvider(t, env.db, nil)
	victim := seedRegressionUser(t, env, "alice", "placeholder-secret", func(u *model.User) {
		u.ProvisioningOrigin = model.AuthSourceOIDC
		u.ExternalCredential = true
	})
	seedIdentity(t, env.db, victim, p, "sub-alice")

	// 目錄側存在同名帳號且會為任何密碼放行（＝目錄管理員可自行控制的前提）
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{
		Username: "alice", Email: "attacker@corp.example", FullName: "Directory Alice"}}
	env.auth.SetLDAPResolver(staticLDAPResolver(fake))

	resp, err := env.auth.Login(&LoginRequest{Username: "alice", Password: "directory-password"})
	if resp != nil {
		t.Fatal("OIDC 帳號不得因目錄側同名帳號而取得會話")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("同名目錄憑證 = %v, want ErrInvalidCredentials（與一般憑證錯誤不可區分）", err)
	}
	if fake.calls != 0 {
		t.Fatalf("目錄呼叫次數 = %d, want 0（OIDC 帳號根本不該進入目錄分支）", fake.calls)
	}

	// 帳號本體零變動：不得被目錄屬性覆寫，也不得因此被計數／鎖死
	reloaded := reloadUser(t, env.db, victim.ID)
	if reloaded.IsLDAP || reloaded.ProvisioningOrigin != model.AuthSourceOIDC {
		t.Fatalf("OIDC 帳號不得被目錄接管，got (is_ldap=%v, origin=%q)",
			reloaded.IsLDAP, reloaded.ProvisioningOrigin)
	}
	if reloaded.FailedLoginAttempts != 0 || reloaded.LockedUntil != nil {
		t.Fatal("外部帳號的本地/目錄登入嘗試不得計數（否則可被遠端鎖死）")
	}
	var users int64
	env.db.Model(&model.User{}).Count(&users)
	if users != 1 {
		t.Fatalf("不得為同名目錄帳號另行供應影子帳號，users = %d", users)
	}
	if n := countAuditEvent(t, env.db, "external_user_local_login_attempt"); n != 1 {
		t.Fatalf("應留下一筆外部帳號登入嘗試審計，got %d", n)
	}
}

// TestRegressionDirectoryAccountUnaffectedByOIDCNamesake（2.9）反向：目錄帳號
// 的登入不因系統內存在 OIDC 帳號而受阻，且兩者是**不同的帳號列**
func TestRegressionDirectoryAccountUnaffectedByOIDCNamesake(t *testing.T) {
	env := setupRegressionEnv(t)
	p := seedProvider(t, env.db, nil)
	sso := seedRegressionUser(t, env, "alice", "placeholder", func(u *model.User) {
		u.ProvisioningOrigin = model.AuthSourceOIDC
		u.ExternalCredential = true
	})
	seedIdentity(t, env.db, sso, p, "sub-alice")
	env.auth.SetLDAPResolver(staticLDAPResolver(&fakeLDAPAuthenticator{
		info: &LDAPUserInfo{Username: "bob", Email: "bob@corp.example"}}))

	resp, err := env.auth.Login(&LoginRequest{Username: "bob", Password: "dirpass"})
	if err != nil {
		t.Fatalf("目錄帳號登入應成功: %v", err)
	}
	if resp.AuthSource != model.AuthSourceLDAP || resp.Token == "" {
		t.Fatalf("目錄登入回應 = (source=%q, token 空=%v)", resp.AuthSource, resp.Token == "")
	}
	if resp.User.ID == sso.ID {
		t.Fatal("目錄登入不得落到 OIDC 帳號上")
	}
	if !strings.EqualFold(resp.User.Username, "bob") {
		t.Fatalf("登入身分 = %q, want bob", resp.User.Username)
	}
}
