package api

import (
	"bytes"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"net/http"
	"net/http/httptest"
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

// 改密後認證脈絡不被洗白。
//
// 混合帳號（有本地密碼、同時綁了外部身分）以 OIDC 登入後自願改密，handler 會
// **直接換發正式 token**（見 auth_handler.go 的 ChangePassword：不重走登入）。換發時若把脈絡
// 當成新的一次本地登入（method=local_password、provider_id=0），使用者就得到一張
// 對 provider 停用完全免疫的憑證——「改個密碼即可脫離 IdP 治理」是一條靠改密
// 就能自助取得的永久後門，而所有既有測試（改密成功、refresh 被撤、政策驗證）
// 都會照樣全綠。
//
// 本檔的核心斷言只有一句：**換發後的 access 與 refresh 仍帶原本的 provider 脈絡，
// 且 provider 停用時一併失效**。
//
// 突變自檢：把 auth_handler.go 的
// `h.authService.IssueSessionResponse(claims.UserID, claims.EffectiveMethod(), claims.ProviderID)`
// 改成 `..., crypto.AuthMethodLocalPassword, 0)`，本檔前兩個測試轉紅。

const (
	pwCtxOldPassword = "OldPassw0rd!x"
	pwCtxNewPassword = "NewPassw0rd!y"
)

type pwCtxEnv struct {
	h    *AuthHandler
	auth *identity.AuthService
	db   *gorm.DB
	pid  uint
	uid  uint
}

func setupPasswordContextEnv(t *testing.T) *pwCtxEnv {
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
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.RefreshToken{},
		&model.SecurityPolicy{}, &model.PasswordHistory{}, &model.OIDCProvider{},
		&model.UserExternalIdentity{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	policies := policy.NewSecurityPolicyService(db)
	auth := identity.NewAuthService("test-secret", 15*time.Minute)
	auth.SetSecurityPolicies(policies)
	users := identity.NewUserService(db, authz.NewAssetAuthorizationService(db))
	users.SetSecurityPolicies(policies)

	h := NewAuthHandler(auth, nil)
	h.SetSourcePolicyReader(unrestrictedSourcePolicy())
	h.SetUserService(users)

	env := &pwCtxEnv{h: h, auth: auth, db: db}
	env.pid = seedPwCtxProvider(t, db)
	env.uid = seedMixedUser(t, db, env.pid)
	return env
}

func seedPwCtxProvider(t *testing.T, db *gorm.DB) uint {
	t.Helper()
	p := model.OIDCProvider{
		Name: "corp", Issuer: "https://idp.example.com", ClientID: "cid",
		Enabled: true, AuthEpoch: 3, // 非零起始：驗「換發時現查」而非「填零值」
	}
	if err := db.Create(&p).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).
		Update("enabled", true).Error; err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	return p.ID
}

// seedMixedUser 混合帳號：有可用的本地密碼（故可自助改密），同時綁了外部身分。
// ProvisioningOrigin 必須是 local——否則 IsExternal() 成立，改密會被 service 直接拒絕
func seedMixedUser(t *testing.T, db *gorm.DB, providerID uint) uint {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(pwCtxOldPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	u := model.User{
		Username: "mixed", Password: string(hash), Active: true,
		ExternalCredential: false, ProvisioningOrigin: model.AuthSourceLocal,
	}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&model.UserExternalIdentity{
		UserID: u.ID, ProviderID: providerID,
		Issuer: "https://idp.example.com", ClientID: "cid", Subject: "sub-mixed",
	}).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	return u.ID
}

// changePassword 打自助改密端點，回傳狀態碼與回應
func (e *pwCtxEnv) changePassword(t *testing.T, bearer, oldPw, newPw string) (int, *identity.LoginResponse) {
	t.Helper()
	router := setupTestRouter()
	router.POST("/auth/change-password", e.h.ChangePassword)

	body, _ := json.Marshal(map[string]string{"old_password": oldPw, "new_password": newPw})
	req := httptest.NewRequest("POST", "/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp identity.LoginResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, &resp
}

// latestRefresh 取該使用者最新一筆未撤銷的 refresh 憑證
func (e *pwCtxEnv) latestRefresh(t *testing.T) *model.RefreshToken {
	t.Helper()
	var r model.RefreshToken
	if err := e.db.Where("user_id = ? AND revoked_at IS NULL", e.uid).
		Order("id DESC").First(&r).Error; err != nil {
		t.Fatalf("查最新 refresh: %v", err)
	}
	return &r
}

// TestChangePasswordKeepsProviderContext 4.14f：改密換發的 access 仍帶 provider 脈絡
func TestChangePasswordKeepsProviderContext(t *testing.T) {
	env := setupPasswordContextEnv(t)

	// 以 OIDC 登入（等同 exchange 完成後拿到的正式會話）
	login, err := env.auth.IssueSessionResponse(env.uid, crypto.AuthMethodOIDC, env.pid)
	if err != nil {
		t.Fatalf("OIDC 登入: %v", err)
	}
	beforeClaims, err := env.auth.ValidateToken(login.Token)
	if err != nil {
		t.Fatalf("驗證登入 token: %v", err)
	}
	if beforeClaims.ProviderID != env.pid || beforeClaims.EffectiveMethod() != crypto.AuthMethodOIDC {
		t.Fatalf("前提不成立：登入 token 未帶 OIDC 脈絡 (%+v)", beforeClaims.AuthContext)
	}

	code, resp := env.changePassword(t, login.Token, pwCtxOldPassword, pwCtxNewPassword)
	if code != http.StatusOK {
		t.Fatalf("改密應成功: code=%d body=%+v", code, resp)
	}
	if resp.Token == "" {
		t.Fatal("改密應直接換發正式 token")
	}

	after, err := env.auth.ValidateToken(resp.Token)
	if err != nil {
		t.Fatalf("驗證換發 token: %v", err)
	}
	if after.EffectiveMethod() != crypto.AuthMethodOIDC {
		t.Errorf("換發 token 的認證方式 = %q，改密把 OIDC 會話洗成了本地會話",
			after.EffectiveMethod())
	}
	if after.ProviderID != env.pid {
		t.Errorf("換發 token 的 provider_id = %d, want %d（脈絡遺失即脫離 provider 治理）",
			after.ProviderID, env.pid)
	}
	if after.AuthEpoch != 3 {
		t.Errorf("換發 token 的 auth_epoch = %d, want 3（應現查 provider 現值）", after.AuthEpoch)
	}

	// 使用者世代必須是**現查值**而非沿用舊 token 的快照
	var user model.User
	if err := env.db.First(&user, env.uid).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if after.CredEpoch != user.CredentialEpoch {
		t.Errorf("換發 token 的 cred_epoch = %d, DB 現值 = %d（沿用舊世代會使新 token 立即失效）",
			after.CredEpoch, user.CredentialEpoch)
	}

	// refresh 亦須帶脈絡：只顧 access 的話，下一次輪替就把脈絡洗掉了
	r := env.latestRefresh(t)
	if r.ProviderID != env.pid || r.AuthMethod != crypto.AuthMethodOIDC {
		t.Errorf("換發的 refresh 脈絡 = (provider=%d, method=%q), want (%d, %q)",
			r.ProviderID, r.AuthMethod, env.pid, crypto.AuthMethodOIDC)
	}
}

// TestChangePasswordIssuedTokenDiesWithProvider 4.14f 的收尾斷言：
// 換發的憑證在 provider 停用時失效。
//
// 前一個測試驗欄位、這一個驗**後果**——欄位對但世代閘接不上（例如 epoch 填了
// 但驗證點沒讀）時，前者仍綠而治理其實不存在
func TestChangePasswordIssuedTokenDiesWithProvider(t *testing.T) {
	env := setupPasswordContextEnv(t)
	login, err := env.auth.IssueSessionResponse(env.uid, crypto.AuthMethodOIDC, env.pid)
	if err != nil {
		t.Fatalf("OIDC 登入: %v", err)
	}
	code, resp := env.changePassword(t, login.Token, pwCtxOldPassword, pwCtxNewPassword)
	if code != http.StatusOK {
		t.Fatalf("改密應成功: code=%d", code)
	}
	claims, err := env.auth.ValidateToken(resp.Token)
	if err != nil {
		t.Fatalf("驗證換發 token: %v", err)
	}

	// 正向對照：停用前該 token 通得過世代閘
	if err := env.auth.VerifyCredentialGenerationByUserID(claims.AuthContext, env.uid); err != nil {
		t.Fatalf("停用前換發的 token 應有效: %v", err)
	}

	// provider 停用（推進世代 + enabled=false，同 3.8 的 DB 效果）
	if err := env.db.Model(&model.OIDCProvider{}).Where("id = ?", env.pid).
		Updates(map[string]any{"enabled": false, "auth_epoch": gorm.Expr("auth_epoch + 1")}).
		Error; err != nil {
		t.Fatalf("停用 provider: %v", err)
	}

	if err := env.auth.VerifyCredentialGenerationByUserID(claims.AuthContext, env.uid); err == nil {
		t.Fatal("provider 停用後，改密換發的 token 仍通過世代閘——改密成了脫離 IdP 治理的後門")
	}
}

// TestChangePasswordLocalLoginStaysLocal 4.14f 的反面對照：
// 本地密碼登入者改密後仍是本地會話，不得憑空長出 provider 脈絡，
// 也不受任何 provider 停用影響（混合帳號的本地那一半不被牽連）
func TestChangePasswordLocalLoginStaysLocal(t *testing.T) {
	env := setupPasswordContextEnv(t)
	login, err := env.auth.IssueSessionResponse(env.uid, crypto.AuthMethodLocalPassword, 0)
	if err != nil {
		t.Fatalf("本地登入: %v", err)
	}
	code, resp := env.changePassword(t, login.Token, pwCtxOldPassword, pwCtxNewPassword)
	if code != http.StatusOK {
		t.Fatalf("改密應成功: code=%d", code)
	}
	claims, err := env.auth.ValidateToken(resp.Token)
	if err != nil {
		t.Fatalf("驗證換發 token: %v", err)
	}
	if claims.ProviderID != 0 {
		t.Errorf("本地登入改密後 provider_id = %d, want 0", claims.ProviderID)
	}
	if claims.EffectiveMethod() != crypto.AuthMethodLocalPassword {
		t.Errorf("本地登入改密後認證方式 = %q, want %q",
			claims.EffectiveMethod(), crypto.AuthMethodLocalPassword)
	}

	if err := env.db.Model(&model.OIDCProvider{}).Where("id = ?", env.pid).
		Updates(map[string]any{"enabled": false, "auth_epoch": gorm.Expr("auth_epoch + 1")}).
		Error; err != nil {
		t.Fatalf("停用 provider: %v", err)
	}
	if err := env.auth.VerifyCredentialGenerationByUserID(claims.AuthContext, env.uid); err != nil {
		t.Errorf("本地會話不應被 provider 停用牽連: %v", err)
	}
}
