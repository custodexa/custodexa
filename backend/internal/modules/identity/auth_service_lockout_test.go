package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupLockoutEnv sqlite in-memory + 全域 database.DB 置換（AuthService 走全域 DB）
func setupLockoutEnv(t *testing.T) (*AuthService, *policy.SecurityPolicyService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{}, &model.PasswordHistory{}, &model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	auth := NewAuthService("test-secret", 15*time.Minute)
	policies := policy.NewSecurityPolicyService(db)
	auth.SetSecurityPolicies(policies)
	return auth, policies, db
}

func seedLockoutUser(t *testing.T, db *gorm.DB, password string) *model.User {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	user := &model.User{Username: "bob", Email: strPtr("b@x"), Password: string(hash), Active: true}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func TestLockoutAfterMaxAttempts(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin")
	user := seedLockoutUser(t, db, "right-pass-1")

	// 前 2 次失敗回憑證錯誤
	for i := 0; i < 2; i++ {
		_, err := auth.Login(&LoginRequest{Username: "bob", Password: "wrong"})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("第 %d 次失敗 = %v, want ErrInvalidCredentials", i+1, err)
		}
	}

	// 第 3 次達門檻：明示鎖定訊息
	_, err := auth.Login(&LoginRequest{Username: "bob", Password: "wrong"})
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("達門檻 = %v, want ErrAccountLocked", err)
	}

	// 鎖定中即使密碼正確也拒絕（鎖定 gate 先於密碼驗證）
	_, err = auth.Login(&LoginRequest{Username: "bob", Password: "right-pass-1"})
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("鎖定中正確密碼 = %v, want ErrAccountLocked", err)
	}

	var reloaded model.User
	db.First(&reloaded, user.ID)
	if reloaded.LockedUntil == nil {
		t.Fatal("locked_until 應已設定")
	}
}

// TestLockoutExpiryResetsCounter 到期放行時計數歸零，否則合法用戶每 30 分只能試 1 次
func TestLockoutExpiryResetsCounter(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin")
	user := seedLockoutUser(t, db, "right-pass-1")

	// 模擬已達門檻且鎖定已過期
	past := time.Now().Add(-time.Minute)
	db.Model(user).Updates(map[string]interface{}{
		"failed_login_attempts": 3,
		"locked_until":          past,
	})

	// 到期後第一次失敗：計數應已歸零再 +1（=1 < 3），回憑證錯誤而非立刻再鎖
	_, err := auth.Login(&LoginRequest{Username: "bob", Password: "wrong"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("到期後首次失敗 = %v, want ErrInvalidCredentials（死循環未修）", err)
	}

	var reloaded model.User
	db.First(&reloaded, user.ID)
	if reloaded.FailedLoginAttempts != 1 {
		t.Errorf("計數 = %d, want 1（到期放行應歸零後再計）", reloaded.FailedLoginAttempts)
	}
	if reloaded.LockedUntil != nil {
		t.Error("locked_until 應已清除")
	}
}

func TestLockoutDisabledByZero(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	policies.Update(policy.PolicyLockoutMaxAttempts, "0", "admin")
	seedLockoutUser(t, db, "right-pass-1")

	// 0=停用：連錯 20 次也不鎖（dev/E2E 開關）
	for i := 0; i < 20; i++ {
		_, err := auth.Login(&LoginRequest{Username: "bob", Password: "wrong"})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("停用鎖定時第 %d 次 = %v, want ErrInvalidCredentials", i+1, err)
		}
	}

	_, err := auth.Login(&LoginRequest{Username: "bob", Password: "right-pass-1"})
	if err != nil {
		t.Fatalf("停用鎖定後正確密碼 = %v, want 成功", err)
	}
}

func TestLoginSuccessResetsCounterAndLastLogin(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	policies.Update(policy.PolicyLockoutMaxAttempts, "5", "admin")
	user := seedLockoutUser(t, db, "right-pass-1")

	auth.Login(&LoginRequest{Username: "bob", Password: "wrong"})
	auth.Login(&LoginRequest{Username: "bob", Password: "wrong"})

	resp, err := auth.Login(&LoginRequest{Username: "bob", Password: "right-pass-1"})
	if err != nil || resp.Token == "" {
		t.Fatalf("成功登入 = %v", err)
	}

	var reloaded model.User
	db.First(&reloaded, user.ID)
	if reloaded.FailedLoginAttempts != 0 {
		t.Errorf("成功後計數 = %d, want 0", reloaded.FailedLoginAttempts)
	}
	if reloaded.LastLoginAt == nil {
		t.Error("last_login_at 應更新")
	}
}

func TestMustChangeGateIssuesScopedToken(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")
	db.Model(user).Update("must_change_password", true)

	resp, err := auth.Login(&LoginRequest{Username: "bob", Password: "right-pass-1"})
	if err != nil {
		t.Fatalf("登入 = %v", err)
	}
	if !resp.PasswordChangeRequired || resp.ChangeToken == "" {
		t.Fatalf("應回 password_change_required + change_token, got %+v", resp)
	}
	if resp.Token != "" {
		t.Error("強制改密時不得發正式 token")
	}

	// change token 帶 password_change scope（handler 以 ValidateToken + inline scope 檢查解析）
	claims, err := auth.ValidateToken(resp.ChangeToken)
	if err != nil {
		t.Fatalf("ValidateToken = %v", err)
	}
	if claims.UserID != user.ID || claims.Scope != crypto.ScopePasswordChange {
		t.Errorf("claims = %+v", claims)
	}

	// 正式 token 不得走改密 scoped 通道以外的驗證：scoped token 不可建連線
	if _, err := auth.ValidateConnectionToken(resp.ChangeToken); !errors.Is(err, ErrConnectionNotAuthorized) {
		t.Errorf("scoped token 建連線 = %v, want ErrConnectionNotAuthorized", err)
	}
}

// TestMFAFailureSharesLockoutCounter TOTP 失敗與密碼失敗共用計數，
// 否則持被竊密碼者可在每個 pending 窗內無限暴力猜 6 位 TOTP
func TestMFAFailureSharesLockoutCounter(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{}, &model.PasswordHistory{}, &model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	auth, err := NewAuthServiceWithMFA("test-secret", 15*time.Minute, aesColumnCodec(t, []byte("dev-key-for-testing-only-ok32bts")))
	if err != nil {
		t.Fatalf("NewAuthServiceWithMFA: %v", err)
	}
	policies := policy.NewSecurityPolicyService(db)
	policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin")
	auth.SetSecurityPolicies(policies)

	user := seedLockoutUser(t, db, "right-pass-1")
	setup, err := auth.GenerateMFASetup(user.ID)
	if err != nil {
		t.Fatalf("GenerateMFASetup: %v", err)
	}
	code, _ := totp.GenerateCode(setup.Secret, time.Now())
	if err := auth.EnableMFA(user.ID, code); err != nil {
		t.Fatalf("EnableMFA: %v", err)
	}

	resp, err := auth.Login(&LoginRequest{Username: "bob", Password: "right-pass-1"})
	if err != nil || !resp.MFARequired {
		t.Fatalf("MFA 第一階段 = %+v, %v", resp, err)
	}

	// 保證錯誤的碼：正確碼首位數字 +1（mod 10）
	wrongCode := string(rune('0'+((code[0]-'0'+1)%10))) + code[1:]

	// 前 2 次 TOTP 失敗
	for i := 0; i < 2; i++ {
		_, err := auth.VerifyMFALogin(&MFAVerifyRequest{PendingToken: resp.PendingToken, Code: wrongCode})
		if !errors.Is(err, ErrMFAInvalidCode) {
			t.Fatalf("第 %d 次 TOTP 失敗 = %v, want ErrMFAInvalidCode", i+1, err)
		}
	}

	// 第 3 次達門檻鎖定（與密碼失敗共用計數）
	_, err = auth.VerifyMFALogin(&MFAVerifyRequest{PendingToken: resp.PendingToken, Code: wrongCode})
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("TOTP 達門檻 = %v, want ErrAccountLocked", err)
	}

	// 鎖定中正確 TOTP 也拒絕
	freshCode, _ := totp.GenerateCode(setup.Secret, time.Now())
	_, err = auth.VerifyMFALogin(&MFAVerifyRequest{PendingToken: resp.PendingToken, Code: freshCode})
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("鎖定中正確 TOTP = %v, want ErrAccountLocked", err)
	}
}

// TestFinishLoginReChecksLockout LOCK-2：密碼 gate 通過後、發 token 前，若帳號已被
// 並發失敗鎖定，不得放行（模擬突發中夾帶正確密碼）
func TestFinishLoginReChecksLockout(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin")
	user := seedLockoutUser(t, db, "right-pass-1")

	// 模擬：密碼正確通過 verifyCredentials 後，另一並發失敗突發把帳號鎖了
	future := time.Now().Add(30 * time.Minute)
	db.Model(user).Update("locked_until", future)

	// 直接呼叫 finishLogin（等同密碼已過 gate）：複查應攔下
	if _, err := auth.finishLogin(user, nil, crypto.AuthContext{}); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("發 token 前複查 = %v, want ErrAccountLocked", err)
	}
}

// TestLockoutDurationOverflowRejected LOCK-1：溢位級鎖定時長被政策層擋下，
// 不會產生落到過去的 locked_until 而靜默解鎖
func TestLockoutDurationOverflowRejected(t *testing.T) {
	_, policies, _ := setupLockoutEnv(t)
	if _, err := policies.Update(policy.PolicyLockoutDurationMinutes, "200000000", "admin"); !errors.Is(err, policy.ErrPolicyInvalidValue) {
		t.Errorf("溢位級鎖定時長 = %v, want policy.ErrPolicyInvalidValue（不得落庫致靜默解鎖）", err)
	}
}

// TestCheckUserConnectable AUTH-1：connect-token 路徑共用的用戶狀態重載
func TestCheckUserConnectable(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")

	if err := auth.CheckUserConnectable(user.ID); err != nil {
		t.Fatalf("正常用戶 = %v, want nil", err)
	}

	db.Model(user).Update("active", false)
	if err := auth.CheckUserConnectable(user.ID); !errors.Is(err, ErrUserInactive) {
		t.Errorf("停用 = %v, want ErrUserInactive", err)
	}

	future := time.Now().Add(30 * time.Minute)
	db.Model(user).Updates(map[string]interface{}{"active": true, "locked_until": future})
	if err := auth.CheckUserConnectable(user.ID); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("鎖定中 = %v, want ErrAccountLocked", err)
	}
}

func TestValidateConnectionTokenReloadsUserState(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")

	resp, err := auth.Login(&LoginRequest{Username: "bob", Password: "right-pass-1"})
	if err != nil || resp.Token == "" {
		t.Fatalf("登入 = %v", err)
	}

	// 正常 token 可建連線
	if _, err := auth.ValidateConnectionToken(resp.Token); err != nil {
		t.Fatalf("正常 token = %v", err)
	}

	// 停用後：未過期 token 不得開新連線（即時撤權殘窗）
	db.Model(user).Update("active", false)
	if _, err := auth.ValidateConnectionToken(resp.Token); !errors.Is(err, ErrUserInactive) {
		t.Errorf("停用後 = %v, want ErrUserInactive", err)
	}

	// 鎖定中：不得開新連線（既有會話不砍，僅擋新連線）
	future := time.Now().Add(30 * time.Minute)
	db.Model(user).Updates(map[string]interface{}{"active": true, "locked_until": future})
	if _, err := auth.ValidateConnectionToken(resp.Token); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("鎖定中 = %v, want ErrAccountLocked", err)
	}
}
