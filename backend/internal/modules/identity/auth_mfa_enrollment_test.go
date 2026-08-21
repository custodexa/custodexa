package identity

import (
	"context"
	"errors"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupMFAEnv sqlite in-memory + database.DB 置換 + 含 MFA 加密的 AuthService（真 DB，
// 供 TOTP 防重放 CAS 與 enrollment 流程做確定性測試，避開 sqlmock 對條件 UPDATE 的脆弱）
func setupMFAEnv(t *testing.T) (*AuthService, *policy.SecurityPolicyService, *gorm.DB) {
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

	auth, err := NewAuthServiceWithMFA("secret", 15*time.Minute, aesColumnCodec(t, testMFAKey))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	policies := policy.NewSecurityPolicyService(db)
	auth.SetSecurityPolicies(policies)
	return auth, policies, db
}

// seedMFAUser 建立已啟用 TOTP 的用戶（secret=testTOTPSecret 密文）
func seedMFAUser(t *testing.T, auth *AuthService, db *gorm.DB, roleName string) *model.User {
	t.Helper()
	enc, err := auth.mfaCrypto.EncryptFor(context.Background(), keyvault.RefUserTOTPSecret, testTOTPSecret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("right-pass-1"), bcrypt.MinCost)
	user := &model.User{
		Username: "mfauser", Email: strPtr("m@x"), Password: string(hash), Active: true,
		TOTPSecretEnc: enc, TOTPEnabled: true,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	if roleName != "" {
		role := &model.Role{Name: roleName}
		db.Create(role)
		db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", user.ID, role.ID)
	}
	return user
}

// TestTOTPReplayRejected 8.5.1：同碼再次提交（即使仍在 skew 窗）被拒
func TestTOTPReplayRejected(t *testing.T) {
	auth, _, db := setupMFAEnv(t)
	user := seedMFAUser(t, auth, db, "")

	code, _ := totp.GenerateCode(testTOTPSecret, time.Now())

	// 首次驗證成功並消耗該 step
	if err := auth.VerifyMFACode(user.ID, code); err != nil {
		t.Fatalf("首次驗證 = %v, want nil", err)
	}
	// 同碼重放被拒（step ≤ 已消耗）
	if err := auth.VerifyMFACode(user.ID, code); !errors.Is(err, ErrMFAReplay) {
		t.Errorf("重放 = %v, want ErrMFAReplay", err)
	}

	// last_step 已被推進
	var reloaded model.User
	db.First(&reloaded, user.ID)
	if reloaded.TOTPLastStep == nil {
		t.Error("totp_last_step 應已推進")
	}
}

// TestTOTPNextStepAccepted 下一 step 的新碼正常通過
func TestTOTPNextStepAccepted(t *testing.T) {
	auth, _, db := setupMFAEnv(t)
	user := seedMFAUser(t, auth, db, "")

	now := time.Now()
	code1, _ := totp.GenerateCode(testTOTPSecret, now)
	if err := auth.VerifyMFACode(user.ID, code1); err != nil {
		t.Fatalf("step1: %v", err)
	}

	// 前進 60 秒（跨兩個 step，確保不同碼且 step 遞增）
	future := now.Add(60 * time.Second)
	code2, _ := totp.GenerateCode(testTOTPSecret, future)
	if code2 == code1 {
		t.Skip("相鄰碼碰撞（極罕見），跳過")
	}
	// consumeTOTP 用 time.Now()，此測試僅能驗證「新碼在當下 step 視為新」——
	// 直接改 last_step 到過去 step 模擬時間前進後的狀態
	prev := uint64(now.Unix())/30 - 2
	db.Model(user).Update("totp_last_step", prev)
	if err := auth.VerifyMFACode(user.ID, code1); err != nil {
		t.Errorf("step > last 的碼應通過 = %v", err)
	}
}

// TestMFAEnrollmentGateByPolicy D5：三態政策決定誰被導向強制註冊
func TestMFAEnrollmentGateByPolicy(t *testing.T) {
	auth, policies, db := setupMFAEnv(t)

	// 未註冊 TOTP 的一般用戶與 admin
	mkUser := func(name, role string) {
		hash, _ := bcrypt.GenerateFromPassword([]byte("right-pass-1"), bcrypt.MinCost)
		u := &model.User{Username: name, Email: strPtr(name + "@x"), Password: string(hash), Active: true}
		db.Create(u)
		r := &model.Role{Name: role}
		db.Where("name = ?", role).FirstOrCreate(r)
		db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", u.ID, r.ID)
	}
	mkUser("alice", "user")
	mkUser("adminuser", "admin")

	login := func(name string) *LoginResponse {
		resp, err := auth.Login(&LoginRequest{Username: name, Password: "right-pass-1"})
		if err != nil {
			t.Fatalf("login %s: %v", name, err)
		}
		return resp
	}

	// off（預設）：都不強制，直接發 token
	if resp := login("alice"); resp.MFAEnrollmentRequired || resp.Token == "" {
		t.Error("off：一般用戶應直接登入")
	}

	// admin_only：僅 admin 被導向註冊
	policies.Update(policy.PolicyMFARequired, policy.MFARequiredAdminOnly, "admin")
	if resp := login("alice"); resp.MFAEnrollmentRequired {
		t.Error("admin_only：一般用戶不應被強制註冊")
	}
	if resp := login("adminuser"); !resp.MFAEnrollmentRequired || resp.EnrollmentToken == "" {
		t.Error("admin_only：admin 應被導向註冊")
	}

	// all：都被導向註冊
	policies.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin")
	if resp := login("alice"); !resp.MFAEnrollmentRequired || resp.EnrollmentToken == "" {
		t.Error("all：一般用戶應被導向註冊")
	}
}

// TestEnrollmentTokenScopeAndDenyByDefault enrollment token 不可建連線、不可打改密
func TestEnrollmentTokenScopeAndDenyByDefault(t *testing.T) {
	auth, policies, db := setupMFAEnv(t)
	policies.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin")

	hash, _ := bcrypt.GenerateFromPassword([]byte("right-pass-1"), bcrypt.MinCost)
	u := &model.User{Username: "alice", Email: strPtr("a@x"), Password: string(hash), Active: true}
	db.Create(u)

	resp, err := auth.Login(&LoginRequest{Username: "alice", Password: "right-pass-1"})
	if err != nil || resp.EnrollmentToken == "" {
		t.Fatalf("login: %v", err)
	}

	// enrollment token 帶正確 scope
	claims, err := auth.ValidateToken(resp.EnrollmentToken)
	if err != nil || claims.Scope != crypto.ScopeMFAEnrollment {
		t.Fatalf("scope = %+v, %v", claims, err)
	}
	// 不可用於建立連線（deny-by-default）
	if _, err := auth.ValidateConnectionToken(resp.EnrollmentToken); !errors.Is(err, ErrConnectionNotAuthorized) {
		t.Errorf("enrollment 建連線 = %v, want ErrConnectionNotAuthorized", err)
	}
}

// TestCompleteEnrollmentIssuesSession D12：綁定完成直接換發正式 token
func TestCompleteEnrollmentIssuesSession(t *testing.T) {
	auth, policies, db := setupMFAEnv(t)
	policies.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin")

	hash, _ := bcrypt.GenerateFromPassword([]byte("right-pass-1"), bcrypt.MinCost)
	u := &model.User{Username: "alice", Email: strPtr("a@x"), Password: string(hash), Active: true}
	db.Create(u)

	resp, err := auth.Login(&LoginRequest{Username: "alice", Password: "right-pass-1"})
	if err != nil || resp.EnrollmentToken == "" {
		t.Fatalf("login: %v", err)
	}

	// setup 產生 secret
	setup, err := auth.EnrollmentSetup(resp.EnrollmentToken)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// 以產生的 secret 算碼完成綁定
	code, _ := totp.GenerateCode(setup.Secret, time.Now())
	final, err := auth.CompleteEnrollment(resp.EnrollmentToken, code)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if final.Token == "" || final.MFAEnrollmentRequired {
		t.Errorf("綁定後應直接換發正式 token, got %+v", final)
	}

	// TOTP 已啟用
	var reloaded model.User
	db.First(&reloaded, u.ID)
	if !reloaded.TOTPEnabled {
		t.Error("綁定後 totp_enabled 應為 true")
	}
}

// TestEnrollmentTokenReplayCannotRebind 對抗驗證 MFA-1：綁定完成後同枚 enrollment token
// 重放 setup/confirm 不得重置或改綁已註冊帳號的第二因子
func TestEnrollmentTokenReplayCannotRebind(t *testing.T) {
	auth, policies, db := setupMFAEnv(t)
	policies.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin")

	hash, _ := bcrypt.GenerateFromPassword([]byte("right-pass-1"), bcrypt.MinCost)
	u := &model.User{Username: "alice", Email: strPtr("a@x"), Password: string(hash), Active: true}
	db.Create(u)

	resp, err := auth.Login(&LoginRequest{Username: "alice", Password: "right-pass-1"})
	if err != nil || resp.EnrollmentToken == "" {
		t.Fatalf("login: %v", err)
	}
	enrollTok := resp.EnrollmentToken

	// 合法完成綁定
	setup, err := auth.EnrollmentSetup(enrollTok)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	boundSecret := setup.Secret
	code, _ := totp.GenerateCode(boundSecret, time.Now())
	if _, err := auth.CompleteEnrollment(enrollTok, code); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// 攻擊：同枚 enrollment token（TTL 未過）重放 setup → 必須被拒（不得重置因子）
	if _, err := auth.EnrollmentSetup(enrollTok); !errors.Is(err, ErrMFAAlreadyEnrolled) {
		t.Errorf("已註冊後 EnrollmentSetup = %v, want ErrMFAAlreadyEnrolled", err)
	}
	// confirm 亦須被拒（縱使搶在他處 setup 之後）
	if _, err := auth.CompleteEnrollment(enrollTok, "000000"); !errors.Is(err, ErrMFAAlreadyEnrolled) {
		t.Errorf("已註冊後 CompleteEnrollment = %v, want ErrMFAAlreadyEnrolled", err)
	}

	// secret 未被改綁：仍為首次綁定的 secret
	var reloaded model.User
	db.First(&reloaded, u.ID)
	if !reloaded.TOTPEnabled {
		t.Error("重放攻擊後 totp_enabled 不應被打回 false")
	}
	dec, _ := auth.mfaCrypto.DecryptFor(context.Background(), keyvault.RefUserTOTPSecret, reloaded.TOTPSecretEnc)
	if dec != boundSecret {
		t.Error("secret 不應被 enrollment token 重放改綁")
	}
}

// TestEnrollmentConfirmFailureCountsToLockout 對抗驗證 MFA-2：綁定確認的碼錯計入共用鎖定計數
func TestEnrollmentConfirmFailureCountsToLockout(t *testing.T) {
	auth, policies, db := setupMFAEnv(t)
	policies.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin")
	policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin")

	hash, _ := bcrypt.GenerateFromPassword([]byte("right-pass-1"), bcrypt.MinCost)
	u := &model.User{Username: "alice", Email: strPtr("a@x"), Password: string(hash), Active: true}
	db.Create(u)

	resp, err := auth.Login(&LoginRequest{Username: "alice", Password: "right-pass-1"})
	if err != nil || resp.EnrollmentToken == "" {
		t.Fatalf("login: %v", err)
	}
	if _, err := auth.EnrollmentSetup(resp.EnrollmentToken); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// 連續錯碼綁定：達門檻後回鎖定（與 VerifyMFALogin 共用計數）
	var lastErr error
	for i := 0; i < 3; i++ {
		_, lastErr = auth.CompleteEnrollment(resp.EnrollmentToken, "000000")
	}
	if !errors.Is(lastErr, ErrAccountLocked) {
		t.Errorf("綁定碼暴力達門檻 = %v, want ErrAccountLocked", lastErr)
	}
	var reloaded model.User
	db.First(&reloaded, u.ID)
	if reloaded.LockedUntil == nil {
		t.Error("綁定碼暴力應觸發帳號鎖定")
	}
}
