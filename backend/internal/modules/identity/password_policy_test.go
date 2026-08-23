package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupPasswordDB(t *testing.T) (*UserService, *policy.SecurityPolicyService, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{}, &model.PasswordHistory{}, &model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	policies := policy.NewSecurityPolicyService(db)
	users := NewUserService(db, authz.NewAssetAuthorizationService(db))
	users.SetSecurityPolicies(policies)
	return users, policies, db
}

func createTestUser(t *testing.T, users *UserService, db *gorm.DB, password string) *model.User {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	user := &model.User{Username: "alice", Email: strPtr("a@x"), Password: string(hash), Active: true}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	// 初始密碼入歷史（seed/Create 皆如此）
	if err := db.Create(&model.PasswordHistory{UserID: user.ID, PasswordHash: string(hash)}).Error; err != nil {
		t.Fatalf("seed history: %v", err)
	}
	return user
}

func TestValidateNewPasswordLengthAndComposition(t *testing.T) {
	users, _, _ := setupPasswordDB(t)

	// 長度不足（政策預設 12）
	err := users.ValidateNewPassword(0, "Short1")
	if !errors.Is(err, policy.ErrPasswordTooShort) {
		t.Errorf("短密碼 = %v, want policy.ErrPasswordTooShort", err)
	}

	// 純字母（缺數字）
	err = users.ValidateNewPassword(0, "abcdefghijkl")
	if !errors.Is(err, policy.ErrPasswordComplexity) {
		t.Errorf("純字母 = %v, want policy.ErrPasswordComplexity", err)
	}

	// 純數字（缺字母）
	err = users.ValidateNewPassword(0, "123456789012")
	if !errors.Is(err, policy.ErrPasswordComplexity) {
		t.Errorf("純數字 = %v, want policy.ErrPasswordComplexity", err)
	}

	// 合規
	if err := users.ValidateNewPassword(0, "correct-h0rse-battery"); err != nil {
		t.Errorf("合規密碼 = %v, want nil", err)
	}
}

func TestValidateNewPasswordCountsRunesNotBytes(t *testing.T) {
	users, _, _ := setupPasswordDB(t)

	// "密碼安全1a" = 6 runes / 14 bytes；min-length=12 下應以字元數判定為過短
	err := users.ValidateNewPassword(0, "密碼安全1a")
	if !errors.Is(err, policy.ErrPasswordTooShort) {
		t.Errorf("6 字元多位元組密碼 = %v, want policy.ErrPasswordTooShort（byte 數會誤放行）", err)
	}

	// 12 個中文字（36 bytes）應通過長度但缺數字被組成擋——證明長度以 rune 計
	err = users.ValidateNewPassword(0, "密碼安全政策十二三四五六")
	if !errors.Is(err, policy.ErrPasswordComplexity) {
		t.Errorf("純中文 = %v, want policy.ErrPasswordComplexity（長度應以 rune 通過）", err)
	}
}

func TestValidateNewPasswordRejectsOverBcryptLimit(t *testing.T) {
	users, _, _ := setupPasswordDB(t)

	// 73 bytes 超過 bcrypt 72-byte 上限：應回政策違規（→400）而非落到 bcrypt 錯誤（→500，PW-2）
	long := ""
	for i := 0; i < 73; i++ {
		long += "a"
	}
	long += "1" // 確保含數字，排除組成因素
	err := users.ValidateNewPassword(0, long)
	if !errors.Is(err, policy.ErrPasswordTooLong) {
		t.Errorf("超長密碼 = %v, want policy.ErrPasswordTooLong", err)
	}
	var violation *policy.PasswordPolicyViolation
	if !errors.As(err, &violation) {
		t.Errorf("超長密碼應為 policy.PasswordPolicyViolation（映射 400），got %T", err)
	}
}

func TestSetPasswordRejectsSameAsCurrent(t *testing.T) {
	users, policies, db := setupPasswordDB(t)
	// 即使關閉歷史，新舊相同仍須被獨立檢查擋下
	policies.Update(policy.PolicyPasswordHistoryCount, "0", "admin")
	user := createTestUser(t, users, db, "current-pass-1")

	err := users.SelfChangePassword(user.ID, "current-pass-1", "current-pass-1")
	if !errors.Is(err, policy.ErrPasswordReused) {
		t.Errorf("新密碼同現行 = %v, want policy.ErrPasswordReused", err)
	}
}

func TestValidateNewPasswordFollowsPolicy(t *testing.T) {
	users, policies, _ := setupPasswordDB(t)

	// 放寬長度到 8、關閉組成要求
	policies.Update(policy.PolicyPasswordMinLength, "8", "admin")
	policies.Update(policy.PolicyPasswordRequireAlnum, "false", "admin")

	if err := users.ValidateNewPassword(0, "abcdefgh"); err != nil {
		t.Errorf("放寬後 8 字元純字母 = %v, want nil", err)
	}
}

func TestPasswordHistoryRejectsReuse(t *testing.T) {
	users, _, db := setupPasswordDB(t)
	user := createTestUser(t, users, db, "initial-pass-1")

	// 設回初始密碼被拒（初始密碼已入歷史）
	err := users.SelfChangePassword(user.ID, "initial-pass-1", "initial-pass-1")
	if !errors.Is(err, policy.ErrPasswordReused) {
		t.Errorf("設回初始密碼 = %v, want policy.ErrPasswordReused", err)
	}

	// 改成新密碼成功
	if err := users.SelfChangePassword(user.ID, "initial-pass-1", "brand-new-pw-2"); err != nil {
		t.Fatalf("正常改密 = %v", err)
	}

	// 改回上一個舊密碼被拒
	err = users.SelfChangePassword(user.ID, "brand-new-pw-2", "initial-pass-1")
	if !errors.Is(err, policy.ErrPasswordReused) {
		t.Errorf("重用舊密碼 = %v, want policy.ErrPasswordReused", err)
	}
}

func TestPasswordHistoryDisabledByPolicy(t *testing.T) {
	users, policies, db := setupPasswordDB(t)
	policies.Update(policy.PolicyPasswordHistoryCount, "0", "admin")
	user := createTestUser(t, users, db, "initial-pass-1")

	// 先改到 second-pass-2（現行密碼變 second-pass-2）
	if err := users.SelfChangePassword(user.ID, "initial-pass-1", "second-pass-2"); err != nil {
		t.Fatalf("首次改密: %v", err)
	}
	// 歷史關閉（0）：可重用較早的非現行密碼
	if err := users.SelfChangePassword(user.ID, "second-pass-2", "initial-pass-1"); err != nil {
		t.Errorf("歷史關閉後重用舊密碼 = %v, want nil", err)
	}
	// 但 PW-3 獨立檢查仍擋「設成與現行相同」——防 must_change 用戶假改密
	err := users.SelfChangePassword(user.ID, "initial-pass-1", "initial-pass-1")
	if !errors.Is(err, policy.ErrPasswordReused) {
		t.Errorf("設回現行密碼 = %v, want policy.ErrPasswordReused（PW-3）", err)
	}
}

func TestSelfChangePasswordVerifiesOldPassword(t *testing.T) {
	users, _, db := setupPasswordDB(t)
	user := createTestUser(t, users, db, "initial-pass-1")

	err := users.SelfChangePassword(user.ID, "wrong-old", "brand-new-pw-2")
	if !errors.Is(err, ErrOldPasswordMismatch) {
		t.Errorf("舊密碼錯誤 = %v, want ErrOldPasswordMismatch", err)
	}
}

func TestSelfChangePasswordClearsMustChange(t *testing.T) {
	users, _, db := setupPasswordDB(t)
	user := createTestUser(t, users, db, "initial-pass-1")
	db.Model(user).Update("must_change_password", true)

	if err := users.SelfChangePassword(user.ID, "initial-pass-1", "brand-new-pw-2"); err != nil {
		t.Fatalf("改密: %v", err)
	}

	var reloaded model.User
	db.First(&reloaded, user.ID)
	if reloaded.MustChangePassword {
		t.Error("自助改密後 must_change_password 應清除")
	}
	if reloaded.PasswordChangedAt == nil {
		t.Error("password_changed_at 應更新")
	}
}

func TestAdminResetSetsMustChangeByPolicy(t *testing.T) {
	users, policies, db := setupPasswordDB(t)
	user := createTestUser(t, users, db, "initial-pass-1")

	// 政策開（預設）：admin 重設後 must_change=true
	if err := users.ChangePassword(user.ID, "admin-set-pw-9"); err != nil {
		t.Fatalf("admin 重設: %v", err)
	}
	var reloaded model.User
	db.First(&reloaded, user.ID)
	if !reloaded.MustChangePassword {
		t.Error("政策開啟時 admin 重設後應強制改密")
	}

	// 政策關：重設不強制
	policies.Update(policy.PolicyForceChangeOnReset, "false", "admin")
	if err := users.ChangePassword(user.ID, "admin-set-pw-10"); err != nil {
		t.Fatalf("admin 重設2: %v", err)
	}
	db.First(&reloaded, user.ID)
	if reloaded.MustChangePassword {
		t.Error("政策關閉時 admin 重設不應強制改密")
	}
}

func TestPasswordHistoryPruning(t *testing.T) {
	users, _, db := setupPasswordDB(t)
	user := createTestUser(t, users, db, "initial-pass-1")

	// 連改 6 次（歷史保底 4 筆＝max(政策4, floor 4)），舊紀錄應被裁剪
	prev := "initial-pass-1"
	for i := 0; i < 6; i++ {
		next := "rotating-pw-" + string(rune('a'+i)) + "12345678"
		if err := users.SelfChangePassword(user.ID, prev, next); err != nil {
			t.Fatalf("第 %d 次改密: %v", i, err)
		}
		prev = next
	}

	var count int64
	db.Model(&model.PasswordHistory{}).Where("user_id = ?", user.ID).Count(&count)
	if count > historyRetentionFloor {
		t.Errorf("歷史筆數 = %d, 應被裁剪至 <= %d", count, historyRetentionFloor)
	}
	if count == 0 {
		t.Error("歷史不應為空")
	}
}

func TestValidateSkippedWithoutPolicyService(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	users := NewUserService(db, authz.NewAssetAuthorizationService(db))

	// 政策服務未注入（僅測試建構路徑）：不做政策驗證
	if err := users.ValidateNewPassword(0, "x"); err != nil {
		t.Errorf("未注入政策服務 = %v, want nil", err)
	}
}
