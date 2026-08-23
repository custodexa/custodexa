package identity

import (
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 登入回應不洩漏帳號存在性（塊 4）。
//
// 缺陷本體：停用判定原本在 bcrypt 比對**之前**，於是未認證者送任意密碼即可
// 分辨「此帳號存在但已停用」（403 user_inactive）與「此帳號不存在」
// （401 invalid_credentials）——一個不需任何權限的帳號存在性預言機。
//
// 同函式的 OIDC 分支早已為此刻意收斂回應，本地與 LDAP 分支漏了。

func seedEnumUser(t *testing.T, db *gorm.DB, username, password string, active bool) *model.User {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	email := username + "@x"
	user := &model.User{
		Username: username, Email: &email,
		Password: string(hash), Active: active,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	// **Active=false 必須顯式再寫一次**：`model.User.Active` 帶 `gorm:"default:true"`，
	// Create 時 bool 零值被 GORM 視為未設定而套用 DB 預設 true。少了這一步，
	// 「停用帳號」的測試其實建的是啟用帳號，斷言會在錯誤的前提上跑
	if !active {
		if err := db.Model(user).Update("active", false).Error; err != nil {
			t.Fatalf("set inactive: %v", err)
		}
		var check model.User
		if err := db.First(&check, user.ID).Error; err != nil {
			t.Fatalf("reload: %v", err)
		}
		if check.Active {
			t.Fatalf("前置條件失敗：使用者 %s 應為停用態，實得 active=true", username)
		}
	}
	return user
}

// 核心斷言：兩條路徑的**錯誤完全相同**。
//
// 只斷言「停用帳號回 ErrInvalidCredentials」是不夠的——那不能證明它與
// 「不存在帳號」不可區分。要比的是兩者相等
func TestLogin_InactiveAndNonexistentAreIndistinguishable(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	seedEnumUser(t, db, "disabled-user", "correct-password", false)

	_, errInactive := auth.Login(&LoginRequest{
		Username: "disabled-user", Password: "any-guess",
	})
	_, errNonexistent := auth.Login(&LoginRequest{
		Username: "no-such-user", Password: "any-guess",
	})

	if !errors.Is(errInactive, ErrInvalidCredentials) {
		t.Fatalf("停用帳號＋錯密碼 = %v, want ErrInvalidCredentials"+
			"（回 ErrUserInactive 即為帳號存在性預言機）", errInactive)
	}
	if !errors.Is(errNonexistent, ErrInvalidCredentials) {
		t.Fatalf("不存在帳號 = %v, want ErrInvalidCredentials", errNonexistent)
	}
	if errInactive.Error() != errNonexistent.Error() {
		t.Fatalf("兩者訊息可區分：停用=%q 不存在=%q——未認證者據此即可枚舉帳號",
			errInactive, errNonexistent)
	}
}

// 憑證正確時仍明示停用：此時對方已證明持有該帳號憑證，告知不構成洩漏，
// 且正當使用者需要據此知道該找管理員而非反覆重試密碼
func TestLogin_InactiveWithCorrectPasswordStillReportsInactive(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	seedEnumUser(t, db, "disabled-user", "correct-password", false)

	_, err := auth.Login(&LoginRequest{
		Username: "disabled-user", Password: "correct-password",
	})
	if !errors.Is(err, ErrUserInactive) {
		t.Fatalf("停用帳號＋正確密碼 = %v, want ErrUserInactive"+
			"（收斂過頭會讓正當使用者只看到「帳號或密碼錯誤」而不斷重試）", err)
	}
}

// 啟用帳號的正常路徑不受影響（回歸）
func TestLogin_ActiveUserUnaffected(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	seedEnumUser(t, db, "normal-user", "correct-password", true)

	if _, err := auth.Login(&LoginRequest{
		Username: "normal-user", Password: "correct-password",
	}); err != nil {
		t.Fatalf("啟用帳號＋正確密碼應成功，實得 %v", err)
	}

	_, err := auth.Login(&LoginRequest{Username: "normal-user", Password: "wrong"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("啟用帳號＋錯密碼 = %v, want ErrInvalidCredentials", err)
	}
}
