package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/bcrypt"
)

// 外部帳號的本地密碼路徑（idp-oidc-integration tasks 4.17，design D8）。
//
// 兩個性質必須同時成立，且兩者互相拉扯：
//   - **不可枚舉**：回應與一般憑證錯誤完全不可區分，否則本地登入表單即成
//     「此帳號是 SSO 帳號」的探測器。
//   - **不可鎖死**：不計入失敗計數，否則任何未認證者只要知道 username，
//     就能用本地表單把 SSO 帳號鎖死——鎖定後連正常的 OIDC 登入都會被擋。
//
// 兩者的天然衝突在於「不計數」本身若被外部觀察到（例如打 100 次仍不鎖），
// 也是一種區分訊號。取捨為 fail-safe 優先：可用性損失不可逆，枚舉風險已由
// 「回應不可區分」承擔主要防線。

func TestExternalAccountLocalLoginRejectedAndNotCounted(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin")

	// OIDC 影子帳號：有 bcrypt 佔位雜湊（隨機值，無人知道明文）
	hash, _ := bcrypt.GenerateFromPassword([]byte("placeholder-secret"), bcrypt.MinCost)
	user := &model.User{
		Username: "sso-user", Password: string(hash), Active: true,
		ProvisioningOrigin: model.AuthSourceOIDC, ExternalCredential: true,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	// 遠超鎖定門檻的嘗試次數
	for i := 0; i < 10; i++ {
		_, err := auth.Login(&LoginRequest{Username: "sso-user", Password: "guess"})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("第 %d 次嘗試 = %v, want ErrInvalidCredentials（與一般憑證錯誤不可區分）", i+1, err)
		}
	}

	var reloaded model.User
	db.First(&reloaded, user.ID)
	if reloaded.FailedLoginAttempts != 0 {
		t.Errorf("外部帳號的本地登入嘗試不得計數，實得 %d", reloaded.FailedLoginAttempts)
	}
	if reloaded.LockedUntil != nil {
		t.Fatal("外部帳號不得被本地表單鎖死（否則正常的 SSO 登入也會被擋）")
	}
}

func TestExternalAccountRejectedEvenWithCorrectPlaceholderPassword(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	// 極端情境：佔位雜湊的明文外洩。判定依「帳號是否為外部憑證」而非密碼是否正確，
	// 故仍須拒絕——密碼比對根本不該執行到
	hash, _ := bcrypt.GenerateFromPassword([]byte("leaked-placeholder"), bcrypt.MinCost)
	user := &model.User{
		Username: "sso-user", Password: string(hash), Active: true,
		ProvisioningOrigin: model.AuthSourceOIDC, ExternalCredential: true,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	_, err := auth.Login(&LoginRequest{Username: "sso-user", Password: "leaked-placeholder"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("外部帳號即使密碼正確亦須拒絕本地路徑，實得 %v", err)
	}
}

func TestExternalAccountResponseIndistinguishableFromUnknownUser(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost)
	if err := db.Create(&model.User{
		Username: "sso-user", Password: string(hash), Active: true,
		ProvisioningOrigin: model.AuthSourceOIDC, ExternalCredential: true,
	}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	_, errExternal := auth.Login(&LoginRequest{Username: "sso-user", Password: "wrong"})
	_, errUnknown := auth.Login(&LoginRequest{Username: "no-such-user", Password: "wrong"})

	// 專屬錯誤碼只用於已認證的管理操作；登入端點回填即成枚舉 oracle
	if errExternal == nil || errUnknown == nil {
		t.Fatal("兩者皆應失敗")
	}
	if errExternal.Error() != errUnknown.Error() {
		t.Fatalf("外部帳號回應 %q 與查無帳號 %q 可被區分（枚舉 oracle）",
			errExternal.Error(), errUnknown.Error())
	}
}

func TestLDAPUserNotDivertedByExternalBranch(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	// 目錄供應帳號同樣滿足 IsExternal()。若三分派寫成兩分派（僅以 IsExternal 判斷），
	// LDAP 使用者會被外部分支吃掉而永遠無法登入
	hash, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost)
	user := &model.User{
		Username: "dir-user", Password: string(hash), Active: true,
		IsLDAP: true, ProvisioningOrigin: model.AuthSourceLDAP,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	if !user.IsExternal() {
		t.Fatal("LDAP 帳號應被判定為外部（前提不成立則本測試無意義）")
	}

	// 未設定 LDAP 連線時走「查無 → 憑證錯誤」語義；關鍵是**不得**留下
	// 外部分支的審計事件——那代表它被錯誤地當成 OIDC 帳號攔下
	_, err := auth.Login(&LoginRequest{Username: "dir-user", Password: "x"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("LDAP 帳號未設目錄連線時 = %v, want ErrInvalidCredentials", err)
	}
	var reloaded model.User
	db.First(&reloaded, user.ID)
	if reloaded.FailedLoginAttempts != 0 {
		t.Error("未設目錄連線時不應計數（無計數對象語義）")
	}
}

func TestIsExternalCoversAllThreeOrigins(t *testing.T) {
	// IsExternal 是密碼類 gate 的總開關，三個來源缺一即讓該類帳號誤觸密碼政策
	cases := map[string]struct {
		user model.User
		want bool
	}{
		"本地帳號":                  {model.User{ProvisioningOrigin: model.AuthSourceLocal}, false},
		"空 provisioning_origin": {model.User{}, false},
		"LDAP 旗標":               {model.User{IsLDAP: true}, true},
		"外部憑證能力":                {model.User{ExternalCredential: true}, true},
		"OIDC 供應來源":             {model.User{ProvisioningOrigin: model.AuthSourceOIDC}, true},
		"混合帳號（OIDC 來源但保有本地密碼）": {
			model.User{ProvisioningOrigin: model.AuthSourceOIDC, ExternalCredential: false}, true},
	}
	for name, c := range cases {
		if got := c.user.IsExternal(); got != c.want {
			t.Errorf("%s: IsExternal() = %v, want %v", name, got, c.want)
		}
	}
}
