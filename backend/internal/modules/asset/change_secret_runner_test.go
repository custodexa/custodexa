package asset

import (
	"testing"
)

// TestGeneratePasswordUnique 同策略連續生成不得重複（隨機源真的在動）。
//
// 長度／字類／硬排除的斷言在 change_secret_password_policy_test.go；
// 本檔只保留 runner 層面的性質。
func TestGeneratePasswordUnique(t *testing.T) {
	p := PasswordPolicy{Length: 24, IncludeSymbol: true, ExcludeAmbiguous: true}
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		pw, err := GeneratePassword(p)
		if err != nil {
			t.Fatalf("GeneratePassword: %v", err)
		}
		if seen[pw] {
			t.Fatal("連續生成出現重複密碼")
		}
		seen[pw] = true
	}
}

// TestRunChpasswdRejectsStdinInjection user/新密含換行會在 chpasswd stdin 拆出
// 額外條目改非目標帳號；驗證在 client.NewSession 前攔截（故 nil client 不被觸及）
func TestRunChpasswdRejectsStdinInjection(t *testing.T) {
	cases := []struct {
		name, user, newPass string
	}{
		{"user 換行注入", "root\nbackdoor:knownpass", "NewPass123!"},
		{"user 含冒號", "ro:ot", "NewPass123!"},
		{"新密換行注入", "root", "x\nroot:attacker"},
		{"新密含 NUL", "root", "x\x00y"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := runChpasswd(nil, c.user, "old", c.newPass)
			if err == nil {
				t.Errorf("%s 應被拒絕", c.name)
			}
		})
	}
}
