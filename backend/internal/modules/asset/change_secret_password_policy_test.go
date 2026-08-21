package asset

import (
	"errors"
	"strings"
	"testing"
	"unicode"

	"github.com/custodexa/backend/internal/model"
)

// generateSample 產生 n 條密碼供統計性斷言使用
func generateSample(t *testing.T, p PasswordPolicy, n int) []string {
	t.Helper()
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		pw, err := GeneratePassword(p)
		if err != nil {
			t.Fatalf("GeneratePassword: %v", err)
		}
		out = append(out, pw)
	}
	return out
}

func TestChangeSecretPasswordLengthAndClasses(t *testing.T) {
	for _, length := range []int{12, 16, 32, 64} {
		p := PasswordPolicy{Length: length, IncludeSymbol: true, ExcludeAmbiguous: true}
		for _, pw := range generateSample(t, p, 30) {
			if len([]byte(pw)) != length {
				t.Fatalf("長度 %d，實得 %d（%q）", length, len(pw), pw)
			}
			if !strings.ContainsFunc(pw, unicode.IsUpper) {
				t.Fatalf("缺大寫: %q", pw)
			}
			if !strings.ContainsFunc(pw, unicode.IsLower) {
				t.Fatalf("缺小寫: %q", pw)
			}
			if !strings.ContainsFunc(pw, unicode.IsDigit) {
				t.Fatalf("缺數字: %q", pw)
			}
			if !strings.ContainsAny(pw, passwordSymbol) {
				t.Fatalf("缺符號: %q", pw)
			}
		}
	}
}

// TestChangeSecretPasswordHardExclusionCannotBeWidened 是硬排除的**雙向守衛**：
// 任何策略組合下都不得出現 shell 敏感字元、控制字元或空白。
//
// 突變自證的著力點是 passwordSymbol／passwordUpper 等字集常數——把任一個
// shell 敏感字元加回字集，本測試必轉紅（不是「可能」轉紅：樣本量使
// 單一字元出現機率趨近 1）。
func TestChangeSecretPasswordHardExclusionCannotBeWidened(t *testing.T) {
	// 字集本身即不得含硬排除字元——這一層在生成前就成立，不依賴抽樣
	for _, set := range []string{passwordUpper, passwordLower, passwordDigit, passwordSymbol} {
		if idx := strings.IndexAny(set, shellSensitiveChars); idx >= 0 {
			t.Fatalf("字集 %q 含 shell 敏感字元 %q：硬排除已被放寬", set, set[idx])
		}
		for _, r := range set {
			if unicode.IsControl(r) || unicode.IsSpace(r) {
				t.Fatalf("字集 %q 含控制字元或空白 %q", set, r)
			}
		}
	}

	// 生成面：所有策略組合大量抽樣
	combos := []PasswordPolicy{
		{Length: 12, IncludeSymbol: true, ExcludeAmbiguous: true},
		{Length: 16, IncludeSymbol: true, ExcludeAmbiguous: false},
		{Length: 24, IncludeSymbol: false, ExcludeAmbiguous: true},
		{Length: 64, IncludeSymbol: false, ExcludeAmbiguous: false},
	}
	total := 0
	for _, p := range combos {
		for _, pw := range generateSample(t, p, 200) {
			total++
			if idx := strings.IndexAny(pw, shellSensitiveChars); idx >= 0 {
				t.Fatalf("密碼含 shell 敏感字元 %q: %q（策略 %+v）", pw[idx], pw, p)
			}
			for _, r := range pw {
				if unicode.IsControl(r) || unicode.IsSpace(r) {
					t.Fatalf("密碼含控制字元或空白 %q: %q", r, pw)
				}
			}
		}
	}
	// 抽樣量下界：樣本過少會讓本測試在字集被放寬時仍偶然全綠
	if total < 800 {
		t.Fatalf("抽樣量 %d 過低（下界 800）：本守衛將在字集被放寬時假綠", total)
	}
}

func TestChangeSecretPasswordSymbolToggle(t *testing.T) {
	p := PasswordPolicy{Length: 20, IncludeSymbol: false, ExcludeAmbiguous: true}
	for _, pw := range generateSample(t, p, 100) {
		if strings.ContainsAny(pw, passwordSymbol) {
			t.Fatalf("關閉符號後仍含符號: %q", pw)
		}
	}
}

func TestChangeSecretPasswordAmbiguousToggle(t *testing.T) {
	on := PasswordPolicy{Length: 64, IncludeSymbol: true, ExcludeAmbiguous: true}
	for _, pw := range generateSample(t, on, 100) {
		if strings.ContainsAny(pw, passwordAmbiguous) {
			t.Fatalf("排除易混淆時仍含 %q: %q", passwordAmbiguous, pw)
		}
	}
	// 關閉時應**可能**出現易混淆字元；64 字 × 100 條下不出現即代表過濾未受開關控制
	off := PasswordPolicy{Length: 64, IncludeSymbol: true, ExcludeAmbiguous: false}
	seen := false
	for _, pw := range generateSample(t, off, 100) {
		if strings.ContainsAny(pw, passwordAmbiguous) {
			seen = true
			break
		}
	}
	if !seen {
		t.Fatal("關閉易混淆排除後仍未出現任何易混淆字元：開關未生效（過濾恆開）")
	}
}

func TestChangeSecretPasswordLengthOutOfRange(t *testing.T) {
	for _, length := range []int{1, model.PasswordLengthMin - 1, model.PasswordLengthMax + 1, 1000} {
		if _, err := GeneratePassword(PasswordPolicy{Length: length, IncludeSymbol: true}); !errors.Is(err, ErrPasswordLengthOutOfRange) {
			t.Fatalf("長度 %d 應回 ErrPasswordLengthOutOfRange，實得 %v", length, err)
		}
		if err := ValidatePasswordLength(length); !errors.Is(err, ErrPasswordLengthOutOfRange) {
			t.Fatalf("ValidatePasswordLength(%d) 應拒絕，實得 %v", length, err)
		}
	}
	// 0＝未設定，取預設，非越界
	if err := ValidatePasswordLength(0); err != nil {
		t.Fatalf("長度 0（未設定）應允許，實得 %v", err)
	}
}

func TestChangeSecretPolicyFromPlanDefaults(t *testing.T) {
	p := PolicyFromPlan(&model.ChangeSecretPlan{})
	if p.Length != model.PasswordLengthDefault {
		t.Fatalf("未設長度應取預設 %d，實得 %d", model.PasswordLengthDefault, p.Length)
	}
	p2 := PolicyFromPlan(&model.ChangeSecretPlan{PasswordLength: 32, PasswordIncludeSymbol: true})
	if p2.Length != 32 || !p2.IncludeSymbol {
		t.Fatalf("策略未自計劃帶出: %+v", p2)
	}
}

// TestChangeSecretPasswordEntropySanity 洗牌真的有洗：字類不得固定落在前四位
func TestChangeSecretPasswordEntropySanity(t *testing.T) {
	p := PasswordPolicy{Length: 16, IncludeSymbol: true, ExcludeAmbiguous: true}
	firstIsUpper := 0
	const n = 300
	for _, pw := range generateSample(t, p, n) {
		if unicode.IsUpper(rune(pw[0])) {
			firstIsUpper++
		}
	}
	if firstIsUpper == n {
		t.Fatal("首位恆為大寫：Fisher-Yates 洗牌未生效，字類位置可預測")
	}
}
