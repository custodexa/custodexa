package config

import (
	"os"
	"strings"
	"testing"
)

// TestValidateAdminInitialPassword 覆蓋 bootstrap 初始密碼 byte 契約（deployment-hardening）：
// 未設/placeholder/legacy admin123/過短/前後空白/CR-LF/控制字元皆須判為違規；合格值放行。
func TestValidateAdminInitialPassword(t *testing.T) {
	cases := []struct {
		name  string
		pw    string
		valid bool
	}{
		{"empty", "", false},
		{"placeholder", DefaultAdminInitialPassword, false},
		{"legacy_admin123", "admin123", false},
		{"too_short", "Ab1!xyz", false}, // 7 < 12
		{"leading_space", " Str0ngPassw0rd!", false},
		{"trailing_space", "Str0ngPassw0rd! ", false},
		{"trailing_newline", "Str0ngPassw0rd!\n", false},
		{"internal_newline", "Str0ng\nPassw0rd!", false},
		{"tab", "Str0ng\tPassw0rd!", false},
		{"valid", "Str0ngInitialPw2026", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ValidateAdminInitialPassword(c.pw)
			if c.valid && got != "" {
				t.Errorf("預期合格，卻回違規 %q", got)
			}
			if !c.valid && got == "" {
				t.Errorf("預期違規，卻判為合格")
			}
		})
	}
}

// TestEnvExampleAdminInitialPasswordIsDenylistedPlaceholder：.env.example 出貨的
// ADMIN_INITIAL_PASSWORD 值必須（1）直接解析恰為 denylisted placeholder（證明未被行內註解污染），
// （2）被 ValidateAdminInitialPassword 擋下——否則該值會成為 release 也接受的公開已知憑證。
func TestEnvExampleAdminInitialPasswordIsDenylistedPlaceholder(t *testing.T) {
	path := envExamplePath(t, backendRoot(t)) // 沿用 env_drift_test.go 的定位 helper（同套件）
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀 .env.example 失敗: %v", err)
	}
	var val string
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "ADMIN_INITIAL_PASSWORD=") {
			val = strings.TrimPrefix(trimmed, "ADMIN_INITIAL_PASSWORD=")
			found = true
			break
		}
	}
	if !found {
		t.Fatal(".env.example 缺 ADMIN_INITIAL_PASSWORD")
	}
	if val != DefaultAdminInitialPassword {
		t.Errorf(".env.example 的 ADMIN_INITIAL_PASSWORD 值 %q 未等於 denylisted placeholder %q（行內註解污染或值漂移？）",
			val, DefaultAdminInitialPassword)
	}
	if ValidateAdminInitialPassword(val) == "" {
		t.Error(".env.example 的 placeholder 竟通過驗證：release 空 DB 會以公開已知值建 admin")
	}
}
