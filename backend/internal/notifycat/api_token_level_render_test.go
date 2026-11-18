package notifycat

import (
	"strings"
	"testing"
)

// 高權限 API token 告警的角色清單逐項附層級（三語定稿寫法），項數不同時退回只列名稱。
func TestPrivilegedAPITokenAlertRendersRoleLevels(t *testing.T) {
	base := map[string]string{
		"actor": "ops", "severity": "high", "token_name": "tf",
		"privileged_roles": "super_admin", "privileged_role_levels": "read",
		"granted_roles": "super_admin,identity_admin", "granted_role_levels": "read,read_write",
		"access": "mixed", "expiry": "never",
	}
	cases := map[string][]string{
		"zh-TW": {"高權限角色：super_admin（唯讀）；", "全部授權角色：super_admin（唯讀）、identity_admin（讀寫）；", "永不到期"},
		"en-US": {"granting privileged roles: super_admin (read-only);", "all granted roles: super_admin (read-only), identity_admin (read-write);"},
		"ja-JP": {"高権限ロールを付与しました：super_admin（参照のみ）。", "付与したロール：super_admin（参照のみ）、identity_admin（参照・変更）；"},
	}
	for lang, wants := range cases {
		_, text := Render(lang, EventSystemAlertPrivilegedAPITokenCreated, base)
		for _, w := range wants {
			if !strings.Contains(text, w) {
				t.Errorf("%s 文案缺 %q：%s", lang, w, text)
			}
		}
		if strings.Contains(text, "mixed") || strings.Contains(text, "read_write") {
			t.Errorf("%s 文案不應露出機器值：%s", lang, text)
		}
	}
	// 項數不同：退回只列名稱，不把層級配錯角色
	bad := map[string]string{}
	for k, v := range base {
		bad[k] = v
	}
	bad["granted_role_levels"] = "read"
	_, text := Render("zh-TW", EventSystemAlertPrivilegedAPITokenCreated, bad)
	if !strings.Contains(text, "全部授權角色：super_admin,identity_admin；") {
		t.Errorf("項數不同時應只列名稱：%s", text)
	}
	if _, err := Validate(EventSystemAlertPrivilegedAPITokenCreated, base); err != nil {
		t.Fatalf("完整參數應通過驗證：%v", err)
	}
}
