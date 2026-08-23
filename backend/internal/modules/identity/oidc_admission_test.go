package identity

import (
	"errors"
	"testing"
)

// TestEffectiveIssuerKindPrecedence 身分域判定的固定優先序。
//
// 這條的價值在於「管理者不能放寬」：判定權歸系統，未知 issuer 一律 fail-close
// 視為共用；部署層可宣告專屬 issuer（Okta 等不發組織 claim 者的必要逃生口），
// 但內建共用清單優先——不得以部署設定把 Google 宣告為專屬。
func TestEffectiveIssuerKindPrecedence(t *testing.T) {
	tr := true
	fa := false
	cases := []struct {
		name       string
		issuer     string
		force      *bool
		deployDed  []string
		wantShared bool
	}{
		{"Google 為內建共用", "https://accounts.google.com", nil, nil, true},
		{"Google 尾斜線亦命中", "https://accounts.google.com/", nil, nil, true},
		{"Microsoft common 為內建共用", "https://login.microsoftonline.com/common/v2.0", nil, nil, true},
		{"Microsoft 消費者租戶為內建共用", "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0", nil, nil, true},
		{"未知 issuer 預設共用（fail-close）", "https://idp.example.com", nil, nil, true},
		{"部署層宣告使未知 issuer 成為專屬", "https://acme.okta.com", nil, []string{"https://acme.okta.com"}, false},
		{"管理者收緊可覆寫部署宣告", "https://acme.okta.com", &tr, []string{"https://acme.okta.com"}, true},
		{"管理者的 false 不構成放寬", "https://idp.example.com", &fa, nil, true},
		{"部署宣告不得推翻內建共用清單", "https://accounts.google.com", nil, []string{"https://accounts.google.com"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EffectiveIssuerKind(c.issuer, c.force, c.deployDed); got != c.wantShared {
				t.Fatalf("EffectiveIssuerKind = %v, want %v", got, c.wantShared)
			}
		})
	}
}

// TestValidateAdmissionConfig 准入組態的設定期驗證。
//
// 最重要的一格是「共用身分域拒絕僅 email 網域規則」：Google 的 issuer 是全球
// 共用的，個人帳號可把 email 設為任何已驗證地址（含曾持有的公司信箱），
// 故只驗 email 網域等同放行任何知道該網域的人。
func TestValidateAdmissionConfig(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		rules    AdmissionRules
		shared   bool
		wantErr  error
		wantPass bool
	}{
		{
			name: "prebound_only 不需規則",
			mode: "prebound_only", rules: AdmissionRules{}, shared: true, wantPass: true,
		},
		{
			name: "JIT 空規則集被拒",
			mode: admissionJIT, rules: AdmissionRules{}, shared: false, wantErr: ErrAdmissionEmptyRuleSet,
		},
		{
			name: "共用身分域僅 email 網域被拒",
			mode: admissionJIT, shared: true,
			rules:   AdmissionRules{EmailDomains: []string{"corp.example"}, EmailVerified: true},
			wantErr: ErrAdmissionSharedNeedsOrgRule,
		},
		{
			name: "共用身分域帶 hd 通過",
			mode: admissionJIT, shared: true,
			rules:    AdmissionRules{HostedDomains: []string{"corp.example"}},
			wantPass: true,
		},
		{
			name: "專屬身分域僅 email 網域可通過",
			mode: admissionJIT, shared: false,
			rules:    AdmissionRules{EmailDomains: []string{"corp.example"}, EmailVerified: true},
			wantPass: true,
		},
		{
			name: "email 網域未併同已驗證要求被拒",
			mode: admissionJIT, shared: false,
			rules:   AdmissionRules{EmailDomains: []string{"corp.example"}},
			wantErr: ErrAdmissionEmailNeedsVerified,
		},
		{
			name: "消費者租戶識別值被拒",
			mode: admissionJIT, shared: true,
			rules:   AdmissionRules{TenantIDs: []string{microsoftConsumerTenantID}},
			wantErr: ErrAdmissionConsumerTenant,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateAdmissionConfig(c.mode, c.rules, c.shared)
			if c.wantPass {
				if err != nil {
					t.Fatalf("預期通過，得 %v", err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("預期 %v，得 %v", c.wantErr, err)
			}
		})
	}
}

// TestParseAdmissionRulesRejectsUnknownKeys 未知規則鍵於設定時即拒絕。
//
// 「封閉集合」是安全要求：未知鍵若存入後於執行期被忽略，一份看似有限制的組態
// 會靜默退化為無限制——管理者以為設了白名單，實際上全世界都能進。
func TestParseAdmissionRulesRejectsUnknownKeys(t *testing.T) {
	if _, err := ParseAdmissionRules(`{"tid":["abc"],"unknown_rule":["x"]}`); !errors.Is(err, ErrAdmissionUnknownRule) {
		t.Fatalf("未知鍵應被拒絕，得 %v", err)
	}
	if _, err := ParseAdmissionRules(`{"tid":["abc"]}`); err != nil {
		t.Fatalf("已知鍵應通過，得 %v", err)
	}
	if _, err := ParseAdmissionRules(""); err != nil {
		t.Fatalf("空字串應通過，得 %v", err)
	}
}

// TestEvaluateAdmissionFailClose claim 缺失／型別不符一律不匹配。
//
// 寬鬆轉型是這裡最危險的實作誤區：把字串 "true" 當作已驗證、把缺失的 tid
// 當作通過，都會使規則形同虛設。
func TestEvaluateAdmissionFailClose(t *testing.T) {
	rules := AdmissionRules{TenantIDs: []string{"tenant-a"}, EmailVerified: true}

	cases := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"全部相符", map[string]any{"tid": "tenant-a", "email_verified": true}, true},
		{"tid 大小寫不敏感", map[string]any{"tid": "TENANT-A", "email_verified": true}, true},
		{"tid 缺失", map[string]any{"email_verified": true}, false},
		{"tid 不在清單", map[string]any{"tid": "tenant-b", "email_verified": true}, false},
		{"tid 為 null", map[string]any{"tid": nil, "email_verified": true}, false},
		{"tid 型別錯誤", map[string]any{"tid": 123, "email_verified": true}, false},
		{"email_verified 為字串 true 不算", map[string]any{"tid": "tenant-a", "email_verified": "true"}, false},
		{"email_verified 缺失", map[string]any{"tid": "tenant-a"}, false},
		{"email_verified 為 false", map[string]any{"tid": "tenant-a", "email_verified": false}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := EvaluateAdmission(rules, c.claims)
			if got != c.want {
				t.Fatalf("EvaluateAdmission = %v, want %v", got, c.want)
			}
		})
	}
}

// TestEvaluateAdmissionEmailDomain email 網域比對取 @ 之後的部分
func TestEvaluateAdmissionEmailDomain(t *testing.T) {
	rules := AdmissionRules{EmailDomains: []string{"corp.example"}, EmailVerified: true}
	cases := []struct {
		email string
		want  bool
	}{
		{"alice@corp.example", true},
		{"alice@CORP.EXAMPLE", true},
		{"alice@evil.com", false},
		{"alice@corp.example.evil.com", false},
		{"corp.example", false},
		{"alice@", false},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.email, func(t *testing.T) {
			got, _ := EvaluateAdmission(rules, map[string]any{"email": c.email, "email_verified": true})
			if got != c.want {
				t.Fatalf("email %q → %v, want %v", c.email, got, c.want)
			}
		})
	}
}

// TestEvaluateAdmissionAllowListIsOR 同一規則的允許清單內為 OR。
//
// 其他准入測試的清單一律只有單一元素，於是「命中即回 true」與「只比對第一個
// 元素」兩種實作**無法被區分**——一份列了三個租戶的組態可能只有第一個真的生效，
// 而症狀是「某些部門的人登不進來」，看起來像 IdP 問題而非我方的規則求值錯誤。
// 故每組清單都取三個元素，並刻意命中中間與最後一個。
func TestEvaluateAdmissionAllowListIsOR(t *testing.T) {
	cases := []struct {
		name     string
		rules    AdmissionRules
		claims   map[string]any
		want     bool
		wantRule string
	}{
		{
			name:   "tid 命中清單中間元素",
			rules:  AdmissionRules{TenantIDs: []string{"tenant-a", "tenant-b", "tenant-c"}},
			claims: map[string]any{"tid": "tenant-b"},
			want:   true,
		},
		{
			name:   "tid 命中清單最後一個元素",
			rules:  AdmissionRules{TenantIDs: []string{"tenant-a", "tenant-b", "tenant-c"}},
			claims: map[string]any{"tid": "tenant-c"},
			want:   true,
		},
		{
			name:     "tid 全部不中即拒",
			rules:    AdmissionRules{TenantIDs: []string{"tenant-a", "tenant-b", "tenant-c"}},
			claims:   map[string]any{"tid": "tenant-z"},
			want:     false,
			wantRule: AdmissionRuleTenantID,
		},
		{
			name:   "hd 命中清單中間元素",
			rules:  AdmissionRules{HostedDomains: []string{"a.example", "b.example", "c.example"}},
			claims: map[string]any{"hd": "b.example"},
			want:   true,
		},
		{
			name:     "hd 全部不中即拒",
			rules:    AdmissionRules{HostedDomains: []string{"a.example", "b.example", "c.example"}},
			claims:   map[string]any{"hd": "z.example"},
			want:     false,
			wantRule: AdmissionRuleHostedDomain,
		},
		{
			name: "email_domain 命中清單最後一個元素",
			rules: AdmissionRules{
				EmailDomains: []string{"a.example", "b.example", "c.example"}, EmailVerified: true},
			claims: map[string]any{"email": "alice@c.example", "email_verified": true},
			want:   true,
		},
		{
			name: "email_domain 全部不中即拒",
			rules: AdmissionRules{
				EmailDomains: []string{"a.example", "b.example", "c.example"}, EmailVerified: true},
			claims:   map[string]any{"email": "alice@z.example", "email_verified": true},
			want:     false,
			wantRule: AdmissionRuleEmailDomain,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, rule := EvaluateAdmission(c.rules, c.claims)
			if got != c.want {
				t.Fatalf("EvaluateAdmission = %v（failedRule=%q）, want %v", got, rule, c.want)
			}
			if rule != c.wantRule {
				t.Fatalf("failedRule = %q, want %q", rule, c.wantRule)
			}
		})
	}
}

// TestEvaluateAdmissionCrossRuleIsANDWithMultiValueLists 跨規則 AND 與清單內 OR 並存。
//
// 對照組：兩個鍵各自的清單都是多值，兩鍵各命中清單的非首個元素才放行；
// 任一鍵不中即拒，且回報的正是**不中的那個鍵**——若 AND 被誤實作為 OR，
// 「只滿足一個鍵」的兩格會變綠。
func TestEvaluateAdmissionCrossRuleIsANDWithMultiValueLists(t *testing.T) {
	rules := AdmissionRules{
		TenantIDs:     []string{"tenant-a", "tenant-b"},
		HostedDomains: []string{"a.example", "b.example"},
	}
	cases := []struct {
		name     string
		claims   map[string]any
		want     bool
		wantRule string
	}{
		{
			name:   "兩鍵各命中清單第二個元素",
			claims: map[string]any{"tid": "tenant-b", "hd": "b.example"},
			want:   true,
		},
		{
			name:     "只滿足 tid（hd 不中）",
			claims:   map[string]any{"tid": "tenant-b", "hd": "z.example"},
			want:     false,
			wantRule: AdmissionRuleHostedDomain,
		},
		{
			name:     "只滿足 hd（tid 不中）",
			claims:   map[string]any{"tid": "tenant-z", "hd": "b.example"},
			want:     false,
			wantRule: AdmissionRuleTenantID,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, rule := EvaluateAdmission(rules, c.claims)
			if got != c.want {
				t.Fatalf("EvaluateAdmission = %v（failedRule=%q）, want %v", got, rule, c.want)
			}
			if rule != c.wantRule {
				t.Fatalf("failedRule = %q, want %q", rule, c.wantRule)
			}
		})
	}
}
