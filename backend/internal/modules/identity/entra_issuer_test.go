package identity

import (
	"errors"
	"testing"
)

// Entra 來源的辨識與 groups 授權範圍確認的豁免（openspec/specs/oidc-auth/spec.md
// 「Microsoft Entra 來源的設定引導」）。

func TestIsEntraIssuer(t *testing.T) {
	cases := []struct {
		name   string
		issuer string
		want   bool
	}{
		{"租戶專屬 v2.0 端點", "https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0", true},
		{"多租戶 common 端點", "https://login.microsoftonline.com/common/v2.0", true},
		{"主機大寫", "https://LOGIN.MicrosoftOnline.COM/tenant-a/v2.0", true},
		{"前後空白", "  https://login.microsoftonline.com/tenant-a/v2.0  ", true},
		{"非 Entra 主機", "https://idp.example.com", false},
		{"主機只是前綴相同", "https://login.microsoftonline.com.evil.example/tenant/v2.0", false},
		{"路徑含 Entra 主機字樣", "https://idp.example.com/login.microsoftonline.com", false},
		{"無法解析的字串", "https://[::1", false},
		{"空字串", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isEntraIssuer(tc.issuer); got != tc.want {
				t.Fatalf("isEntraIssuer(%q) = %v，want %v", tc.issuer, got, tc.want)
			}
		})
	}
}

const entraTenantIssuer = "https://login.microsoftonline.com/tenant-a/v2.0"

// isMappingAckRequired 錯誤是否為「需風險確認」且帶缺範圍警告碼
func isMappingAckRequired(err error) bool {
	var ackErr *MappingAckRequiredError
	if !errors.As(err, &ackErr) {
		return false
	}
	for _, w := range ackErr.Warnings {
		if w == mappingWarningGroupsScopeMissing {
			return true
		}
	}
	return false
}

// Scenario: Entra 不自動索取 groups 範圍（儲存不要求風險確認）
func TestProviderCreateUpdateEntraSkipsGroupsScopeAck(t *testing.T) {
	_, providers, _ := setupOIDCEnv(t)
	claim := "groups"

	created, err := providers.Create(providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = entraTenantIssuer
		r.GroupsClaim = &claim
		r.Scopes = "profile email"
	}))
	if err != nil {
		t.Fatalf("Entra 建立帶群組宣告名、無 groups 範圍：err = %v，want nil", err)
	}

	// 更新時只送範圍（issuer 不可改，判定取既有列的 issuer）
	_, err = providers.Update(created.ID, &OIDCProviderRequest{Scopes: "profile"})
	if err != nil {
		t.Fatalf("Entra 更新範圍、仍無 groups：err = %v，want nil", err)
	}
}

// Scenario: 非 Entra 行為不變（儲存仍回可辨識的確認要求）
func TestProviderCreateUpdateNonEntraRequiresGroupsScopeAck(t *testing.T) {
	_, providers, _ := setupOIDCEnv(t)
	claim := "groups"

	_, err := providers.Create(providerReq(func(r *OIDCProviderRequest) {
		r.GroupsClaim = &claim
		r.Scopes = "profile email"
	}))
	if !isMappingAckRequired(err) {
		t.Fatalf("非 Entra 建立帶群組宣告名、無 groups 範圍：err = %v，want MappingAckRequiredError", err)
	}

	// 確認後放行（不阻擋）
	created, err := providers.Create(providerReq(func(r *OIDCProviderRequest) {
		r.GroupsClaim = &claim
		r.Scopes = "profile email"
		r.RiskAcknowledged = true
	}))
	if err != nil {
		t.Fatalf("非 Entra 帶確認建立：err = %v，want nil", err)
	}

	// 更新只改範圍：以合併後的值判定，仍缺 groups 即要求確認
	_, err = providers.Update(created.ID, &OIDCProviderRequest{Scopes: "profile"})
	if !isMappingAckRequired(err) {
		t.Fatalf("非 Entra 更新範圍、仍無 groups：err = %v，want MappingAckRequiredError", err)
	}
}
