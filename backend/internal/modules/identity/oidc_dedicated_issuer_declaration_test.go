package identity

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 部署層專用 issuer 宣告（OIDC_DEDICATED_ISSUERS）的補格測試（idp-oidc-integration tasks 4.18）。
//
// 既有覆蓋（oidc_provider_service_test.go）：
//   - Okta 型 issuer 經宣告後可設僅含 email 網域的 JIT 規則（DedicatedIssuerAllowsEmailOnlyRules）
//   - Google 的宣告不生效（BuiltinSharedOverridesDeployDeclaration）
//   - 宣告移除後回復共用並重驗既有規則（DeployDeclarationRemovalRevertsToShared）
//
// 本檔補三格：
//  1. **Microsoft** 那幾個內建共用端點的宣告同樣不生效（既有只驗了 Google，
//     內建清單漏掉任一項的後果是該 issuer 可被宣告為專用 → 全體個人／他組織帳號
//     符合 email 網域即自動供應）。
//  2. 「宣告」是唯一的差異因子——同一 issuer、同一份規則，有宣告則准、無宣告則拒。
//     既有測試各驗一半，配對之後拿掉宣告查詢才會轉紅。
//  3. 比對語義：尾斜線／大小寫差異視為同一 issuer（部署方多打一個斜線不得靜默失效），
//     但**不做前綴比對**——宣告某 host 不得順帶把該 host 底下的其他 issuer 路徑
//     一併變成專用。

const oktaTypeIssuer = "https://corp.okta.example.com"

// emailOnlyJITReq 僅含 email 網域條件的 JIT 規則（共用身分域一律不足）
func emailOnlyJITReq(issuer, clientID string) *OIDCProviderRequest {
	return providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = issuer
		r.ClientID = clientID
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"email_domain":["corp.example"],"email_verified":true}`
	})
}

// Scenario: 已知共用身分域不可經部署層宣告為專用——Microsoft 端點（spec L165-167）
func TestOIDCProviderDeployDeclarationIneffectiveForMicrosoftIssuers(t *testing.T) {
	microsoftShared := []string{
		"https://login.microsoftonline.com/common/v2.0",
		"https://login.microsoftonline.com/organizations/v2.0",
		"https://login.microsoftonline.com/consumers/v2.0",
		"https://login.microsoftonline.com/" + microsoftConsumerTenantID + "/v2.0",
	}
	for i, issuer := range microsoftShared {
		issuer := issuer
		t.Run(issuer, func(t *testing.T) {
			_, _, db := setupOIDCEnv(t)
			// 部署方把該端點列入專用宣告——內建清單優先，宣告不生效
			svc := newProviderSvcFor(db, testEgress(), []string{issuer}, "https://bastion.example.com")

			if _, err := svc.Create(emailOnlyJITReq(issuer, "cid-ms-a")); !errors.Is(err, ErrAdmissionSharedNeedsOrgRule) {
				t.Fatalf("內建共用端點仍須組織歸屬規則 → %v, want ErrAdmissionSharedNeedsOrgRule", err)
			}

			// 帶 tid 組織歸屬規則則可設定，且判定來源須標示為內建清單——
			// 來源顯示為 deploy_declared 代表宣告其實生效了，只是規則恰好也合格
			dto, err := svc.Create(providerReq(func(r *OIDCProviderRequest) {
				r.Issuer = issuer
				r.ClientID = "cid-ms-b"
				r.AdmissionMode = string(model.AdmissionJITWithRules)
				r.AdmissionRules = `{"tid":["11111111-2222-3333-4444-55555555555` + string(rune('0'+i)) + `"]}`
			}))
			if err != nil {
				t.Fatalf("內建共用端點＋tid 規則應可設定: %v", err)
			}
			if dto.IssuerKind != "shared" || dto.IssuerKindSource != "builtin_list" {
				t.Errorf("issuer_kind = %q/%q, want shared/builtin_list（部署宣告不得推翻內建清單）",
					dto.IssuerKind, dto.IssuerKindSource)
			}
		})
	}
}

// Scenario: 專屬身分提供者可組態自動供應——宣告是唯一的差異因子（spec L157-159）
//
// Okta 型 issuer 不發 hd/tid，可用的組織歸屬證明只有 email 網域；沒有部署層宣告時
// 它落在「未知 → 一律共用」的 fail-close 分支，同一份規則必被拒
func TestOIDCProviderDedicatedDeclarationIsTheDecidingFactor(t *testing.T) {
	// (a) 未宣告：fail-close 視為共用，僅 email 網域的規則不足
	t.Run("未宣告", func(t *testing.T) {
		_, _, db := setupOIDCEnv(t)
		svc := newProviderSvcFor(db, testEgress(), nil, "https://bastion.example.com")
		if _, err := svc.Create(emailOnlyJITReq(oktaTypeIssuer, "cid-okta")); !errors.Is(err, ErrAdmissionSharedNeedsOrgRule) {
			t.Fatalf("未宣告的 Okta 型 issuer → %v, want ErrAdmissionSharedNeedsOrgRule", err)
		}
	})

	// (b) 已宣告：同一 issuer、同一份規則即可組態 JIT
	t.Run("已宣告", func(t *testing.T) {
		_, _, db := setupOIDCEnv(t)
		svc := newProviderSvcFor(db, testEgress(), []string{oktaTypeIssuer}, "https://bastion.example.com")
		dto, err := svc.Create(emailOnlyJITReq(oktaTypeIssuer, "cid-okta"))
		if err != nil {
			t.Fatalf("宣告為專用者應可設僅含 email 網域的規則: %v", err)
		}
		if dto.IssuerKind != "dedicated" || dto.IssuerKindSource != "deploy_declared" {
			t.Errorf("issuer_kind = %q/%q, want dedicated/deploy_declared", dto.IssuerKind, dto.IssuerKindSource)
		}
		if !dto.AdmissionCompliant {
			t.Error("宣告仍在時規則集須為合規")
		}
	})
}

// Scenario: 宣告比對的正規化與邊界（spec L157-167 的實作前提）
func TestOIDCProviderDeclarationMatchingNormalizationAndScope(t *testing.T) {
	cases := []struct {
		name        string
		declaration string
		issuer      string
		wantAllowed bool
	}{
		// 尾斜線與大小寫是部署設定最常見的形狀差異；不正規化的後果是宣告靜默失效，
		// 症狀只有「使用者無法自動供應」而管理端查不到原因
		{"宣告帶尾斜線", oktaTypeIssuer + "/", oktaTypeIssuer, true},
		{"宣告 host 大寫", "https://CORP.OKTA.EXAMPLE.COM", oktaTypeIssuer, true},
		{"宣告帶前後空白", "  " + oktaTypeIssuer + "  ", oktaTypeIssuer, true},
		// 反面：宣告一個 host 不得順帶放行該 host 底下其他路徑的 issuer。
		// 前綴比對會讓「宣告 https://corp.okta.example.com」意外涵蓋所有
		// /oauth2/<任意授權伺服器>，其中可能包含對外開放註冊的那一個
		{"不同路徑不得被前綴涵蓋", oktaTypeIssuer, oktaTypeIssuer + "/oauth2/default", false},
		{"不同 host 不得命中", "https://other.okta.example.com", oktaTypeIssuer, false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			_, _, db := setupOIDCEnv(t)
			svc := newProviderSvcFor(db, testEgress(), []string{c.declaration}, "https://bastion.example.com")
			dto, err := svc.Create(emailOnlyJITReq(c.issuer, "cid-norm"))
			if c.wantAllowed {
				if err != nil {
					t.Fatalf("宣告 %q 應涵蓋 issuer %q: %v", c.declaration, c.issuer, err)
				}
				if dto.IssuerKind != "dedicated" {
					t.Errorf("issuer_kind = %q, want dedicated", dto.IssuerKind)
				}
				return
			}
			if !errors.Is(err, ErrAdmissionSharedNeedsOrgRule) {
				t.Fatalf("宣告 %q 不得涵蓋 issuer %q → %v, want ErrAdmissionSharedNeedsOrgRule",
					c.declaration, c.issuer, err)
			}
		})
	}
}
