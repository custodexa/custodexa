package identity

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 登入路徑上的規則集合規性重驗（F1 / spec oidc-auth L161-163）。
//
// 缺這一步的實際後果：部署方把某 issuer 自 OIDC_DEDICATED_ISSUERS 移除後，
// 原本合法的「僅 email 網域」規則就地變成不合規，但**沒有任何寫入操作發生**，
// 寫入期的 ValidateAdmissionConfig 永遠不會被觸發。於是該 provider 繼續以
// email 網域自動供應——而 email 網域在共用身分域（Google／Entra common）上
// 由 IdP 使用者自選，等同任何人都能在本系統開帳號。
//
// fail-close 的邊界同樣要測：**既有已綁身分的登入不受影響**，否則管理者收拾
// 殘局的期間會把全體既有 SSO 使用者一起鎖在門外。

func recheckClaims(subject, email string) *VerifiedClaims {
	return &VerifiedClaims{
		Subject: subject, PreferredUsername: subject,
		Email: email, EmailVerified: true, Name: subject,
		Raw: map[string]any{"email": email, "email_verified": true},
	}
}

func TestJITProvisioningFailsClosedWhenRulesBecomeNoncompliant(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	const issuer = "https://corp.okta.example.com"
	const baseURL = "https://bastion.example.com"

	// 部署方宣告該 issuer 為專用 → 僅 email 網域的規則合法
	declared := newProviderSvcFor(db, testEgress(), []string{issuer}, baseURL)
	dto := mustCreateProvider(t, declared, providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = issuer
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"email_domain":["corp.example"],"email_verified":true}`
	}))
	p := reloadProvider(t, db, dto.ID)

	// (1) 宣告仍在：自動供應正常運作（fail-close 不得誤傷合法組態）
	login.providers = declared
	first, err := login.resolveOrProvision(p, recheckClaims("sub-early", "early@corp.example"), &oidcAuditTrail{})
	if err != nil {
		t.Fatalf("宣告仍在時的自動供應應成功: %v", err)
	}
	if first.Username != "sub-early" {
		t.Errorf("供應所得 username = %q, want sub-early", first.Username)
	}

	// (2) 部署方移除宣告（判定不持久化，重建服務即等同重啟後的新組態）：
	// 同一份規則就地不合規 → 新使用者的自動供應 fail-close 停止
	login.providers = newProviderSvcFor(db, testEgress(), nil, baseURL)
	if _, err := login.resolveOrProvision(p, recheckClaims("sub-late", "late@corp.example"), &oidcAuditTrail{}); !errors.Is(err, ErrOIDCAdmissionDenied) {
		t.Fatalf("宣告移除後的自動供應 → %v, want ErrOIDCAdmissionDenied", err)
	}
	var provisioned int64
	if err := db.Model(&model.User{}).Where("username = ?", "sub-late").
		Count(&provisioned).Error; err != nil {
		t.Fatalf("統計帳號: %v", err)
	}
	if provisioned != 0 {
		t.Error("fail-close 期間不得留下任何供應痕跡")
	}

	// (3) 既有已綁身分的登入**不受影響**：規則不合規是管理者要修的組態問題，
	// 不是把既有使用者全部鎖在門外的理由
	again, err := login.resolveOrProvision(p, recheckClaims("sub-early", "early@corp.example"), &oidcAuditTrail{})
	if err != nil {
		t.Fatalf("既有身分的登入不應被 fail-close 牽連: %v", err)
	}
	if again.ID != first.ID {
		t.Errorf("既有身分應對應同一帳號: %d vs %d", again.ID, first.ID)
	}
}

// prebound_only 的 provider 不受本重驗影響：它根本不自動供應，
// 規則集是否合規與登入判定無關（判定條件即「身分是否已綁定」）
func TestPreboundOnlyUnaffectedByComplianceRecheck(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	const issuer = "https://corp.okta.example.com"
	svc := newProviderSvcFor(db, testEgress(), nil, "https://bastion.example.com")
	dto := mustCreateProvider(t, svc, providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = issuer
	}))
	p := reloadProvider(t, db, dto.ID)
	login.providers = svc

	// 未綁定者一律被拒，成因是 not_prebound 而非規則不合規
	if _, err := login.resolveOrProvision(p, recheckClaims("sub-x", "x@corp.example"), &oidcAuditTrail{}); !errors.Is(err, ErrOIDCAdmissionDenied) {
		t.Fatalf("prebound_only 未綁定者 → %v, want ErrOIDCAdmissionDenied", err)
	}
	// DTO 亦不得因 prebound_only 的空規則集而被標示為不合規
	list, err := svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, d := range list {
		if d.ID == dto.ID && !d.AdmissionCompliant {
			t.Errorf("prebound_only 的空規則集不應被標示為不合規（issue=%q）", d.AdmissionIssue)
		}
	}
}
