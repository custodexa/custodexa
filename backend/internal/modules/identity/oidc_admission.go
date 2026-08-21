package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// 准入規則鍵（封閉集合，idp-oidc-integration D7a）。
//
// 「封閉」是安全要求而非潔癖：未知鍵若被存入後於執行期忽略，一份看似有限制的
// 組態會靜默退化為「無限制」——管理者以為設了 tenant 白名單，實際上全世界都能進。
// 故未知鍵於 CRUD 時即拒絕。
const (
	// AdmissionRuleTenantID Entra 租戶識別（tid claim）∈ 允許清單
	AdmissionRuleTenantID = "tid"
	// AdmissionRuleHostedDomain Google Workspace 組織網域（hd claim）∈ 允許清單。
	// hd 只在使用者屬於 Workspace/Cloud 組織時出現，且 token 內的值受簽章保護
	//（有別於可被客戶端竄改的 hd 請求參數），故可作組織歸屬證明
	AdmissionRuleHostedDomain = "hd"
	// AdmissionRuleEmailDomain email 網域 ∈ 允許清單。
	// **單獨使用不足以證明組織歸屬**——個人帳號可將 email 設為任何已驗證地址
	//（含曾持有的公司信箱），故共用身分域下必須搭配組織歸屬類規則
	AdmissionRuleEmailDomain = "email_domain"
	// AdmissionRuleEmailVerified 要求 email_verified 為布林真值
	AdmissionRuleEmailVerified = "email_verified"
)

// Microsoft 消費者（個人帳號）租戶識別。
//
// 它是 tenant-specific 形狀故會通過 issuer 檢查，但其「租戶」就是全體個人 Microsoft
// 帳號——納入 tid 允許清單等同放行所有個人帳號，故設定時即拒絕
const microsoftConsumerTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

var (
	// ErrAdmissionUnknownRule 規則鍵不在封閉集合內
	ErrAdmissionUnknownRule = errors.New("准入規則含未知的規則鍵")
	// ErrAdmissionEmptyRuleSet 啟用自動供應卻未提供任何規則
	ErrAdmissionEmptyRuleSet = errors.New("啟用自動供應時必須提供至少一條准入規則")
	// ErrAdmissionSharedNeedsOrgRule 共用身分域缺少組織歸屬類規則
	ErrAdmissionSharedNeedsOrgRule = errors.New("共用身分域的准入規則必須包含租戶識別或 hosted domain")
	// ErrAdmissionConsumerTenant 允許清單含消費者租戶識別
	ErrAdmissionConsumerTenant = errors.New("租戶允許清單不得包含身分提供者的消費者租戶識別值")
	// ErrAdmissionEmailNeedsVerified 採 email 類規則卻未要求已驗證
	ErrAdmissionEmailNeedsVerified = errors.New("採用 email 網域規則時必須同時要求 email 已驗證")
)

// AdmissionRules 准入規則集。
//
// 語義完全確定（D7a）：**跨規則 AND、同規則清單內 OR**；claim 缺失、為 null
// 或型別不符一律視為不匹配（fail-close，不做寬鬆轉型）。
type AdmissionRules struct {
	// TenantIDs Entra tid 允許清單
	TenantIDs []string `json:"tid,omitempty"`
	// HostedDomains Google hd 允許清單
	HostedDomains []string `json:"hd,omitempty"`
	// EmailDomains email 網域允許清單（須併同 EmailVerified）
	EmailDomains []string `json:"email_domain,omitempty"`
	// EmailVerified 要求 email_verified 為布林 true
	EmailVerified bool `json:"email_verified,omitempty"`
}

// IsEmpty 規則集是否為空（不含任何限制）
func (r AdmissionRules) IsEmpty() bool {
	return len(r.TenantIDs) == 0 && len(r.HostedDomains) == 0 &&
		len(r.EmailDomains) == 0 && !r.EmailVerified
}

// HasOrgRule 是否含組織歸屬類規則（租戶識別或 hosted domain）
func (r AdmissionRules) HasOrgRule() bool {
	return len(r.TenantIDs) > 0 || len(r.HostedDomains) > 0
}

// ParseAdmissionRules 解析並驗證規則集 JSON。
//
// 未知鍵於此拒絕（DisallowUnknownFields）——這是「封閉集合」的執行點
func ParseAdmissionRules(raw string) (AdmissionRules, error) {
	var rules AdmissionRules
	if strings.TrimSpace(raw) == "" {
		return rules, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rules); err != nil {
		return rules, fmt.Errorf("%w: %v", ErrAdmissionUnknownRule, err)
	}
	return rules, nil
}

// ValidateAdmissionConfig 驗證 provider 的准入組態（CRUD 時呼叫）。
//
// sharedIssuer 為 effective issuer kind 的計算結果（見 EffectiveIssuerKind），
// 由呼叫端傳入而非在此重算——判定輸入含部署層設定，屬 provider service 的職責
func ValidateAdmissionConfig(mode string, rules AdmissionRules, sharedIssuer bool) error {
	if mode != string(admissionJIT) {
		// prebound_only：規則不參與判定，無須驗證
		return nil
	}
	if rules.IsEmpty() {
		return ErrAdmissionEmptyRuleSet
	}
	// 共用身分域（同一 issuer 服務多個組織與個人帳號）必須有組織歸屬證明。
	// 缺此檢查則「Google + 只驗 email 網域」的組態會放行任何把 email 設為
	// 該網域的個人帳號
	if sharedIssuer && !rules.HasOrgRule() {
		return ErrAdmissionSharedNeedsOrgRule
	}
	for _, tid := range rules.TenantIDs {
		if strings.EqualFold(strings.TrimSpace(tid), microsoftConsumerTenantID) {
			return ErrAdmissionConsumerTenant
		}
	}
	if len(rules.EmailDomains) > 0 && !rules.EmailVerified {
		return ErrAdmissionEmailNeedsVerified
	}
	return nil
}

// admissionJIT 內部別名，避免與 model 套件循環引用
const admissionJIT = "jit_with_rules"

// EvaluateAdmission 以 id_token claims 求值准入規則。
//
// **每次認證都呼叫**（D7b），不只首次供應——規則收緊或使用者 claim 變更後，
// 既有身分再次登入須依現行規則判定。身分已存在不使判定被略過。
//
// claims 須為已通過簽章與 iss/aud 驗證的 id_token 內容（不取 userinfo 未驗證回應）。
// 回傳未通過的規則類別供審計（不含 claim 明文）
func EvaluateAdmission(rules AdmissionRules, claims map[string]any) (bool, string) {
	if rules.EmailVerified {
		// 僅接受 JSON 布林真值：字串 "true"、數字 1 一律不算——寬鬆轉型會讓
		// 「宣稱已驗證」的偽造值通過
		v, ok := claims["email_verified"].(bool)
		if !ok || !v {
			return false, AdmissionRuleEmailVerified
		}
	}
	if len(rules.TenantIDs) > 0 && !claimInList(claims, "tid", rules.TenantIDs) {
		return false, AdmissionRuleTenantID
	}
	if len(rules.HostedDomains) > 0 && !claimInList(claims, "hd", rules.HostedDomains) {
		return false, AdmissionRuleHostedDomain
	}
	if len(rules.EmailDomains) > 0 {
		email, ok := claims["email"].(string)
		if !ok || !emailDomainInList(email, rules.EmailDomains) {
			return false, AdmissionRuleEmailDomain
		}
	}
	return true, ""
}

// claimInList claim 值是否在允許清單內（清單內為 OR）。
// claim 缺失、null 或非字串一律不匹配
func claimInList(claims map[string]any, key string, allow []string) bool {
	v, ok := claims[key].(string)
	if !ok || v == "" {
		return false
	}
	for _, a := range allow {
		if strings.EqualFold(strings.TrimSpace(a), v) {
			return true
		}
	}
	return false
}

// emailDomainInList email 的網域部分是否在允許清單內
func emailDomainInList(email string, allow []string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := email[at+1:]
	for _, a := range allow {
		if strings.EqualFold(strings.TrimSpace(a), domain) {
			return true
		}
	}
	return false
}

// 內建的共用身分域清單（idp-oidc-integration D7a）。
//
// 「共用」指同一 issuer 服務多個組織與個人帳號——此時 issuer 本身不構成任何
// 組織歸屬證明，故其准入規則必須含 tid/hd 類條件。
//
// 判定權歸系統：**未知 issuer 一律預設共用**（fail-close），管理者只能改嚴
// 不能放寬；部署層可經 OIDC_DEDICATED_ISSUERS 宣告專屬 issuer，但**本清單優先**
// （不得以部署設定把 Google 宣告為專屬）。
var builtinSharedIssuers = []string{
	"accounts.google.com",
	"https://accounts.google.com",
	// Microsoft 多租戶端點（其 issuer 帶 {tenantid} placeholder，實際上無法通過
	// 嚴格 issuer 比對，此處列入使設定階段即可給出明確診斷）
	"https://login.microsoftonline.com/common/v2.0",
	"https://login.microsoftonline.com/organizations/v2.0",
	"https://login.microsoftonline.com/consumers/v2.0",
	// Microsoft 消費者租戶：形狀是 tenant-specific 但其「租戶」即全體個人帳號
	"https://login.microsoftonline.com/" + microsoftConsumerTenantID + "/v2.0",
}

// EffectiveIssuerKind 現算身分域類型（idp-oidc-integration D7a）。
//
// **不持久化**：三個判定來源（內建清單／管理者收緊／部署層宣告）若壓成單一
// 持久欄位即無法分辨來源——啟動時以部署宣告覆寫會抹掉管理者的收緊，不覆寫則
// 新增宣告不生效，且曾存為 dedicated 者在部署方移除錯誤宣告後仍維持 dedicated。
//
// 固定優先序：
//  1. 內建共用清單命中 → shared（最高，部署宣告不可推翻）
//  2. forceShared == true → shared（管理者收緊）
//  3. 部署層宣告命中 → dedicated
//  4. 其餘 → shared（未知即 fail-close）
func EffectiveIssuerKind(issuer string, forceShared *bool, deployDedicated []string) (shared bool) {
	norm := normalizeIssuer(issuer)
	for _, s := range builtinSharedIssuers {
		if normalizeIssuer(s) == norm {
			return true
		}
	}
	if forceShared != nil && *forceShared {
		return true
	}
	for _, d := range deployDedicated {
		if normalizeIssuer(d) == norm {
			return false
		}
	}
	return true
}

// normalizeIssuer issuer 正規化（去尾斜線、小寫 host）供比對用。
// 僅用於清單比對——id_token 的 iss 驗證一律以原值完整字串比對，不經此正規化
func normalizeIssuer(raw string) string {
	s := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), "/"))
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.ToLower(s)
	}
	u.Host = strings.ToLower(u.Host)
	u.Scheme = strings.ToLower(u.Scheme)
	return strings.TrimSuffix(u.String(), "/")
}
