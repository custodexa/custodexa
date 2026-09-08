package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

var (
	// ErrOIDCProviderNotFound provider 不存在
	ErrOIDCProviderNotFound = errors.New("OIDC provider 不存在")
	// ErrOIDCImmutableField 嘗試變更建後不可變的身分域欄位
	ErrOIDCImmutableField = errors.New("issuer 與 client_id 建立後不可變更")
	// ErrOIDCProviderInUse provider 仍有外部身分關聯，不可刪除
	ErrOIDCProviderInUse = errors.New("此 provider 仍有使用者外部身分關聯，請改為停用")
	// ErrOIDCDuplicateIdentityDomain (issuer, client_id) 已存在
	ErrOIDCDuplicateIdentityDomain = errors.New("已存在相同 issuer 與 client_id 的 provider")
	// ErrOIDCUnknownScope scope 不在允許清單
	ErrOIDCUnknownScope = errors.New("scope 不在允許清單內")
	// ErrOIDCBaseURLMissing 未設定對外基準網址
	ErrOIDCBaseURLMissing = errors.New("未設定 PUBLIC_BASE_URL，無法組出 redirect_uri")
	// ErrOIDCSharedCannotWiden 嘗試把系統判定為共用的身分域標記為專用（spec L169-171）。
	//
	// 「靜默接受但不生效」不可接受：管理者會以為自己已把 provider 設為專用，
	// 據以放寬准入規則（僅 email 網域），下一步的規則檢查卻以共用身分域為準而拒絕，
	// 症狀表現為「規則設定莫名被拒」而非「你的專用宣告無效」——這正是
	// issuer_kind_source 要避免的那種難查故障
	ErrOIDCSharedCannotWiden = errors.New("此 issuer 由系統判定為共用身分域，不可標記為專用；如為企業專屬 IdP 請於部署層宣告")
	// ErrOIDCInvalidClaimName 宣告名稱不合法（過長或含空白）
	ErrOIDCInvalidClaimName = errors.New("宣告名稱不合法")
	// ErrOIDCProviderHasMappings provider 仍有群組映射規則，不可刪除
	ErrOIDCProviderHasMappings = errors.New("此 provider 仍有群組映射規則，請先移除規則")
)

// oidcAllowedExtraScopes 附加 scope 允許清單。
//
// openid 由伺服端強制注入，不需列入。**offline_access 刻意不在清單**：
// v1 明訂不保存 IdP 的 refresh token（會話生命週期不依賴 IdP token），
// 索取它只會擴大同意畫面與 token 暴露面而無任何用途。
//
// **groups 在清單內**：多數提供者只有在授權請求帶這個 scope 時才發出群組宣告，
// 不放行等於群組映射在那些部署上不論怎麼設定都零命中，且沒有任何訊號。
// 它與 offline_access 的差別在於用途明確且只影響本次身分權杖的內容。
var oidcAllowedExtraScopes = map[string]bool{
	"profile": true,
	"email":   true,
	"groups":  true,
}

// oidcClaimNameMaxLen 宣告名稱長度上限（與欄位寬度一致）
const oidcClaimNameMaxLen = 64

// oidcClaimNames 一次請求帶來的四個宣告名稱（皆已驗證）
type oidcClaimNames struct {
	groups      string
	username    string
	email       string
	displayName string
}

// claimNamesFrom 自建立請求取四個宣告名稱（未給即空）
func claimNamesFrom(req *OIDCProviderRequest) (oidcClaimNames, error) {
	var out oidcClaimNames
	fields := []struct {
		src *string
		dst *string
	}{
		{req.GroupsClaim, &out.groups},
		{req.UsernameClaim, &out.username},
		{req.EmailClaim, &out.email},
		{req.DisplayNameClaim, &out.displayName},
	}
	for _, f := range fields {
		if f.src == nil {
			continue
		}
		v, err := normalizeClaimName(*f.src)
		if err != nil {
			return oidcClaimNames{}, err
		}
		*f.dst = v
	}
	return out, nil
}

// normalizeClaimName 宣告名稱的驗證與正規化。
//
// 只去頭尾空白、不折疊大小寫——宣告鍵在 JSON 物件裡是逐字的，折疊會使
// 設定看起來被接受而實際永遠取不到值。含空白者直接拒絕：那必定是誤填
// （例如把兩個候選鍵寫在一起），靜默接受的症狀是「設定存好了但沒作用」。
func normalizeClaimName(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", nil
	}
	if len(v) > oidcClaimNameMaxLen {
		return "", fmt.Errorf("%w: 長度上限 %d", ErrOIDCInvalidClaimName, oidcClaimNameMaxLen)
	}
	if strings.ContainsAny(v, " \t\r\n") {
		return "", fmt.Errorf("%w: 不得含空白", ErrOIDCInvalidClaimName)
	}
	return v, nil
}

// OIDCProviderService OIDC provider 設定管理。
//
// 安全性質：
//   - client_secret 走信封加密，write-only——任何讀取回應皆不含明文或密文，
//     更新時空值沿用既有值（管理者不需為了改顯示名而重新輸入密鑰）
//   - issuer 與 client_id 建後不可變，**由後端強制**（非僅前端停用輸入——
//     API 可繞過 UI）。它們是外部身分的鍵，變更即等同換身分域，會使既有使用者全數失聯
//   - 停用、刪除、密鑰輪替皆推進 auth_epoch，使既簽憑證立即失效且重新啟用不復活
type OIDCProviderService struct {
	db    *gorm.DB
	codec crypto.ColumnCodec
	// egress 出站信任邊界（issuer 形狀與 scheme 驗證）
	egress *OIDCEgressPolicy
	// deployDedicatedIssuers 部署層宣告的專屬 issuer（OIDC_DEDICATED_ISSUERS）。
	// 這是 Okta／自架 IdP 的必要逃生口——它們不發 hd/tid 類組織歸屬 claim，
	// 若無此宣告，其自動供應在「未知 issuer 即共用、共用須含組織規則」下不可組態
	deployDedicatedIssuers []string
	// baseURL 對外基準網址（PUBLIC_BASE_URL），用於組 redirect_uri
	baseURL string

	// --- 停用／刪除的全面失效管道（3.8；未注入者該管道不生效） ---
	// sessions 協議會話終斷（兩階段：鎖內標記、鎖外關 WS）
	sessions ProviderSessionTerminator
	// subscriptions 唯讀訂閱收線（監看／分享不建 sessions 列，會話掃描掃不到）
	subscriptions ProviderSubscriptionTerminator
	// recordingTokens 錄影 token 撤銷（in-memory 且不做世代比對，唯一失效途徑）
	recordingTokens ProviderRecordingTokenRevoker
}

// NewOIDCProviderService 建立 provider 設定服務
func NewOIDCProviderService(db *gorm.DB, codec crypto.ColumnCodec, egress *OIDCEgressPolicy,
	deployDedicated []string, baseURL string) *OIDCProviderService {
	return &OIDCProviderService{
		db:                     db,
		codec:                  codec,
		egress:                 egress,
		deployDedicatedIssuers: deployDedicated,
		baseURL:                strings.TrimRight(strings.TrimSpace(baseURL), "/"),
	}
}

// OIDCProviderRequest provider 建立/更新請求
type OIDCProviderRequest struct {
	Name           string `json:"name" binding:"required"`
	Issuer         string `json:"issuer"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	Scopes         string `json:"scopes"`
	AdmissionMode  string `json:"admission_mode"`
	AdmissionRules string `json:"admission_rules"`
	ForceShared    *bool  `json:"force_shared"`
	Enabled        *bool  `json:"enabled"`

	// 宣告名稱四欄一律用指標：nil＝本次請求不動這一欄，空字串＝清回未設定。
	// 用值型別的話「清回未設定」與「沒送這一欄」同形，管理者就再也關不掉
	// 一條已經設過的群組映射
	GroupsClaim      *string `json:"groups_claim"`
	UsernameClaim    *string `json:"username_claim"`
	EmailClaim       *string `json:"email_claim"`
	DisplayNameClaim *string `json:"display_name_claim"`

	// RiskAcknowledged 風險確認聲明（欄名與目錄設定、通知通道一致）。
	//
	// 目前唯一要求它的情形：設了群組宣告名卻沒帶 groups 授權範圍。
	// **警告加確認、不阻擋**——Entra 走權杖設定不需要這個範圍，逕行阻擋會把
	// 一個合法組態鎖在門外；而多數提供者缺了它就不發群組宣告，
	// 症狀是全體映射角色被撤且沒有任何訊號，所以也不能靜默放過
	RiskAcknowledged bool `json:"risk_acknowledged"`
}

// OIDCProviderDTO provider 對外呈現（**不含 client_secret 的任何形式**）
type OIDCProviderDTO struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	Issuer         string `json:"issuer"`
	ClientID       string `json:"client_id"`
	Scopes         string `json:"scopes"`
	AdmissionMode  string `json:"admission_mode"`
	AdmissionRules string `json:"admission_rules"`
	Enabled        bool   `json:"enabled"`
	// GroupsClaim 群組資訊取自哪個宣告；空＝此 provider 的群組映射關閉
	GroupsClaim string `json:"groups_claim"`
	// 宣告對應三欄；空＝沿用系統既有的預設宣告與回退規則
	UsernameClaim    string `json:"username_claim"`
	EmailClaim       string `json:"email_claim"`
	DisplayNameClaim string `json:"display_name_claim"`
	// HasSecret 是否已設定密鑰（供 UI 顯示「留空沿用」的提示，不洩漏值本身）
	HasSecret bool `json:"has_secret"`
	// RedirectURI 本系統的固定回呼位址（要登記到提供者端的值）。
	// 未設定對外基準網址時為空字串，並由 RedirectURIState 說明原因——
	// 現況是按下登入才失敗，管理端在設定階段看不出缺了什麼
	RedirectURI string `json:"redirect_uri"`
	// RedirectURIState ready 或 base_url_unset
	RedirectURIState string `json:"redirect_uri_state"`
	// IssuerKind effective 判定結果（現算，不持久化）
	IssuerKind string `json:"issuer_kind"`
	// IssuerKindSource 判定來源，使「部署宣告打錯字而未生效」可被立即看出，
	// 而非表現為「規則設定莫名被拒」
	IssuerKindSource string `json:"issuer_kind_source"`
	// ConfigComplete 設定是否完整（缺對外基準網址時 begin 必失敗，
	// 此類 provider 不應出現在登入頁）
	ConfigComplete bool   `json:"config_complete"`
	IncompleteHint string `json:"incomplete_hint,omitempty"`
	// IdentityCount 已綁定此 provider 的外部身分數。
	//
	// 兩處需要具體數字而非語義提示：切換為 prebound_only 時「既有 N 個身分沿用、
	// 新使用者不再自動供應」，以及刪除被拒時「請先解綁 N 個身分」。
	// 只說「有既有身分」會讓管理者無從判斷這個操作的影響面
	IdentityCount int64 `json:"identity_count"`
	// AdmissionCompliant 現行規則集是否仍符合**現算**身分域的合規要求（spec L161-163）。
	//
	// 為什麼需要獨立欄位：issuer kind 不持久化、每次現算，故部署層移除某 issuer
	// 的專用宣告後，原本合法的「僅 email 網域」規則會就地變成不合規，但沒有任何
	// 寫入操作發生、也沒有任何錯誤回應——管理端若不標示，唯一的症狀是使用者
	// 突然無法自動供應而管理者查不到原因
	AdmissionCompliant bool `json:"admission_compliant"`
	// AdmissionIssue 不合規成因的機器碼（合規時為空）。
	// 只給機器可辨的分類，前端負責文案（三語）
	AdmissionIssue string `json:"admission_issue,omitempty"`
}

// toDTO 組裝對外呈現
func (s *OIDCProviderService) toDTO(p *model.OIDCProvider) OIDCProviderDTO {
	shared := EffectiveIssuerKind(p.Issuer, p.ForceShared, s.deployDedicatedIssuers)
	kind, source := "dedicated", "deploy_declared"
	if shared {
		kind = "shared"
		switch {
		case s.isBuiltinShared(p.Issuer):
			source = "builtin_list"
		case p.ForceShared != nil && *p.ForceShared:
			source = "admin_forced"
		default:
			source = "unknown_default"
		}
	}
	dto := OIDCProviderDTO{
		ID: p.ID, Name: p.Name, Issuer: p.Issuer, ClientID: p.ClientID,
		Scopes: p.Scopes, AdmissionMode: string(p.AdmissionMode),
		AdmissionRules: p.AdmissionRules, Enabled: p.Enabled,
		HasSecret: p.ClientSecretEnc != "", IssuerKind: kind, IssuerKindSource: source,
		ConfigComplete:   true,
		GroupsClaim:      p.GroupsClaim,
		UsernameClaim:    p.UsernameClaim,
		EmailClaim:       p.EmailClaim,
		DisplayNameClaim: p.DisplayNameClaim,
	}
	if uri, err := s.RedirectURI(); err == nil {
		dto.RedirectURI = uri
		dto.RedirectURIState = RedirectURIStateReady
	} else {
		dto.RedirectURIState = RedirectURIStateBaseURLUnset
	}
	if s.baseURL == "" {
		dto.ConfigComplete = false
		dto.IncompleteHint = "public_base_url_missing"
	}
	if err := s.AdmissionComplianceOf(p); err != nil {
		dto.AdmissionIssue = admissionIssueCode(err)
	} else {
		dto.AdmissionCompliant = true
	}
	return dto
}

// AdmissionComplianceOf 現算該 provider 的規則集是否仍合規（nil 即合規）。
//
// 判定與 Create／Update 的寫入期驗證**同源**（ValidateAdmissionConfig）——
// 這是關鍵：若兩處各寫一份判定，部署宣告變更後「寫入時會被拒的設定」與
// 「執行期仍被放行的設定」會分岔，fail-close 就會有漏。
//
// 用於兩處：管理端 DTO 的不合規標示，以及登入路徑上自動供應前的重驗。
func (s *OIDCProviderService) AdmissionComplianceOf(p *model.OIDCProvider) error {
	rules, err := ParseAdmissionRules(p.AdmissionRules)
	if err != nil {
		return err
	}
	shared := EffectiveIssuerKind(p.Issuer, p.ForceShared, s.deployDedicatedIssuers)
	return ValidateAdmissionConfig(string(p.AdmissionMode), rules, shared)
}

// admissionIssueCode 不合規成因 → 機器碼（前端負責文案）
func admissionIssueCode(err error) string {
	switch {
	case errors.Is(err, ErrAdmissionSharedNeedsOrgRule):
		return "shared_needs_org_rule"
	case errors.Is(err, ErrAdmissionEmptyRuleSet):
		return "empty_rule_set"
	case errors.Is(err, ErrAdmissionConsumerTenant):
		return "consumer_tenant"
	case errors.Is(err, ErrAdmissionEmailNeedsVerified):
		return "email_needs_verified"
	case errors.Is(err, ErrAdmissionUnknownRule):
		return "unknown_rule"
	default:
		return "invalid_rules"
	}
}

func (s *OIDCProviderService) isBuiltinShared(issuer string) bool {
	// 以「未提供任何覆寫來源」重算：若此時仍為 shared，即來自內建清單
	return EffectiveIssuerKind(issuer, nil, []string{issuer})
}

// 回呼網址的兩種狀態（機器碼；對外文案由用戶端依碼決定）
const (
	// RedirectURIStateReady 已由對外基準網址算出
	RedirectURIStateReady = "ready"
	// RedirectURIStateBaseURLUnset 尚未設定對外基準網址，回呼網址無從算出。
	// **回可辨識的狀態而非空字串**：空字串與「算出來是空的」同形，
	// 而管理者要知道的是「去把基準網址設起來」
	RedirectURIStateBaseURLUnset = "base_url_unset"
)

// scopesContainGroups 授權範圍是否含 groups。
//
// 設了群組宣告名卻沒帶這個範圍時，多數提供者不發群組宣告；判定的是
// 已正規化的範圍字串，故逐欄位比對即可（不做前綴或子字串匹配——
// 那會讓 `groups_extra` 之類的自訂範圍被誤判為已具備）
func scopesContainGroups(scopes string) bool {
	for _, f := range strings.Fields(scopes) {
		if strings.EqualFold(f, "groups") {
			return true
		}
	}
	return false
}

// requireGroupsScopeAck 設了群組宣告名卻沒帶 groups 授權範圍時要求確認。
//
// 不阻擋（確認即放行）：Entra 走權杖設定，不需要這個範圍，逕行阻擋會把一個
// 合法組態鎖在門外。但也不能靜默——多數提供者缺了它就不發群組宣告，
// 而鍵缺席依既有判準是「空集合」，於是全體映射角色被撤，且沒有任何訊號。
func requireGroupsScopeAck(groupsClaim, scopes string, acknowledged bool) error {
	if groupsClaim == "" || scopesContainGroups(scopes) || acknowledged {
		return nil
	}
	return &MappingAckRequiredError{Warnings: []string{mappingWarningGroupsScopeMissing}}
}

// Egress 對外出站政策（探索預覽沿用同一份信任邊界，不另建撥號路徑）
func (s *OIDCProviderService) Egress() *OIDCEgressPolicy {
	return s.egress
}

// Get 單筆 provider 詳情（含回呼網址與宣告對應四欄）
func (s *OIDCProviderService) Get(id uint) (*OIDCProviderDTO, error) {
	var p model.OIDCProvider
	if err := s.db.First(&p, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOIDCProviderNotFound
		}
		return nil, err
	}
	dto := s.toDTO(&p)
	dto.IdentityCount = s.identityCounts()[p.ID]
	return &dto, nil
}

// RedirectURI 組出固定的 callback 位址（單一 URI，provider 由 state 關聯）
func (s *OIDCProviderService) RedirectURI() (string, error) {
	if s.baseURL == "" {
		return "", ErrOIDCBaseURLMissing
	}
	return s.baseURL + "/api/v1/auth/oidc/callback", nil
}

// normalizeScopes 驗證並正規化 scope：強制注入 openid，附加項限允許清單
func normalizeScopes(raw string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(raw))
	out := []string{"openid"}
	seen := map[string]bool{"openid": true}
	for _, f := range fields {
		f = strings.ToLower(f)
		if seen[f] {
			continue
		}
		if f == "openid" {
			continue
		}
		if !oidcAllowedExtraScopes[f] {
			return "", fmt.Errorf("%w: %s", ErrOIDCUnknownScope, f)
		}
		out = append(out, f)
		seen[f] = true
	}
	return strings.Join(out, " "), nil
}

// Create 建立 provider
func (s *OIDCProviderService) Create(req *OIDCProviderRequest) (*OIDCProviderDTO, error) {
	issuer := strings.TrimSpace(req.Issuer)
	clientID := strings.TrimSpace(req.ClientID)
	if issuer == "" || clientID == "" {
		return nil, errors.New("issuer 與 client_id 為必填")
	}
	if err := s.egress.ValidateIssuerURL(issuer); err != nil {
		return nil, err
	}

	scopes, err := normalizeScopes(req.Scopes)
	if err != nil {
		return nil, err
	}

	mode := strings.TrimSpace(req.AdmissionMode)
	if mode == "" {
		mode = string(model.AdmissionPreboundOnly)
	}
	if mode != string(model.AdmissionPreboundOnly) && mode != string(model.AdmissionJITWithRules) {
		return nil, errors.New("admission_mode 值域為 prebound_only 或 jit_with_rules")
	}
	rules, err := ParseAdmissionRules(req.AdmissionRules)
	if err != nil {
		return nil, err
	}
	if err := s.rejectSharedWidening(issuer, req.ForceShared); err != nil {
		return nil, err
	}
	shared := EffectiveIssuerKind(issuer, req.ForceShared, s.deployDedicatedIssuers)
	if err := ValidateAdmissionConfig(mode, rules, shared); err != nil {
		return nil, err
	}

	// 唯一性先查（DB partial unique index 為最終仲裁，此處提供友善錯誤）
	var dup int64
	if err := s.db.Model(&model.OIDCProvider{}).
		Where("issuer = ? AND client_id = ?", issuer, clientID).Count(&dup).Error; err != nil {
		return nil, err
	}
	if dup > 0 {
		return nil, ErrOIDCDuplicateIdentityDomain
	}

	claims, err := claimNamesFrom(req)
	if err != nil {
		return nil, err
	}
	if err := requireGroupsScopeAck(claims.groups, scopes, req.RiskAcknowledged); err != nil {
		return nil, err
	}

	p := model.OIDCProvider{
		Name: strings.TrimSpace(req.Name), Issuer: issuer, ClientID: clientID,
		Scopes: scopes, AdmissionMode: model.AdmissionMode(mode),
		AdmissionRules: req.AdmissionRules, ForceShared: req.ForceShared,
		GroupsClaim:      claims.groups,
		UsernameClaim:    claims.username,
		EmailClaim:       claims.email,
		DisplayNameClaim: claims.displayName,
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}
	if strings.TrimSpace(req.ClientSecret) != "" {
		enc, err := s.encryptSecret(req.ClientSecret)
		if err != nil {
			return nil, err
		}
		p.ClientSecretEnc = enc
	}
	if err := s.db.Create(&p).Error; err != nil {
		return nil, fmt.Errorf("建立 OIDC provider 失敗: %w", err)
	}
	dto := s.toDTO(&p)
	return &dto, nil
}

// Update 更新 provider。
//
// issuer 與 client_id 於此**強制不可變**——前端雖已停用輸入，但 API 可繞過 UI；
// 身分域一旦變更，既有外部身分全數失聯（Entra 的 sub 更是 per-client pairwise，
// 換 client_id 後同一人會拿到完全不同的 subject）
func (s *OIDCProviderService) Update(id uint, req *OIDCProviderRequest) (*OIDCProviderDTO, error) {
	var p model.OIDCProvider
	if err := s.db.First(&p, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOIDCProviderNotFound
		}
		return nil, err
	}

	if v := strings.TrimSpace(req.Issuer); v != "" && v != p.Issuer {
		return nil, ErrOIDCImmutableField
	}
	if v := strings.TrimSpace(req.ClientID); v != "" && v != p.ClientID {
		return nil, ErrOIDCImmutableField
	}

	updates := map[string]any{}
	if v := strings.TrimSpace(req.Name); v != "" {
		updates["name"] = v
	}
	if strings.TrimSpace(req.Scopes) != "" {
		scopes, err := normalizeScopes(req.Scopes)
		if err != nil {
			return nil, err
		}
		updates["scopes"] = scopes
	}

	// 宣告名稱四欄：nil＝不動，空字串＝清回未設定（見請求結構的註解）
	for _, f := range []struct {
		src    *string
		column string
	}{
		{req.GroupsClaim, "groups_claim"},
		{req.UsernameClaim, "username_claim"},
		{req.EmailClaim, "email_claim"},
		{req.DisplayNameClaim, "display_name_claim"},
	} {
		if f.src == nil {
			continue
		}
		v, err := normalizeClaimName(*f.src)
		if err != nil {
			return nil, err
		}
		updates[f.column] = v
	}

	// 群組宣告名與 groups 授權範圍是一組，判定吃的是**套用之後**的值：
	// 只改其中一欄的請求也必須以合併後的結果判斷，否則分兩次送就繞過了確認
	effScopes := p.Scopes
	if v, ok := updates["scopes"].(string); ok {
		effScopes = v
	}
	effGroupsClaim := p.GroupsClaim
	if v, ok := updates["groups_claim"].(string); ok {
		effGroupsClaim = v
	}
	if err := requireGroupsScopeAck(effGroupsClaim, effScopes, req.RiskAcknowledged); err != nil {
		return nil, err
	}

	mode := string(p.AdmissionMode)
	if v := strings.TrimSpace(req.AdmissionMode); v != "" {
		if v != string(model.AdmissionPreboundOnly) && v != string(model.AdmissionJITWithRules) {
			return nil, errors.New("admission_mode 值域為 prebound_only 或 jit_with_rules")
		}
		mode = v
		updates["admission_mode"] = v
	}
	rulesRaw := p.AdmissionRules
	if req.AdmissionRules != "" {
		rulesRaw = req.AdmissionRules
		updates["admission_rules"] = req.AdmissionRules
	}
	rules, err := ParseAdmissionRules(rulesRaw)
	if err != nil {
		return nil, err
	}
	forceShared := p.ForceShared
	if req.ForceShared != nil {
		// 放寬企圖須**拒絕並回明確錯誤**（spec L169-171），不得靜默接受
		if err := s.rejectSharedWidening(p.Issuer, req.ForceShared); err != nil {
			return nil, err
		}
		forceShared = req.ForceShared
		updates["force_shared"] = req.ForceShared
	}
	shared := EffectiveIssuerKind(p.Issuer, forceShared, s.deployDedicatedIssuers)
	if err := ValidateAdmissionConfig(mode, rules, shared); err != nil {
		return nil, err
	}

	// 密鑰輪替：推進 auth_epoch 並執行完整失效流程。
	// 輪替的動機是「舊密鑰可能已洩漏」——僅換密鑰而不使既有存取失效與該動機矛盾
	secretRotated := strings.TrimSpace(req.ClientSecret) != ""
	if secretRotated {
		enc, err := s.encryptSecret(req.ClientSecret)
		if err != nil {
			return nil, err
		}
		updates["client_secret_enc"] = enc
	}

	// 停用：推進世代（重新啟用不回退，故舊憑證永久失效）
	disabling := req.Enabled != nil && !*req.Enabled && p.Enabled
	if req.Enabled != nil {
		// **啟用時重驗 issuer scheme**（spec L67-69）：issuer 建後不可變，
		// 但 AllowInsecureHosts 是部署層狀態——dev 建立的 http provider 在同一份
		// DB 升為 release 後，若只有 Create 驗過 scheme，一句 `{"enabled":true}`
		// 即可讓明文 issuer 重新上線。
		// **只擋啟用、不擋停用**：停用只會縮小攻擊面，一併擋下會把管理者鎖在
		// 「不能啟用也不能停用」的死角
		if *req.Enabled {
			if err := s.egress.ValidateIssuerURL(p.Issuer); err != nil {
				return nil, err
			}
		}
		updates["enabled"] = *req.Enabled
	}

	// **世代推進與掃描標記一律走 invalidateProviderLocked**（3.8a）：
	// 早期版本把 `auth_epoch + 1` 混進 updates map，那使推進與收線分屬兩個時刻，
	// 中間的窗口正是 design 行 266 的 TOCTOU
	needsInvalidation := disabling || secretRotated
	var plan *providerRevocationPlan
	reason := invalidationReason(disabling, secretRotated)

	err = WithOIDCProviderLock(s.db, id, func(tx *gorm.DB) error {
		if len(updates) > 0 {
			if err := tx.Model(&model.OIDCProvider{}).Where("id = ?", id).
				Updates(updates).Error; err != nil {
				return fmt.Errorf("更新 OIDC provider 失敗: %w", err)
			}
		}
		if !needsInvalidation {
			return nil
		}
		var perr error
		plan, perr = s.invalidateProviderLocked(tx, id, reason)
		return perr
	})
	if err != nil {
		return nil, err
	}

	if needsInvalidation {
		log.Printf("[OIDC] provider %d 憑證世代已推進（停用=%v 密鑰輪替=%v）", id, disabling, secretRotated)
		// 鎖外收線（design 行 268：持鎖時長界定為單次 DB 往返級）
		s.revokeProviderAccess(id, plan, reason)
	}

	if err := s.db.First(&p, id).Error; err != nil {
		return nil, err
	}
	dto := s.toDTO(&p)
	return &dto, nil
}

// invalidationReason 失效成因的機器碼（審計與日誌用）
func invalidationReason(disabling, secretRotated bool) string {
	switch {
	case disabling && secretRotated:
		return "provider_disabled_and_secret_rotated"
	case secretRotated:
		return "provider_secret_rotated"
	default:
		return "provider_disabled"
	}
}

// rejectSharedWidening 「共用身分域不可被放寬為專用」（spec L169-171）。
//
// 判準是「送出 force_shared=false 之後，系統的**現算**判定是否仍為共用」：
//   - 內建共用清單成員（Google／Entra common 等）→ 仍為共用 → 拒絕
//   - 未知 issuer（fail-close 預設共用、無部署宣告）→ 仍為共用 → 拒絕
//   - 部署層已宣告專用者 → 判定即為專用，force_shared=false 與系統判定一致 → 放行
//     （這是管理者撤回自己先前 force_shared=true 收緊的正當途徑）
func (s *OIDCProviderService) rejectSharedWidening(issuer string, forceShared *bool) error {
	if forceShared == nil || *forceShared {
		return nil // 未表態，或表態為「收緊為共用」——收緊一律允許
	}
	if EffectiveIssuerKind(issuer, forceShared, s.deployDedicatedIssuers) {
		return ErrOIDCSharedCannotWiden
	}
	return nil
}

// Delete 刪除 provider（軟刪）。
//
// 有外部身分關聯者拒絕——身分以 (issuer, client_id, subject) 為鍵，provider 列
// 只是設定載體，但刪除後管理端將無從按 provider 收線或重新啟用，故要求先解綁
func (s *OIDCProviderService) Delete(id uint) error {
	var p model.OIDCProvider
	if err := s.db.First(&p, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrOIDCProviderNotFound
		}
		return err
	}
	var linked int64
	if err := s.db.Model(&model.UserExternalIdentity{}).
		Where("provider_id = ?", id).Count(&linked).Error; err != nil {
		return err
	}
	if linked > 0 {
		return ErrOIDCProviderInUse
	}
	// 仍有映射規則者拒刪：不擋的話「刪掉重設」之後全部規則變孤兒，
	// 而來源詳情頁的映射區段看不出異常（同目錄側的裁決）
	total, _, err := CountMappings(s.db, model.RoleMappingChannelKindProvider, id)
	if err != nil {
		return err
	}
	if total > 0 {
		return ErrOIDCProviderHasMappings
	}
	// 刪除亦走**完整**失效流程（design 行 64）：推進世代 → 撤 refresh → 終斷協議
	// 連線 → 收線監看訂閱 → 撤銷錄影 token，與停用同一套。
	// 只推進世代不夠：「外部身分已全數解綁、但先前建立的協議連線仍在」的狀態下
	// 刪除 provider，那些連線會繼續存活，且軟刪後管理端**再也無從按 provider 收線**。
	//
	// 軟刪與失效同鎖同交易：分開做會留下「已刪除但尚未收線」的中間態，
	// 而該態下任何殘留的兌換都不再有 provider 列可鎖
	var plan *providerRevocationPlan
	err = WithOIDCProviderLock(s.db, id, func(tx *gorm.DB) error {
		var perr error
		plan, perr = s.invalidateProviderLocked(tx, id, "provider_deleted")
		if perr != nil {
			return perr
		}
		return tx.Delete(&model.OIDCProvider{}, id).Error
	})
	if err != nil {
		return err
	}
	s.revokeProviderAccess(id, plan, "provider_deleted")
	return nil
}

// List 列出全部 provider（管理端）
func (s *OIDCProviderService) List() ([]OIDCProviderDTO, error) {
	var rows []model.OIDCProvider
	if err := s.db.Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	// 身分數單次批量查詢：逐 provider 查會在 provider 數成長時線性放大往返
	counts := s.identityCounts()
	out := make([]OIDCProviderDTO, 0, len(rows))
	for i := range rows {
		dto := s.toDTO(&rows[i])
		dto.IdentityCount = counts[rows[i].ID]
		out = append(out, dto)
	}
	return out, nil
}

// identityCounts 各 provider 的已綁定外部身分數。
// 查詢失敗回空 map 而非中斷——數字是輔助資訊，不值得讓整份設定讀不出來
func (s *OIDCProviderService) identityCounts() map[uint]int64 {
	var rows []struct {
		ProviderID uint
		N          int64
	}
	if err := s.db.Model(&model.UserExternalIdentity{}).
		Select("provider_id, COUNT(*) AS n").
		Group("provider_id").
		Scan(&rows).Error; err != nil {
		log.Printf("[OIDC] 統計外部身分數失敗: %v", err)
		return map[uint]int64{}
	}
	out := make(map[uint]int64, len(rows))
	for _, r := range rows {
		out[r.ProviderID] = r.N
	}
	return out
}

// LoginMethod 登入頁的 provider 呈現（**僅識別與顯示所需**，不洩漏設定值）
type LoginMethod struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// ListLoginMethods 未認證可讀的登入方法清單。
//
// 過濾條件有二：未啟用者不列；**設定不完整者亦不列**——否則按鈕看得到、
// 按下去必失敗（缺對外基準網址時 begin 無法組出 redirect_uri）
func (s *OIDCProviderService) ListLoginMethods() ([]LoginMethod, error) {
	if s.baseURL == "" {
		return []LoginMethod{}, nil
	}
	var rows []model.OIDCProvider
	if err := s.db.Where("enabled = ?", true).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]LoginMethod, 0, len(rows))
	for _, r := range rows {
		out = append(out, LoginMethod{ID: r.ID, Name: r.Name})
	}
	return out, nil
}

// GetForAuth 取得供認證流程使用的 provider（含解密後的 secret）。
//
// **授權關鍵欄位一律現查**（不經任何程序快取）：epoch 驗證與 admission 每次求值
// 的價值就在於讀到最新狀態，落入行程快取會使多副本下的停用形同虛設
func (s *OIDCProviderService) GetForAuth(id uint) (*model.OIDCProvider, string, error) {
	var p model.OIDCProvider
	if err := s.db.First(&p, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", ErrOIDCProviderNotFound
		}
		return nil, "", err
	}
	secret, err := s.decryptSecret(p.ClientSecretEnc)
	if err != nil {
		return nil, "", err
	}
	return &p, secret, nil
}

// IsSharedIssuer 現算該 provider 的身分域類型
func (s *OIDCProviderService) IsSharedIssuer(p *model.OIDCProvider) bool {
	return EffectiveIssuerKind(p.Issuer, p.ForceShared, s.deployDedicatedIssuers)
}

// AdmissionRulesOf 解析該 provider 的准入規則
func (s *OIDCProviderService) AdmissionRulesOf(p *model.OIDCProvider) (AdmissionRules, error) {
	return ParseAdmissionRules(p.AdmissionRules)
}

func (s *OIDCProviderService) encryptSecret(plain string) (string, error) {
	if s.codec == nil {
		return plain, nil // 僅測試建構路徑
	}
	return s.codec.EncryptFor(context.Background(), keyvault.RefOIDCClientSecret, plain)
}

func (s *OIDCProviderService) decryptSecret(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	if s.codec == nil {
		return enc, nil
	}
	return s.codec.DecryptFor(context.Background(), keyvault.RefOIDCClientSecret, enc)
}

// MarshalAdmissionRules 供測試與管理端組裝規則 JSON
func MarshalAdmissionRules(r AdmissionRules) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
