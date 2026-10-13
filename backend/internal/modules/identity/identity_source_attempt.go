package identity

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 檢核面板的「最近一次登入嘗試」：從稽核紀錄取某個身分提供者最近一次登入的結果。
//
// # 為什麼查稽核而不另立摘要表
//
// 登入的每一種結局（成功、等待第二因素、准入拒絕、換權杖失敗、提供者回報錯誤⋯）
// 本來就逐筆寫進稽核，且都帶 provider_id。另立一張「每來源最近一次」的表，
// 等於在稽核之外再養一份必須與它一致的事實，登入尖峰時還會反覆改寫同一列。
// 查詢限在最近 30 天內，走建立時間索引反向讀。讀取經稽核模組的分批讀取面
// （audit.ScanAuditBackwards），本模組只交出條件值，不直接查稽核表。
//
// # 為什麼分批往後讀、在程式端精確比對
//
// details 是文字欄，只能以 LIKE 先篩。單用 `"provider_id":5` 會配到 50、51⋯，
// 所以預篩連同其後的分隔字元（, 或 }）一起比對；精確比對仍在解析 JSON 之後做，
// 並且一批讀完沒找到就接著讀下一批，直到找到或掃完整個時間窗——不設候選上限。設上限的話，以本來源識別碼為前綴的另一個
// 來源只要登入夠頻繁，就能讓本來源的紀錄被判成「查無」。
//
// # 原因只回機器碼
//
// 白話原因與建議由介面依碼決定。子類別（准入規則不合規的子碼、提供者錯誤碼）
// 先對照白名單，不在名單者一律回 other，介面只依受控的值查文案。

const (
	// lastAttemptWindowDays 查詢的時間窗（天）
	lastAttemptWindowDays = 30
	// providerErrorDescriptionMaxRunes 提供者自報說明在面板上的長度上限（字元）
	providerErrorDescriptionMaxRunes = 200
)

// LastAttempt 某來源最近一次登入嘗試
type LastAttempt struct {
	At time.Time `json:"at"`
	// Outcome success／pending／denied／failed
	Outcome string `json:"outcome"`
	// ReasonCode 原因機器碼（介面依碼查白話原因與建議）
	ReasonCode string `json:"reason_code"`
	// ReasonDetail 受控子碼（只在准入規則不合規與提供者回報錯誤時出現）
	ReasonDetail string `json:"reason_detail,omitempty"`
	// Event 原因為 unknown 時的稽核事件名（不符格式即省略）
	Event    string `json:"event,omitempty"`
	Username string `json:"username"`
	// ProviderError 提供者回報的錯誤碼（寫入稽核前已限定字元集與長度）
	ProviderError string `json:"provider_error,omitempty"`
	// ProviderErrorDescription 提供者自報的錯誤說明（外部資料，已截斷）
	ProviderErrorDescription string `json:"provider_error_description,omitempty"`
	WindowDays               int    `json:"window_days"`
}

// LastSuccess 某來源最近一次成功類登入（成功或等待第二因素、變更密碼）
type LastSuccess struct {
	At time.Time `json:"at"`
	// MappingEligible 該帳號目前是否適用群組映射（本地帳號綁外部身分者不適用）
	MappingEligible bool `json:"mapping_eligible"`
	// AccountRemoved 該次登入的帳號已不存在（已刪除）：此時不適用群組映射，
	// 但原因不是「本地帳號」，介面要分開說
	AccountRemoved bool `json:"account_removed"`
}

// 原因碼
const (
	AttemptReasonSuccess                    = "success"
	AttemptReasonPendingMFA                 = "pending_mfa"
	AttemptReasonPendingMFAEnrollment       = "pending_mfa_enrollment"
	AttemptReasonPendingPasswordChange      = "pending_password_change"
	AttemptReasonSourceDenied               = "source_denied"
	AttemptReasonAdmissionTID               = "admission_tid"
	AttemptReasonAdmissionHD                = "admission_hd"
	AttemptReasonAdmissionEmailDomain       = "admission_email_domain"
	AttemptReasonAdmissionEmailVerified     = "admission_email_verified"
	AttemptReasonAdmissionNotPrebound       = "admission_not_prebound"
	AttemptReasonAdmissionRulesNoncompliant = "admission_rules_noncompliant"
	AttemptReasonCodeExchangeFailed         = "code_exchange_failed"
	AttemptReasonIDTokenMissing             = "id_token_missing"
	AttemptReasonIDTokenInvalid             = "id_token_invalid"
	AttemptReasonProviderUnavailable        = "provider_unavailable"
	AttemptReasonInternalError              = "internal_error"
	AttemptReasonProviderError              = "provider_error"
	AttemptReasonUsernameConflict           = "username_conflict"
	AttemptReasonAccountRemoved             = "account_removed"
	AttemptReasonUserInactive               = "user_inactive"
	AttemptReasonUnknown                    = "unknown"

	// AttemptDetailOther 子碼不在白名單時的歸類
	AttemptDetailOther = "other"
)

// AttemptReasonCodes 全部原因碼（介面三語完整性檢查的對照基準）
var AttemptReasonCodes = []string{
	AttemptReasonSuccess, AttemptReasonPendingMFA, AttemptReasonPendingMFAEnrollment,
	AttemptReasonPendingPasswordChange, AttemptReasonSourceDenied, AttemptReasonAdmissionTID,
	AttemptReasonAdmissionHD, AttemptReasonAdmissionEmailDomain, AttemptReasonAdmissionEmailVerified,
	AttemptReasonAdmissionNotPrebound, AttemptReasonAdmissionRulesNoncompliant,
	AttemptReasonCodeExchangeFailed, AttemptReasonIDTokenMissing, AttemptReasonIDTokenInvalid,
	AttemptReasonProviderUnavailable, AttemptReasonInternalError, AttemptReasonProviderError,
	AttemptReasonUsernameConflict, AttemptReasonAccountRemoved, AttemptReasonUserInactive,
	AttemptReasonUnknown,
}

// AttemptRulesNoncompliantDetails 准入規則不合規的子碼白名單（admissionIssueCode 的全部輸出＋other）
var AttemptRulesNoncompliantDetails = []string{
	"shared_needs_org_rule", "empty_rule_set", "consumer_tenant",
	"email_needs_verified", "unknown_rule", "invalid_rules", AttemptDetailOther,
}

// AttemptProviderErrorDetails 提供者錯誤碼白名單（常見的 OAuth／OIDC 授權錯誤＋other）
var AttemptProviderErrorDetails = []string{
	"access_denied", "invalid_scope", "unauthorized_client", "server_error",
	"temporarily_unavailable", "login_required", "interaction_required",
	"consent_required", AttemptDetailOther,
}

// attemptEventName unknown 時回傳的事件名格式
var attemptEventName = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// providerAttempts 某身分提供者在時間窗內最近一次登入嘗試與最近一次成功類登入。
// 兩者皆查無即各回 nil。
func (s *IdentitySourceService) providerAttempts(providerID uint, now time.Time) (*LastAttempt, *LastSuccess, error) {
	since := now.AddDate(0, 0, -lastAttemptWindowDays)
	// 預篩連同識別碼後的分隔字元一起比對（details 為緊湊 JSON，數字後只會接 , 或 }），
	// 在資料庫端就擋掉 50、51⋯ 這類前綴誤配；程式端的精確比對仍保留為第二道
	filter := audit.AuditScanFilter{
		Resource: model.ResourceAuth, Action: model.ActionLogin, Since: since,
		DetailsLike: []string{
			fmt.Sprintf(`%%"provider_id":%d,%%`, providerID),
			fmt.Sprintf(`%%"provider_id":%d}%%`, providerID),
		},
	}
	var attempt *LastAttempt
	var successRow *audit.AuditScanRow
	err := audit.ScanAuditBackwards(s.db, filter, func(r audit.AuditScanRow) bool {
		a, ok := classifyLoginAudit(r, providerID)
		if !ok {
			return false
		}
		if attempt == nil {
			attempt = a
		}
		if a.Outcome == "success" || a.Outcome == "pending" {
			row := r
			successRow = &row
			return true
		}
		return false
	})
	if err != nil {
		return nil, nil, err
	}
	if successRow == nil {
		return attempt, nil, nil
	}
	eligible, removed, err := s.userMappingEligible(successRow.UserID)
	if err != nil {
		return nil, nil, err
	}
	return attempt, &LastSuccess{At: successRow.CreatedAt, MappingEligible: eligible, AccountRemoved: removed}, nil
}

// userMappingEligible 帳號目前是否適用群組映射；帳號已不存在即不適用，並回報已刪除
func (s *IdentitySourceService) userMappingEligible(userID uint) (eligible, removed bool, err error) {
	if userID == 0 {
		return false, false, nil
	}
	var users []model.User
	if err := s.db.Where("id = ?", userID).Limit(1).Find(&users).Error; err != nil {
		return false, false, fmt.Errorf("讀取登入帳號失敗: %w", err)
	}
	if len(users) == 0 {
		return false, true, nil
	}
	return roleMappingEligible(&users[0]), false, nil
}

// classifyLoginAudit 把一列登入稽核轉成最近一次登入嘗試。
// 第二個回傳值為 false 表示這列不屬於該提供者，或不是登入嘗試的結局。
func classifyLoginAudit(r audit.AuditScanRow, providerID uint) (*LastAttempt, bool) {
	var d map[string]any
	if err := json.Unmarshal([]byte(r.Details), &d); err != nil {
		return nil, false
	}
	// 預篩已在資料庫端排除前綴誤配；這裡再精確比對一次，作為第二道
	pid, ok := d["provider_id"].(float64)
	if !ok || pid != float64(providerID) {
		return nil, false
	}
	if m, ok := d["auth_method"].(string); ok && m != model.AuthSourceOIDC {
		return nil, false
	}
	str := func(k string) string { v, _ := d[k].(string); return v }
	a := &LastAttempt{At: r.CreatedAt, Username: r.Username, WindowDays: lastAttemptWindowDays}
	event := str("event")
	switch event {
	case "":
		// 第二因素完成點的成功列不帶事件名，只帶提供者標註
		if r.Status != string(model.StatusSuccess) {
			return nil, false
		}
		a.Outcome, a.ReasonCode = "success", AttemptReasonSuccess
	case "oidc_login":
		a.Outcome, a.ReasonCode = classifyLoginStage(str("stage"))
	case "oidc_admission_denied":
		a.Outcome = "denied"
		a.ReasonCode, a.ReasonDetail = classifyAdmission(str("failed_rule"))
	case "oidc_flow_error":
		a.Outcome, a.ReasonCode = "failed", classifyFlowError(str("reason"))
	case "oidc_provider_denied":
		a.Outcome, a.ReasonCode = "denied", AttemptReasonProviderError
		a.ProviderError = str("provider_error")
		a.ReasonDetail = whitelisted(a.ProviderError, AttemptProviderErrorDetails)
		a.ProviderErrorDescription = truncateRunes(str("provider_error_description"),
			providerErrorDescriptionMaxRunes)
	case "oidc_username_conflict":
		a.Outcome, a.ReasonCode = "denied", AttemptReasonUsernameConflict
	case "oidc_account_removed":
		a.Outcome, a.ReasonCode = "denied", AttemptReasonAccountRemoved
	case "oidc_user_inactive":
		a.Outcome, a.ReasonCode = "denied", AttemptReasonUserInactive
	default:
		a.Outcome, a.ReasonCode = "failed", AttemptReasonUnknown
	}
	if a.ReasonCode == AttemptReasonUnknown && attemptEventName.MatchString(event) {
		a.Event = event
	}
	return a, true
}

func classifyLoginStage(stage string) (string, string) {
	switch stage {
	case "":
		return "success", AttemptReasonSuccess
	case "mfa_pending":
		return "pending", AttemptReasonPendingMFA
	case "mfa_enrollment_required":
		return "pending", AttemptReasonPendingMFAEnrollment
	case "password_change_required":
		return "pending", AttemptReasonPendingPasswordChange
	case "source_denied":
		return "denied", AttemptReasonSourceDenied
	}
	return "failed", AttemptReasonUnknown
}

func classifyAdmission(rule string) (string, string) {
	switch rule {
	case AdmissionRuleTenantID:
		return AttemptReasonAdmissionTID, ""
	case AdmissionRuleHostedDomain:
		return AttemptReasonAdmissionHD, ""
	case AdmissionRuleEmailDomain:
		return AttemptReasonAdmissionEmailDomain, ""
	case AdmissionRuleEmailVerified:
		return AttemptReasonAdmissionEmailVerified, ""
	case "not_prebound":
		return AttemptReasonAdmissionNotPrebound, ""
	}
	if sub, ok := strings.CutPrefix(rule, "rules_noncompliant:"); ok {
		return AttemptReasonAdmissionRulesNoncompliant, whitelisted(sub, AttemptRulesNoncompliantDetails)
	}
	return AttemptReasonUnknown, ""
}

func classifyFlowError(reason string) string {
	switch reason {
	case "code_exchange_failed":
		return AttemptReasonCodeExchangeFailed
	case "id_token_missing":
		return AttemptReasonIDTokenMissing
	case "id_token_invalid":
		return AttemptReasonIDTokenInvalid
	case "provider_unavailable":
		return AttemptReasonProviderUnavailable
	case "identity_lookup_failed":
		return AttemptReasonInternalError
	}
	return AttemptReasonUnknown
}

// whitelisted 值在白名單內即原樣回傳，否則回 other
func whitelisted(v string, allowed []string) string {
	for _, a := range allowed {
		if v == a && v != AttemptDetailOther {
			return v
		}
	}
	return AttemptDetailOther
}

// truncateRunes 以字元計截斷，不切斷多位元組字元
func truncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}

// groupsUnknownAt 某通道在時間窗內最近一次「讀不到完整群組」的時間；查無即 nil
func (s *IdentitySourceService) groupsUnknownAt(channel string, now time.Time) (*time.Time, error) {
	since := now.AddDate(0, 0, -lastAttemptWindowDays)
	filter := audit.AuditScanFilter{
		Resource: model.ResourceUser, Action: model.ActionUpdate,
		ErrorMsg: RoleMappingSkipGroupsUnknown, Since: since,
		DetailsLike: []string{`%"channel":"` + channel + `"%`},
	}
	var found *time.Time
	err := audit.ScanAuditBackwards(s.db, filter, func(r audit.AuditScanRow) bool {
		var d struct {
			Channel string `json:"channel"`
		}
		if json.Unmarshal([]byte(r.Details), &d) != nil || d.Channel != channel {
			return false
		}
		at := r.CreatedAt
		found = &at
		return true
	})
	return found, err
}
