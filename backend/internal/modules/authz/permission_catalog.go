package authz

import (
	"fmt"
	"sort"
	"strings"
)

// 權限點目錄。
//
// 每個權限點宣告：鍵、群組、類別、範圍屬性。鍵名沿用既有 11 個（route_permissions.go），
// 其餘 26 個依「目前只以角色守住的路由」的資源與動作補上同格式的鍵。目錄、各群組與各範本的
// 計數一律由本檔的資料產生，文件與測試引用數字時以產生結果為準。
//
// 目錄**不收**：查看明文類能力、超管保留能力（超管身分、連線短路、角色定義權）。
// 後者是內建身分而非權限點，見 reserved_identity.go；載入目錄時以 validateCatalog
// 拒絕任何以保留能力為名的權限點。

// PermGroup 權限點群組。
type PermGroup string

const (
	GroupAsset       PermGroup = "asset"         // 資產
	GroupAuthzRule   PermGroup = "authorization" // 授權規則
	GroupIdentity    PermGroup = "identity"      // 身分
	GroupSettings    PermGroup = "settings"      // 設定
	GroupAudit       PermGroup = "audit"         // 稽核
	GroupSelfService PermGroup = "self"          // 自助
)

// PermCategory 權限點類別。
type PermCategory string

const (
	CategoryManage PermCategory = "manage" // 管理
	CategoryAudit  PermCategory = "audit"  // 稽核
	CategoryReview PermCategory = "review" // 審核
	CategoryBasic  PermCategory = "basic"  // 基本
)

// ScopeAttr 範圍屬性。
type ScopeAttr string

const (
	// ScopeGlobalOnly 只有全域指派生效；非全域指派對該權限點不生效。
	ScopeGlobalOnly ScopeAttr = "global-only"
	// ScopeEnforced 範圍已實際過濾，逐鍵啟用：啟用前須宣告該鍵全部登錄項的目標解析或列表投影。
	ScopeEnforced ScopeAttr = "scoped-enforced"
	// ScopeReserved 範圍屬性預留，過濾尚未實作：非全域指派在實作前一律不生效，也不回退成全域。
	ScopeReserved ScopeAttr = "scoped-reserved"
)

// 新增的 26 個權限點鍵（既有 11 個見 route_permissions.go）。
const (
	PermAccessReviewManage  Permission = "accessreview:manage"
	PermAlertRuleManage     Permission = "alertrule:manage"
	PermApproverScopeManage Permission = "approverscope:manage"
	// PermApproverScopeApplicantManage 申請人型審核範圍的管理：全域限定，須與全域的審核範圍管理同時具備才生效。
	PermApproverScopeApplicantManage Permission = "approverscope:manage_applicant"
	PermAssetGroupManage             Permission = "assetgroup:manage"
	PermAuditIntegrityView           Permission = "audit:integrity_view"
	PermAuthorizationManage          Permission = "authorization:manage"
	PermChangeSecretManage           Permission = "changesecret:manage"
	PermComplianceView               Permission = "compliance:view"
	PermHostKeyReset                 Permission = "hostkey:reset"
	PermIdentitySourceManage         Permission = "identity_source:manage"
	PermInstanceGuardView            Permission = "instanceguard:view"
	PermKeyManage                    Permission = "key:manage"
	PermLDAPManage                   Permission = "ldap:manage"
	PermNotificationChannel          Permission = "notification_channel:manage"
	PermOffsiteManage                Permission = "offsite:manage"
	PermOIDCManage                   Permission = "oidc:manage"
	PermPolicyGroupManage            Permission = "policygroup:manage"
	PermPolicyGroupView              Permission = "policygroup:view"
	PermRoleView                     Permission = "role:view"
	PermRotationSchedule             Permission = "rotation_schedule:manage"
	PermScheduleManage               Permission = "schedule:manage"
	PermSecurityPolicyManage         Permission = "securitypolicy:manage"
	PermSyslogManage                 Permission = "syslog:manage"
	PermTransmissionManage           Permission = "transmission:manage"
	PermUserManage                   Permission = "user:manage"
	PermUserGroupManage              Permission = "usergroup:manage"
	// 自訂角色定義時目錄缺口補上的兩個鍵（初版權限目錄沒有）。
	// role:assign 是「指派角色」權限點（身分組、global-only，單一全域語義）；
	// systemalert:manage 是系統告警分級權限點（設定組、global-only），系統告警分級入口使用。
	PermRoleAssign        Permission = "role:assign"
	PermSystemAlertManage Permission = "systemalert:manage"
	// 單台存取政策覆寫的設定與清除（授權規則組、管理類）。P3 之前只經全域指派生效。
	PermAccessPolicyManage Permission = "access_policy:manage"
	// 刪除單一會話錄影（設定組、global-only、無依賴）：刪除證據是全系統層級的動作，
	// 不放稽核組以免範圍化指派落地後可分節點委派；只有 API，沒有畫面入口。
	PermRecordingDelete Permission = "recording:delete"
)

// 憑證背景工作授權：憑證管理六類語義能力與支持能力。
// 九個 credential:* 語義鍵為 scoped-enforced：範圍以憑證歸屬與明確目標資產判定，全部登錄要求皆已宣告。
// 舊 credential:manage 保留為相容鍵，只剩兩種用途：憑證寫入路由的路由級入口（與語義鍵並列），以及資產
// 與帳號表單憑證欄位條件的相容並列能力（只在全域持有時生效，經它通過者不另做語義目標判定）。服務層不以它
// 放行任何語義動作，維持 scoped-reserved，不列入範圍化範本。
const (
	PermCredentialView         Permission = "credential:view"
	PermCredentialCreate       Permission = "credential:create"
	PermCredentialUpdate       Permission = "credential:update"
	PermCredentialSetSecret    Permission = "credential:set-secret"
	PermCredentialRotate       Permission = "credential:rotate"
	PermCredentialConvertScope Permission = "credential:convert-scope"
	PermCredentialDetach       Permission = "credential:detach"
	PermCredentialDelete       Permission = "credential:delete"
	PermCredentialBind         Permission = "credential:bind"
	PermAccountRotate          Permission = "account:rotate"
)

// PermissionDef 一個權限點的宣告。
type PermissionDef struct {
	Key      Permission
	Group    PermGroup
	Category PermCategory
	Scope    ScopeAttr
}

// permissionCatalog 目錄本體（鍵排序，載入時由 validateCatalog 檢查）。
//
// 範圍屬性取值：身分、設定、指派角色類為 global-only；資產組與授權規則組在
// 實作過濾之前一律 scoped-reserved；稽核組 scoped-reserved。
var permissionCatalog = mustValidateCatalog([]PermissionDef{
	{PermAccessPolicyManage, GroupAuthzRule, CategoryManage, ScopeEnforced},
	{PermAccessReviewManage, GroupAudit, CategoryManage, ScopeReserved},
	{PermAlertManage, GroupAudit, CategoryManage, ScopeReserved},
	{PermAlertRuleManage, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermAlertView, GroupAudit, CategoryAudit, ScopeReserved},
	{PermApproverScopeManage, GroupAuthzRule, CategoryManage, ScopeEnforced},
	{PermApproverScopeApplicantManage, GroupAuthzRule, CategoryManage, ScopeGlobalOnly},
	{PermAssetCreate, GroupAsset, CategoryManage, ScopeEnforced},
	{PermAssetDelete, GroupAsset, CategoryManage, ScopeEnforced},
	{PermAssetGroupManage, GroupAsset, CategoryManage, ScopeEnforced},
	{PermAssetTest, GroupAsset, CategoryManage, ScopeEnforced},
	{PermAssetUpdate, GroupAsset, CategoryManage, ScopeEnforced},
	{PermAssetView, GroupAsset, CategoryBasic, ScopeEnforced},
	{PermAuditIntegrityView, GroupAudit, CategoryAudit, ScopeReserved},
	{PermAuditView, GroupAudit, CategoryAudit, ScopeReserved},
	{PermAuthorizationManage, GroupAuthzRule, CategoryManage, ScopeEnforced},
	{PermChangeSecretManage, GroupAsset, CategoryManage, ScopeEnforced},
	{PermComplianceView, GroupAudit, CategoryAudit, ScopeReserved},
	{PermAccountRotate, GroupAsset, CategoryManage, ScopeEnforced},
	{PermCredentialBind, GroupAsset, CategoryManage, ScopeEnforced},
	{PermCredentialConvertScope, GroupAsset, CategoryManage, ScopeEnforced},
	{PermCredentialCreate, GroupAsset, CategoryManage, ScopeEnforced},
	{PermCredentialDelete, GroupAsset, CategoryManage, ScopeEnforced},
	{PermCredentialDetach, GroupAsset, CategoryManage, ScopeEnforced},
	{PermCredentialManage, GroupAsset, CategoryManage, ScopeReserved},
	{PermCredentialRotate, GroupAsset, CategoryManage, ScopeEnforced},
	{PermCredentialSetSecret, GroupAsset, CategoryManage, ScopeEnforced},
	{PermCredentialUpdate, GroupAsset, CategoryManage, ScopeEnforced},
	{PermCredentialView, GroupAsset, CategoryManage, ScopeEnforced},
	{PermHostKeyReset, GroupAsset, CategoryManage, ScopeReserved},
	{PermIdentitySourceManage, GroupIdentity, CategoryManage, ScopeGlobalOnly},
	{PermInstanceGuardView, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermKeyManage, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermLDAPManage, GroupIdentity, CategoryManage, ScopeGlobalOnly},
	{PermNotificationChannel, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermOffsiteManage, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermOIDCManage, GroupIdentity, CategoryManage, ScopeGlobalOnly},
	{PermPolicyGroupManage, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermPolicyGroupView, GroupSettings, CategoryAudit, ScopeGlobalOnly},
	{PermRecordingDelete, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermRoleAssign, GroupIdentity, CategoryManage, ScopeGlobalOnly},
	{PermRoleView, GroupIdentity, CategoryManage, ScopeGlobalOnly},
	{PermRotationSchedule, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermScheduleManage, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermSecurityPolicyManage, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermSessionTerminate, GroupAudit, CategoryManage, ScopeReserved},
	{PermSessionView, GroupAudit, CategoryAudit, ScopeReserved},
	{PermSyslogManage, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermSystemAlertManage, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermTransmissionManage, GroupSettings, CategoryManage, ScopeGlobalOnly},
	{PermUserGroupManage, GroupIdentity, CategoryManage, ScopeGlobalOnly},
	{PermUserManage, GroupIdentity, CategoryManage, ScopeGlobalOnly},
})

// reservedCapabilityWords 保留能力的名稱片段：超管身分、連線短路、角色定義權、
// 查看明文類。任何權限點鍵含其一即被目錄拒絕（比對時忽略大小寫與分隔符）。
func reservedCapabilityWords() []string {
	return []string{
		"superadmin", "connectshortcut", "connectbypass", "roledefine", "roledefinition",
		"reveal", "plaintext", "cleartext", "secretread", "readsecret",
	}
}

// ValidatePermissionKey 檢查鍵是否為合法的目錄鍵：格式 `resource:action`，且不以保留能力為名。
func ValidatePermissionKey(key Permission) error {
	k := string(key)
	parts := strings.Split(k, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("權限點鍵 %q 格式須為 resource:action", k)
	}
	norm := strings.ToLower(strings.NewReplacer("_", "", "-", "", ":", "", ".", "").Replace(k))
	for _, w := range reservedCapabilityWords() {
		if strings.Contains(norm, w) {
			return fmt.Errorf("權限點鍵 %q 以保留能力 %q 為名；保留能力是內建身分，不是權限點", k, w)
		}
	}
	return nil
}

func mustValidateCatalog(defs []PermissionDef) []PermissionDef {
	if err := validateCatalog(defs); err != nil {
		panic("authz: 權限點目錄無效: " + err.Error())
	}
	return defs
}

// validateCatalog 載入時檢查：鍵合法且唯一、群組／類別／範圍屬性值域。
func validateCatalog(defs []PermissionDef) error {
	seen := make(map[Permission]bool, len(defs))
	for _, d := range defs {
		if err := ValidatePermissionKey(d.Key); err != nil {
			return err
		}
		if seen[d.Key] {
			return fmt.Errorf("權限點 %q 重複", d.Key)
		}
		seen[d.Key] = true
		switch d.Group {
		case GroupAsset, GroupAuthzRule, GroupIdentity, GroupSettings, GroupAudit, GroupSelfService:
		default:
			return fmt.Errorf("權限點 %q 群組 %q 不合法", d.Key, d.Group)
		}
		switch d.Category {
		case CategoryManage, CategoryAudit, CategoryReview, CategoryBasic:
		default:
			return fmt.Errorf("權限點 %q 類別 %q 不合法", d.Key, d.Category)
		}
		switch d.Scope {
		case ScopeGlobalOnly, ScopeEnforced, ScopeReserved:
		default:
			return fmt.Errorf("權限點 %q 範圍屬性 %q 不合法", d.Key, d.Scope)
		}
	}
	return nil
}

// ValidateCatalog 對一份目錄套用載入規則（鍵合法且唯一、拒保留名稱、值域）。
func ValidateCatalog(defs []PermissionDef) error { return validateCatalog(defs) }

// IsAssignable 目錄中的鍵是否可指派給自訂角色。
//
// 主機金鑰重置雖在目錄內（既有範本的能力投影不變），卻是超管保留操作：只由內建超管身分執行，
// 不可由自訂角色持有——角色定義拒絕此鍵，既存自訂角色集合內的此鍵也不生效。
// 用函式而不是包級表，避免多一個需要登記時序的全域變數。
func IsAssignable(key Permission) bool {
	return key != PermHostKeyReset
}

// Catalog 回傳目錄的副本（依鍵排序）。
func Catalog() []PermissionDef {
	out := make([]PermissionDef, len(permissionCatalog))
	copy(out, permissionCatalog)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// LookupPermission 依鍵查目錄。
func LookupPermission(key Permission) (PermissionDef, bool) {
	for _, d := range permissionCatalog {
		if d.Key == key {
			return d, true
		}
	}
	return PermissionDef{}, false
}

// CatalogKeys 目錄內全部權限點鍵（依鍵排序）。
func CatalogKeys() []Permission {
	defs := Catalog()
	out := make([]Permission, len(defs))
	for i, d := range defs {
		out[i] = d.Key
	}
	return out
}

// AssignableKeys 可指派給自訂角色的目錄鍵（目錄鍵扣除超管保留者，依鍵排序）。
func AssignableKeys() []Permission {
	var out []Permission
	for _, k := range CatalogKeys() {
		if IsAssignable(k) {
			out = append(out, k)
		}
	}
	return out
}
