package authz

import (
	"sort"

	"github.com/custodexa/backend/internal/model"
)

// 內建範本與舊相容設定檔。
//
// 範本的權限點集合定義在程式碼，不存資料庫：內建範本鎖定，存進資料表只會多一個可被
// 直接竄改的面。目前的有效能力依「舊相容設定檔」計算：取主體所有有效指派中的內建範本，
// 依 super_admin > auditor > user 折疊出舊主角色；沒有任何指派時舊主角色為 user；
// 只有 approver 或非內建角色時舊主角色為空（能力為空）。
//
// 折疊而不是聯集的理由：三個範本目前是巢狀的（超管 ⊇ 稽核員 ⊇ 一般使用者），能力上
// 聯集等於折疊；但「零角色視同 user」與「依主角色選回應形狀」只有折疊能重現。

// 舊主角色字串（與 identity 的 primaryRoleOf 輸出相同：admin／auditor／user，空＝無能力）。
const (
	LegacyRoleAdmin   = model.RoleAdmin
	LegacyRoleAuditor = model.RoleAuditor
	LegacyRoleUser    = model.RoleUser
	LegacyRoleNone    = ""
)

// TemplatePermissions 回傳內建範本的權限點集合（副本）。
// super_admin 為目錄全部；approver 為空（審核資格是獨立的內建身分判定，不經能力集合）；
// 未知的範本鍵回傳 nil。
func TemplatePermissions(builtinKey string) []Permission {
	switch builtinKey {
	case model.BuiltinSuperAdmin:
		return CatalogKeys()
	case model.BuiltinAuditor:
		// 稽核員範本：舊稽核員角色的 5 個鍵（資產、會話、審計、告警檢視與告警管理），加舊「管理者或稽核員」雙角色守衛
		// 路由所用的 audit:integrity_view、compliance:view、policygroup:view。
		return []Permission{
			PermAssetView, PermSessionView, PermAuditView, PermAlertView, PermAlertManage,
			PermAuditIntegrityView, PermComplianceView, PermPolicyGroupView,
		}
	case model.BuiltinUser:
		return []Permission{PermAssetView} // 一般使用者範本：asset:view
	case model.BuiltinApprover:
		return []Permission{}
	case model.BuiltinIdentityAdmin:
		return identityAdminPermissions()
	case model.BuiltinSecurityAdmin:
		return securityAdminPermissions()
	case model.BuiltinAssetAdmin:
		return ScopedTemplateAssetAdminPermissions()
	case model.BuiltinAuthzAdmin:
		return ScopedTemplateAuthorizationAdminPermissions()
	}
	return nil
}

// legacyTemplateKey 舊主角色對應的內建範本鍵。
func legacyTemplateKey(legacyRole string) string {
	switch legacyRole {
	case LegacyRoleAdmin:
		return model.BuiltinSuperAdmin
	case LegacyRoleAuditor:
		return model.BuiltinAuditor
	case LegacyRoleUser:
		return model.BuiltinUser
	}
	return ""
}

// identityAdminPermissions 身分管理員範本（鎖定）：
// 使用者、使用者群組、身分來源與全域角色指派能力；不含角色定義、通知通道、告警分級或連線豁免。
// 集合為凍結表，以本函式與 TestLockedManagementTemplates 為準；不從群組過濾推導，目錄新增鍵不會自動進範本。
func identityAdminPermissions() []Permission {
	return []Permission{
		PermIdentitySourceManage, PermLDAPManage, PermOIDCManage, PermRoleAssign,
		PermRoleView, PermUserGroupManage, PermUserManage,
	}
}

// securityAdminPermissions 系統安全管理員範本（鎖定）：設定組全部（含通知通道、
// 系統告警分級、金鑰／離機／syslog、安全政策含全系統預設）；不含身分或資產／授權管理。
func securityAdminPermissions() []Permission {
	return []Permission{
		PermAlertRuleManage, PermInstanceGuardView, PermKeyManage, PermNotificationChannel,
		PermOffsiteManage, PermPolicyGroupManage, PermPolicyGroupView, PermRecordingDelete, PermRotationSchedule,
		PermScheduleManage, PermSecurityPolicyManage, PermSyslogManage, PermSystemAlertManage,
		PermTransmissionManage,
	}
}

// builtinTemplateKeys 全部內建範本鍵（新增範本時同步這裡）。每次呼叫回新切片，不留包級狀態。
func builtinTemplateKeys() []string {
	return []string{
		model.BuiltinSuperAdmin, model.BuiltinAuditor, model.BuiltinUser, model.BuiltinApprover,
		model.BuiltinIdentityAdmin, model.BuiltinSecurityAdmin,
		model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin,
	}
}

// SecurityAdminExclusivePermissions 系統安全管理員專屬的權限點（排序後的副本）：
// 系統安全管理員範本持有、而超管與系統安全管理員以外的其他內建範本都不持有的鍵。
//
// 集合由範本定義推導，不另列清單。指派保護只看其中的高風險子集（ProtectedAssignmentPermissions）。
// 範本內容改動時，TestSecurityAdminExclusivePermissions 會轉紅，提醒人審這個集合的新內容。
func SecurityAdminExclusivePermissions() []Permission {
	shared := map[Permission]bool{}
	for _, k := range builtinTemplateKeys() {
		if k == model.BuiltinSuperAdmin || k == model.BuiltinSecurityAdmin {
			continue
		}
		for _, p := range TemplatePermissions(k) {
			shared[p] = true
		}
	}
	out := []Permission{}
	for _, p := range TemplatePermissions(model.BuiltinSecurityAdmin) {
		if !shared[p] {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// HoldsSecurityAdminExclusive 權限集合是否含任一系統安全管理員專屬權限點。
func HoldsSecurityAdminExclusive(perms []Permission) bool {
	exclusive := map[Permission]bool{}
	for _, p := range SecurityAdminExclusivePermissions() {
		exclusive[p] = true
	}
	for _, p := range perms {
		if exclusive[p] {
			return true
		}
	}
	return false
}

// ProtectedAssignmentPermissions 指派保護的高風險權限點（排序後的副本，每次呼叫回新切片）：
// 能刪除證據、關閉或改道告警、放寬安全控制或管理金鑰的點。自訂角色含其中任一鍵即為保護角色，
// 只有超級管理者能讓任何帳號取得或失去它。集合須為 SecurityAdminExclusivePermissions 的子集，
// TestSecurityAdminExclusivePermissions 鎖住內容與子集關係。
func ProtectedAssignmentPermissions() []Permission {
	out := []Permission{
		PermAlertRuleManage, PermKeyManage, PermNotificationChannel, PermOffsiteManage,
		PermPolicyGroupManage, PermRecordingDelete, PermSecurityPolicyManage, PermSyslogManage,
		PermSystemAlertManage,
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// HoldsProtectedAssignmentPermission 權限集合是否含任一指派保護的高風險權限點。
func HoldsProtectedAssignmentPermission(perms []Permission) bool {
	protected := map[Permission]bool{}
	for _, p := range ProtectedAssignmentPermissions() {
		protected[p] = true
	}
	for _, p := range perms {
		if protected[p] {
			return true
		}
	}
	return false
}

// IsLockedManagementTemplate 是否為鎖定管理範本之一（身分管理員、系統安全管理員，
// 以及兩個範圍化範本：資產管理員、授權管理員）。權限解析只對這些識別載入程式中的範本集合。
func IsLockedManagementTemplate(builtinKey string) bool {
	switch builtinKey {
	case model.BuiltinIdentityAdmin, model.BuiltinSecurityAdmin,
		model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin:
		return true
	}
	return false
}
