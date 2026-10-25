package authz

import "github.com/custodexa/backend/internal/model"

// 自動化主體（agent）的角色限制依能力類別判定，不依角色名稱清單：
//   - 不得持有內建超管、稽核員、審核者範本；
//   - 不得持有任何含管理、稽核、審核類權限點的角色。
//
// 內建範本的權限點取程式定義（RolePermissionsForGuard）。自訂角色（有定義版本者）的權限點
// 集合存於角色權限表，由指派關卡讀出後交 CapabilityRestrictedForAgent 判定；沒有定義版本的
// 舊式非內建角色沒有權限點集合，視為空集合。

// CapabilityRestrictedForAgent 權限點集合是否含管理、稽核或審核類權限點。
// 權限點不在目錄內時 fail-closed（視為受限）。
func CapabilityRestrictedForAgent(perms []Permission) bool {
	for _, p := range perms {
		def, ok := LookupPermission(p)
		if !ok {
			return true
		}
		switch def.Category {
		case CategoryManage, CategoryAudit, CategoryReview:
			return true
		}
	}
	return false
}

// RolePermissionsForGuard 內建範本的權限點集合（取程式定義）；非內建角色回空，自訂角色的集合由呼叫端自角色權限表讀取。
func RolePermissionsForGuard(builtinKey string) []Permission {
	if builtinKey == "" {
		return nil
	}
	return TemplatePermissions(builtinKey)
}

// RoleForbiddenForAgent 該角色（以內建範本識別表示，空＝非內建）是否禁止指派給自動化主體。
func RoleForbiddenForAgent(builtinKey string) bool {
	switch builtinKey {
	case model.BuiltinSuperAdmin, model.BuiltinAuditor, model.BuiltinApprover:
		return true
	}
	return CapabilityRestrictedForAgent(RolePermissionsForGuard(builtinKey))
}
