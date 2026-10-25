package authz

import "github.com/custodexa/backend/internal/model"

// 角色能否限定節點的三態判定。
//
// 寫入關卡、寫入回應的「範圍不生效」清單與角色標示共用這一個函式，呼叫端不另行推算。
// 判定以指派當下的目錄與角色定義計算，不快取。

// NodeScopability 角色以節點範圍指派時的判定結果。
type NodeScopability string

const (
	// NodeScopabilityRejected 不能限定節點：權限集合含只能套用到全系統或範圍尚未實作的權限點。
	NodeScopabilityRejected NodeScopability = "rejected"
	// NodeScopabilityEffective 可限定節點，範圍生效。
	NodeScopabilityEffective NodeScopability = "effective"
	// NodeScopabilityNoEffect 可限定節點，但範圍不會產生任何能力。
	NodeScopabilityNoEffect NodeScopability = "no_effect"
)

// NodeScopeNoEffectReason 範圍不生效的原因；只在 NodeScopabilityNoEffect 時有值。
type NodeScopeNoEffectReason string

const (
	// NoEffectBuiltinGlobalOnly 內建角色（兩個鎖定管理範本以外）只在全域指派時套用其範本。
	NoEffectBuiltinGlobalOnly NodeScopeNoEffectReason = "builtin_global_only"
	// NoEffectNoScopedPermission 權限集合沒有任何範圍已實際過濾的權限點。
	NoEffectNoScopedPermission NodeScopeNoEffectReason = "no_scoped_permission"
)

// ClassifyNodeScopability 判定角色以節點範圍指派時的結果。
// builtinKey 為內建範本識別（自訂角色傳空字串），perms 為該角色的權限集合。
func ClassifyNodeScopability(builtinKey string, perms []Permission) (NodeScopability, NodeScopeNoEffectReason) {
	enforced := false
	for _, p := range perms {
		d, ok := LookupPermission(p)
		if !ok {
			// 目錄外的鍵無法判定範圍屬性，保守視為不能限定
			return NodeScopabilityRejected, ""
		}
		switch d.Scope {
		case ScopeEnforced:
			enforced = true
		default:
			return NodeScopabilityRejected, ""
		}
	}
	if builtinKey != "" && !IsLockedManagementTemplate(builtinKey) {
		return NodeScopabilityNoEffect, NoEffectBuiltinGlobalOnly
	}
	if !enforced {
		return NodeScopabilityNoEffect, NoEffectNoScopedPermission
	}
	return NodeScopabilityEffective, ""
}

// ClassifyRoleNodeScopability 依角色列判定：內建角色取程式定義的範本集合，
// 自訂角色取呼叫端讀出的權限集合；升級前存量且沒有內建識別的角色無法判定，視為不能限定。
func ClassifyRoleNodeScopability(r model.Role, customPerms []Permission) (NodeScopability, NodeScopeNoEffectReason) {
	if r.BuiltinKey != nil {
		return ClassifyNodeScopability(*r.BuiltinKey, TemplatePermissions(*r.BuiltinKey))
	}
	if r.DefinitionVersion < 1 {
		return NodeScopabilityRejected, ""
	}
	return ClassifyNodeScopability("", customPerms)
}
