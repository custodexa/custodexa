package authz

// 角色定義畫面用的範圍標示。判定一律呼叫 ClassifyNodeScopability，這裡只做輸入整理，不另寫規則。

// PermissionScopeEnforced 權限點的範圍屬性是否為已實作範圍過濾（目錄外的鍵為假）。
func PermissionScopeEnforced(p Permission) bool {
	d, ok := LookupPermission(p)
	return ok && d.Scope == ScopeEnforced
}

// EntryNodeScopable 編輯描述入口是否可限定節點：以入口最後一態（管理或可用態，含依賴鍵）的
// 精確權限集合，用無內建識別的純集合輸入呼叫三態判定，`effective` 才為真。
func EntryNodeScopable(e EntryDescriptor) bool {
	if len(e.States) == 0 {
		return false
	}
	class, _ := ClassifyNodeScopability("", e.States[len(e.States)-1].Keys)
	return class == NodeScopabilityEffective
}

// ScopeSummaryTokens 角色摘要的兩個範圍 token。
// nodeSelectable：可限定節點且範圍會生效；mixedGlobalOnly：含已實作範圍過濾的權限點，
// 但另含只能全系統生效的權限點。其餘情形（含兩個鎖定管理範本以外的內建角色）兩者皆假，
// 摘要沿用原本的「範圍僅全系統」token。
func ScopeSummaryTokens(builtinKey string, perms []Permission) (nodeSelectable, mixedGlobalOnly bool) {
	if builtinKey != "" && !IsLockedManagementTemplate(builtinKey) {
		return false, false
	}
	class, _ := ClassifyNodeScopability(builtinKey, perms)
	switch class {
	case NodeScopabilityEffective:
		return true, false
	case NodeScopabilityRejected:
		for _, p := range perms {
			if PermissionScopeEnforced(p) {
				return false, true
			}
		}
	}
	return false, false
}
