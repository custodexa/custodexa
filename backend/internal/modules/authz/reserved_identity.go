package authz

import "github.com/custodexa/backend/internal/model"

// 超級管理者保留身分。
//
// 超管是**內建身分**，不是權限點：不能由「擁有全部權限點」推得，自訂角色即使持有目錄內
// 全部權限點也不是超管。連線短路（對所有資產的全權）同樣只認內建超管身分；稽核員的 view
// 短路依舊主角色判定，與現況相同（admin＋auditor 主體走 admin 路徑）。

// IsSuperAdmin 有效指派中存在全域生效的內建範本 super_admin（任一來源）。
// 只看 roles.builtin_key，不看角色名稱，也不看能力集合。
func (p *Principal) IsSuperAdmin() bool { return p.HasBuiltin(model.BuiltinSuperAdmin) }

// ConnectionShortcut 連線短路：內建超管對所有資產全權放行；舊主角色為 auditor 者僅對
// 非連線（view）權限短路放行，connect 須經正常授權查詢（職責分離：稽核者只檢視不連線）。
func (p *Principal) ConnectionShortcut(required model.PermissionType) bool {
	if p.IsSuperAdmin() {
		return true
	}
	return p.LegacyRole() == LegacyRoleAuditor && required != model.PermissionConnect
}

// ReservedCapabilityNames 保留能力的名稱（目錄載入時拒絕以這些為名的權限點）。
func ReservedCapabilityNames() []string {
	return reservedCapabilityWords()
}
