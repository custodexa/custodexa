package authz

import "context"

// 主體隨 context 傳遞。
//
// 原本以 context.WithValue(ctx, "role", 角色字串) 把角色帶進 CheckPermission 等服務呼叫；
// 現在改帶解析後的主體，短路判定走 Principal 的保留身分方法（ConnectionShortcut 等），
// 服務層不再比對角色名稱。context 沒有主體（內部呼叫、未經認證中介層）時等同沒有任何
// 保留身分：不短路、落正常授權查詢，與原本「context 沒有 role」相同。

type principalContextKey struct{}

// ContextWithPrincipal 回傳帶有主體的 context；p 為 nil 時原樣回傳。
func ContextWithPrincipal(ctx context.Context, p *Principal) context.Context {
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, principalContextKey{}, p)
}

// PrincipalFromContext 取 context 內的主體；沒有回傳 nil（nil 主體的所有判定方法皆為否）。
func PrincipalFromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalContextKey{}).(*Principal)
	return p
}

// IsAuditor 舊主角色為稽核員（折疊後：沒有超管身分、有稽核員身分）。
func (p *Principal) IsAuditor() bool { return p.LegacyRole() == LegacyRoleAuditor }

// ViewShortcut 檢視類全量視圖資格：內建超管，或舊主角色為稽核員。
// 與 ConnectionShortcut 在非連線（view）權限上同語義；用於「管理視圖恆全量」的判定。
func (p *Principal) ViewShortcut() bool { return p.IsSuperAdmin() || p.IsAuditor() }
