package authz

import (
	"context"

	"github.com/custodexa/backend/internal/model"
)

// legacyRoleContext 以舊角色字串建立帶主體的 context（測試夾具）：
// 該角色對應的內建範本以全域直接指派表示，短路判定走主體而非角色字串。
func legacyRoleContext(role string) context.Context {
	key := ""
	switch role {
	case model.RoleAdmin:
		key = model.BuiltinSuperAdmin
	case model.RoleAuditor:
		key = model.BuiltinAuditor
	case model.RoleUser:
		key = model.BuiltinUser
	case model.RoleApprover:
		key = model.BuiltinApprover
	}
	p := NewPrincipal(1, TokenFacts{}, []Assignment{{
		RoleName: role, BuiltinKey: key, Via: ViaDirect, Scope: model.ScopeKindGlobal,
	}})
	return ContextWithPrincipal(context.Background(), p)
}
