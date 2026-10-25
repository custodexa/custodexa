package middleware

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// legacyPrincipal 以舊角色字串建立測試用主體：該角色對應的內建範本以全域直接指派表示。
// 空字串＝沒有任何指派（視同一般使用者）；未知角色名稱＝非內建角色（沒有能力）。
func legacyPrincipal(role string) *authz.Principal {
	if role == "" {
		return authz.NewPrincipal(1, authz.TokenFacts{}, nil)
	}
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
	return authz.NewPrincipal(1, authz.TokenFacts{}, []authz.Assignment{{
		RoleName: role, BuiltinKey: key, Via: authz.ViaDirect, Scope: model.ScopeKindGlobal,
	}})
}
