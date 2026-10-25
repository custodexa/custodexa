package authz

import (
	"context"

	"github.com/custodexa/backend/internal/model"
)

// superAdminOperatorCtx 帶內建超管主體的服務層 context：既有「管理員代為操作」的服務層
// 測試沿用它表達操作者身分——授權規則與帳號範圍的本人範圍守衛對超管不適用，
// 且帳號範圍調整在脈絡無主體時 fail-close。
func superAdminOperatorCtx(userID uint) context.Context {
	p := NewPrincipal(userID, TokenFacts{}, []Assignment{{
		RoleName: model.RoleAdmin, BuiltinKey: model.BuiltinSuperAdmin, Via: ViaDirect, Scope: model.ScopeKindGlobal,
	}})
	return ContextWithPrincipal(context.Background(), p)
}

// operatorCtx 帶一般（非超管）主體的服務層 context：本人範圍守衛以它認出操作者。
func operatorCtx(userID uint) context.Context {
	p := NewPrincipal(userID, TokenFacts{}, []Assignment{{
		RoleName: "authz-admin-custom", Via: ViaDirect, Scope: model.ScopeKindGlobal,
		Permissions: []Permission{PermAuthorizationManage, PermApproverScopeManage}, Custom: true,
	}})
	return ContextWithPrincipal(context.Background(), p)
}
