package api

import (
	"context"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"gorm.io/gorm"
)

// 接入層測試自組檢查點服務與對帳器時，沿用產品組裝的 user_roles 來源
func init() {
	audit.SetUserRolesSource(identity.SnapshotUserRolePairs)
	resetPrincipalTestSources()
}

func resetPrincipalTestSources() {
	audit.SetPrincipalSource(func(context.Context, *gorm.DB) ([]audit.PrincipalState, error) { return nil, nil })
	audit.SetAgentTokenSource(func(context.Context, *gorm.DB) ([]audit.AgentTokenState, error) { return nil, nil })
}
