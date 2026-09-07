package api

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 接入層測試自組檢查點服務與對帳器時，沿用產品組裝的 user_roles 來源
func init() {
	audit.SetUserRolesSource(identity.SnapshotUserRolePairs)
}
