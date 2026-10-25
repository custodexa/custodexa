package authz_test

import (
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 把 identity 的使用者憑證鎖入口交給 authz 內部測試的 lock_order_probe_fires 子測試
// （內部測試不能 import identity）。
func init() {
	authz.UserCredentialLockForProbeTest = identity.WithUserCredentialLock
}
