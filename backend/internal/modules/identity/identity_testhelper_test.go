package identity

// 搬包後的夾具複本（modular-architecture W8 9.9）。
//
// 這幾個 helper 原本住在 `internal/service` 的測試檔裡，而那些檔案因為真的用到
// session（`SessionService`／`JoinWithGenerationGuard`）必須留在原包——identity 的
// 測試包不得 import `internal/service`（session 於 W8 起 import identity，
// 反向 import 會構成 `import cycle not allowed in test`，W7 踩坑 #1）。
// 故此處各留一份最小複本，比照 W2／W3／W4／W6／W7 的夾具複本作法。

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"gorm.io/gorm"
)

// epochGateForTest 世代閘的測試入口。
//
// **9.3 把 `VerifyCredentialGeneration`／`VerifyCredentialGenerationByUserID`
// 由包級函式改為 `*AuthService` 的方法**後，既有測試需要一個接收者。
// 這裡刻意用**零值** `AuthService`：未注入 `epochGateDB` ⇒ `epochDB()` 回退
// 全域 `database.DB`，與改動前那兩個包級函式讀的是**同一個**來源，
// 故所有既有斷言的語義逐位不變（不是放寬，也不是加嚴）。
var epochGateForTest = &AuthService{}

// reloadRefresh 依 token hash 重讀 refresh 列（複本；原在
// `internal/service/oidc_provider_revocation_test.go`）
func reloadRefresh(t *testing.T, db *gorm.DB, hash string) *model.RefreshToken {
	t.Helper()
	var r model.RefreshToken
	if err := db.Where("token_hash = ?", hash).First(&r).Error; err != nil {
		t.Fatalf("reload refresh %s: %v", hash, err)
	}
	return &r
}

// capabilityBrowserSecret 能力憑證測試的固定 browser secret（複本；原在
// `internal/service/oidc_provider_revocation_points_test.go`）
const capabilityBrowserSecret = "browser-secret"

// unknownDialector 未知方言的替身（複本；原在
// `internal/service/oidc_provider_revocation_test.go`）：用來驗證
// 「方言不認得時一律 fail-close」而不是靜默走某條分支。
type unknownDialector struct{ gorm.Dialector }

func (unknownDialector) Name() string { return "mystery" }

// registerBuiltinsLikeAssembly 以與組裝根相同的方式登記解封後遷移（複本；原在
// `internal/service/post_unseal_guard_test.go`）。
//
// **複本而非共用**：真正的守衛（「組裝根確有這一行」）在
// `internal/modules/keyvault/post_unseal_guard_test.go`（W2-W8 期間住 `internal/service`，
// W9 該包解散後遷入），本複本只是讓 identity 的 ldap_seed 測試能重現生產佇列的內容；
// 若把守衛也複製過來，兩份會各自漂移。
func registerBuiltinsLikeAssembly() {
	keyvault.RegisterPostUnsealBuiltin(PostUnsealMigrationLDAPSeed, func() {
		RegisterLDAPSeedMigration(audit.NewTxSink())
	})
}
