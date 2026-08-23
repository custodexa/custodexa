package identity

// 跨包測試接縫（`export_test.go` 形態）。
//
// # 為何需要這個檔
//
// 3.8b 的序列化契約橫跨兩個模組：**判定**（能力鎖、世代閘、同步點）在 identity，
// **長效能力的建立**（兌換建 session、監看／分享訂閱 Join）在 session。
// 驗證兩者交錯的並發測試必須同時驅動兩邊。
//
// # 為何是 export_test.go 而不是生產檔
//
// 初版把這些接縫寫在生產檔 `testseams.go`，代價是 **16 個純為測試而生的符號
// 永久留在 identity 的公開 API 上**——搬包降低耦合的同時把 private 實作細節
// 固化成跨包介面，正是搬包本意的反面。
//
// Go 的標準解法是 `export_test.go`：本檔屬 `package identity`（故看得見未匯出成員），
// 但因為是 `_test.go`，**只在測試 identity 這個包時被編進去**——對任何其他包
// （含生產組裝根）而言，下列符號一律不存在。消費端隨之改為住在 identity 目錄的
// **外部測試包** `package identity_test`：它不在 identity 的 import 圖裡，
// 故可合法 import `internal/service`（`identity_test → service → identity` 無環）。
//
// # 紀律
//
//   - 一律 `ForTest` 後綴，且註解寫明唯一消費者；
//   - **只做委派，不含任何判定**——接縫本身不得成為第二條語義路徑；
//   - 生產零可見性由編譯器保證（本檔是 `_test.go`），不需另設守衛。

import (
	"context"
	"sync"

	"github.com/custodexa/backend/pkg/crypto"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"

	"gorm.io/gorm"
)

// ── 審計出口 ────────────────────────────────────────────────

// AuditSink identity 內部審計出口的測試別名（單方法 `Log`）。
//
// 別名而非另立型別：與 `oidcAuditSink` 是同一個型別，
// 故不會出現「兩個看起來一樣但不可互換」的介面。
type AuditSink = oidcAuditSink

// SetAuditSinkForTest 注入 OIDC 登入流程的審計出口。
// 唯一消費者：本目錄 `package identity_test` 的 OIDC 並發／撤銷矩陣測試。
func (s *OIDCLoginService) SetAuditSinkForTest(a AuditSink) { s.audit = a }

// SetOIDCAuditSinkForTest 注入使用者服務的外部身分審計出口。
// 唯一消費者同上。生產路徑走 `SetAuditSink(*audit.AuditLogService)`。
func (s *UserService) SetOIDCAuditSinkForTest(a AuditSink) { s.audit = a }

// ── 生產私有路徑的原樣委派 ──────────────────────────────────

// IssueTicketForTest 直接簽發 OIDC 交棒憑證（`issueTicket` 的委派）。
//
// 唯一消費者：`TestPGConcurrentTicketIssueVsUnbind`
// ——它要讓**真的**簽票路徑與解綁在鎖上對撞，換成任何替身都測不到序列化。
func (s *OIDCLoginService) IssueTicketForTest(user *model.User, p *model.OIDCProvider,
	browserSecretHash, redirectTo string) (string, error) {
	return s.issueTicket(user, p, browserSecretHash, redirectTo)
}

// LoadTOTPSecretForTest 以服務自身的讀取路徑取出 TOTP secret（`loadTOTPSecret` 的委派）。
//
// 唯一消費者：`aad_cutover_write_test.go`——它要證明
// 「服務讀取路徑與 keyvault 的 DecryptFor 解出同一個值」，故必須走服務自己那條路。
func (s *AuthService) LoadTOTPSecretForTest(userID uint) (*model.User, string, error) {
	return s.loadTOTPSecret(userID)
}

// EncryptTOTPSecretForTest 以服務自身的 MFA codec 加密 TOTP secret。
//
// 唯一消費者：OIDC 撤銷矩陣夾具——它要造出「與生產寫入逐位同源」的密文，
// 而 codec 是建構時注入的未匯出欄位。
func (s *AuthService) EncryptTOTPSecretForTest(ctx context.Context, secret string) (string, error) {
	return s.mfaCrypto.EncryptFor(ctx, keyvault.RefUserTOTPSecret, secret)
}

// BuildAuthContextForTest 以生產同源的方式組出認證脈絡（`buildAuthContext` 的委派）。
//
// 唯一消費者：OIDC 生命週期夾具——它要造出與登入路徑逐位相同的脈絡（世代現查），
// 自行拼欄位就會與生產漂移。
func (s *AuthService) BuildAuthContextForTest(user *model.User, method string, providerID uint) crypto.AuthContext {
	return s.buildAuthContext(user, method, providerID)
}

// ── 序列化同步點 ────────────────────────────────────────────

// 同步點位置標籤的測試別名。
//
// `OIDCSiteSessionCreate`／`OIDCSiteMonitorJoin` **不在此列**：它們有生產跨包
// 消費者（`internal/service/session_provider_termination.go` 呼叫
// `FirePreWriteHook`），故必須留在生產 API 上。其餘三個只有 identity 自己
// 與測試會提到，一律收回未匯出。
const (
	OIDCSiteProviderInvalidate = oidcSiteProviderInvalidate
	OIDCSiteTicketIssue        = oidcSiteTicketIssue
	OIDCSiteTicketExchange     = oidcSiteTicketExchange
)

// SetPreWriteHookForTest 設定序列化同步點的測試 hook（傳 nil 即清除）。
//
// **變數本身維持未匯出**：匯出可寫的包級 hook 等於讓任何包都能覆寫別人掛的同步點。
func SetPreWriteHookForTest(fn func(site string)) {
	oidcProviderPreWriteHook = fn
}

// SetUserCredentialPreWriteHookForTest 設定使用者憑證同步點的測試 hook（nil 即清除）。
// 理由同上。
func SetUserCredentialPreWriteHookForTest(fn func()) {
	userCredentialPreWriteHook = fn
}

// ── 交易內取鎖（死鎖順序測試專用）────────────────────────────

// WithCapabilityLocksTxForTest 於既有交易內依固定順序取 provider 與 user 鎖
// （`withCapabilityLocksTx` 的測試出口）。
//
// 取鎖順序的死鎖測試要組出 `system → provider → user` 的疊加形狀，
// 而內層是未匯出的 tx-taking helper。**不是通用 API**——生產路徑一律走
// `WithCapabilityLocks`。
func WithCapabilityLocksTxForTest(tx *gorm.DB, providerID, userID uint, fn func(tx *gorm.DB) error) error {
	return withCapabilityLocksTx(tx, providerID, userID, fn)
}

// WithUserCredentialLockTxForTest 於既有交易內取得使用者級鎖
// （`withUserCredentialLockTx` 的測試出口）。理由與約束同上。
func WithUserCredentialLockTxForTest(tx *gorm.DB, userID uint, fn func(tx *gorm.DB) error) error {
	return withUserCredentialLockTx(tx, userID, fn)
}

// ── 能力鎖持有狀態的唯讀探針 ────────────────────────────

// ProviderLockHeldForTest／UserCredentialLockHeldForTest 回報指定 key 的能力鎖
// 此刻是否被任何人持有。
//
// **唯一消費者**＝`identity_test` 的 `TestSessionCallSitesPassProviderAndUserInOrder`
// ——它要證的是 session 的兩個跨模組呼叫點把 providerID 與 userID **放在正確的位置**
// （兩者同為 `uint`，對調不會編譯失敗，也不會讓任何既有測試轉紅）。
//
// 只做委派、不含判定：以 TryLock 探測後立刻還原，不改變任何鎖的持有狀態。
func ProviderLockHeldForTest(providerID uint) bool {
	return heldForTest(oidcProviderLockFor(providerID))
}

func UserCredentialLockHeldForTest(userID uint) bool {
	return heldForTest(userCredentialLockFor(userID))
}

func heldForTest(mu *sync.Mutex) bool {
	if mu.TryLock() {
		mu.Unlock()
		return false
	}
	return true
}
