package identity_test

// identity 測試夾具的複本。
//
// **為何是複本而非共用**：留在本包的六支測試（OIDC 並發矩陣、撤銷矩陣、
// provider 撤銷點、輪替撤銷、使用者生命週期撤銷、AAD cutover）同時驅動 identity
// 與 session，而 identity 的**同包**測試不得 import `internal/service`
// （session 端 import identity ⇒ `import cycle not allowed in test`）。
// 兩邊都需要這些夾具，故各留一份，比照其他模組的夾具複本作法。
//
// 檔尾三個是 identity 未匯出**生產**函式的等價複本：**刻意不為它們開匯出接縫**
// ——前兩者是 sha256-hex 這種無語義的純函式，第三者是純字串對應，
// 複製一份不會產生「兩份會漂移的判定」。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// authContextUnknownRecv 解析不出接收者識別字時的佔位鍵（複本；原件隨
// auth_context_touchpoints_guard_test.go 已遷入 cmd/server）
const authContextUnknownRecv = "<unknown>"

// testTOTPSecret identity 測試常數的複本
const testTOTPSecret = "JBSWY3DPEHPK3PXP"

// [internal/modules/identity/auth_mfa_service_test.go] 的複本
// encryptTestSecret 以測試金鑰加密 secret（模擬 setup 後的 DB 狀態）
func encryptTestSecret(t *testing.T, svc *identity.AuthService) string {
	enc, err := svc.EncryptTOTPSecretForTest(context.Background(), testTOTPSecret)
	if err != nil {
		t.Fatalf("Failed to encrypt test secret: %v", err)
	}
	return enc
}

// [internal/modules/identity/oidc_flow_test.go] 的複本
// issueTestTicket 簽出憑證並回傳明文
func issueTestTicket(t *testing.T, login *identity.OIDCLoginService, user *model.User,
	p *model.OIDCProvider, browserSecret string) string {
	t.Helper()
	plain, err := login.IssueTicketForTest(user, p, sha256Hex(browserSecret), "/dashboard")
	if err != nil {
		t.Fatalf("issueTicket: %v", err)
	}
	return plain
}

// [internal/modules/identity/ldap_directory_service_test.go] 的複本
// ldapAllowAllGate 明確的放行閘（測試專用）。
//
// **測試不得靠 nil gate 取得放行**：nil 已是 fail-close 的哨兵語義
// （identity.ErrLDAPTransmissionGateUnavailable），若測試沿用 nil 表達「不關心閘」，
// 「閘缺席等於沒有防護」這個突變就永遠不會被任何一格抓到
type ldapAllowAllGate struct{}

// [internal/modules/identity/oidc_flow_test.go] 的複本
func newRecordingAudit() *recordingAudit { return &recordingAudit{} }

// [internal/modules/identity/oidc_provider_service_test.go] 的複本
// providerReq 一份可通過驗證的建立請求（預設 prebound_only、已啟用）
func providerReq(mutate func(*identity.OIDCProviderRequest)) *identity.OIDCProviderRequest {
	req := &identity.OIDCProviderRequest{
		Name: "corp", Issuer: "https://idp.example.com", ClientID: "cid-1",
		ClientSecret: "s3cret-value", Scopes: "profile email",
		Enabled: boolPtr(true),
	}
	if mutate != nil {
		mutate(req)
	}
	return req
}

// [internal/modules/identity/oidc_flow_test.go] 的複本
// recordingAudit 同步記錄審計事件，使「該落的有落、**不該落的沒落**」可被斷言。
// 真實服務是非同步的（worker＋channel＋2 秒 flush），無法證明「沒有落」
type recordingAudit struct {
	entries []*audit.AuditLogEntry
}

// [internal/modules/identity/oidc_provider_service_test.go] 的複本
// reloadProvider 直接自 DB 取回（繞過 DTO，用於斷言落庫狀態）
func reloadProvider(t *testing.T, db *gorm.DB, id uint) *model.OIDCProvider {
	t.Helper()
	var p model.OIDCProvider
	if err := db.Unscoped().First(&p, id).Error; err != nil {
		t.Fatalf("reload provider %d: %v", id, err)
	}
	return &p
}

// [internal/modules/identity/external_identity_service_test.go] 的複本
func reloadUser(t *testing.T, db *gorm.DB, userID uint) *model.User {
	t.Helper()
	var u model.User
	if err := db.First(&u, userID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	return &u
}

// [internal/modules/identity/oidc_flow_test.go] 的複本
func seedOIDCUser(t *testing.T, db *gorm.DB, username string) *model.User {
	t.Helper()
	u := &model.User{
		Username: username, Password: "x", Active: true,
		ProvisioningOrigin: model.AuthSourceOIDC, ExternalCredential: true,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

// [internal/modules/identity/oidc_flow_test.go] 的複本
// seedProvider 建立一個啟用中的 provider
func seedProvider(t *testing.T, db *gorm.DB, mutate func(*model.OIDCProvider)) *model.OIDCProvider {
	t.Helper()
	p := &model.OIDCProvider{
		Name: "corp", Issuer: "https://idp.example.com", ClientID: "cid-1",
		Scopes: "openid profile email", AdmissionMode: model.AdmissionPreboundOnly,
		Enabled: true,
	}
	if mutate != nil {
		mutate(p)
	}
	if err := db.Create(p).Error; err != nil {
		t.Fatalf("create provider: %v", err)
	}
	return p
}

// [internal/modules/identity/user_group_service_test.go] 的複本
func setupUserGroupDB(t *testing.T) (*identity.UserGroupService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetAuthorization{},
		&model.ApproverScope{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return identity.NewUserGroupService(db, audit.NewTxSink(), authz.NewAssetAuthorizationService(db)), db
}

// [internal/modules/identity/user_group_service_test.go] 的複本
func strPtr(s string) *string { return &s }

// [internal/modules/identity/external_identity_service_test.go] 的複本
var testActor = identity.IdentityAdminActor{UserID: 99, Username: "root", ClientIP: "10.0.0.1"}

// [internal/modules/identity/oidc_verify_test.go] 的複本
// testEgress dev 靶機式出站政策：httptest 伺服器位於 loopback，
// 預設政策會擋（正是 SSRF 防線生效的證明），測試以顯式放行取得可測性
func testEgress() *identity.OIDCEgressPolicy {
	return &identity.OIDCEgressPolicy{AllowInsecureHosts: []string{"127.0.0.1"}}
}

// [internal/modules/identity/auth_mfa_service_test.go] 的複本
// 測試用 AES-256 金鑰（32 bytes）
var testMFAKey = []byte("0123456789abcdef0123456789abcdef")

// [internal/modules/identity/auth_mfa_service_test.go] 的複本
// validTestCode 產生目前時間窗的有效 TOTP 碼
func validTestCode(t *testing.T) string {
	code, err := totp.GenerateCode(testTOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}
	return code
}

// [cmd/server/auth_context_touchpoints_guard_test.go] 的複本
// receiverKey 方法呼叫接收者的辨識鍵：取運算式最後一個識別字
// （`h.ConnectTokens` → `ConnectTokens`、`strings` → `strings`）。
// 取不到識別字（如 `f().Join(...)`）回 authContextUnknownRecv，一律不套用例外清單
// ——即 fail-close，強迫登記。
func receiverKey(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	default:
		return authContextUnknownRecv
	}
}

// [internal/modules/identity/oidc_flow_test.go] 的複本
// setupOIDCEnv sqlite in-memory 環境。SetMaxOpenConns(1) 為必要——
// 純 Go driver 的每條連線是各自獨立的空 DB（ff51836 教訓）
func setupOIDCEnv(t *testing.T) (*identity.OIDCLoginService, *identity.OIDCProviderService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{},
		&model.PasswordHistory{}, &model.RefreshToken{},
		&model.OIDCProvider{}, &model.UserExternalIdentity{},
		&model.OIDCFlowState{}, &model.OIDCLoginTicket{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS user_roles (
		user_id INTEGER NOT NULL, role_id INTEGER NOT NULL)`).Error; err != nil {
		t.Fatalf("user_roles: %v", err)
	}
	// 身分域三元組的唯一索引：production 由 migration 建（partial，排除軟刪），
	// AutoMigrate 不會產生。**少了它，測試環境比 production 寬鬆**——
	// 「唯一約束失敗後收斂」這條路徑會永遠走不到，該分支形同未測
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_uei_identity_domain
		ON user_external_identities(issuer, client_id, subject) WHERE deleted_at IS NULL`).Error; err != nil {
		t.Fatalf("identity domain unique index: %v", err)
	}
	if err := db.Create(&model.Role{Name: model.RoleUser, Description: "一般使用者"}).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}

	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	auth := identity.NewAuthService("test-secret", 15*time.Minute)
	auth.SetSecurityPolicies(policy.NewSecurityPolicyService(db))
	providers := identity.NewOIDCProviderService(db, nil, testEgress(), nil, "https://bastion.example.com")
	// discovery 於本檔不參與（測試直接呼叫流程狀態與憑證層，不經 IdP 往返）
	login := identity.NewOIDCLoginService(db, providers, identity.NewOIDCDiscoveryService(testEgress()), auth, nil)
	login.SetAuditSinkForTest(newRecordingAudit())
	return login, providers, db
}

func (ldapAllowAllGate) CheckSettingSave(string, []policy.RiskItem, bool) error { return nil }

func (ldapAllowAllGate) ChannelLevel(string) string { return policy.TransportLevelOff }

func (r *recordingAudit) Log(entry *audit.AuditLogEntry) {
	r.entries = append(r.entries, entry)
}

// countEvent 統計 Details 內含指定 event 字串的筆數
func (r *recordingAudit) countEvent(event string) int {
	n := 0
	for _, e := range r.entries {
		if strings.Contains(e.Details, `"event":"`+event+`"`) {
			n++
		}
	}
	return n
}

// hashRefreshToken identity 未匯出生產函式的等價複本（sha256 hex）
func hashRefreshToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// sha256Hex identity 未匯出生產函式的等價複本
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// invalidationReason identity 未匯出生產函式的等價複本（純字串對應）
func invalidationReason(disabling, secretRotated bool) string {
	switch {
	case disabling && secretRotated:
		return "provider_disabled_and_secret_rotated"
	case secretRotated:
		return "provider_secret_rotated"
	default:
		return "provider_disabled"
	}
}
