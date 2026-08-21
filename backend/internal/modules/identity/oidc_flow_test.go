package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// OIDC 流程安全測試（idp-oidc-integration tasks 4.3/4.4）：
// flow state 一次性與過期、交棒憑證的瀏覽器綁定與消費、世代閘於兌換點的執行。

// setupOIDCEnv sqlite in-memory 環境。SetMaxOpenConns(1) 為必要——
// 純 Go driver 的每條連線是各自獨立的空 DB（ff51836 教訓）
func setupOIDCEnv(t *testing.T) (*OIDCLoginService, *OIDCProviderService, *gorm.DB) {
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

	auth := NewAuthService("test-secret", 15*time.Minute)
	auth.SetSecurityPolicies(policy.NewSecurityPolicyService(db))
	providers := NewOIDCProviderService(db, nil, testEgress(), nil, "https://bastion.example.com")
	// discovery 於本檔不參與（測試直接呼叫流程狀態與憑證層，不經 IdP 往返）
	login := NewOIDCLoginService(db, providers, NewOIDCDiscoveryService(testEgress()), auth, nil)
	login.audit = newRecordingAudit()
	return login, providers, db
}

// recordingAudit 同步記錄審計事件，使「該落的有落、**不該落的沒落**」可被斷言。
// 真實服務是非同步的（worker＋channel＋2 秒 flush），無法證明「沒有落」
type recordingAudit struct {
	entries []*audit.AuditLogEntry
}

func newRecordingAudit() *recordingAudit { return &recordingAudit{} }

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

// ── 審計意向的斷言面（audit-coverage-closure 批 2）────────────────────────
//
// 流程審計已改由 handler 落地（service 拿不到 *gin.Context，自寫必是四欄皆空的
// 殘列），service 交回的是 `[]OIDCAuditEvent` 意向。故本包的斷言對象隨之從
// recordingAudit 換成意向清單——**斷言強度不減反增**：意向帶 Status／Resource，
// 原本只驗得到 Details 字串。列真的有落、且四欄非空，由 internal/api 的
// oidc_login_audit_test.go 與實走驗證承接。

// auditEvents 取出事件名相符的審計意向
func auditEvents(events []OIDCAuditEvent, name string) []OIDCAuditEvent {
	var out []OIDCAuditEvent
	for _, e := range events {
		if ev, _ := e.Details["event"].(string); ev == name {
			out = append(out, e)
		}
	}
	return out
}

// countAuditIntent 統計指定事件名的意向筆數（與 countAuditEvent 不同：後者數的是
// 已落庫的列，本函式數的是 service 交回、尚未落地的意向）
func countAuditIntent(events []OIDCAuditEvent, name string) int {
	return len(auditEvents(events, name))
}

// auditOf 取出測試環境的審計記錄器
func auditOf(t *testing.T, login *OIDCLoginService) *recordingAudit {
	t.Helper()
	rec, ok := login.audit.(*recordingAudit)
	if !ok {
		t.Fatal("測試環境應注入 recordingAudit")
	}
	return rec
}

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

// --- flow state 一次性與過期 ---

func TestConsumeFlowStateIsSingleUse(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	flow := model.OIDCFlowState{
		State: "state-1", Nonce: "n", PKCEVerifier: "v", ProviderID: 1,
		ExpiresAt: time.Now().Add(oidcFlowTTL),
	}
	if err := db.Create(&flow).Error; err != nil {
		t.Fatalf("seed flow: %v", err)
	}

	if _, err := login.consumeFlowState("state-1"); err != nil {
		t.Fatalf("首次消費應成功: %v", err)
	}
	// 重放同一個 state（授權碼可被中途擷取後重送）必須失敗
	if _, err := login.consumeFlowState("state-1"); !errors.Is(err, ErrOIDCFlowInvalid) {
		t.Fatalf("重放 = %v, want ErrOIDCFlowInvalid", err)
	}
}

func TestConsumeFlowStateRejectsExpiredEvenBeforeCleanup(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	// 清理排程尚未執行的過期記錄：排程延遲不得擴大有效窗口
	flow := model.OIDCFlowState{
		State: "state-old", Nonce: "n", PKCEVerifier: "v", ProviderID: 1,
		ExpiresAt: time.Now().Add(-time.Second),
	}
	if err := db.Create(&flow).Error; err != nil {
		t.Fatalf("seed flow: %v", err)
	}

	if _, err := login.consumeFlowState("state-old"); !errors.Is(err, ErrOIDCFlowInvalid) {
		t.Fatalf("過期 state = %v, want ErrOIDCFlowInvalid", err)
	}
	// 記錄仍在（過期判定不依賴清理），確認拒絕來自條件查詢而非「剛好被刪掉」
	var cnt int64
	db.Model(&model.OIDCFlowState{}).Where("state = ?", "state-old").Count(&cnt)
	if cnt != 1 {
		t.Errorf("過期記錄應仍存在（拒絕來自條件判定），count = %d", cnt)
	}
}

func TestConsumeFlowStateRejectsUnknownAndEmpty(t *testing.T) {
	login, _, _ := setupOIDCEnv(t)
	for _, s := range []string{"", "   ", "never-issued"} {
		if _, err := login.consumeFlowState(s); !errors.Is(err, ErrOIDCFlowInvalid) {
			t.Errorf("state=%q → %v, want ErrOIDCFlowInvalid", s, err)
		}
	}
}

func TestCleanupExpiredRemovesOnlyExpired(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	db.Create(&model.OIDCFlowState{State: "live", Nonce: "n", PKCEVerifier: "v",
		ProviderID: 1, ExpiresAt: time.Now().Add(time.Minute)})
	db.Create(&model.OIDCFlowState{State: "dead", Nonce: "n", PKCEVerifier: "v",
		ProviderID: 1, ExpiresAt: time.Now().Add(-time.Minute)})
	db.Create(&model.OIDCLoginTicket{TokenHash: "h-live", UserID: 1, ProviderID: 1,
		AuthMethod: crypto.AuthMethodOIDC, ExpiresAt: time.Now().Add(time.Minute)})
	db.Create(&model.OIDCLoginTicket{TokenHash: "h-dead", UserID: 1, ProviderID: 1,
		AuthMethod: crypto.AuthMethodOIDC, ExpiresAt: time.Now().Add(-time.Minute)})

	login.CleanupExpired()

	var states []model.OIDCFlowState
	db.Find(&states)
	if len(states) != 1 || states[0].State != "live" {
		t.Errorf("清理後應僅留未過期的 flow state，實得 %+v", states)
	}
	var tickets []model.OIDCLoginTicket
	db.Find(&tickets)
	if len(tickets) != 1 || tickets[0].TokenHash != "h-live" {
		t.Errorf("清理後應僅留未過期的 ticket，實得 %+v", tickets)
	}
}

// --- 交棒憑證：綁定、消費、過期 ---

// issueTestTicket 簽出憑證並回傳明文
func issueTestTicket(t *testing.T, login *OIDCLoginService, user *model.User,
	p *model.OIDCProvider, browserSecret string) string {
	t.Helper()
	plain, err := login.issueTicket(user, p, sha256Hex(browserSecret), "/dashboard")
	if err != nil {
		t.Fatalf("issueTicket: %v", err)
	}
	return plain
}

func TestExchangeTicketSucceedsWithMatchingBinding(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")

	ticket := issueTestTicket(t, login, user, p, "browser-secret")
	resp, next, err := login.Exchange(ticket, "browser-secret")
	if err != nil {
		t.Fatalf("兌換應成功: %v", err)
	}
	if resp.Token == "" {
		t.Error("應發放正式 token")
	}
	if next != "/dashboard" {
		t.Errorf("redirect_next = %q, want /dashboard（來自伺服端已驗證值）", next)
	}
	// 一次性：同一憑證再兌換必失敗
	if _, _, err := login.Exchange(ticket, "browser-secret"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("重放兌換 = %v, want ErrOIDCTicketInvalid", err)
	}
}

func TestExchangeTicketRejectsWrongBrowserWithoutConsuming(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	ticket := issueTestTicket(t, login, user, p, "browser-secret")

	// 落到錯誤分頁：拒絕，但**不得消耗**——否則「請回到原分頁重試」不可能成立
	if _, _, err := login.Exchange(ticket, "wrong-secret"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("綁定不符 = %v, want ErrOIDCTicketInvalid", err)
	}
	var cnt int64
	db.Model(&model.OIDCLoginTicket{}).Where("token_hash = ?", sha256Hex(ticket)).Count(&cnt)
	if cnt != 1 {
		t.Fatal("綁定不符不應消耗憑證（原分頁需能重試）")
	}
	// 回到原分頁重試仍應成功
	if _, _, err := login.Exchange(ticket, "browser-secret"); err != nil {
		t.Fatalf("回原分頁重試應成功: %v", err)
	}
}

func TestExchangeTicketVoidedAfterMaxBindingFailures(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	ticket := issueTestTicket(t, login, user, p, "browser-secret")

	// 「不消耗」不得退化為「可無限猜」：達上限即作廢
	for i := 0; i < oidcTicketMaxBindingFailures; i++ {
		if _, _, err := login.Exchange(ticket, "wrong-secret"); !errors.Is(err, ErrOIDCTicketInvalid) {
			t.Fatalf("第 %d 次錯誤綁定 = %v", i+1, err)
		}
	}
	var cnt int64
	db.Model(&model.OIDCLoginTicket{}).Where("token_hash = ?", sha256Hex(ticket)).Count(&cnt)
	if cnt != 0 {
		t.Fatalf("達 %d 次綁定失敗應作廢憑證", oidcTicketMaxBindingFailures)
	}
	// 作廢後即使拿對 secret 也不能兌換
	if _, _, err := login.Exchange(ticket, "browser-secret"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("作廢後兌換 = %v, want ErrOIDCTicketInvalid", err)
	}
}

func TestExchangeRejectsEmptyBrowserSecret(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")

	// login CSRF 的實際攻擊路徑（codex HIGH）：攻擊者以 SHA256("") 當 binding 發起
	// 流程、用自己的 IdP 帳號完成授權，再把 callback URL 交給受害者。受害者的
	// sessionStorage 沒有 secret，若 exchange 接受空字串，雜湊恰好相符 → 受害者
	// 被登入攻擊者帳號，其後全部操作與審計歸屬錯誤
	ticket := issueTestTicket(t, login, user, p, "")
	if _, _, err := login.Exchange(ticket, ""); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("空的 browser secret 必須被拒（否則 SHA256(\"\") 綁定可被滿足），實得 %v", err)
	}
	if _, _, err := login.Exchange(ticket, "   "); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("純空白的 browser secret 亦須被拒，實得 %v", err)
	}
}

func TestExchangeTicketRejectsExpired(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	ticket := issueTestTicket(t, login, user, p, "s")
	// 手動撥回到過期（TTL 僅 60 秒，但測試不等真實時間）
	db.Model(&model.OIDCLoginTicket{}).Where("token_hash = ?", sha256Hex(ticket)).
		UpdateColumn("expires_at", time.Now().Add(-time.Second))

	if _, _, err := login.Exchange(ticket, "s"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("過期憑證 = %v, want ErrOIDCTicketInvalid", err)
	}
}

func TestExchangeTicketRejectsUnknownHash(t *testing.T) {
	login, _, _ := setupOIDCEnv(t)
	if _, _, err := login.Exchange("never-issued", "s"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("未簽發的憑證 = %v, want ErrOIDCTicketInvalid", err)
	}
}

func TestTicketPlaintextNotPersisted(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	ticket := issueTestTicket(t, login, user, p, "s")

	var rows []model.OIDCLoginTicket
	db.Find(&rows)
	if len(rows) != 1 {
		t.Fatalf("應有 1 筆憑證，實得 %d", len(rows))
	}
	if rows[0].TokenHash == ticket {
		t.Fatal("DB 不得保存憑證明文（只存 SHA256）")
	}
	if rows[0].TokenHash != sha256Hex(ticket) {
		t.Error("落庫值應為明文的 SHA256")
	}
}

// --- 世代閘於兌換點的執行（gate chain） ---

func TestExchangeRejectedAfterProviderDisabled(t *testing.T) {
	login, providers, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	ticket := issueTestTicket(t, login, user, p, "s")

	// 憑證簽出後才停用：尚未兌換的能力憑證亦須失效（掃描既有連線管不到它）
	disabled := false
	if _, err := providers.Update(p.ID, &OIDCProviderRequest{Name: "corp", Enabled: &disabled}); err != nil {
		t.Fatalf("停用 provider: %v", err)
	}

	if _, _, err := login.Exchange(ticket, "s"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("provider 已停用時兌換 = %v, want ErrOIDCTicketInvalid", err)
	}
}

func TestExchangeRejectedAfterProviderReEnabled(t *testing.T) {
	login, providers, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	ticket := issueTestTicket(t, login, user, p, "s")

	// 停用→重新啟用：世代不回退，故舊憑證**永久**失效。
	// 純 stateless JWT 靠撤銷 refresh 救不了既簽憑證，這是世代維度存在的理由
	no, yes := false, true
	providers.Update(p.ID, &OIDCProviderRequest{Name: "corp", Enabled: &no})
	providers.Update(p.ID, &OIDCProviderRequest{Name: "corp", Enabled: &yes})

	var reloaded model.OIDCProvider
	db.First(&reloaded, p.ID)
	if !reloaded.Enabled {
		t.Fatal("provider 應已重新啟用（前提不成立則本測試無意義）")
	}
	if reloaded.AuthEpoch == p.AuthEpoch {
		t.Fatal("停用應推進 auth_epoch")
	}
	if _, _, err := login.Exchange(ticket, "s"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("重新啟用後舊憑證 = %v, want 仍失效", err)
	}
}

func TestExchangeRejectedAfterSecretRotation(t *testing.T) {
	login, providers, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	ticket := issueTestTicket(t, login, user, p, "s")

	// 輪替動機是「舊密鑰可能已洩漏」——僅換密鑰而不使既有存取失效與該動機矛盾
	if _, err := providers.Update(p.ID, &OIDCProviderRequest{
		Name: "corp", ClientSecret: "new-secret"}); err != nil {
		t.Fatalf("輪替密鑰: %v", err)
	}
	if _, _, err := login.Exchange(ticket, "s"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("密鑰輪替後兌換 = %v, want ErrOIDCTicketInvalid", err)
	}
}

func TestExchangeRejectedAfterCredentialEpochBump(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	ticket := issueTestTicket(t, login, user, p, "s")

	// 使用者維度：解綁外部身分／停用帳號／改密皆推進，涵蓋與 provider 無關的失效
	if err := BumpCredentialEpoch(db, user.ID, "test_unbind"); err != nil {
		t.Fatalf("BumpCredentialEpoch: %v", err)
	}
	if _, _, err := login.Exchange(ticket, "s"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("使用者世代推進後兌換 = %v, want ErrOIDCTicketInvalid", err)
	}
}

func TestExchangeRejectedAfterProviderDeleted(t *testing.T) {
	login, providers, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	ticket := issueTestTicket(t, login, user, p, "s")

	// 「沒有 provider」（零值）與「宣稱某 provider 但它已不存在」是兩件事，
	// 後者失去可驗證的來源 → fail-close
	if err := providers.Delete(p.ID); err != nil {
		t.Fatalf("刪除 provider: %v", err)
	}
	if _, _, err := login.Exchange(ticket, "s"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("provider 已刪除時兌換 = %v, want ErrOIDCTicketInvalid", err)
	}
}

func TestExchangeRejectedForInactiveUser(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	ticket := issueTestTicket(t, login, user, p, "s")

	db.Model(&model.User{}).Where("id = ?", user.ID).UpdateColumn("active", false)
	if _, _, err := login.Exchange(ticket, "s"); !errors.Is(err, ErrUserInactive) {
		t.Fatalf("停用帳號兌換 = %v, want ErrUserInactive", err)
	}
}

// --- 世代閘本體（VerifyCredentialGeneration） ---

func TestVerifyCredentialGenerationLocalLoginUnaffectedByProvider(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	no := false
	db.Model(p).Updates(map[string]any{"enabled": no, "auth_epoch": 99})

	user := seedOIDCUser(t, db, "local-user")
	// ProviderID 零值＝本地/LDAP 登入，不受任何 provider 停用影響
	err := epochGateForTest.VerifyCredentialGeneration(crypto.AuthContext{
		AuthMethod: crypto.AuthMethodLocalPassword}, user)
	if err != nil {
		t.Fatalf("本地登入不應受 provider 世代影響: %v", err)
	}
}

func TestVerifyCredentialGenerationFailsCloseOnMissingProvider(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	user := seedOIDCUser(t, db, "alice")
	err := epochGateForTest.VerifyCredentialGeneration(crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: 4242}, user)
	if !errors.Is(err, ErrCredentialGenerationStale) {
		t.Fatalf("宣稱不存在的 provider = %v, want ErrCredentialGenerationStale", err)
	}
}

func TestVerifyCredentialGenerationZeroValuesAreValid(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	user := seedOIDCUser(t, db, "legacy")
	// 升級期相容：既有 token 不帶脈絡，世代 0 與 DB default 一致 → 天然有效
	if err := epochGateForTest.VerifyCredentialGeneration(crypto.AuthContext{}, user); err != nil {
		t.Fatalf("零值脈絡應視為有效（升級期相容）: %v", err)
	}
}

func TestBumpCredentialEpochInvalidatesButLockoutDoesNot(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	policy.NewSecurityPolicyService(db).Update(policy.PolicyLockoutMaxAttempts, "3", "admin")

	// **必須走真實鎖定路徑**：直接 UPDATE locked_until 只是在斷言我們剛寫進去的值，
	// 即使生產碼在鎖定時推進世代，那樣的測試也不會紅
	hash, _ := bcrypt.GenerateFromPassword([]byte("right-password-1"), bcrypt.MinCost)
	user := &model.User{Username: "victim", Password: string(hash), Active: true,
		ProvisioningOrigin: model.AuthSourceLocal}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	before := user.CredentialEpoch

	// 第三方連續輸錯密碼觸發自動鎖定（未認證者只要知道 username 即可辦到）
	for i := 0; i < 3; i++ {
		if _, err := login.auth.Login(&LoginRequest{Username: "victim", Password: "wrong"}); err == nil {
			t.Fatalf("第 %d 次錯誤密碼不應成功", i+1)
		}
	}
	var afterLock model.User
	db.First(&afterLock, user.ID)
	if afterLock.LockedUntil == nil {
		t.Fatal("應已觸發自動鎖定（前提不成立則本測試無意義）")
	}
	// 若推進世代，攻擊者即可遠端切斷受害者進行中的連線與監看
	if afterLock.CredentialEpoch != before {
		t.Fatalf("鎖定不得推進憑證世代（會成為遠端斷線武器），%d → %d",
			before, afterLock.CredentialEpoch)
	}

	// 對照：管理者的顯式撤銷動作才推進
	if err := BumpCredentialEpoch(db, user.ID, "account_disabled"); err != nil {
		t.Fatalf("BumpCredentialEpoch: %v", err)
	}
	var afterBump model.User
	db.First(&afterBump, user.ID)
	if afterBump.CredentialEpoch != before+1 {
		t.Fatalf("顯式撤銷應推進世代，%d → %d", before, afterBump.CredentialEpoch)
	}
}
