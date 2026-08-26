package identity_test

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
	"sync"
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

// 撤銷矩陣的**使用者維度**。
//
// 與既有三檔的分工：
//
//	oidc_provider_revocation_test.go        provider 維度「停用做了什麼」（五管道）
//	oidc_provider_revocation_points_test.go provider 維度「停用之後還能用什麼」（七點）
//	external_identity_service_test.go       四操作的正反矩陣與並發 write-skew
//	**本檔**                                「不該被撤的沒被撤」（4.14g）與
//	                                        「該被撤的撤得夠廣」（4.14b／4.14d）
//
// 本檔一律以**真** SessionService 當終斷管道（TerminateAllByUser 的 SQL 與 CAS
// 本身就是被測對象），訂閱與錄影 token 才用假管道——它們的真身在 sshproxy／api
// 層，於本層只能觀測「有沒有被呼叫、對誰呼叫」。

// --- fixture ---

// revMatrixDB 單連線 :memory:（ff51836：sqlite `:memory:` 的第二條連線是另一個
// 空 DB，連線池放行即出現「建了資料卻查不到」的假紅）
func revMatrixDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{},
		&model.ApproverScope{}, &model.SecurityPolicy{}, &model.PasswordHistory{},
		&model.RefreshToken{}, &model.OIDCProvider{}, &model.UserExternalIdentity{},
		&model.OIDCFlowState{}, &model.OIDCLoginTicket{}, &model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS user_roles (
		user_id INTEGER NOT NULL, role_id INTEGER NOT NULL)`).Error; err != nil {
		t.Fatalf("user_roles: %v", err)
	}
	// 身分域 partial unique index：production 由 migration 建，AutoMigrate 不產生。
	// 少了它，測試環境比 production 寬鬆，衝突分支形同未測
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_uei_domain_matrix
		ON user_external_identities(issuer, client_id, subject) WHERE deleted_at IS NULL`).Error; err != nil {
		t.Fatalf("identity domain unique index: %v", err)
	}
	for _, name := range []string{model.RoleAdmin, model.RoleUser} {
		if err := db.Create(&model.Role{Name: name}).Error; err != nil {
			t.Fatalf("seed role %s: %v", name, err)
		}
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// revMatrixObserver 一筆唯讀訂閱（監看或分享觀看）的認證脈絡。
// ProviderID 0＝本地／LDAP 登入的觀察者
type revMatrixObserver struct {
	userID     uint
	providerID uint
	tag        string
}

// revMatrixHub MonitorHub 的最小等價模型：真的持有一組觀察者，
// 使「訂閱有沒有逃過收線」以集合是否清空來斷言（而非只看有沒有呼叫過）。
//
// 三個 Disconnect 的匹配語義刻意與 sshproxy/monitor.go 同源，
// 尤其 **providerID 0 不是萬用字元**（見 TestDisconnectByProviderIgnoresZero）
type revMatrixHub struct {
	mu        sync.Mutex
	observers []revMatrixObserver
	userCalls []uint
	provCalls []uint
}

func newRevMatrixHub() *revMatrixHub { return &revMatrixHub{} }

func (h *revMatrixHub) join(userID, providerID uint, tag string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.observers = append(h.observers, revMatrixObserver{userID: userID, providerID: providerID, tag: tag})
}

func (h *revMatrixHub) disconnectMatching(match func(revMatrixObserver) bool) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	kept := h.observers[:0:0]
	n := 0
	for _, o := range h.observers {
		if match(o) {
			n++
			continue
		}
		kept = append(kept, o)
	}
	h.observers = kept
	return n
}

func (h *revMatrixHub) DisconnectByUser(userID uint) int {
	h.mu.Lock()
	h.userCalls = append(h.userCalls, userID)
	h.mu.Unlock()
	return h.disconnectMatching(func(o revMatrixObserver) bool { return o.userID == userID })
}

func (h *revMatrixHub) DisconnectByProvider(providerID uint) int {
	h.mu.Lock()
	h.provCalls = append(h.provCalls, providerID)
	h.mu.Unlock()
	if providerID == 0 {
		return 0
	}
	return h.disconnectMatching(func(o revMatrixObserver) bool { return o.providerID == providerID })
}

// aliveTags 目前仍存活的訂閱標籤（斷言用；順序即加入順序）
func (h *revMatrixHub) aliveTags() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.observers))
	for _, o := range h.observers {
		out = append(out, o.tag)
	}
	return out
}

func (h *revMatrixHub) alive(tag string) bool {
	for _, got := range h.aliveTags() {
		if got == tag {
			return true
		}
	}
	return false
}

func (h *revMatrixHub) userSweeps() []uint {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]uint(nil), h.userCalls...)
}

// revMatrixRegistry 實際關閉 WS 的觀測點
type revMatrixRegistry struct {
	mu     sync.Mutex
	closed []uint
}

func (r *revMatrixRegistry) Close(sessionID uint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = append(r.closed, sessionID)
	return nil
}

func (r *revMatrixRegistry) closedIDs() []uint {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint(nil), r.closed...)
}

// revMatrixTokens 錄影 token 的按-user／按-provider 撤銷觀測點
type revMatrixTokens struct {
	mu       sync.Mutex
	byUser   []uint
	byProvID []uint
}

func (r *revMatrixTokens) RevokeByUser(userID uint) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byUser = append(r.byUser, userID)
	return 1
}

func (r *revMatrixTokens) RevokeByProvider(providerID uint) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byProvID = append(r.byProvID, providerID)
	return 1
}

func (r *revMatrixTokens) userCalls() []uint {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint(nil), r.byUser...)
}

type revMatrixEnv struct {
	db        *gorm.DB
	auth      *identity.AuthService
	policies  *policy.SecurityPolicyService
	users     *identity.UserService
	providers *identity.OIDCProviderService
	login     *identity.OIDCLoginService
	sessions  *session.SessionService
	hub       *revMatrixHub
	registry  *revMatrixRegistry
	tokens    *revMatrixTokens
	audit     *recordingAudit
}

// newRevMatrixEnv 一組互相接得起來的服務（共用同一個 DB 與 database.DB）。
//
// auth 走 identity.NewAuthServiceWithMFA：沒有 mfaCrypto 就簽不出**可完成**的 pending
// token，4.14d 的「MFA pending 無法完成拿正式會話」只能驗到錯誤訊息形狀
func newRevMatrixEnv(t *testing.T, db *gorm.DB) *revMatrixEnv {
	t.Helper()
	auth, err := identity.NewAuthServiceWithMFA("test-secret", 15*time.Minute, aesColumnCodec(t, testMFAKey))
	if err != nil {
		t.Fatalf("identity.NewAuthServiceWithMFA: %v", err)
	}
	policies := policy.NewSecurityPolicyService(db)
	auth.SetSecurityPolicies(policies)

	registry := &revMatrixRegistry{}
	sessions := session.NewSessionService(registry)
	providers := identity.NewOIDCProviderService(db, nil, testEgress(), nil, "https://bastion.example.com")
	login := identity.NewOIDCLoginService(db, providers, identity.NewOIDCDiscoveryService(testEgress()), auth, nil)
	login.SetAuditSinkForTest(newRecordingAudit())

	env := &revMatrixEnv{
		db: db, auth: auth, policies: policies,
		users: identity.NewUserService(db, authz.NewAssetAuthorizationService(db)), providers: providers, login: login,
		sessions: sessions, hub: newRevMatrixHub(), registry: registry,
		tokens: &revMatrixTokens{}, audit: newRecordingAudit(),
	}
	env.users.SetOIDCAuditSinkForTest(env.audit)
	env.users.SetSecurityPolicies(policies)
	// 真 SessionService：TerminateAllByUser 的查詢條件與 Terminate 的 CAS
	// 本身即被測對象，換成假的等於只驗到「有呼叫」
	env.users.SetSessionTerminator(sessions)
	env.users.SetSubscriptionTerminator(env.hub)
	env.users.SetRecordingTokenRevoker(env.tokens)
	env.providers.SetSessionTerminator(sessions)
	env.providers.SetSubscriptionTerminator(env.hub)
	env.providers.SetRecordingTokenRevoker(env.tokens)
	return env
}

// revMatrixLocalUser 具本地密碼的啟用帳號（origin=local、external_credential=false）
func revMatrixLocalUser(t *testing.T, db *gorm.DB, username, password string,
	mutate func(*model.User)) *model.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	now := time.Now()
	u := &model.User{
		Username: username, Password: string(hash), Active: true,
		ProvisioningOrigin: model.AuthSourceLocal, PasswordChangedAt: &now,
	}
	if mutate != nil {
		mutate(u)
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建立本地使用者 %s: %v", username, err)
	}
	return u
}

// revMatrixBind 綁定外部身分並回傳 identityID（走管理服務，與 production 同路徑）
func revMatrixBind(t *testing.T, env *revMatrixEnv, userID uint,
	p *model.OIDCProvider, subject string) uint {
	t.Helper()
	dto, err := env.users.BindExternalIdentity(userID, p.ID, subject, testActor)
	if err != nil {
		t.Fatalf("綁定外部身分 %s: %v", subject, err)
	}
	return dto.ID
}

// revMatrixOIDCCtx 本次以該 provider 認證的脈絡（世代取現值，與 buildAuthContext 同源）
func revMatrixOIDCCtx(t *testing.T, db *gorm.DB, u *model.User, p *model.OIDCProvider) crypto.AuthContext {
	t.Helper()
	return crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: p.ID,
		AuthEpoch: reloadProvider(t, db, p.ID).AuthEpoch,
		CredEpoch: reloadUser(t, db, u.ID).CredentialEpoch,
	}
}

// revMatrixAttachAdminRole 讓帳號成為本地 admin（UpdateStatus 的不變式路徑需要）
func revMatrixAttachAdminRole(t *testing.T, db *gorm.DB, userID uint) {
	t.Helper()
	var role model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&role).Error; err != nil {
		t.Fatalf("load admin role: %v", err)
	}
	if err := db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
		userID, role.ID).Error; err != nil {
		t.Fatalf("attach admin role: %v", err)
	}
}

// --- 4.14g 鎖定不得成為斷線武器 ---

// TestLockoutIsNotADisconnectWeapon 自動鎖定 SHALL NOT 影響受害者**既有**的
// 協議連線與唯讀訂閱。
//
// 攻擊面：鎖定可由**未認證的第三方**觸發——只要知道 username，連續打錯密碼即可，
// 且每個鎖定窗結束後可重複。若鎖定順帶推進 credential_epoch 或走按-user 收線，
// 攻擊者就得到一個「遠端切斷任意使用者進行中連線與監看」的原語。
//
// 與既有 TestBumpCredentialEpochInvalidatesButLockoutDoesNot 的分工：該測試斷言
// 「epoch 欄位沒被推進」（機制面）；**本測試補的是行為面**——即使某天有人在
// recordFailedAttempt 裡直接呼叫 TerminateAllByUser／DisconnectByUser（不碰 epoch），
// 那個突變只有本測試會紅。
//
// **不斷言「鎖定期間 access 仍可用」**：ValidateConnectionToken 經
// CheckUserConnectable 對鎖定中帳號回 identity.ErrAccountLocked，那是「阻止**新**連線」的
// 既有設計，與本任務的「既有連線不受影響」不衝突。
func TestLockoutIsNotADisconnectWeapon(t *testing.T) {
	db := revMatrixDB(t)
	env := newRevMatrixEnv(t, db)
	if _, err := env.policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin"); err != nil {
		t.Fatalf("設定鎖定門檻: %v", err)
	}

	p := seedProvider(t, db, nil)
	const password = "Str0ng-Passw0rd!x"
	victim := revMatrixLocalUser(t, db, "victim", password, nil)
	// 混合帳號：具本地密碼（故鎖定計數適用）且綁一筆外部身分（供末段對照組）
	identityID := revMatrixBind(t, env, victim.ID, p, "sub-victim")

	// 進行中的協議連線（本地登入建立，auth_provider_id 為 NULL）
	sess := seedSession(t, db, victim.ID, 0, 0, "sess-victim")
	// 進行中的監看訂閱（本地登入的觀察者，providerID=0）
	env.hub.join(victim.ID, 0, "victim-monitor")

	// 受害者本人的 Web 會話（鎖定會撤 refresh，這是**允許**的那一項）
	loggedIn, err := env.auth.Login(&identity.LoginRequest{Username: "victim", Password: password})
	if err != nil {
		t.Fatalf("受害者登入應成功（前提不成立則本測試無意義）: %v", err)
	}
	if loggedIn.RefreshToken == "" {
		t.Fatalf("登入應發出 refresh，實得 %+v", loggedIn)
	}
	epochBefore := reloadUser(t, db, victim.ID).CredentialEpoch

	// 第三方連續輸錯密碼觸發自動鎖定
	var lastErr error
	for i := 0; i < 3; i++ {
		if _, lastErr = env.auth.Login(&identity.LoginRequest{
			Username: "victim", Password: "definitely-wrong"}); lastErr == nil {
			t.Fatalf("第 %d 次錯誤密碼不應成功", i+1)
		}
	}
	if !errors.Is(lastErr, identity.ErrAccountLocked) {
		t.Fatalf("達門檻應回 identity.ErrAccountLocked，實得 %v", lastErr)
	}
	if locked := reloadUser(t, db, victim.ID); locked.LockedUntil == nil {
		t.Fatal("應已觸發自動鎖定（前提不成立則本測試無意義）")
	}

	// --- 不得發生的四件事 ---
	if got := reloadUser(t, db, victim.ID).CredentialEpoch; got != epochBefore {
		t.Errorf("鎖定不得推進 credential_epoch（會使既簽憑證與未兌換能力全滅）: %d → %d",
			epochBefore, got)
	}
	if s := reloadRevocationSession(t, db, sess.ID); s.Status != model.SessionStatusActive {
		t.Errorf("鎖定不得終斷既有協議連線: status=%q end_reason=%q", s.Status, s.EndReason)
	}
	if closed := env.registry.closedIDs(); len(closed) != 0 {
		t.Errorf("鎖定不得關閉任何會話 WebSocket，實得 %v", closed)
	}
	if !env.hub.alive("victim-monitor") {
		t.Errorf("鎖定不得收線既有唯讀訂閱，存活集合 = %v", env.hub.aliveTags())
	}
	if sweeps := env.hub.userSweeps(); len(sweeps) != 0 {
		t.Errorf("鎖定不得觸發按-user 訂閱收線，實得呼叫 %v", sweeps)
	}

	// --- 應當發生的兩件事 ---
	r := reloadRefresh(t, db, hashRefreshToken(loggedIn.RefreshToken))
	if r.RevokedAt == nil {
		t.Error("鎖定應撤銷 refresh（阻既有 Web 會話續命）")
	} else if r.RevokedReason != model.RefreshRevokeLocked {
		t.Errorf("撤銷成因 = %q, want %q", r.RevokedReason, model.RefreshRevokeLocked)
	}
	if _, err := env.auth.Login(&identity.LoginRequest{
		Username: "victim", Password: password}); !errors.Is(err, identity.ErrAccountLocked) {
		t.Errorf("鎖定期間持正確密碼的新登入 = %v, want identity.ErrAccountLocked", err)
	}

	// --- 對照組：管理者的顯式撤銷動作**確實**收得掉 ---
	// 少了這段，上面五條「沒被收線」的斷言無法排除「這些管道根本沒接上」
	if err := env.users.UnbindExternalIdentity(victim.ID, identityID, testActor); err != nil {
		t.Fatalf("對照組解綁應成功（仍具本地密碼）: %v", err)
	}
	if got := reloadUser(t, db, victim.ID).CredentialEpoch; got != epochBefore+1 {
		t.Errorf("解綁應推進 credential_epoch: %d → %d", epochBefore, got)
	}
	if s := reloadRevocationSession(t, db, sess.ID); s.Status != model.SessionStatusDisconnected {
		t.Errorf("解綁應終斷協議連線: status=%q", s.Status)
	}
	if closed := env.registry.closedIDs(); len(closed) != 1 || closed[0] != sess.ID {
		t.Errorf("解綁應關閉該會話 WebSocket: %v, want [%d]", closed, sess.ID)
	}
	if env.hub.alive("victim-monitor") {
		t.Errorf("解綁應收線唯讀訂閱，存活集合 = %v", env.hub.aliveTags())
	}
}

// --- 4.14d credential_epoch 三情境 ---

// TestUnbindRejectsUnredeemedCapabilitiesAndRebindDoesNotRevive
// 解綁後**未兌換**的 ticket／MFA pending／connect grant 皆拒；身分重綁後舊憑證不復活
// （第一、二情境）。
//
// 「未兌換」是關鍵字：掃描既有連線完全管不到它們——ticket 與 pending 是 stateless
// 或半 stateless 的能力憑證，connect grant 尚未變成 session 列，三者都不在任何
// 收線集合內，唯一的失效途徑就是 credential_epoch。
//
// **重綁不得復活**：epoch 是單調遞增的計數而非「是否已綁定」的布林，
// 若改成解綁時歸零／重綁時回退，攻擊者只要說服管理者「解錯了、綁回去」，
// 手上全部舊憑證就一起復活。
func TestUnbindRejectsUnredeemedCapabilitiesAndRebindDoesNotRevive(t *testing.T) {
	db := revMatrixDB(t)
	env := newRevMatrixEnv(t, db)
	p := seedProvider(t, db, nil)

	// 甲：交棒憑證與 connect grant 的持有者
	alice := revMatrixLocalUser(t, db, "alice", "Str0ng-Passw0rd!a", nil)
	aliceIdentity := revMatrixBind(t, env, alice.ID, p, "sub-alice")

	// 正向控制：解綁**之前**，同型憑證確實可兌換
	// （少了它，「全部被拒」無法排除「這些路徑本來就不通」）
	ctlTicket := issueTestTicket(t, env.login, alice, p, "browser-secret")
	if _, _, err := env.login.Exchange(ctlTicket, "browser-secret"); err != nil {
		t.Fatalf("解綁前的兌換應成功: %v", err)
	}

	// 待測的三張未兌換憑證
	ticket := issueTestTicket(t, env.login, alice, p, "browser-secret")
	grantCtx := revMatrixOIDCCtx(t, db, alice, p)

	// 乙：MFA 第一因子已過、第二因子未完成（各用各的使用者——TOTP 的已消耗 step
	// 是 per-user 欄位，共用會讓「閘被拿掉也還是失敗」而失去辨識力）
	carol := revMatrixLocalUser(t, db, "carol", "Str0ng-Passw0rd!c", func(u *model.User) {
		u.TOTPSecretEnc = encryptTestSecret(t, env.auth)
		u.TOTPEnabled = true
	})
	carolIdentity := revMatrixBind(t, env, carol.ID, p, "sub-carol")
	pendingResp, err := env.auth.LoginWithExternalIdentity(carol, revMatrixOIDCCtx(t, db, carol, p))
	if err != nil {
		t.Fatalf("MFA 使用者的 OIDC 登入應進入第二階段: %v", err)
	}
	if !pendingResp.MFARequired || pendingResp.PendingToken == "" {
		t.Fatalf("應簽出 pending token，實得 %+v", pendingResp)
	}

	// --- 解綁（推進 credential_epoch） ---
	if err := env.users.UnbindExternalIdentity(alice.ID, aliceIdentity, testActor); err != nil {
		t.Fatalf("解綁 alice 應成功: %v", err)
	}
	if err := env.users.UnbindExternalIdentity(carol.ID, carolIdentity, testActor); err != nil {
		t.Fatalf("解綁 carol 應成功: %v", err)
	}
	aliceEpoch := reloadUser(t, db, alice.ID).CredentialEpoch
	if aliceEpoch == 0 {
		t.Fatal("解綁應推進 credential_epoch（前提不成立則後續斷言無意義）")
	}

	assertUnredeemedRejected := func(phase string) {
		t.Helper()
		// (1) 未兌換的交棒憑證
		if _, _, err := env.login.Exchange(ticket, "browser-secret"); !errors.Is(err, identity.ErrOIDCTicketInvalid) {
			t.Errorf("[%s] ticket 兌換 = %v, want identity.ErrOIDCTicketInvalid", phase, err)
		}
		// (2) 未完成的 MFA pending
		if _, err := env.auth.VerifyMFALogin(&identity.MFAVerifyRequest{
			PendingToken: pendingResp.PendingToken,
			Code:         validTestCode(t)}); !errors.Is(err, identity.ErrMFAPendingTokenInvalid) {
			t.Errorf("[%s] MFA 完成 = %v, want identity.ErrMFAPendingTokenInvalid", phase, err)
		}
		// (3) 未兌換的 connect grant：走真正的兌換點（鎖內重讀世代），
		// 不是只呼叫世代閘——兌換點才是「產生長效能力」的位置
		assetID := uint(1)
		grantSession := &model.Session{
			SessionID: "sess-grant-" + phase, UserID: alice.ID, AssetID: &assetID,
			Protocol: model.ProtocolSSH, StartTime: time.Now(),
			AuthEpoch: grantCtx.AuthEpoch, AuthProviderID: &grantCtx.ProviderID,
		}
		if err := env.sessions.CreateWithGenerationGuard(grantCtx, grantSession); !errors.Is(err, identity.ErrCredentialGenerationStale) {
			t.Errorf("[%s] connect grant 兌換 = %v, want identity.ErrCredentialGenerationStale", phase, err)
		}
		var lingering int64
		if err := db.Model(&model.Session{}).
			Where("session_id = ?", grantSession.SessionID).Count(&lingering).Error; err != nil {
			t.Fatalf("[%s] 統計殘留會話: %v", phase, err)
		}
		if lingering != 0 {
			t.Errorf("[%s] 被拒的 connect grant 不得留下 session 列，實得 %d 筆", phase, lingering)
		}
	}

	assertUnredeemedRejected("解綁後")

	// --- 重綁：epoch 不回退，舊憑證不復活 ---
	if _, err := env.users.BindExternalIdentity(alice.ID, p.ID, "sub-alice", testActor); err != nil {
		t.Fatalf("重新綁定應成功: %v", err)
	}
	if _, err := env.users.BindExternalIdentity(carol.ID, p.ID, "sub-carol", testActor); err != nil {
		t.Fatalf("重新綁定 carol 應成功: %v", err)
	}
	if got := reloadUser(t, db, alice.ID).CredentialEpoch; got < aliceEpoch {
		t.Fatalf("重綁不得回退 credential_epoch: %d → %d", aliceEpoch, got)
	}
	assertUnredeemedRejected("重綁後")

	// 重綁後的**新**登入必須完全正常（撤銷針對既簽憑證，不得把帳號變成永久不可用）
	fresh := issueTestTicket(t, env.login, reloadUser(t, db, alice.ID), p, "browser-secret")
	resp, _, err := env.login.Exchange(fresh, "browser-secret")
	if err != nil {
		t.Fatalf("重綁後的新登入應成功: %v", err)
	}
	if _, err := env.auth.ValidateConnectionToken(resp.Token); err != nil {
		t.Errorf("重綁後新簽的 access 應可用: %v", err)
	}
}

// TestAccountDisableCutsLocalAdminSubscription 帳號停用 SHALL 收線該帳號的監看訂閱，
// 涵蓋 providerID=0 的本地 admin（第三情境）。
//
// 為什麼一定要按**觀察者**收線：監看訂閱不建 sessions 列，TerminateAllByUser
// 完全掃不到；而本地 admin 的 providerID=0，按 provider 的收線也掃不到。
// 缺這條時，被停用的管理員帳號正在進行的監看會繼續存活並可讀他人終端內容——
// 訂閱建立後不再重驗任何憑證，帳號停用對它完全免疫。
//
// hub 端的匹配語義已由 sshproxy/monitor_revoke_test.go 的
// TestDisconnectByUserCoversLocalObserver 驗過；**本測試驗的是 service 的停用路徑
// 真的把這條管道打出去**（那支測試直接呼叫 hub 方法，service 漏接完全不會紅）。
//
// **本測試原為 t.Skip（實作與規格不符，屬既有缺陷）**，缺口已由
// UpdateStatus 的 !active 分支與 Delete 成功後皆呼叫 revokeUserAccess
// （user_service.go），故 subscriptions.DisconnectByUser 與 recordingTokens.RevokeByUser
// 兩條管道在停用／刪除路徑上都有呼叫點。修復前本測試的實際紅訊為：
//
//	停用應觸發按-user 訂閱收線 = [], want [1]
//	被停用帳號的監看訂閱應被收線，存活集合 = [auditor-monitor keeper-monitor]
//
// 停用與刪除的完整四件事（世代／refresh／協議會話／訂閱與錄影 token）另見
// user_lifecycle_revocation_test.go。
func TestAccountDisableCutsLocalAdminSubscription(t *testing.T) {
	db := revMatrixDB(t)
	env := newRevMatrixEnv(t, db)

	auditor := revMatrixLocalUser(t, db, "auditor", "Str0ng-Passw0rd!x", nil)
	revMatrixAttachAdminRole(t, db, auditor.ID)
	// 第二位 admin：否則停用會被「最後一個 admin」不變式擋下，測不到收線
	keeper := revMatrixLocalUser(t, db, "keeper", "Str0ng-Passw0rd!k", nil)
	revMatrixAttachAdminRole(t, db, keeper.ID)

	// 被監看的會話由**別人**建立（監看的常態），故按 session 掃描與本帳號無關
	target := revMatrixLocalUser(t, db, "target", "Str0ng-Passw0rd!t", nil)
	watched := seedSession(t, db, target.ID, 0, 0, "sess-watched")
	env.hub.join(auditor.ID, 0, "auditor-monitor")
	env.hub.join(keeper.ID, 0, "keeper-monitor")

	if err := env.users.UpdateStatus(auditor.ID, false); err != nil {
		t.Fatalf("停用帳號: %v", err)
	}
	if reloadUser(t, db, auditor.ID).Active {
		t.Fatal("帳號應已停用（前提不成立則本測試無意義）")
	}

	if sweeps := env.hub.userSweeps(); len(sweeps) != 1 || sweeps[0] != auditor.ID {
		t.Errorf("停用應觸發按-user 訂閱收線 = %v, want [%d]", sweeps, auditor.ID)
	}
	if env.hub.alive("auditor-monitor") {
		t.Errorf("被停用帳號的監看訂閱應被收線，存活集合 = %v", env.hub.aliveTags())
	}
	// 精準性：不得誤殺其他觀察者，也不得牽連被監看的會話本身
	if !env.hub.alive("keeper-monitor") {
		t.Errorf("其他管理員的監看不應被牽連，存活集合 = %v", env.hub.aliveTags())
	}
	if s := reloadRevocationSession(t, db, watched.ID); s.Status != model.SessionStatusActive {
		t.Errorf("被監看的他人會話不應被牽連: status=%q", s.Status)
	}
}

// TestConvertToExternalOnlyBlocksMFAPendingCompletion 轉換為僅外部登入後，
// 以本地密碼啟動的 MFA pending **無法完成、拿不到正式會話**（第四情境）。
//
// 與既有 TestConvertToExternalOnlyKillsMFAPending 的分工：該測試自行簽 pending
// token 並以固定錯碼呼叫，斷言錯誤型別；**本測試補的是全鏈**——真的走本地密碼
// 登入拿 pending、以**有效** TOTP 碼完成，且有正向控制證明「同樣的操作在轉換前
// 拿得到正式會話」。少了正向控制，把 VerifyMFALogin 改成永遠失敗也一樣是綠的。
//
// 為什麼這條非擋不可：轉換會清空密碼雜湊並標記 external_credential，此後
// finishLogin 的密碼類 gate 對該帳號一律跳過——pending 若存活，其持有者完成
// 第二因子即可直接取得正式會話，而「管理者已把此帳號改為僅外部登入」的意圖是
// 本地密碼路徑不再可用。
func TestConvertToExternalOnlyBlocksMFAPendingCompletion(t *testing.T) {
	db := revMatrixDB(t)
	env := newRevMatrixEnv(t, db)
	p := seedProvider(t, db, nil)

	const password = "Str0ng-Passw0rd!m"
	newMFAUser := func(username, subject string) *model.User {
		u := revMatrixLocalUser(t, db, username, password, func(u *model.User) {
			u.TOTPSecretEnc = encryptTestSecret(t, env.auth)
			u.TOTPEnabled = true
		})
		revMatrixBind(t, env, u.ID, p, subject)
		return u
	}
	// 正向控制與待測各用一個使用者（TOTP 已消耗 step 為 per-user 欄位）
	control := newMFAUser("control", "sub-control")
	victim := newMFAUser("victim", "sub-victim")

	startLocalMFA := func(username string) string {
		t.Helper()
		resp, err := env.auth.Login(&identity.LoginRequest{Username: username, Password: password})
		if err != nil {
			t.Fatalf("%s 本地第一因子應通過: %v", username, err)
		}
		if !resp.MFARequired || resp.PendingToken == "" {
			t.Fatalf("%s 應進入第二階段，實得 %+v", username, resp)
		}
		return resp.PendingToken
	}

	// 正向控制：轉換前，同樣的 pending 以有效碼完成即可取得正式會話
	controlPending := startLocalMFA(control.Username)
	done, err := env.auth.VerifyMFALogin(&identity.MFAVerifyRequest{
		PendingToken: controlPending, Code: validTestCode(t)})
	if err != nil {
		t.Fatalf("轉換前的 MFA 完成應成功（前提不成立則本測試無意義）: %v", err)
	}
	if done.Token == "" || done.RefreshToken == "" {
		t.Fatalf("轉換前完成 MFA 應發出正式會話，實得 %+v", done)
	}

	// 待測：pending 已簽出，管理者隨後把帳號改為僅外部登入
	victimPending := startLocalMFA(victim.Username)
	if err := env.users.ConvertToExternalOnly(victim.ID, testActor); err != nil {
		t.Fatalf("改為僅外部登入: %v", err)
	}
	converted := reloadUser(t, db, victim.ID)
	if converted.Password != "" || !converted.ExternalCredential {
		t.Fatalf("轉換應清空密碼雜湊並標記外部化，實得 password=%q external=%v",
			converted.Password, converted.ExternalCredential)
	}

	resp, err := env.auth.VerifyMFALogin(&identity.MFAVerifyRequest{
		PendingToken: victimPending, Code: validTestCode(t)})
	if !errors.Is(err, identity.ErrMFAPendingTokenInvalid) {
		t.Errorf("轉換後的 MFA 完成 = %v, want identity.ErrMFAPendingTokenInvalid", err)
	}
	if resp != nil {
		t.Errorf("轉換後的 MFA 完成不得回傳任何會話，實得 %+v", resp)
	}
	// 全鏈斷言：整個流程不得為該帳號留下任何可用的長效憑證
	var live int64
	if err := db.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", victim.ID).Count(&live).Error; err != nil {
		t.Fatalf("統計未撤銷 refresh: %v", err)
	}
	if live != 0 {
		t.Errorf("轉換後該帳號不得有未撤銷的 refresh，實得 %d 筆", live)
	}
	if calls := env.tokens.userCalls(); len(calls) != 1 || calls[0] != victim.ID {
		t.Errorf("轉換應撤銷該帳號的錄影存取憑證 = %v, want [%d]", calls, victim.ID)
	}
}

// --- 4.14b 解綁的使用者級粒度 ---

// TestUnbindOneProviderRevokesUserWide 綁兩個 provider 的帳號解綁其一 →
// 該**使用者**的全部憑證／連線／訂閱失效（含經另一 provider 建立者），
// 重新登入後正常。
//
// 為什麼粒度是使用者而非 (使用者, provider)：解綁的動機是「這個身分不該再代表
// 這個人」，最常見的情境正是該身分已遭入侵。若只撤 provider A 那一份，攻擊者
// 早先用 A 登入時取得的會話固然沒了，但他若在被發現前也走過 B（或單純持有一條
// 經 B 建立的連線），那條路徑會完好無損地留下來——而管理者以為已經收回。
//
// **兩個 provider 的 auth_epoch 不得被推進**：解綁是使用者級動作，推進 provider
// 世代會把該 provider 底下**其他所有人**的憑證一起打掉。
func TestUnbindOneProviderRevokesUserWide(t *testing.T) {
	db := revMatrixDB(t)
	env := newRevMatrixEnv(t, db)
	p1 := seedProvider(t, db, func(p *model.OIDCProvider) {
		p.Name = "corp"
		p.Issuer = "https://idp-a.example.com"
		p.ClientID = "cid-a"
	})
	p2 := seedProvider(t, db, func(p *model.OIDCProvider) {
		p.Name = "okta"
		p.Issuer = "https://idp-b.example.com"
		p.ClientID = "cid-b"
	})

	// 憑證已外部化、綁兩個 provider（解綁其一仍剩一條登入途徑，故判準放行）
	dual := seedOIDCUser(t, db, "dual")
	idP1 := revMatrixBind(t, env, dual.ID, p1, "sub-dual-a")
	revMatrixBind(t, env, dual.ID, p2, "sub-dual-b")

	// 旁觀者：同樣經 p2 認證的另一個人，全程不得被牽連
	bystander := seedOIDCUser(t, db, "bystander")
	revMatrixBind(t, env, bystander.ID, p2, "sub-bystander")

	base1 := reloadProvider(t, db, p1.ID).AuthEpoch
	base2 := reloadProvider(t, db, p2.ID).AuthEpoch

	sessA := seedSession(t, db, dual.ID, p1.ID, base1, "sess-dual-a")
	sessB := seedSession(t, db, dual.ID, p2.ID, base2, "sess-dual-b")
	sessOther := seedSession(t, db, bystander.ID, p2.ID, base2, "sess-bystander")
	seedRefresh(t, db, dual.ID, p1.ID, "hash-dual-a")
	seedRefresh(t, db, dual.ID, p2.ID, "hash-dual-b")
	seedRefresh(t, db, bystander.ID, p2.ID, "hash-bystander")
	env.hub.join(dual.ID, p1.ID, "dual-monitor-a")
	env.hub.join(dual.ID, p2.ID, "dual-share-b") // 分享觀看與監看同一收線管道
	env.hub.join(bystander.ID, p2.ID, "bystander-monitor")

	// --- 只解綁 p1 那一筆 ---
	if err := env.users.UnbindExternalIdentity(dual.ID, idP1, testActor); err != nil {
		t.Fatalf("解綁 p1 身分應成功（仍剩 p2 一條登入途徑）: %v", err)
	}

	// 該使用者全部失效——包含經**另一個** provider 建立的那些
	if got := reloadUser(t, db, dual.ID).CredentialEpoch; got == 0 {
		t.Fatal("解綁應推進 credential_epoch（前提不成立則後續斷言無意義）")
	}
	for _, s := range []*model.Session{sessA, sessB} {
		got := reloadRevocationSession(t, db, s.ID)
		if got.Status != model.SessionStatusDisconnected {
			t.Errorf("會話 %s 應被終斷: status=%q", s.SessionID, got.Status)
		}
		if got.EndReason != model.EndReasonAdminTerminate {
			t.Errorf("會話 %s end_reason = %q, want %q", s.SessionID,
				got.EndReason, model.EndReasonAdminTerminate)
		}
	}
	for _, hash := range []string{"hash-dual-a", "hash-dual-b"} {
		r := reloadRefresh(t, db, hash)
		if r.RevokedAt == nil {
			t.Errorf("refresh %s 應被撤銷（使用者級粒度）", hash)
		} else if r.RevokedReason != model.RefreshRevokeCredentialEpoch {
			t.Errorf("refresh %s 撤銷成因 = %q, want %q", hash,
				r.RevokedReason, model.RefreshRevokeCredentialEpoch)
		}
	}
	if env.hub.alive("dual-monitor-a") || env.hub.alive("dual-share-b") {
		t.Errorf("該使用者的監看與分享訂閱應全數收線，存活集合 = %v", env.hub.aliveTags())
	}

	// 旁觀者與兩個 provider 皆不受影響
	if s := reloadRevocationSession(t, db, sessOther.ID); s.Status != model.SessionStatusActive {
		t.Errorf("旁觀者的會話不應被牽連: status=%q", s.Status)
	}
	if r := reloadRefresh(t, db, "hash-bystander"); r.RevokedAt != nil {
		t.Errorf("旁觀者的 refresh 不應被撤銷（成因 %q）", r.RevokedReason)
	}
	if !env.hub.alive("bystander-monitor") {
		t.Errorf("旁觀者的訂閱不應被收線，存活集合 = %v", env.hub.aliveTags())
	}
	if got := reloadProvider(t, db, p1.ID).AuthEpoch; got != base1 {
		t.Errorf("解綁是使用者級動作，不得推進 p1 的 auth_epoch: %d → %d", base1, got)
	}
	if got := reloadProvider(t, db, p2.ID).AuthEpoch; got != base2 {
		t.Errorf("解綁是使用者級動作，不得推進 p2 的 auth_epoch: %d → %d", base2, got)
	}

	// --- 重新登入後正常（剩下的 p2 身分仍是有效登入途徑） ---
	relogin := issueTestTicket(t, env.login, reloadUser(t, db, dual.ID), p2, "browser-secret")
	resp, _, err := env.login.Exchange(relogin, "browser-secret")
	if err != nil {
		t.Fatalf("經 p2 重新登入應成功: %v", err)
	}
	if resp.Token == "" || resp.RefreshToken == "" {
		t.Fatalf("重新登入應發出正式會話，實得 %+v", resp)
	}
	if _, err := env.auth.ValidateConnectionToken(resp.Token); err != nil {
		t.Errorf("重新登入後的 access 應可用: %v", err)
	}
	if _, err := env.auth.RefreshSession(resp.RefreshToken, ""); err != nil {
		t.Errorf("重新登入後的 refresh 應可輪替: %v", err)
	}
}
