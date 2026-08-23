package identity_test

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 並發不變式矩陣的**補缺格**。
//
// 4.14a 要求的格子與其覆蓋位置：
//
//	兩個 admin 並發停用／外部化 → 至多一個成功       既有 local_admin_invariant_test.go
//	兩筆外部身分並發各解綁一筆 → 至多一個成功       既有 external_identity_service_test.go
//	callback 隨機 state 洪水 → 寫入有界             既有 oidc_flow_capacity_test.go／oidc_abuse_guard
//	舊 grant「通過檢查後、建立前推進世代」（provider）既有 oidc_provider_revocation_test.go（PG）
//	舊觀察者 Join 同型競態（provider）              既有 oidc_provider_revocation_test.go（PG）
//	併發兌換洪水 vs 停用                            既有 oidc_provider_revocation_points_test.go（PG）
//	**進行中的 callback（簽 ticket 點）**            本檔（新增）
//	**交棒憑證兌換點**                              本檔（新增）
//	**user 世代版的三個同型競態**                    本檔（新增；既有全為 provider 世代版）
//	**監看與分享同測**                              本檔（新增）
//	**取鎖順序 system → provider → user 無死鎖**     本檔（新增）
//
// user 世代版為什麼不能靠 provider 版類推：兩者的撤銷側是**不同的鎖與不同的
// 收線管道**——provider 版由 identity.OIDCProviderService 於 provider 列鎖內推進
// auth_epoch 並掃描；user 版由 identity.UserService 於 user advisory lock 內推進
// credential_epoch，且收線走 TerminateAllByUser／DisconnectByUser（按-user）。
// 兩邊的鎖若有一邊漏持，另一邊的測試完全不會紅。
//
// **為什麼並發格子一律 pg-gated**：sqlite 是單寫者引擎，一個開著的寫交易就把
// 另一端擋到 busy_timeout，等於免費提供與鎖等價的互斥——把鎖拿掉，sqlite 版
// 仍然全綠（oidc_provider_revocation_test.go 已實測並記錄）。postgres 的 MVCC
// 沒有這個副作用，兩端唯一的序列化來源就是列鎖／advisory lock 本身。
// 例外是最後一支取鎖順序測試：死鎖只發生在真的「持有兩把鎖」的路徑上，
// sqlite 的 per-key mutex 正是該路徑，故它在 sqlite 上就有辨識力。
//
// 跑法（pg 格子）：
//
//	docker compose exec -T backend sh -c \
//	  'TEST_PG_DSN="host=postgres user=postgres password=postgres dbname=postgres port=5432 sslmode=disable" \
//	   go test ./internal/service -run TestPGConcurrent -race -v'

// --- pg fixture ---

const pgMatrixTestSchema = "oidc_matrix_test"

// matrixMigrate 比 revocationMigrate 多兩張表：交棒憑證與流程狀態
// （本檔的競態發生在簽 ticket 與兌換 ticket 兩個點上）
func matrixMigrate(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.RefreshToken{},
		&model.OIDCProvider{}, &model.UserExternalIdentity{}, &model.Session{},
		&model.OIDCLoginTicket{}, &model.OIDCFlowState{}, &model.SecurityPolicy{},
		&model.PasswordHistory{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// setupPGMatrixSchema 專用 schema（測前後 DROP CASCADE，可重複執行）。
// 不共用 oidc_race_test：兩檔的表集合不同，且共用會讓任一支的 cleanup
// 把另一支的資料一起 DROP（同包測試循序執行時仍屬不必要的耦合）
func setupPGMatrixSchema(t *testing.T, baseDSN string) string {
	t.Helper()
	admin := openPGLockDB(t, baseDSN)
	drop := "DROP SCHEMA IF EXISTS " + pgMatrixTestSchema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatalf("清理舊測試 schema 失敗: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + pgMatrixTestSchema).Error; err != nil {
		t.Fatalf("建立測試 schema 失敗: %v", err)
	}
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v",
				pgMatrixTestSchema, err)
		}
	})
	scoped := baseDSN + " search_path=" + pgMatrixTestSchema
	matrixMigrate(t, openPGLockDB(t, scoped))
	return scoped
}

// matrixEnv 兩個獨立連線池＝兩個後端副本：
// dbA 跑「產生新長效能力」的那一側（經 database.DB），dbB 跑管理端的撤銷動作。
// 跨副本序列化正是列鎖／advisory lock 存在的理由——行程內 mutex 對此完全無效
type matrixEnv struct {
	dbA, dbB *gorm.DB
	auth     *identity.AuthService
	login    *identity.OIDCLoginService
	users    *identity.UserService
	sessions *session.SessionService
	registry *revMatrixRegistry
	hub      *revMatrixHub
	tokens   *revMatrixTokens
}

func newPGMatrixEnv(t *testing.T) *matrixEnv {
	t.Helper()
	dsn := setupPGMatrixSchema(t, pgLockTestDSN(t))
	dbA := openPGLockDB(t, dsn)
	dbB := openPGLockDB(t, dsn)
	if name := dbA.Dialector.Name(); name != "postgres" {
		t.Fatalf("本測試必須跑在 postgres 分流，實得 dialect %q", name)
	}
	oldDB := database.DB
	database.DB = dbA
	t.Cleanup(func() { database.DB = oldDB })
	return newMatrixEnvOn(t, dbA, dbB)
}

// newMatrixEnvOn 以指定的兩個 *gorm.DB 組裝服務（pg 用兩個池，sqlite 用同一個）
func newMatrixEnvOn(t *testing.T, dbA, dbB *gorm.DB) *matrixEnv {
	t.Helper()
	auth := identity.NewAuthService("test-secret", 15*time.Minute)
	auth.SetSecurityPolicies(policy.NewSecurityPolicyService(dbA))

	providers := identity.NewOIDCProviderService(dbA, nil, testEgress(), nil, "https://bastion.example.com")
	login := identity.NewOIDCLoginService(dbA, providers, identity.NewOIDCDiscoveryService(testEgress()), auth, nil)
	login.SetAuditSinkForTest(newRecordingAudit())

	registry := &revMatrixRegistry{}
	env := &matrixEnv{
		dbA: dbA, dbB: dbB, auth: auth, login: login,
		users: identity.NewUserService(dbB, authz.NewAssetAuthorizationService(dbB)), sessions: session.NewSessionService(registry),
		registry: registry, hub: newRevMatrixHub(), tokens: &revMatrixTokens{},
	}
	env.users.SetOIDCAuditSinkForTest(newRecordingAudit())
	env.users.SetSessionTerminator(env.sessions)
	env.users.SetSubscriptionTerminator(env.hub)
	env.users.SetRecordingTokenRevoker(env.tokens)
	return env
}

// matrixProvider 直接落庫的啟用中 provider（不經 Create：本檔不測建立流程）
func matrixProvider(t *testing.T, db *gorm.DB, name, issuer, clientID string) *model.OIDCProvider {
	t.Helper()
	p := &model.OIDCProvider{
		Name: name, Issuer: issuer, ClientID: clientID, Scopes: "openid",
		AdmissionMode: model.AdmissionPreboundOnly, Enabled: true,
	}
	if err := db.Create(p).Error; err != nil {
		t.Fatalf("seed provider %s: %v", name, err)
	}
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).
		Update("enabled", true).Error; err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	return p
}

// matrixIdentityUser 綁兩筆外部身分的外部化帳號。
//
// **兩筆是刻意的**：解綁一筆之後仍剩一條登入途徑，故 UnbindExternalIdentity
// 的登入途徑判準會放行——只綁一筆時解綁會被 ErrLastLoginPath 擋下，
// 整組並發測試會因為撤銷側根本沒發生而恆綠
func matrixIdentityUser(t *testing.T, db *gorm.DB, username string,
	primary, spare *model.OIDCProvider) (*model.User, uint) {
	t.Helper()
	u := &model.User{
		Username: username, Password: "x", Active: true,
		ProvisioningOrigin: model.AuthSourceOIDC, ExternalCredential: true,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
	main := model.UserExternalIdentity{
		UserID: u.ID, ProviderID: primary.ID, Issuer: primary.Issuer,
		ClientID: primary.ClientID, Subject: "sub-" + username + "-primary",
	}
	if err := db.Create(&main).Error; err != nil {
		t.Fatalf("seed identity(primary) %s: %v", username, err)
	}
	if err := db.Create(&model.UserExternalIdentity{
		UserID: u.ID, ProviderID: spare.ID, Issuer: spare.Issuer,
		ClientID: spare.ClientID, Subject: "sub-" + username + "-spare",
	}).Error; err != nil {
		t.Fatalf("seed identity(spare) %s: %v", username, err)
	}
	return u, main.ID
}

// matrixUserGate 在指定同步點掛住呼叫者，直到 release 關閉或逾時。
//
// 逾時是必要的：序列化正確時另一邊會被鎖擋住而永遠等不到 release，
// 沒有逾時整個測試會死鎖而非通過
func matrixUserGate(t *testing.T, arrived chan<- struct{}, release <-chan struct{}) {
	t.Helper()
	var once sync.Once
	identity.SetUserCredentialPreWriteHookForTest(func() {
		once.Do(func() { close(arrived) })
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	})
	t.Cleanup(func() { identity.SetUserCredentialPreWriteHookForTest(nil) })
}

// matrixSiteGate 同 gateHook，但獨立一份以免與 revocation 檔的 t.Cleanup 互相清空
func matrixSiteGate(t *testing.T, site string, arrived chan<- struct{}, release <-chan struct{}) {
	t.Helper()
	var once sync.Once
	identity.SetPreWriteHookForTest(func(s string) {
		if s != site {
			return
		}
		once.Do(func() { close(arrived) })
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	})
	t.Cleanup(func() { identity.SetPreWriteHookForTest(nil) })
}

// matrixLiveRefreshCount 該使用者未撤銷的 refresh 列數
func matrixLiveRefreshCount(t *testing.T, db *gorm.DB, userID uint) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).Count(&n).Error; err != nil {
		t.Fatalf("統計未撤銷 refresh: %v", err)
	}
	return n
}

// --- 4.14a：進行中的 callback（簽 ticket 點）的 user 世代競態 ---

// TestPGConcurrentTicketIssueVsUnbind 進行中的 callback 於「鎖內前提通過、
// 寫入交棒憑證之前」，管理者解綁該使用者的外部身分。
//
// 既有的兩支 PG 並發測試打在 session_create 與 monitor_join 兩個點上，
// **簽 ticket 是第三個「以既有身分產生新長效能力」的點，且是使用者世代的第一個
// 攜帶者**（flow state 於 begin 時尚未認證，不帶 cred_epoch）。
// 該點若未序列化，序列
//
//	callback 鎖外讀到 cred_epoch=0 → 解綁推進至 1 並完成收線 → callback 才簽 ticket
//
// 會產出一張「解綁之後才誕生」的交棒憑證，而收線掃描早已跑完、掃不到它。
//
// 不變量與交錯無關：解綁完成後，該交棒憑證 SHALL NOT 兌換出可用的會話。
//
// **突變自檢**：拿掉 Exchange 內的 VerifyCredentialGenerationTx（世代比對），
// 本測試轉紅——ticket 帶著舊 cred_epoch 仍會被放行，兌換出一組完全可用的
// access／refresh，解綁等於沒做。
func TestPGConcurrentTicketIssueVsUnbind(t *testing.T) {
	env := newPGMatrixEnv(t)
	p := matrixProvider(t, env.dbA, "corp", "https://idp-a.example.com", "cid-a")
	spare := matrixProvider(t, env.dbA, "okta", "https://idp-b.example.com", "cid-b")
	user, identityID := matrixIdentityUser(t, env.dbA, "callbacker", p, spare)

	// 正向控制：解綁之前，同型交棒憑證確實可兌換
	// （少了它，「兌換失敗」無法排除「這條路本來就不通」）
	ctl := issueTestTicket(t, env.login, user, p, "browser-secret")
	if _, _, err := env.login.Exchange(ctl, "browser-secret"); err != nil {
		t.Fatalf("解綁前的兌換應成功: %v", err)
	}

	arrived := make(chan struct{})
	release := make(chan struct{})
	matrixSiteGate(t, identity.OIDCSiteTicketIssue, arrived, release)

	var wg sync.WaitGroup
	var ticket string
	var issueErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticket, issueErr = env.login.IssueTicketForTest(user, p, sha256Hex("browser-secret"), "/dashboard")
	}()

	<-arrived
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(release)
		if err := env.users.UnbindExternalIdentity(user.ID, identityID, testActor); err != nil {
			t.Errorf("解綁: %v", err)
		}
	}()
	wg.Wait()

	if got := reloadUser(t, env.dbA, user.ID).CredentialEpoch; got == 0 {
		t.Fatalf("解綁應推進 credential_epoch（前提不成立則本測試無意義），實得 %d", got)
	}
	// 兩種合法結局：簽發本身失敗，或簽出的憑證兌換必被世代閘拒。
	// 不合法的是「兌換成功並拿到可用會話」
	if issueErr != nil {
		return
	}
	resp, _, err := env.login.Exchange(ticket, "browser-secret")
	if err == nil {
		t.Fatalf("解綁後在途 callback 簽出的交棒憑證竟兌換成功（token=%q）——"+
			"簽 ticket 點未與解綁序列化，該憑證誕生於收線掃描之後、且不在任何掃描集合內",
			resp.Token)
	}
	if !errors.Is(err, identity.ErrOIDCTicketInvalid) {
		t.Errorf("兌換 = %v, want identity.ErrOIDCTicketInvalid", err)
	}
	if n := matrixLiveRefreshCount(t, env.dbA, user.ID); n != 0 {
		t.Errorf("解綁後該使用者不得留下未撤銷的 refresh，實得 %d 筆", n)
	}
}

// TestPGConcurrentTicketExchangeVsUnbind 交棒憑證兌換於「鎖內世代比對通過、
// 原子消費之前」，管理者解綁該使用者的外部身分。
//
// 兌換點是「以既有憑證產生新長效能力」的典型：它把一張一次性的 ticket 換成
// access ＋ refresh 一整組長效憑證。**簽出動作刻意在鎖外**（不讓 JWT 簽章這類
// CPU 工作進入持鎖區間），故本測試的不變量不是「refresh 列有沒有被撤」——
// 那一列可能誕生於撤銷掃描之後——而是**它不得可用**：憑證帶的是 ticket 上的
// 舊世代，每個驗證點都須拒絕它。
//
// **突變自檢**：拿掉 RefreshSession／ValidateConnectionToken 的世代閘，
// 本測試轉紅——解綁後兌換出的那一組憑證會完全可用。
func TestPGConcurrentTicketExchangeVsUnbind(t *testing.T) {
	env := newPGMatrixEnv(t)
	p := matrixProvider(t, env.dbA, "corp", "https://idp-a.example.com", "cid-a")
	spare := matrixProvider(t, env.dbA, "okta", "https://idp-b.example.com", "cid-b")
	user, identityID := matrixIdentityUser(t, env.dbA, "exchanger", p, spare)

	ticket := issueTestTicket(t, env.login, user, p, "browser-secret")

	arrived := make(chan struct{})
	release := make(chan struct{})
	matrixSiteGate(t, identity.OIDCSiteTicketExchange, arrived, release)

	var wg sync.WaitGroup
	var resp *identity.LoginResponse
	var exchangeErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, _, exchangeErr = env.login.Exchange(ticket, "browser-secret")
	}()

	<-arrived
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(release)
		if err := env.users.UnbindExternalIdentity(user.ID, identityID, testActor); err != nil {
			t.Errorf("解綁: %v", err)
		}
	}()
	wg.Wait()

	if got := reloadUser(t, env.dbA, user.ID).CredentialEpoch; got == 0 {
		t.Fatalf("解綁應推進 credential_epoch（前提不成立則本測試無意義），實得 %d", got)
	}
	if exchangeErr != nil {
		return // 兌換被鎖內世代重讀拒絕，合法結局之一
	}
	// 兌換成功時，換發的兩枚憑證都必須已失效
	if _, err := env.auth.ValidateConnectionToken(resp.Token); err == nil {
		t.Error("解綁後兌換出的 access 竟仍可開啟 WS 旁路連線——" +
			"該憑證帶舊世代，世代閘必須拒絕它")
	}
	if _, err := env.auth.RefreshSession(resp.RefreshToken); err == nil {
		t.Error("解綁後兌換出的 refresh 竟仍可輪替——" +
			"持有者可藉此無限續命，解綁等於沒做")
	}
}

// --- 4.14a：user 世代版的「舊 grant」與「舊觀察者」 ---

// TestPGConcurrentSessionCreateVsUnbind connect grant 兌換建 session 於
// 「鎖內世代重讀通過、插入之前」，管理者解綁該使用者的外部身分。
//
// 這是既有 TestPGConcurrentExchangeVsDisable 的 **user 世代版**。兩者的撤銷側
// 完全不同：provider 版走 identity.OIDCProviderService 的列鎖＋按-provider 掃描；
// user 版走 identity.UserService 的 advisory lock＋TerminateAllByUser（按-user）。
// user 版若漏持鎖，provider 版的測試一個都不會紅。
//
// 不變量：解綁完成後，該使用者名下不得有任何 active 會話——協議連線建立後
// 不再出示憑證，對世代完全免疫，逃過這一次掃描即永久存活。
//
// **突變自檢**：把 CreateWithGenerationGuard 的 identity.WithCapabilityLocks 換成
// database.DB.Transaction，本測試轉紅——解綁在副本 B 完成推進並跑完
// TerminateAllByUser（看不到副本 A 尚未提交的 INSERT），兌換隨後插入一筆
// active 會話並永久存活。
func TestPGConcurrentSessionCreateVsUnbind(t *testing.T) {
	env := newPGMatrixEnv(t)
	p := matrixProvider(t, env.dbA, "corp", "https://idp-a.example.com", "cid-a")
	spare := matrixProvider(t, env.dbA, "okta", "https://idp-b.example.com", "cid-b")
	user, identityID := matrixIdentityUser(t, env.dbA, "grantee", p, spare)

	// 解綁之前已建立的一筆會話：確保撤銷側真的有東西可掃，
	// 否則「零殘留」可能只證明了「一筆都沒建成」
	settled := seedSession(t, env.dbA, user.ID, p.ID, p.AuthEpoch, "sess-settled")

	arrived := make(chan struct{})
	release := make(chan struct{})
	matrixSiteGate(t, identity.OIDCSiteSessionCreate, arrived, release)

	assetID := uint(1)
	pid := p.ID
	racing := &model.Session{
		SessionID: "sess-user-race", UserID: user.ID, AssetID: &assetID,
		Protocol: model.ProtocolSSH, StartTime: time.Now(),
		AuthEpoch: p.AuthEpoch, AuthProviderID: &pid,
	}

	var wg sync.WaitGroup
	var createErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		createErr = env.sessions.CreateWithGenerationGuard(crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: p.ID,
			AuthEpoch: p.AuthEpoch, CredEpoch: 0,
		}, racing)
	}()

	<-arrived
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(release)
		if err := env.users.UnbindExternalIdentity(user.ID, identityID, testActor); err != nil {
			t.Errorf("解綁: %v", err)
		}
	}()
	wg.Wait()

	var lingering int64
	if err := env.dbA.Model(&model.Session{}).
		Where("user_id = ? AND status = ?", user.ID, model.SessionStatusActive).
		Count(&lingering).Error; err != nil {
		t.Fatalf("統計殘留會話: %v", err)
	}
	if lingering != 0 {
		t.Fatalf("解綁後仍有 %d 筆 active 會話殘留（createErr=%v）——"+
			"兌換與解綁未被 user 鎖序列化，該連線建立後不再出示憑證，將永久存活",
			lingering, createErr)
	}
	// 解綁前那一筆確實是被收線掃描終斷的（而非「剛好沒建成」）
	if s := reloadRevocationSession(t, env.dbA, settled.ID); s.EndReason != model.EndReasonAdminTerminate {
		t.Errorf("解綁前建立的會話須被掃描終斷: status=%q end_reason=%q", s.Status, s.EndReason)
	}
}

// TestPGConcurrentMonitorAndShareJoinVsUnbind 監看與分享觀看兩條唯讀訂閱同時
// 於「鎖內世代重讀通過、Join 之前」，管理者解綁該使用者的外部身分。
//
// **監看與分享同測**是 4.14a 明列的要求，理由是防「只改一處」：兩者在 handler
// 是兩個入口（HandleMonitor 與分享觀看），各自呼叫 JoinWithGenerationGuard，
// 落到同一個 hub；任一入口漏掛 guard，只測另一個就會全綠。
//
// 兩條訂閱的 providerID 刻意取不同值：監看者經 provider 認證（provider＋user
// 兩把鎖），分享觀看者為本地登入（providerID=0，**只有 user 這一把鎖可守**）。
// 本地那一條正是「user 世代鎖不可省」的唯一證人。
//
// 不變量：解綁完成後 hub 內該使用者的訂閱數為 0。
//
// **突變自檢**：把 JoinWithGenerationGuard 的 identity.WithCapabilityLocks 換成
// database.DB.Transaction，本測試轉紅——DisconnectByUser 先跑完，
// 兩條 Join 隨後建立的訂閱錯過收線且此後不再重驗任何憑證。
func TestPGConcurrentMonitorAndShareJoinVsUnbind(t *testing.T) {
	env := newPGMatrixEnv(t)
	p := matrixProvider(t, env.dbA, "corp", "https://idp-a.example.com", "cid-a")
	spare := matrixProvider(t, env.dbA, "okta", "https://idp-b.example.com", "cid-b")
	user, identityID := matrixIdentityUser(t, env.dbA, "watcher", p, spare)

	// 解綁前已存在的訂閱：確保收線側真的有東西可掃
	env.hub.join(user.ID, p.ID, "settled-monitor")

	arrived := make(chan struct{})
	release := make(chan struct{})
	matrixSiteGate(t, identity.OIDCSiteMonitorJoin, arrived, release)

	var wg sync.WaitGroup
	joinErrs := make([]error, 2)
	// (0) 監看：經 provider 認證 ／ (1) 分享觀看：本地登入（providerID=0）
	ctxs := []crypto.AuthContext{
		{AuthMethod: crypto.AuthMethodOIDC, ProviderID: p.ID, AuthEpoch: p.AuthEpoch},
		{AuthMethod: crypto.AuthMethodLocalPassword},
	}
	tags := []string{"racing-monitor", "racing-share"}
	for i := range ctxs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, joinErrs[i] = session.JoinWithGenerationGuard(ctxs[i], user.ID, func() bool {
				env.hub.join(user.ID, ctxs[i].ProviderID, tags[i])
				return true
			})
		}(i)
	}

	<-arrived
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(release)
		if err := env.users.UnbindExternalIdentity(user.ID, identityID, testActor); err != nil {
			t.Errorf("解綁: %v", err)
		}
	}()
	wg.Wait()

	if alive := env.hub.aliveTags(); len(alive) != 0 {
		t.Fatalf("解綁後仍有訂閱存活 %v（joinErrs=%v）——"+
			"Join 未持 user 鎖，訂閱錯過收線掃描且此後不再重驗任何憑證", alive, joinErrs)
	}
}

// --- 4.14a：取鎖順序 system → provider → user 無死鎖 ---

// TestCapabilityLockOrderingHasNoDeadlock 三個層級的鎖在**全部組合**同時競爭下
// 不得死鎖（取鎖順序項）。
//
// 固定順序是 system（local admin 不變式）→ provider（auth_epoch）→
// user（credential_epoch）。死鎖的成立條件是「兩條路徑以相反順序各持一把、
// 各等對方」，故必須讓所有組合真的同時在跑：
//
//	system → user            UnbindExternalIdentityAndDisable／ConvertToExternalOnly
//	provider                 provider 停用／啟用（identity.WithOIDCProviderLock）
//	provider → user          連線兌換建 session／訂閱 Join／refresh 輪替
//	system → provider → user 三者疊加（identity.WithLocalAdminInvariant 內再取兩把）
//
// **本支刻意跑 sqlite 且 fn 一律為 no-op**：死鎖只發生在真的「同時持有兩把以上」
// 的實作上，sqlite 路徑用的是 per-key sync.Mutex——某條路徑的取鎖順序寫反即
// **確定性**互鎖，而 postgres 會偵測死鎖並讓其中一方報錯（那條由下方的
// TestPGConcurrentCapabilityLockOrdering 以真實服務操作覆蓋）。
//
// fn 內不做任何寫入是刻意的：一旦加入寫入，sqlite 的單寫者引擎會讓每次碰撞都
// 塞到 busy_timeout（實測六種形狀 × 3 波即耗時 20 秒），那是**壅塞而非死鎖**，
// 會把本測試的訊號淹掉並讓 watchdog 變成計時器賭博。取鎖順序的正確性只取決於
// 取鎖動作本身，與鎖內做什麼無關。
//
// 兩個使用者 × 兩個 provider 交叉配對：單一 (user, provider) 配對下所有 goroutine
// 取的是同兩把鎖，順序寫反也只會排隊而不會互鎖，測不出東西。
//
// **突變自檢**：把 lockCapabilityKeys 的取鎖順序改成 user → provider
// （只改這一處，withCapabilityLocksTx 的 pg 分支與 design 文件維持 provider → user），
// 本測試在 watchdog 逾時後轉紅。
func TestCapabilityLockOrderingHasNoDeadlock(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "lockorder.db") + "?_pragma=busy_timeout(5000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	// 多條連線：單連線會把一切 DB 存取序列化，goroutine 根本疊不起來
	sqlDB.SetMaxOpenConns(8)
	matrixMigrate(t, db)
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS user_roles (
		user_id INTEGER NOT NULL, role_id INTEGER NOT NULL)`).Error; err != nil {
		t.Fatalf("user_roles: %v", err)
	}
	if err := db.Create(&model.Role{Name: model.RoleAdmin}).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	providers := []*model.OIDCProvider{
		matrixProvider(t, db, "p1", "https://idp-1.example.com", "cid-1"),
		matrixProvider(t, db, "p2", "https://idp-2.example.com", "cid-2"),
	}
	users := make([]*model.User, 2)
	for i := range users {
		u := &model.User{
			Username: fmt.Sprintf("racer-%d", i), Password: "x", Active: true,
			ProvisioningOrigin: model.AuthSourceOIDC, ExternalCredential: true,
		}
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("seed user %d: %v", i, err)
		}
		users[i] = u
	}

	// 六種取鎖形狀，涵蓋 production 每一條持鎖路徑的**取鎖順序**（fn 一律 no-op，
	// 見上方說明）。只跑得起來即可，不斷言個別操作的成敗——斷言對象是**活性**
	noop := func(tx *gorm.DB) error { return nil }
	const rounds = 40
	ops := []func(u *model.User, p *model.OIDCProvider){
		// provider → user（連線兌換建 session／訂閱 Join／refresh 輪替的共同入口）
		func(u *model.User, p *model.OIDCProvider) {
			_ = identity.WithCapabilityLocks(db, p.ID, u.ID, noop)
		},
		// provider → user（反向配對，加大交錯壓力）
		func(u *model.User, p *model.OIDCProvider) {
			_ = identity.WithCapabilityLocks(db, p.ID, u.ID, noop)
		},
		// provider 單獨（管理端停用／啟用／密鑰輪替）
		func(u *model.User, p *model.OIDCProvider) {
			_ = identity.WithOIDCProviderLock(db, p.ID, noop)
		},
		// user 單獨（解綁判準與世代推進）
		func(u *model.User, p *model.OIDCProvider) {
			_ = identity.WithUserCredentialLock(db, u.ID, noop)
		},
		// system → user（解綁＋停用／改為僅外部登入）
		func(u *model.User, p *model.OIDCProvider) {
			_ = identity.WithLocalAdminInvariant(db, u.ID, func(tx *gorm.DB) error {
				return identity.WithUserCredentialLockTxForTest(tx, u.ID, noop)
			})
		},
		// system → provider → user（三者疊加的完整順序）
		func(u *model.User, p *model.OIDCProvider) {
			_ = identity.WithLocalAdminInvariant(db, u.ID, func(tx *gorm.DB) error {
				return identity.WithCapabilityLocksTxForTest(tx, p.ID, u.ID, noop)
			})
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 逐波推進（每波 = 六種取鎖形狀各一個 goroutine，波內並發、波間等待）。
		// 一次灑出數百個 goroutine 只會讓 sqlite 的單寫者排隊塞到 busy_timeout，
		// 那是壅塞不是死鎖——測不出取鎖順序，卻會穩定逾時
		for r := 0; r < rounds; r++ {
			var wg sync.WaitGroup
			for oi, op := range ops {
				// 交叉配對：不同 goroutine 取到不同的 (user, provider) 組合，
				// 順序寫反才會真的互鎖而非單純排隊
				u := users[(r+oi)%len(users)]
				p := providers[(r+oi/2)%len(providers)]
				wg.Add(1)
				go func(op func(*model.User, *model.OIDCProvider), u *model.User, p *model.OIDCProvider) {
					defer wg.Done()
					op(u, p)
				}(op, u, p)
			}
			wg.Wait()
		}
	}()

	// watchdog：死鎖時 goroutine 永遠不會回來，沒有它測試會卡到 go test 的全域逾時
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("取鎖順序疑似死鎖：system → provider → user 的混合並發在 30 秒內未跑完")
	}
}

// TestPGConcurrentCapabilityLockOrdering 同上，但跑在 postgres 且以**真實服務操作**
// 施壓（取鎖順序項；上一支的互補面）。
//
// 兩支的分工：上一支跑 sqlite、fn 為 no-op，驗的是**取鎖動作的順序**本身
// （per-key mutex 下順序寫反即確定性互鎖）；本支跑 postgres、fn 為真的會寫入的
// production 路徑，驗的是「同時持有 advisory lock／列鎖並且真的在寫」時
// **資料庫層不回報死鎖**。postgres 會主動偵測死鎖並讓其中一方以 SQLSTATE 40P01
// 失敗，故本支不必靠 watchdog 猜——死鎖會以明確錯誤現形。
//
// watchdog 仍保留為第二道防線（advisory lock 是阻塞式的，互等時 postgres 的
// 死鎖偵測器若因跨連線池而看不見完整等待圖，會表現為純粹的卡住）。
func TestPGConcurrentCapabilityLockOrdering(t *testing.T) {
	env := newPGMatrixEnv(t)
	if err := env.dbA.Create(&model.Role{Name: model.RoleAdmin}).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	providers := []*model.OIDCProvider{
		matrixProvider(t, env.dbA, "p1", "https://idp-1.example.com", "cid-1"),
		matrixProvider(t, env.dbA, "p2", "https://idp-2.example.com", "cid-2"),
	}
	users := make([]*model.User, 2)
	for i := range users {
		u := &model.User{
			Username: fmt.Sprintf("pgracer-%d", i), Password: "x", Active: true,
			ProvisioningOrigin: model.AuthSourceOIDC, ExternalCredential: true,
		}
		if err := env.dbA.Create(u).Error; err != nil {
			t.Fatalf("seed user %d: %v", i, err)
		}
		users[i] = u
	}

	var mu sync.Mutex
	var failures []error
	record := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		failures = append(failures, err)
	}

	// 真實路徑：兌換建 session（provider → user，含 INSERT）、訂閱 Join
	//（provider → user，唯讀）、system → user、system → provider → user
	ops := []func(u *model.User, p *model.OIDCProvider){
		func(u *model.User, p *model.OIDCProvider) {
			assetID := uint(1)
			pid := p.ID
			record(env.sessions.CreateWithGenerationGuard(crypto.AuthContext{
				AuthMethod: crypto.AuthMethodOIDC, ProviderID: p.ID, AuthEpoch: p.AuthEpoch,
			}, &model.Session{
				SessionID: fmt.Sprintf("s-%d-%d-%d", u.ID, p.ID, time.Now().UnixNano()),
				UserID:    u.ID, AssetID: &assetID, Protocol: model.ProtocolSSH,
				StartTime: time.Now(), AuthEpoch: p.AuthEpoch, AuthProviderID: &pid,
			}))
		},
		func(u *model.User, p *model.OIDCProvider) {
			_, err := session.JoinWithGenerationGuard(crypto.AuthContext{
				AuthMethod: crypto.AuthMethodOIDC, ProviderID: p.ID, AuthEpoch: p.AuthEpoch,
			}, u.ID, func() bool { return true })
			record(err)
		},
		func(u *model.User, p *model.OIDCProvider) {
			record(identity.WithOIDCProviderLock(env.dbB, p.ID, func(tx *gorm.DB) error {
				return tx.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).
					Update("scopes", "openid").Error
			}))
		},
		func(u *model.User, p *model.OIDCProvider) {
			record(identity.WithUserCredentialLock(env.dbB, u.ID, func(tx *gorm.DB) error {
				return tx.Model(&model.User{}).Where("id = ?", u.ID).
					Update("full_name", "racer").Error
			}))
		},
		func(u *model.User, p *model.OIDCProvider) {
			record(identity.WithLocalAdminInvariant(env.dbB, u.ID, func(tx *gorm.DB) error {
				return identity.WithUserCredentialLockTxForTest(tx, u.ID, func(tx *gorm.DB) error {
					return tx.Model(&model.User{}).Where("id = ?", u.ID).
						Update("full_name", "racer2").Error
				})
			}))
		},
		func(u *model.User, p *model.OIDCProvider) {
			record(identity.WithLocalAdminInvariant(env.dbA, u.ID, func(tx *gorm.DB) error {
				return identity.WithCapabilityLocksTxForTest(tx, p.ID, u.ID, func(tx *gorm.DB) error {
					return tx.Model(&model.User{}).Where("id = ?", u.ID).
						Update("full_name", "racer3").Error
				})
			}))
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 逐波推進：波內六種形狀並發、波間等待（避免把壓力測試變成連線池飢餓）
		for r := 0; r < 20; r++ {
			var wg sync.WaitGroup
			for oi, op := range ops {
				u := users[(r+oi)%len(users)]
				p := providers[(r+oi/2)%len(providers)]
				wg.Add(1)
				go func(op func(*model.User, *model.OIDCProvider), u *model.User, p *model.OIDCProvider) {
					defer wg.Done()
					op(u, p)
				}(op, u, p)
			}
			wg.Wait()
		}
	}()

	select {
	case <-done:
	case <-time.After(25 * time.Second):
		t.Fatal("取鎖順序疑似死鎖：system → provider → user 的混合並發在 25 秒內未跑完")
	}

	// 唯一不可接受的錯誤是資料庫回報的死鎖（SQLSTATE 40P01）。
	// 其他錯誤（世代過期、帳號狀態）屬並發下的正常結局，不在本測試的斷言範圍
	for _, err := range failures {
		if strings.Contains(strings.ToLower(err.Error()), "deadlock") {
			t.Fatalf("取鎖順序造成資料庫死鎖: %v", err)
		}
	}
}
