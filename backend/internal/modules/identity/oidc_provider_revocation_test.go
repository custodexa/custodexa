package identity_test

import (
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
	"path/filepath"
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

// provider 停用／刪除的全面失效與序列化。
//
// 覆蓋兩類斷言：
//
//	靜態  停用與刪除各自觸發五條管道，且混合帳號的本地會話／本地 refresh 不受牽連
//	並發 「兌換 vs 停用」與「Join vs 停用」——AST 守衛封不住這兩個競態，
//	      只能靠在鎖內同步點製造精確交錯的並發測試
//
// 並發測試的突變自檢方式（拿掉序列化即應轉紅）記於各測試的註解。

// --- fixture ---

func revocationMigrate(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.RefreshToken{},
		&model.OIDCProvider{}, &model.UserExternalIdentity{}, &model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// revocationDB 單連線 :memory:（靜態斷言用；ff51836 的連線池假紅防護）
func revocationDB(t *testing.T) *gorm.DB {
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
	revocationMigrate(t, db)
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// revocationConcurrentDB 檔案型 sqlite ＋兩條連線（並發交錯用）。
//
// 理由同 extIdentityConcurrentDB：單連線會把兩個 goroutine 的一切 DB 存取序列化，
// 使突變（拿掉 provider 鎖）看似仍然安全——那樣的測試沒有辨識力
func revocationConcurrentDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "revocation.db") + "?_pragma=busy_timeout(5000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(2)
	revocationMigrate(t, db)
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// fakeRegistry 記錄「哪些 session 的 WS 被實際關閉」（鎖外收線的觀測點）
type fakeRegistry struct {
	mu     sync.Mutex
	closed []uint
}

func (f *fakeRegistry) Close(sessionID uint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = append(f.closed, sessionID)
	return nil
}

func (f *fakeRegistry) closedIDs() []uint {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint(nil), f.closed...)
}

// fakeProviderHub 唯讀訂閱的最小模型：真的持有一組觀察者，
// 使「訂閱有沒有逃過掃描」可用集合是否清空來斷言（而非只看有沒有呼叫過）
type fakeProviderHub struct {
	mu        sync.Mutex
	observers map[uint][]uint // providerID → observer 序號
	sweeps    []uint
	seq       uint
}

func newFakeProviderHub() *fakeProviderHub {
	return &fakeProviderHub{observers: map[uint][]uint{}}
}

func (h *fakeProviderHub) join(providerID uint) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	h.observers[providerID] = append(h.observers[providerID], h.seq)
	return true
}

func (h *fakeProviderHub) DisconnectByProvider(providerID uint) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweeps = append(h.sweeps, providerID)
	n := len(h.observers[providerID])
	delete(h.observers, providerID)
	return n
}

func (h *fakeProviderHub) remaining(providerID uint) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.observers[providerID])
}

func (h *fakeProviderHub) sweptProviders() []uint {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]uint(nil), h.sweeps...)
}

// fakeProviderTokenRevoker 錄影 token 的按-provider 撤銷觀測點
type fakeProviderTokenRevoker struct {
	mu    sync.Mutex
	calls []uint
}

func (f *fakeProviderTokenRevoker) RevokeByProvider(providerID uint) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, providerID)
	return 1
}

func (f *fakeProviderTokenRevoker) called() []uint {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint(nil), f.calls...)
}

type revocationEnv struct {
	svc      *identity.OIDCProviderService
	sessions *session.SessionService
	registry *fakeRegistry
	hub      *fakeProviderHub
	tokens   *fakeProviderTokenRevoker
	db       *gorm.DB
}

func newRevocationEnv(t *testing.T, db *gorm.DB) *revocationEnv {
	t.Helper()
	registry := &fakeRegistry{}
	env := &revocationEnv{
		svc:      identity.NewOIDCProviderService(db, nil, testEgress(), nil, "https://bastion.example.com"),
		sessions: session.NewSessionService(registry),
		registry: registry,
		hub:      newFakeProviderHub(),
		tokens:   &fakeProviderTokenRevoker{},
		db:       db,
	}
	// 真 SessionService（而非假的）：MarkTerminatedByProvider 的 SQL 條件
	//（auth_provider_id 命中、status=active、CAS）本身就是被測對象之一
	env.svc.SetSessionTerminator(env.sessions)
	env.svc.SetSubscriptionTerminator(env.hub)
	env.svc.SetRecordingTokenRevoker(env.tokens)
	return env
}

func seedRevocationUser(t *testing.T, db *gorm.DB, username string) *model.User {
	t.Helper()
	u := &model.User{Username: username, Password: "x", Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

func seedRevocationProvider(t *testing.T, env *revocationEnv, clientID string) *identity.OIDCProviderDTO {
	t.Helper()
	dto, err := env.svc.Create(providerReq(func(r *identity.OIDCProviderRequest) {
		r.ClientID = clientID
	}))
	if err != nil {
		t.Fatalf("Create provider: %v", err)
	}
	return dto
}

// seedSession 建一筆進行中會話；providerID 為 0 時寫 NULL（本地登入語義）
func seedSession(t *testing.T, db *gorm.DB, userID, providerID uint, epoch int, tag string) *model.Session {
	t.Helper()
	assetID := uint(1)
	s := &model.Session{
		SessionID: tag, UserID: userID, AssetID: &assetID,
		Protocol: model.ProtocolSSH, Status: model.SessionStatusActive,
		StartTime: time.Now().Add(-time.Minute), AuthEpoch: epoch,
	}
	if providerID != 0 {
		pid := providerID
		s.AuthProviderID = &pid
	}
	if err := db.Create(s).Error; err != nil {
		t.Fatalf("seed session %s: %v", tag, err)
	}
	return s
}

func seedRefresh(t *testing.T, db *gorm.DB, userID, providerID uint, hash string) *model.RefreshToken {
	t.Helper()
	now := time.Now()
	r := &model.RefreshToken{
		UserID: userID, TokenHash: hash,
		SessionStartedAt: now, ExpiresAt: now.Add(time.Hour), LastUsedAt: now,
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: providerID,
	}
	if providerID == 0 {
		r.AuthMethod = crypto.AuthMethodLocalPassword
	}
	if err := db.Create(r).Error; err != nil {
		t.Fatalf("seed refresh %s: %v", hash, err)
	}
	return r
}

func reloadRevocationSession(t *testing.T, db *gorm.DB, id uint) *model.Session {
	t.Helper()
	var s model.Session
	if err := db.First(&s, id).Error; err != nil {
		t.Fatalf("reload session %d: %v", id, err)
	}
	return &s
}

func reloadRefresh(t *testing.T, db *gorm.DB, hash string) *model.RefreshToken {
	t.Helper()
	var r model.RefreshToken
	if err := db.Where("token_hash = ?", hash).First(&r).Error; err != nil {
		t.Fatalf("reload refresh %s: %v", hash, err)
	}
	return &r
}

// --- 3.8 靜態斷言：停用與刪除各自觸發五條管道 ---

// assertFiveChannels 五條管道的共用斷言（停用與刪除走同一套，故斷言亦同一份）
func assertFiveChannels(t *testing.T, env *revocationEnv, dto *identity.OIDCProviderDTO,
	baseEpoch int, oidcSess, localSess *model.Session, oidcHash, localHash string) {
	t.Helper()

	// (1) auth_epoch 推進——其餘四條的前提
	after := reloadProvider(t, env.db, dto.ID)
	if after.AuthEpoch <= baseEpoch {
		t.Errorf("auth_epoch 未推進: %d → %d", baseEpoch, after.AuthEpoch)
	}

	// (2) 該 provider 的 refresh 全數撤銷，成因可稽核
	r := reloadRefresh(t, env.db, oidcHash)
	if r.RevokedAt == nil {
		t.Error("該 provider 的 refresh 憑證未被撤銷")
	} else if r.RevokedReason != model.RefreshRevokeProviderDisabled {
		t.Errorf("撤銷成因 = %q, want %q", r.RevokedReason, model.RefreshRevokeProviderDisabled)
	}
	// 混合帳號的本地 refresh 不得被牽連（provider_id=0 不是萬用字元）
	if lr := reloadRefresh(t, env.db, localHash); lr.RevokedAt != nil {
		t.Errorf("本地登入的 refresh 不應被 provider 失效牽連（成因 %q）", lr.RevokedReason)
	}

	// (3) 該 provider 的進行中協議會話被終斷
	s := reloadRevocationSession(t, env.db, oidcSess.ID)
	if s.Status != model.SessionStatusDisconnected {
		t.Errorf("provider 會話狀態 = %q, want %q", s.Status, model.SessionStatusDisconnected)
	}
	if s.EndReason != model.EndReasonAdminTerminate {
		t.Errorf("provider 會話 end_reason = %q, want %q", s.EndReason, model.EndReasonAdminTerminate)
	}
	// 鎖外收線確有執行（實際關 WS）
	closed := env.registry.closedIDs()
	if len(closed) != 1 || closed[0] != oidcSess.ID {
		t.Errorf("鎖外關閉的 sessionID = %v, want [%d]", closed, oidcSess.ID)
	}
	// 同一使用者以本地密碼建立的會話不受牽連（混合帳號）
	if ls := reloadRevocationSession(t, env.db, localSess.ID); ls.Status != model.SessionStatusActive {
		t.Errorf("本地會話不應被 provider 失效牽連: status=%q", ls.Status)
	}

	// (4) 唯讀訂閱按 provider 收線（不建 sessions 列，會話掃描掃不到）
	if swept := env.hub.sweptProviders(); len(swept) != 1 || swept[0] != dto.ID {
		t.Errorf("訂閱收線 = %v, want [%d]", swept, dto.ID)
	}

	// (5) 錄影 token 按 provider 撤銷（in-memory、不做世代比對）
	if calls := env.tokens.called(); len(calls) != 1 || calls[0] != dto.ID {
		t.Errorf("錄影 token 撤銷 = %v, want [%d]", calls, dto.ID)
	}
}

// Scenario: provider 停用觸發全面失效
func TestProviderDisableTriggersAllFiveChannels(t *testing.T) {
	db := revocationDB(t)
	env := newRevocationEnv(t, db)
	dto := seedRevocationProvider(t, env, "cid-disable")
	base := reloadProvider(t, db, dto.ID).AuthEpoch
	u := seedRevocationUser(t, db, "mixed")

	oidcSess := seedSession(t, db, u.ID, dto.ID, base, "sess-oidc")
	localSess := seedSession(t, db, u.ID, 0, 0, "sess-local")
	seedRefresh(t, db, u.ID, dto.ID, "hash-oidc")
	seedRefresh(t, db, u.ID, 0, "hash-local")

	if _, err := env.svc.Update(dto.ID, &identity.OIDCProviderRequest{Enabled: boolPtr(false)}); err != nil {
		t.Fatalf("停用: %v", err)
	}
	assertFiveChannels(t, env, dto, base, oidcSess, localSess, "hash-oidc", "hash-local")
}

// Scenario: provider 刪除亦走全套（design 行 64）——**刪除不走則殘留連線永久
// 失去按 provider 收線的途徑**，因為軟刪後管理端再也無從對該 provider 下指令
func TestProviderDeleteTriggersAllFiveChannels(t *testing.T) {
	db := revocationDB(t)
	env := newRevocationEnv(t, db)
	dto := seedRevocationProvider(t, env, "cid-delete")
	base := reloadProvider(t, db, dto.ID).AuthEpoch
	u := seedRevocationUser(t, db, "mixed")

	oidcSess := seedSession(t, db, u.ID, dto.ID, base, "sess-oidc")
	localSess := seedSession(t, db, u.ID, 0, 0, "sess-local")
	seedRefresh(t, db, u.ID, dto.ID, "hash-oidc")
	seedRefresh(t, db, u.ID, 0, "hash-local")

	if err := env.svc.Delete(dto.ID); err != nil {
		t.Fatalf("刪除: %v", err)
	}
	// reloadProvider 走 Unscoped，軟刪後仍可觀測世代
	assertFiveChannels(t, env, dto, base, oidcSess, localSess, "hash-oidc", "hash-local")
	if p := reloadProvider(t, db, dto.ID); p.DeletedAt.Time.IsZero() {
		t.Error("provider 應已軟刪")
	}
}

// Scenario: 密鑰輪替同樣走全套（spec：輪替的動機是舊密鑰可能已洩漏）
func TestProviderSecretRotationTriggersRevocation(t *testing.T) {
	db := revocationDB(t)
	env := newRevocationEnv(t, db)
	dto := seedRevocationProvider(t, env, "cid-rotate")
	base := reloadProvider(t, db, dto.ID).AuthEpoch
	u := seedRevocationUser(t, db, "mixed")

	oidcSess := seedSession(t, db, u.ID, dto.ID, base, "sess-oidc")
	localSess := seedSession(t, db, u.ID, 0, 0, "sess-local")
	seedRefresh(t, db, u.ID, dto.ID, "hash-oidc")
	seedRefresh(t, db, u.ID, 0, "hash-local")

	if _, err := env.svc.Update(dto.ID, &identity.OIDCProviderRequest{ClientSecret: "rotated"}); err != nil {
		t.Fatalf("輪替: %v", err)
	}
	assertFiveChannels(t, env, dto, base, oidcSess, localSess, "hash-oidc", "hash-local")
	// 輪替不停用：provider 仍可用（與停用的差別只在 enabled）
	if p := reloadProvider(t, db, dto.ID); !p.Enabled {
		t.Error("密鑰輪替不應順帶停用 provider")
	}
}

// Scenario: 停用不得牽連其他 provider（跨 provider 隔離）
func TestProviderDisableDoesNotTouchOtherProviders(t *testing.T) {
	db := revocationDB(t)
	env := newRevocationEnv(t, db)
	victim := seedRevocationProvider(t, env, "cid-victim")
	other := seedRevocationProvider(t, env, "cid-other")
	otherBase := reloadProvider(t, db, other.ID).AuthEpoch
	u := seedRevocationUser(t, db, "u1")

	otherSess := seedSession(t, db, u.ID, other.ID, otherBase, "sess-other")
	seedRefresh(t, db, u.ID, other.ID, "hash-other")

	if _, err := env.svc.Update(victim.ID, &identity.OIDCProviderRequest{Enabled: boolPtr(false)}); err != nil {
		t.Fatalf("停用: %v", err)
	}
	if p := reloadProvider(t, db, other.ID); p.AuthEpoch != otherBase {
		t.Errorf("他 provider 世代不應被推進: %d → %d", otherBase, p.AuthEpoch)
	}
	if s := reloadRevocationSession(t, db, otherSess.ID); s.Status != model.SessionStatusActive {
		t.Errorf("他 provider 的會話不應被終斷: status=%q", s.Status)
	}
	if r := reloadRefresh(t, db, "hash-other"); r.RevokedAt != nil {
		t.Error("他 provider 的 refresh 不應被撤銷")
	}
}

// --- 3.8a／3.8b 並發：AST 守衛封不住的兩個競態 ---

// gateHook 在指定同步點掛住呼叫者，直到 release 關閉或逾時。
//
// 逾時是**必要**的：序列化正確時，另一邊會被鎖擋住而永遠等不到 release，
// 沒有逾時整個測試就會死鎖而非通過
func gateHook(t *testing.T, site string, arrived chan<- struct{}, release <-chan struct{}) {
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

// TestConcurrentConnectExchangeVsProviderDisable 兌換建 session vs provider 停用。
//
// design 行 266 的序列：兌換讀到 epoch=7 → 停用推進至 8 並完成 session 掃描終斷 →
// 兌換才插入 epoch=7 的 session。該連線既不在掃描集合內，協議連線建立後又沒有
// 任何持續的 token 檢查，於是**永久存活**。
//
// 交錯由 identity.OIDCSiteSessionCreate 同步點製造：兌換在「鎖內重讀通過、插入之前」停住，
// 停用於此時發動。序列化正確時停用被 provider 鎖擋住，兌換插入後才輪到它掃描，
// 於是那筆 session 落在掃描集合內。
//
// **突變自檢**：把 SessionService.CreateWithGenerationGuard 的 identity.WithCapabilityLocks
// 換成 database.DB.Transaction（即拿掉鎖），本測試轉紅——停用會在兌換插入前
// 掃完，留下一筆 active 的殘留會話。
func TestConcurrentConnectExchangeVsProviderDisable(t *testing.T) {
	db := revocationConcurrentDB(t)
	env := newRevocationEnv(t, db)
	dto := seedRevocationProvider(t, env, "cid-race")
	base := reloadProvider(t, db, dto.ID).AuthEpoch
	u := seedRevocationUser(t, db, "racer")

	arrived := make(chan struct{})
	release := make(chan struct{})
	gateHook(t, identity.OIDCSiteSessionCreate, arrived, release)

	assetID := uint(1)
	sess := &model.Session{
		SessionID: "sess-race", UserID: u.ID, AssetID: &assetID,
		Protocol: model.ProtocolSSH, StartTime: time.Now(), AuthEpoch: base,
	}
	pid := dto.ID
	sess.AuthProviderID = &pid

	var wg sync.WaitGroup
	var createErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		createErr = env.sessions.CreateWithGenerationGuard(crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: dto.ID,
			AuthEpoch: base, CredEpoch: 0,
		}, sess)
	}()

	<-arrived
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(release)
		if _, err := env.svc.Update(dto.ID, &identity.OIDCProviderRequest{Enabled: boolPtr(false)}); err != nil {
			t.Errorf("停用: %v", err)
		}
	}()
	wg.Wait()

	// 兩種合法結局：兌換先成功但隨即被掃描終斷，或兌換本身被世代閘拒。
	// **不合法的是「session 建立成功且仍 active」**
	var lingering int64
	if err := db.Model(&model.Session{}).
		Where("auth_provider_id = ? AND status = ?", dto.ID, model.SessionStatusActive).
		Count(&lingering).Error; err != nil {
		t.Fatalf("統計殘留會話: %v", err)
	}
	if lingering != 0 {
		t.Fatalf("停用後仍有 %d 筆 active 會話殘留（createErr=%v）——"+
			"兌換與停用未被 provider 列鎖序列化，該連線將永久存活", lingering, createErr)
	}
}

// TestConcurrentMonitorJoinVsProviderDisable 訂閱 Join vs provider 停用。
//
// design 行 263 的序列：OIDC 觀察者通過 epoch 檢查後暫停 → admin 停用 provider
// 並掃完既有訂閱 → 舊請求才完成 Join。該訂閱**錯過掃描**，且訂閱建立後不再重驗
// token，可持續讀取他人終端內容。
//
// **突變自檢**：把 JoinWithGenerationGuard 的 identity.WithCapabilityLocks 換成
// database.DB.Transaction（或把 providerID 傳 0 使 provider 鎖不生效），
// 本測試轉紅——收線掃描會發生在 Join 之前，事後 hub 仍留著一個觀察者。
func TestConcurrentMonitorJoinVsProviderDisable(t *testing.T) {
	db := revocationConcurrentDB(t)
	env := newRevocationEnv(t, db)
	dto := seedRevocationProvider(t, env, "cid-join-race")
	base := reloadProvider(t, db, dto.ID).AuthEpoch
	observer := seedRevocationUser(t, db, "watcher")

	arrived := make(chan struct{})
	release := make(chan struct{})
	gateHook(t, identity.OIDCSiteMonitorJoin, arrived, release)

	var wg sync.WaitGroup
	var joined bool
	var joinErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		joined, joinErr = session.JoinWithGenerationGuard(crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: dto.ID,
			AuthEpoch: base, CredEpoch: 0,
		}, observer.ID, func() bool { return env.hub.join(dto.ID) })
	}()

	<-arrived
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(release)
		if _, err := env.svc.Update(dto.ID, &identity.OIDCProviderRequest{Enabled: boolPtr(false)}); err != nil {
			t.Errorf("停用: %v", err)
		}
	}()
	wg.Wait()

	if n := env.hub.remaining(dto.ID); n != 0 {
		t.Fatalf("停用後仍有 %d 個訂閱存活（joined=%v joinErr=%v）——"+
			"Join 未持 provider 鎖，訂閱錯過收線掃描且此後不再重驗", n, joined, joinErr)
	}
}

// TestProviderLockRejectsUnknownDialect 未知 dialect fail-close。
// 靜默退化為行程內鎖會使多副本部署失去序列化保護而毫無徵兆
func TestProviderLockRejectsUnknownDialect(t *testing.T) {
	db := revocationDB(t)
	fake := db.Session(&gorm.Session{})
	fake.Config.Dialector = unknownDialector{Dialector: db.Dialector}
	if err := identity.WithCapabilityLocks(fake, 1, 1, func(tx *gorm.DB) error { return nil }); err == nil {
		t.Fatal("未知 dialect 須 fail-close，不得靜默退化為行程內鎖")
	}
}

type unknownDialector struct{ gorm.Dialector }

func (unknownDialector) Name() string { return "mystery" }

// --- 3.8a／3.8b 的 postgres 真路徑並發（辨識力所在） ---
//
// **為什麼 sqlite 版測不出鎖有沒有被拿掉**：sqlite 是單寫者引擎，一個開著的
// 讀交易就會把另一端的寫入 commit 擋到 busy_timeout，等於免費提供了與
// provider 鎖等價的互斥。把 identity.WithCapabilityLocks 換成裸 db.Transaction 後
// 上面兩個 sqlite 測試**仍然全綠**（已實測），故它們只是端到端的行為斷言，
// 不具突變辨識力。
//
// postgres 的 MVCC 沒有這個副作用：讀交易不擋寫入、寫入也不擋讀，兩端唯一的
// 序列化來源就是 `SELECT ... FOR UPDATE` 的列鎖本身。因此突變自檢必須跑在此處。
//
// gating 同 TestPGAdvisoryLockMutex：未設 TEST_PG_DSN 即 skip。跑法：
//
//	docker compose exec -T backend sh -c \
//	  'TEST_PG_DSN="host=postgres user=postgres password=postgres dbname=postgres port=5432 sslmode=disable" \
//	   go test ./internal/service -run TestPGConcurrent -v'

const pgRaceTestSchema = "oidc_race_test"

// setupPGRaceSchema 專用 schema（測前後 DROP CASCADE，可重複執行）
func setupPGRaceSchema(t *testing.T, baseDSN string) string {
	t.Helper()
	admin := openPGLockDB(t, baseDSN)
	drop := "DROP SCHEMA IF EXISTS " + pgRaceTestSchema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatalf("清理舊測試 schema 失敗: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + pgRaceTestSchema).Error; err != nil {
		t.Fatalf("建立測試 schema 失敗: %v", err)
	}
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", pgRaceTestSchema, err)
		}
	})
	scoped := baseDSN + " search_path=" + pgRaceTestSchema
	mig := openPGLockDB(t, scoped)
	revocationMigrate(t, mig)
	return scoped
}

// newPGRaceEnv 兩個獨立連線池 ＝ 兩個後端副本：
// dbA 跑兌換／Join（經 database.DB），dbB 跑 provider 停用。
// 跨副本序列化正是列鎖存在的理由——行程內 mutex 對此完全無效
func newPGRaceEnv(t *testing.T) (*revocationEnv, *gorm.DB) {
	t.Helper()
	dsn := setupPGRaceSchema(t, pgLockTestDSN(t))
	dbA := openPGLockDB(t, dsn)
	dbB := openPGLockDB(t, dsn)
	if name := dbA.Dialector.Name(); name != "postgres" {
		t.Fatalf("本測試必須跑在 postgres 分流，實得 dialect %q", name)
	}
	oldDB := database.DB
	database.DB = dbA
	t.Cleanup(func() { database.DB = oldDB })

	env := newRevocationEnv(t, dbB) // provider 服務（停用側）掛在副本 B
	return env, dbA
}

// TestPGConcurrentExchangeVsDisable 兌換建 session vs 停用（跨副本，真列鎖）。
//
// **突變自檢（已實測）**：把 CreateWithGenerationGuard 的 identity.WithCapabilityLocks
// 換成 database.DB.Transaction，本測試立即轉紅——停用在副本 B 完成推進與掃描
// （看不到副本 A 尚未提交的 INSERT），兌換隨後插入一筆 active 會話並永久存活。
func TestPGConcurrentExchangeVsDisable(t *testing.T) {
	env, dbA := newPGRaceEnv(t)
	dto := seedRevocationProvider(t, env, "cid-pg-race")
	base := reloadProvider(t, env.db, dto.ID).AuthEpoch
	u := seedRevocationUser(t, dbA, "pgracer")

	arrived := make(chan struct{})
	release := make(chan struct{})
	gateHook(t, identity.OIDCSiteSessionCreate, arrived, release)

	assetID := uint(1)
	sess := &model.Session{
		SessionID: "sess-pg-race", UserID: u.ID, AssetID: &assetID,
		Protocol: model.ProtocolSSH, StartTime: time.Now(), AuthEpoch: base,
	}
	pid := dto.ID
	sess.AuthProviderID = &pid

	var wg sync.WaitGroup
	var createErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		createErr = env.sessions.CreateWithGenerationGuard(crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: dto.ID,
			AuthEpoch: base, CredEpoch: 0,
		}, sess)
	}()

	<-arrived
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(release)
		if _, err := env.svc.Update(dto.ID, &identity.OIDCProviderRequest{Enabled: boolPtr(false)}); err != nil {
			t.Errorf("停用: %v", err)
		}
	}()
	wg.Wait()

	var lingering int64
	if err := dbA.Model(&model.Session{}).
		Where("auth_provider_id = ? AND status = ?", dto.ID, model.SessionStatusActive).
		Count(&lingering).Error; err != nil {
		t.Fatalf("統計殘留會話: %v", err)
	}
	if lingering != 0 {
		t.Fatalf("停用後仍有 %d 筆 active 會話殘留（createErr=%v）——"+
			"兌換與停用未被 provider 列鎖序列化，該連線建立後不再出示憑證，將永久存活",
			lingering, createErr)
	}
	// 兌換成功時，該會話必須落在停用的掃描集合內（而非只是「剛好沒建成」）
	if createErr == nil {
		var s model.Session
		if err := dbA.First(&s, sess.ID).Error; err != nil {
			t.Fatalf("重讀會話: %v", err)
		}
		if s.EndReason != model.EndReasonAdminTerminate {
			t.Errorf("已建立的會話須被停用掃描終斷: status=%q end_reason=%q", s.Status, s.EndReason)
		}
	}
}

// TestPGConcurrentJoinVsDisable 訂閱 Join vs 停用（跨副本，真列鎖）。
//
// **突變自檢（已實測）**：把 JoinWithGenerationGuard 的 identity.WithCapabilityLocks
// 換成 database.DB.Transaction，本測試立即轉紅——收線掃描先跑完，Join 隨後
// 建立的訂閱錯過掃描，且訂閱建立後不再重驗任何憑證。
func TestPGConcurrentJoinVsDisable(t *testing.T) {
	env, dbA := newPGRaceEnv(t)
	dto := seedRevocationProvider(t, env, "cid-pg-join")
	base := reloadProvider(t, env.db, dto.ID).AuthEpoch
	observer := seedRevocationUser(t, dbA, "pgwatcher")

	arrived := make(chan struct{})
	release := make(chan struct{})
	gateHook(t, identity.OIDCSiteMonitorJoin, arrived, release)

	var wg sync.WaitGroup
	var joined bool
	var joinErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		joined, joinErr = session.JoinWithGenerationGuard(crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: dto.ID,
			AuthEpoch: base, CredEpoch: 0,
		}, observer.ID, func() bool { return env.hub.join(dto.ID) })
	}()

	<-arrived
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(release)
		if _, err := env.svc.Update(dto.ID, &identity.OIDCProviderRequest{Enabled: boolPtr(false)}); err != nil {
			t.Errorf("停用: %v", err)
		}
	}()
	wg.Wait()

	if n := env.hub.remaining(dto.ID); n != 0 {
		t.Fatalf("停用後仍有 %d 個訂閱存活（joined=%v joinErr=%v）——"+
			"Join 未持 provider 鎖，訂閱錯過收線掃描且此後不再重驗", n, joined, joinErr)
	}
}

// TestPGConcurrentDisableBeforeExchangeRejects 反向交錯：停用先進鎖，兌換後到。
//
// 本測試針對的是**鎖內重讀**（而非鎖本身）：停用於鎖內完成推進與掃描後，
// 後到的兌換必須讀到新世代而被拒絕。
//
// **突變自檢（已實測）**：拿掉 CreateWithGenerationGuard 內的
// VerifyCredentialGenerationTx（即「鎖內重讀」）後本測試轉紅——兌換會在停用
// 掃描完成之後才插入，留下一筆不在任何掃描集合內的 active 會話。
func TestPGConcurrentDisableBeforeExchangeRejects(t *testing.T) {
	env, dbA := newPGRaceEnv(t)
	dto := seedRevocationProvider(t, env, "cid-pg-reverse")
	base := reloadProvider(t, env.db, dto.ID).AuthEpoch
	u := seedRevocationUser(t, dbA, "pglate")

	arrived := make(chan struct{})
	release := make(chan struct{})
	gateHook(t, identity.OIDCSiteProviderInvalidate, arrived, release)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := env.svc.Update(dto.ID, &identity.OIDCProviderRequest{Enabled: boolPtr(false)}); err != nil {
			t.Errorf("停用: %v", err)
		}
	}()

	<-arrived
	assetID := uint(1)
	sess := &model.Session{
		SessionID: "sess-pg-late", UserID: u.ID, AssetID: &assetID,
		Protocol: model.ProtocolSSH, StartTime: time.Now(), AuthEpoch: base,
	}
	pid := dto.ID
	sess.AuthProviderID = &pid

	var createErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(release)
		createErr = env.sessions.CreateWithGenerationGuard(crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: dto.ID,
			AuthEpoch: base, CredEpoch: 0,
		}, sess)
	}()
	wg.Wait()

	if createErr == nil {
		t.Error("停用完成後到達的兌換必須被鎖內世代重讀拒絕，實得成功建立")
	}
	var lingering int64
	if err := dbA.Model(&model.Session{}).
		Where("auth_provider_id = ? AND status = ?", dto.ID, model.SessionStatusActive).
		Count(&lingering).Error; err != nil {
		t.Fatalf("統計殘留會話: %v", err)
	}
	if lingering != 0 {
		t.Fatalf("停用後到達的兌換留下 %d 筆 active 會話（createErr=%v）", lingering, createErr)
	}
}
