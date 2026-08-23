package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 外部身分管理四操作的正反矩陣。
//
// 覆蓋：(a) 綁定（含身分域衝突）、(b) 解綁的三分支判準與世代推進＋三管道收線、
// (c) 原子「解綁＋停用」與交易失敗零副作用、(d) 改為僅外部登入（含 MFA pending
// 失效與最後本地 admin 不變式），以及並發解綁不得使登入途徑歸零。

// --- fixture ---

func extIdentityMigrate(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{},
		&model.ApproverScope{}, &model.RefreshToken{},
		&model.OIDCProvider{}, &model.UserExternalIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 身分域唯一索引：production 由 migration 建（partial，排除軟刪），AutoMigrate 不產生。
	// 少了它，測試環境比 production 寬鬆，「衝突被擋下」這條路徑形同未測
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_uei_domain_ext
		ON user_external_identities(issuer, client_id, subject) WHERE deleted_at IS NULL`).Error; err != nil {
		t.Fatalf("identity domain unique index: %v", err)
	}
	for _, name := range []string{model.RoleAdmin, model.RoleUser} {
		if err := db.Create(&model.Role{Name: name}).Error; err != nil {
			t.Fatalf("seed role %s: %v", name, err)
		}
	}
}

// extIdentityDB 單連線 :memory: fixture（ff51836：連線池放行第二條即出現
// 「建了資料卻查不到」的假紅）。並發測試另用檔案型 DB，見 extIdentityConcurrentDB
func extIdentityDB(t *testing.T) *gorm.DB {
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
	extIdentityMigrate(t, db)
	// 世代閘（VerifyCredentialGenerationByUserID）走 database.DB，
	// 「解綁後舊世代憑證必被拒」的斷言需要它指向本測試的 DB
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// 三管道收線的假管道：斷言「有沒有呼叫、對誰呼叫」
type fakeSessionTerminator struct{ calls []uint }

func (f *fakeSessionTerminator) TerminateAllByUser(userID uint) (int, error) {
	f.calls = append(f.calls, userID)
	return 1, nil
}

type fakeSubscriptionTerminator struct{ calls []uint }

func (f *fakeSubscriptionTerminator) DisconnectByUser(userID uint) int {
	f.calls = append(f.calls, userID)
	return 1
}

type fakeRecordingTokenRevoker struct{ calls []uint }

func (f *fakeRecordingTokenRevoker) RevokeByUser(userID uint) int {
	f.calls = append(f.calls, userID)
	return 1
}

type extIdentityEnv struct {
	svc      *UserService
	db       *gorm.DB
	audit    *recordingAudit
	sessions *fakeSessionTerminator
	subs     *fakeSubscriptionTerminator
	tokens   *fakeRecordingTokenRevoker
}

func newExtIdentityEnv(t *testing.T, db *gorm.DB) *extIdentityEnv {
	t.Helper()
	env := &extIdentityEnv{
		svc: NewUserService(db, authz.NewAssetAuthorizationService(db)), db: db, audit: newRecordingAudit(),
		sessions: &fakeSessionTerminator{}, subs: &fakeSubscriptionTerminator{},
		tokens: &fakeRecordingTokenRevoker{},
	}
	env.svc.audit = env.audit
	env.svc.SetSessionTerminator(env.sessions)
	env.svc.SetSubscriptionTerminator(env.subs)
	env.svc.SetRecordingTokenRevoker(env.tokens)
	return env
}

var testActor = IdentityAdminActor{UserID: 99, Username: "root", ClientIP: "10.0.0.1"}

func seedExtProvider(t *testing.T, db *gorm.DB, name, issuer, clientID string) *model.OIDCProvider {
	t.Helper()
	p := &model.OIDCProvider{
		Name: name, Issuer: issuer, ClientID: clientID,
		Scopes: "openid", AdmissionMode: model.AdmissionPreboundOnly, Enabled: true,
	}
	if err := db.Create(p).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	return p
}

func mustBind(t *testing.T, env *extIdentityEnv, userID uint, p *model.OIDCProvider, subject string) uint {
	t.Helper()
	dto, err := env.svc.BindExternalIdentity(userID, p.ID, subject, testActor)
	if err != nil {
		t.Fatalf("BindExternalIdentity(%s): %v", subject, err)
	}
	return dto.ID
}

func identityCount(t *testing.T, db *gorm.DB, userID uint) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.UserExternalIdentity{}).
		Where("user_id = ? AND deleted_at IS NULL", userID).Count(&n).Error; err != nil {
		t.Fatalf("count identities: %v", err)
	}
	return n
}

func reloadUser(t *testing.T, db *gorm.DB, userID uint) *model.User {
	t.Helper()
	var u model.User
	if err := db.First(&u, userID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	return &u
}

// --- (a) 綁定 ---

// TestBindExternalIdentityUsesProviderIdentityDomain issuer／client_id 取自 provider
// 列而非請求：可由請求指定即等同讓 admin 綁出偽造身分域
func TestBindExternalIdentityUsesProviderIdentityDomain(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "alice", active: true})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")

	dto, err := env.svc.BindExternalIdentity(u.ID, p.ID, "sub-alice", testActor)
	if err != nil {
		t.Fatalf("綁定失敗: %v", err)
	}
	if dto.Issuer != p.Issuer || dto.ClientID != p.ClientID || dto.Subject != "sub-alice" {
		t.Fatalf("身分域 = (%s,%s,%s)，want (%s,%s,sub-alice)",
			dto.Issuer, dto.ClientID, dto.Subject, p.Issuer, p.ClientID)
	}
	if n := identityCount(t, db, u.ID); n != 1 {
		t.Fatalf("身分數 = %d, want 1", n)
	}
	if got := env.audit.countEvent("external_identity_bound"); got != 1 {
		t.Fatalf("審計事件 external_identity_bound = %d, want 1", got)
	}
	// 綁定不推進世代：新增登入途徑不使既有憑證失效
	if reloadUser(t, db, u.ID).CredentialEpoch != 0 {
		t.Fatal("綁定不應推進 credential_epoch")
	}
}

// TestBindExternalIdentityRejectsDuplicateDomain 身分域三元組唯一（partial index）：
// 第二次綁定必敗且不留任何列
func TestBindExternalIdentityRejectsDuplicateDomain(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	a := seedAccount(t, db, adminSpec{username: "alice", active: true})
	b := seedAccount(t, db, adminSpec{username: "bob", active: true})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	mustBind(t, env, a.ID, p, "shared-sub")

	_, err := env.svc.BindExternalIdentity(b.ID, p.ID, "shared-sub", testActor)
	if !errors.Is(err, ErrExternalIdentityExists) {
		t.Fatalf("重複綁定 = %v, want ErrExternalIdentityExists", err)
	}
	if n := identityCount(t, db, b.ID); n != 0 {
		t.Fatalf("失敗的綁定不得留下列，got %d", n)
	}
	if got := env.audit.countEvent("external_identity_bind_rejected"); got != 1 {
		t.Fatalf("拒絕事件 = %d, want 1", got)
	}
}

func TestBindExternalIdentityRejectsInvalidSubject(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "alice", active: true})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")

	for _, subject := range []string{"", "   ", string(make([]byte, 256))} {
		if _, err := env.svc.BindExternalIdentity(u.ID, p.ID, subject, testActor); !errors.Is(err, ErrExternalIdentitySubjectInvalid) {
			t.Fatalf("subject=%q → %v, want ErrExternalIdentitySubjectInvalid", subject, err)
		}
	}
	if n := identityCount(t, db, u.ID); n != 0 {
		t.Fatalf("不合法 subject 不得留下列，got %d", n)
	}
}

func TestBindExternalIdentityUnknownTargets(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "alice", active: true})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")

	if _, err := env.svc.BindExternalIdentity(9999, p.ID, "s", testActor); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("未知使用者 = %v, want ErrUserNotFound", err)
	}
	if _, err := env.svc.BindExternalIdentity(u.ID, 9999, "s", testActor); !errors.Is(err, ErrOIDCProviderNotFound) {
		t.Fatalf("未知 provider = %v, want ErrOIDCProviderNotFound", err)
	}
}

// --- (b) 解綁：判準三分支 ---

// TestUnbindAllowedWhenLocalPasswordRemains 仍具本地密碼者可解綁最後一筆
func TestUnbindAllowedWhenLocalPasswordRemains(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "alice", active: true}) // 本地帳號，有密碼雜湊
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	id := mustBind(t, env, u.ID, p, "sub-alice")

	if err := env.svc.UnbindExternalIdentity(u.ID, id, testActor); err != nil {
		t.Fatalf("解綁最後一筆（仍有本地密碼）應允許，got %v", err)
	}
	if n := identityCount(t, db, u.ID); n != 0 {
		t.Fatalf("解綁後身分數 = %d, want 0", n)
	}
}

// TestUnbindAllowedForDirectoryAccount 目錄供應帳號的登入不依賴外部身分記錄
func TestUnbindAllowedForDirectoryAccount(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "ldapper", active: true,
		ldapUser: true, origin: model.AuthSourceLDAP})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	id := mustBind(t, env, u.ID, p, "sub-ldapper")

	if err := env.svc.UnbindExternalIdentity(u.ID, id, testActor); err != nil {
		t.Fatalf("LDAP 帳號解綁最後一筆應允許，got %v", err)
	}
}

// TestUnbindRejectedWhenLastLoginPath 外部化且僅剩此途徑者拒絕，且**零副作用**
func TestUnbindRejectedWhenLastLoginPath(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "oidcer", active: true,
		extCred: true, origin: model.AuthSourceOIDC})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	id := mustBind(t, env, u.ID, p, "sub-oidcer")

	err := env.svc.UnbindExternalIdentity(u.ID, id, testActor)
	if !errors.Is(err, ErrLastLoginPath) {
		t.Fatalf("解綁最後一筆（已外部化）= %v, want ErrLastLoginPath", err)
	}
	var typed *LastLoginPathError
	if !errors.As(err, &typed) || typed.Code != apierror.CodeLastLoginPath {
		t.Fatalf("錯誤應帶精確出口碼 %s，got %v", apierror.CodeLastLoginPath, err)
	}
	if n := identityCount(t, db, u.ID); n != 1 {
		t.Fatalf("拒絕後身分應原封不動，got %d", n)
	}
	if e := reloadUser(t, db, u.ID).CredentialEpoch; e != 0 {
		t.Fatalf("拒絕後不得推進世代，got %d", e)
	}
	if len(env.sessions.calls)+len(env.subs.calls)+len(env.tokens.calls) != 0 {
		t.Fatal("拒絕後不得執行任何收線")
	}
	if got := env.audit.countEvent("external_identity_unbind_rejected"); got != 1 {
		t.Fatalf("拒絕事件 = %d, want 1", got)
	}
}

// TestUnbindOfNonLastIdentityAllowed 多筆身分時可逐一解綁到剩最後一筆
func TestUnbindOfNonLastIdentityAllowed(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "oidcer", active: true,
		extCred: true, origin: model.AuthSourceOIDC})
	p1 := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	p2 := seedExtProvider(t, db, "okta", "https://okta.example.com", "cid-2")
	id1 := mustBind(t, env, u.ID, p1, "sub-1")
	mustBind(t, env, u.ID, p2, "sub-2")

	if err := env.svc.UnbindExternalIdentity(u.ID, id1, testActor); err != nil {
		t.Fatalf("解綁非最後一筆應允許，got %v", err)
	}
	if n := identityCount(t, db, u.ID); n != 1 {
		t.Fatalf("剩餘身分數 = %d, want 1", n)
	}
}

// TestUnbindInvalidatesUserLevelAccess 解綁的失效粒度是**使用者級**：
// 推進 credential_epoch、撤全部 refresh、三管道收線皆對該使用者整體
func TestUnbindInvalidatesUserLevelAccess(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "alice", active: true})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	id := mustBind(t, env, u.ID, p, "sub-alice")
	// 另一條途徑建立的 refresh（本地密碼登入）同樣須被撤——刻意的過度撤銷
	rt := &model.RefreshToken{UserID: u.ID, TokenHash: "hash-local", ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Create(rt).Error; err != nil {
		t.Fatalf("seed refresh: %v", err)
	}

	oldCtx := crypto.AuthContext{AuthMethod: model.AuthSourceLocal, CredEpoch: 0}
	if err := epochGateForTest.VerifyCredentialGenerationByUserID(oldCtx, u.ID); err != nil {
		t.Fatalf("解綁前舊世代應有效: %v", err)
	}

	if err := env.svc.UnbindExternalIdentity(u.ID, id, testActor); err != nil {
		t.Fatalf("解綁: %v", err)
	}

	if e := reloadUser(t, db, u.ID).CredentialEpoch; e != 1 {
		t.Fatalf("credential_epoch = %d, want 1", e)
	}
	if err := epochGateForTest.VerifyCredentialGenerationByUserID(oldCtx, u.ID); !errors.Is(err, ErrCredentialGenerationStale) {
		t.Fatalf("舊世代憑證 = %v, want ErrCredentialGenerationStale", err)
	}
	var revoked model.RefreshToken
	if err := db.First(&revoked, rt.ID).Error; err != nil {
		t.Fatalf("reload refresh: %v", err)
	}
	if revoked.RevokedAt == nil || revoked.RevokedReason != model.RefreshRevokeCredentialEpoch {
		t.Fatalf("refresh 應被撤銷且理由為 %s，got revokedAt=%v reason=%q",
			model.RefreshRevokeCredentialEpoch, revoked.RevokedAt, revoked.RevokedReason)
	}
	// 三管道收線：世代閘只能拒絕「下一次出示憑證」，已建立的連線與訂閱對它免疫
	if len(env.sessions.calls) != 1 || env.sessions.calls[0] != u.ID {
		t.Fatalf("協議會話收線 = %v, want [%d]", env.sessions.calls, u.ID)
	}
	if len(env.subs.calls) != 1 || env.subs.calls[0] != u.ID {
		t.Fatalf("唯讀訂閱收線 = %v, want [%d]", env.subs.calls, u.ID)
	}
	if len(env.tokens.calls) != 1 || env.tokens.calls[0] != u.ID {
		t.Fatalf("錄影 token 撤銷 = %v, want [%d]", env.tokens.calls, u.ID)
	}
	if got := env.audit.countEvent("external_identity_unbound"); got != 1 {
		t.Fatalf("審計事件 = %d, want 1", got)
	}
}

func TestUnbindRejectsForeignIdentity(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	a := seedAccount(t, db, adminSpec{username: "alice", active: true})
	b := seedAccount(t, db, adminSpec{username: "bob", active: true})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	id := mustBind(t, env, a.ID, p, "sub-alice")

	// 歸屬校驗：只憑 identityID 查會解到別的帳號頭上
	if err := env.svc.UnbindExternalIdentity(b.ID, id, testActor); !errors.Is(err, ErrExternalIdentityNotFound) {
		t.Fatalf("解他人身分 = %v, want ErrExternalIdentityNotFound", err)
	}
	if n := identityCount(t, db, a.ID); n != 1 {
		t.Fatalf("他人身分不得被移除，got %d", n)
	}
}

// --- (c) 原子「解綁＋停用」---

func TestUnbindAndDisableIsAtomic(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "oidcer", active: true,
		extCred: true, origin: model.AuthSourceOIDC})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	id := mustBind(t, env, u.ID, p, "sub-oidcer")

	// (b) 會拒絕的最後一筆，(c) 是其正當出路
	if err := env.svc.UnbindExternalIdentityAndDisable(u.ID, id, testActor); err != nil {
		t.Fatalf("解綁＋停用: %v", err)
	}
	if n := identityCount(t, db, u.ID); n != 0 {
		t.Fatalf("身分應已解除，got %d", n)
	}
	reloaded := reloadUser(t, db, u.ID)
	if reloaded.Active {
		t.Fatal("帳號應已停用")
	}
	if reloaded.CredentialEpoch != 1 {
		t.Fatalf("credential_epoch = %d, want 1", reloaded.CredentialEpoch)
	}
	if len(env.subs.calls) != 1 || len(env.tokens.calls) != 1 || len(env.sessions.calls) != 1 {
		t.Fatalf("三管道收線缺漏：sessions=%v subs=%v tokens=%v",
			env.sessions.calls, env.subs.calls, env.tokens.calls)
	}
	if got := env.audit.countEvent("external_identity_unbound_and_account_disabled"); got != 1 {
		t.Fatalf("審計事件 = %d, want 1", got)
	}
}

// TestUnbindAndDisableRollsBackOnFailure 交易失敗時**兩者皆不變**。
//
// 失敗注入點取最後一步（撤銷 refresh 需要 refresh_tokens 表）：前面的解綁與停用
// 都已寫入，唯有整段共用同一交易才會一併回滾——分段提交的實作會在此留下
// 「身分已解除、帳號卻仍啟用」的中間態
func TestUnbindAndDisableRollsBackOnFailure(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "oidcer", active: true,
		extCred: true, origin: model.AuthSourceOIDC})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	id := mustBind(t, env, u.ID, p, "sub-oidcer")

	if err := db.Exec("DROP TABLE refresh_tokens").Error; err != nil {
		t.Fatalf("drop refresh_tokens: %v", err)
	}
	if err := env.svc.UnbindExternalIdentityAndDisable(u.ID, id, testActor); err == nil {
		t.Fatal("撤銷 refresh 失敗時整個操作應失敗")
	}
	if n := identityCount(t, db, u.ID); n != 1 {
		t.Fatalf("失敗後身分應原封不動，got %d", n)
	}
	reloaded := reloadUser(t, db, u.ID)
	if !reloaded.Active {
		t.Fatal("失敗後帳號不得被停用")
	}
	if reloaded.CredentialEpoch != 0 {
		t.Fatalf("失敗後不得推進世代，got %d", reloaded.CredentialEpoch)
	}
}

// TestUnbindAndDisableRespectsLocalAdminInvariant 停用是不變式的四條路徑之一
func TestUnbindAndDisableRespectsLocalAdminInvariant(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "only-admin", admin: true, active: true})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	id := mustBind(t, env, u.ID, p, "sub-admin")

	err := env.svc.UnbindExternalIdentityAndDisable(u.ID, id, testActor)
	var typed *LastLocalAdminError
	if !errors.As(err, &typed) || typed.Code != apierror.CodeLastLocalAdmin {
		t.Fatalf("停用最後一個本地 admin = %v, want LastLocalAdminError", err)
	}
	if n := identityCount(t, db, u.ID); n != 1 {
		t.Fatalf("拒絕後身分應原封不動，got %d", n)
	}
	if !reloadUser(t, db, u.ID).Active {
		t.Fatal("拒絕後帳號不得被停用")
	}
}

// --- (d) 改為僅外部登入 ---

func TestConvertToExternalOnly(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	seedAccount(t, db, adminSpec{username: "keeper", admin: true, active: true}) // 保住不變式
	u := seedAccount(t, db, adminSpec{username: "alice", active: true})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	mustBind(t, env, u.ID, p, "sub-alice")
	if err := db.Model(&model.User{}).Where("id = ?", u.ID).
		Update("must_change_password", true).Error; err != nil {
		t.Fatalf("seed must_change_password: %v", err)
	}

	if err := env.svc.ConvertToExternalOnly(u.ID, testActor); err != nil {
		t.Fatalf("轉換: %v", err)
	}
	reloaded := reloadUser(t, db, u.ID)
	if reloaded.Password != "" {
		t.Fatal("密碼雜湊應被清除（不留可比對殘值）")
	}
	if !reloaded.ExternalCredential || !reloaded.IsExternal() {
		t.Fatal("external_credential 應為 true")
	}
	if reloaded.MustChangePassword {
		t.Fatal("外部化帳號不得殘留強制改密旗標")
	}
	if reloaded.CredentialEpoch != 1 {
		t.Fatalf("credential_epoch = %d, want 1", reloaded.CredentialEpoch)
	}
	// 供應來源不因轉換改寫（不可變標註）
	if reloaded.ProvisioningOrigin != model.AuthSourceLocal {
		t.Fatalf("provisioning_origin = %q, want local", reloaded.ProvisioningOrigin)
	}
	if len(env.sessions.calls) != 1 || len(env.subs.calls) != 1 || len(env.tokens.calls) != 1 {
		t.Fatalf("三管道收線缺漏：sessions=%v subs=%v tokens=%v",
			env.sessions.calls, env.subs.calls, env.tokens.calls)
	}
	if got := env.audit.countEvent("user_converted_to_external_only"); got != 1 {
		t.Fatalf("審計事件 = %d, want 1", got)
	}
}

// TestConvertToExternalOnlyKillsMFAPending 轉換 SHALL 撤銷以本地密碼啟動的
// **尚未兌換**憑證：MFA pending token 若存活，其持有者可於轉換後完成驗證，
// 且 finishLogin 會因帳號已外部化而跳過密碼 gate，直接取得正式會話
func TestConvertToExternalOnlyKillsMFAPending(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	seedAccount(t, db, adminSpec{username: "keeper", admin: true, active: true})
	u := seedAccount(t, db, adminSpec{username: "alice", active: true})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	mustBind(t, env, u.ID, p, "sub-alice")

	auth := NewAuthService("test-secret", 15*time.Minute)
	pending, err := auth.jwtManager.GenerateScopedToken(u.ID, u.Username, "", model.RoleUser,
		crypto.ScopeMFAPending, 5*time.Minute,
		crypto.AuthContext{AuthMethod: model.AuthSourceLocal, CredEpoch: 0})
	if err != nil {
		t.Fatalf("簽 pending token: %v", err)
	}

	if err := env.svc.ConvertToExternalOnly(u.ID, testActor); err != nil {
		t.Fatalf("轉換: %v", err)
	}

	_, err = auth.VerifyMFALogin(&MFAVerifyRequest{PendingToken: pending, Code: "000000"})
	if !errors.Is(err, ErrMFAPendingTokenInvalid) {
		t.Fatalf("轉換後 MFA pending = %v, want ErrMFAPendingTokenInvalid", err)
	}
}

func TestConvertToExternalOnlyRequiresIdentity(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	seedAccount(t, db, adminSpec{username: "keeper", admin: true, active: true})
	u := seedAccount(t, db, adminSpec{username: "alice", active: true})

	if err := env.svc.ConvertToExternalOnly(u.ID, testActor); !errors.Is(err, ErrExternalIdentityRequired) {
		t.Fatalf("無外部身分時轉換 = %v, want ErrExternalIdentityRequired", err)
	}
	reloaded := reloadUser(t, db, u.ID)
	if reloaded.Password == "" || reloaded.ExternalCredential {
		t.Fatal("拒絕後密碼與外部化旗標皆不得變動")
	}
	if reloaded.CredentialEpoch != 0 {
		t.Fatal("拒絕後不得推進世代")
	}
}

func TestConvertToExternalOnlyRejectsAlreadyExternal(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "oidcer", active: true,
		extCred: true, origin: model.AuthSourceOIDC})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	mustBind(t, env, u.ID, p, "sub-oidcer")

	if err := env.svc.ConvertToExternalOnly(u.ID, testActor); !errors.Is(err, ErrUserAlreadyExternal) {
		t.Fatalf("已外部化帳號轉換 = %v, want ErrUserAlreadyExternal", err)
	}
}

func TestConvertToExternalOnlyRejectsLastLocalAdmin(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "only-admin", admin: true, active: true})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	mustBind(t, env, u.ID, p, "sub-admin")

	err := env.svc.ConvertToExternalOnly(u.ID, testActor)
	var typed *LastLocalAdminError
	if !errors.As(err, &typed) || typed.Code != apierror.CodeLastLocalAdmin {
		t.Fatalf("外部化最後一個本地 admin = %v, want LastLocalAdminError", err)
	}
	reloaded := reloadUser(t, db, u.ID)
	if reloaded.Password == "" || reloaded.ExternalCredential {
		t.Fatal("拒絕後密碼雜湊與外部化旗標皆不得變動")
	}
}

// --- 檢視 ---

func TestListExternalIdentities(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "alice", active: true})
	p := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	mustBind(t, env, u.ID, p, "sub-alice")

	items, err := env.svc.ListExternalIdentities(u.ID)
	if err != nil {
		t.Fatalf("列出外部身分: %v", err)
	}
	if len(items) != 1 || items[0].ProviderName != "corp" || items[0].Subject != "sub-alice" {
		t.Fatalf("列表內容不符: %+v", items)
	}
}

// --- 並發：write-skew ---

// extIdentityConcurrentDB 檔案型 sqlite ＋兩條連線。
//
// 刻意不同於其他測試的 :memory:＋MaxOpenConns(1)：單連線會把兩個 goroutine 的
// 一切 DB 存取序列化，使「兩者各自讀到對方那筆還在」的交錯無法穩定重現，
// 突變測試（把鎖內重讀改成鎖外預讀）會因此看似仍然安全（同 localAdminConcurrentDB）
func extIdentityConcurrentDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "extidentity.db") + "?_pragma=busy_timeout(5000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(2)
	extIdentityMigrate(t, db)
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// TestConcurrentUnbindKeepsOneLoginPath 一個已外部化帳號有兩筆身分，
// 兩個請求並發各解綁一筆 → 至多一個成功，事後仍保有至少一筆身分。
//
// 單次操作內的檢查對此完全無感（兩者各自看見「還有另一筆」即可同時提交）。
// 交錯由 userCredentialPreWriteHook 在「判定通過、寫入之前」製造：正確實作下
// 第二個操作被 user-scoped 鎖擋在門外，等第一個提交後才重讀而被拒絕
func TestConcurrentUnbindKeepsOneLoginPath(t *testing.T) {
	db := extIdentityConcurrentDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "oidcer", active: true,
		extCred: true, origin: model.AuthSourceOIDC})
	p1 := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	p2 := seedExtProvider(t, db, "okta", "https://okta.example.com", "cid-2")
	id1 := mustBind(t, env, u.ID, p1, "sub-1")
	id2 := mustBind(t, env, u.ID, p2, "sub-2")

	var mu sync.Mutex
	arrived := 0
	gate := make(chan struct{})
	userCredentialPreWriteHook = func() {
		mu.Lock()
		arrived++
		n := arrived
		mu.Unlock()
		if n >= 2 {
			// 兩方都走到「判定已通過、尚未寫入」＝不變式已被突破，
			// 立刻放行讓兩筆寫入都落地，使測試看到歸零的結果而非被計時掩蓋
			close(gate)
			return
		}
		select {
		case <-gate:
		case <-time.After(300 * time.Millisecond):
		}
	}
	defer func() { userCredentialPreWriteHook = nil }()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = env.svc.UnbindExternalIdentity(u.ID, id1, testActor)
	}()
	go func() {
		defer wg.Done()
		errs[1] = env.svc.UnbindExternalIdentity(u.ID, id2, testActor)
	}()
	wg.Wait()

	failures := 0
	for _, err := range errs {
		if err != nil {
			failures++
			if !errors.Is(err, ErrLastLoginPath) {
				t.Fatalf("失敗方應為登入途徑判準拒絕，got %v", err)
			}
		}
	}
	if failures < 1 {
		t.Errorf("兩個並發解綁至少一個應失敗，got 全部成功（errs=%v）", errs)
	}
	if n := identityCount(t, db, u.ID); n < 1 {
		t.Errorf("事後應仍保有至少一筆外部身分，got %d", n)
	}
}
