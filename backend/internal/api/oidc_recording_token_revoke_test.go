package api

import (
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 錄影存取憑證的即時失效。
//
// 錄影 token 是全系統唯一**不做世代比對**的憑證：Resolve 位於 HTTP Range 熱路徑，
// 設計上刻意以 in-memory map ＋ 120 秒 TTL 取代每次查 DB 比對世代
//（見 recording_token.go 的取捨說明）。代價是它對 auth_epoch／credential_epoch
// 完全免疫——被停用者手上那張 token 會安安穩穩活滿 120 秒，而錄影是全系統最敏感
// 的稽核資產（完整終端畫面、憑證輸入、跳板後的一切操作）。
//
// 唯一的失效途徑是直接撤銷，故本檔一律用**真的 RecordingTokenManager**（不是 fake）
// 並斷言 Resolve 立即為 false。用 fake 只能驗到「撤銷函式被呼叫過」，
// 驗不到「述詞寫對了」，而 RevokeByProvider/RevokeByUser 的述詞正是最容易寫錯的地方
//（providerID=0 當成萬用字元即誤殺全部本地登入者的錄影權）。
//
// 突變自檢：把 revokeProviderAccess 內的 s.recordingTokens.RevokeByProvider(providerID)
// 拿掉，TestProviderDisableRevokesRecordingTokensImmediately 轉紅；
// 把 RevokeByProvider 的 `if providerID == 0 { return 0 }` 拿掉，
// TestRecordingTokenRevokeIsNotWildcard 轉紅。

// 型別層守衛：組裝端（cmd/server/stage2.go）以這兩個介面把 manager 接上兩條撤銷
// 管道。介面若被改窄／改名，組裝會斷，此處先於執行期抓到
var (
	_ identity.RecordingTokenRevoker         = (*RecordingTokenManager)(nil)
	_ identity.ProviderRecordingTokenRevoker = (*RecordingTokenManager)(nil)
)

type recTokenEnv struct {
	mgr       *RecordingTokenManager
	users     *identity.UserService
	providers *identity.OIDCProviderService
	db        *gorm.DB
}

func setupRecordingTokenEnv(t *testing.T) *recTokenEnv {
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
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.RefreshToken{},
		&model.OIDCProvider{}, &model.UserExternalIdentity{}, &model.Session{},
		&model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	env := &recTokenEnv{
		mgr:       NewRecordingTokenManager(),
		users:     identity.NewUserService(db, authz.NewAssetAuthorizationService(db)),
		providers: identity.NewOIDCProviderService(db, nil, &identity.OIDCEgressPolicy{}, nil, "https://bastion.example.com"),
		db:        db,
	}
	// 與 cmd/server/stage2.go 的組裝同構：同一個 manager 同時掛在兩條撤銷管道上
	env.users.SetRecordingTokenRevoker(env.mgr)
	env.providers.SetRecordingTokenRevoker(env.mgr)
	return env
}

func (e *recTokenEnv) seedProvider(t *testing.T, clientID string) uint {
	t.Helper()
	enabled := true
	dto, err := e.providers.Create(&identity.OIDCProviderRequest{
		Name: clientID, Issuer: "https://idp.example.com/" + clientID,
		ClientID: clientID, ClientSecret: "s3cret", Scopes: "profile email",
		Enabled: &enabled,
	})
	if err != nil {
		t.Fatalf("建立 provider: %v", err)
	}
	return dto.ID
}

// seedPlainUser 建立一個啟用中的本地帳號，回傳其 ID。
//
// 自 G-C 起簽發走序列化世代閘，任何錄影 token 的簽發都必須對應一位**真實存在且
// 啟用**的使用者——測試不能再用憑空的 userID
func (e *recTokenEnv) seedPlainUser(t *testing.T, username string) uint {
	t.Helper()
	u := model.User{
		Username: username, Password: "$2a$04$abcdefghijklmnopqrstuv", Active: true,
		ProvisioningOrigin: model.AuthSourceLocal,
	}
	if err := e.db.Create(&u).Error; err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
	return u.ID
}

// seedUserWithIdentity 有本地密碼（解綁後仍有登入途徑）並綁一筆外部身分
func (e *recTokenEnv) seedUserWithIdentity(t *testing.T, username string, providerID uint) (uint, uint) {
	t.Helper()
	u := model.User{
		Username: username, Password: "$2a$04$abcdefghijklmnopqrstuv", Active: true,
		ProvisioningOrigin: model.AuthSourceLocal,
	}
	if err := e.db.Create(&u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	var issuer, clientID string
	var p model.OIDCProvider
	if err := e.db.First(&p, providerID).Error; err != nil {
		t.Fatalf("load provider: %v", err)
	}
	issuer, clientID = p.Issuer, p.ClientID
	id := model.UserExternalIdentity{
		UserID: u.ID, ProviderID: providerID,
		Issuer: issuer, ClientID: clientID, Subject: "sub-" + username,
	}
	if err := e.db.Create(&id).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	return u.ID, id.ID
}

// mustIssue 簽發一張錄影 token 並確認它當下可用（前提不成立時測試無意義）。
//
// 簽發自 G-C 起走序列化世代閘，故 userID 必須是**真實存在且啟用**的使用者、
// providerID 必須對應真實且啟用的 provider——這正是該閘要驗的東西
func (e *recTokenEnv) mustIssue(t *testing.T, userID, sessionID, providerID uint) string {
	t.Helper()
	tok, err := e.mgr.Issue(userID, sessionID, "rec-subject", crypto.AuthContext{ProviderID: providerID})
	if err != nil {
		t.Fatalf("簽發錄影 token: %v", err)
	}
	if _, ok := e.mgr.Resolve(tok); !ok {
		t.Fatal("前提不成立：剛簽發的 token 應可用")
	}
	return tok
}

// assertDead 斷言 token 已立即不可用，且**不是靠 TTL 到期**
func (e *recTokenEnv) assertDead(t *testing.T, tok, why string) {
	t.Helper()
	if _, ok := e.mgr.Resolve(tok); ok {
		t.Errorf("%s：錄影 token 仍可用（殘留了 %v 的存取窗口）", why, recordingTokenTTL)
	}
}

func (e *recTokenEnv) assertAlive(t *testing.T, tok, why string) {
	t.Helper()
	if _, ok := e.mgr.Resolve(tok); !ok {
		t.Errorf("%s：錄影 token 不應被撤銷", why)
	}
}

// TestProviderDisableRevokesRecordingTokensImmediately 4.14i：
// provider 停用後，該 provider 簽出的錄影 token 立即不可用
func TestProviderDisableRevokesRecordingTokensImmediately(t *testing.T) {
	env := setupRecordingTokenEnv(t)
	victim := env.seedProvider(t, "cid-victim")
	other := env.seedProvider(t, "cid-other")

	uA := env.seedPlainUser(t, "u-a")
	uB := env.seedPlainUser(t, "u-b")
	uC := env.seedPlainUser(t, "u-c")
	uD := env.seedPlainUser(t, "u-d")

	doomedA := env.mustIssue(t, uA, 100, victim)
	doomedB := env.mustIssue(t, uB, 101, victim) // 同 provider 的另一人也須清掉
	survivorOther := env.mustIssue(t, uC, 102, other)
	survivorLocal := env.mustIssue(t, uD, 103, 0) // 本地登入者

	enabled := false
	if _, err := env.providers.Update(victim, &identity.OIDCProviderRequest{Enabled: &enabled}); err != nil {
		t.Fatalf("停用 provider: %v", err)
	}

	env.assertDead(t, doomedA, "經被停用 provider 認證者")
	env.assertDead(t, doomedB, "同 provider 的另一位使用者")
	env.assertAlive(t, survivorOther, "經另一 provider 認證者")
	env.assertAlive(t, survivorLocal, "本地登入者（providerID=0 不是萬用字元）")
}

// TestProviderSecretRotationRevokesRecordingTokens 4.14i×4.14h：
// 密鑰輪替與停用走同一套失效流程，錄影 token 亦然
func TestProviderSecretRotationRevokesRecordingTokens(t *testing.T) {
	env := setupRecordingTokenEnv(t)
	pid := env.seedProvider(t, "cid-rotate")
	doomed := env.mustIssue(t, env.seedPlainUser(t, "u-rotate"), 100, pid)

	if _, err := env.providers.Update(pid, &identity.OIDCProviderRequest{ClientSecret: "rotated"}); err != nil {
		t.Fatalf("輪替密鑰: %v", err)
	}
	env.assertDead(t, doomed, "密鑰輪替後")
}

// TestProviderDeleteRevokesRecordingTokens 4.14i：刪除亦走全套。
// 刪除之後管理端再也無從按 provider 下指令，漏掉即永久殘留
func TestProviderDeleteRevokesRecordingTokens(t *testing.T) {
	env := setupRecordingTokenEnv(t)
	pid := env.seedProvider(t, "cid-delete")
	doomed := env.mustIssue(t, env.seedPlainUser(t, "u-delete"), 100, pid)

	if err := env.providers.Delete(pid); err != nil {
		t.Fatalf("刪除 provider: %v", err)
	}
	env.assertDead(t, doomed, "provider 刪除後")
}

// TestIdentityOpsRevokeRecordingTokensImmediately 4.14i：
// 外部身分管理操作（解綁／解綁＋停用／轉為僅外部登入）皆立即撤銷該使用者的錄影 token。
//
// 撤銷粒度是**使用者級**：該使用者經任何管道簽出的 token 都要清掉（含 providerID=0
// 的那些）——留一張就等於留一條完整的錄影下載途徑
func TestIdentityOpsRevokeRecordingTokensImmediately(t *testing.T) {
	ops := map[string]func(e *recTokenEnv, userID, identityID uint) error{
		"解綁外部身分": func(e *recTokenEnv, userID, identityID uint) error {
			return e.users.UnbindExternalIdentity(userID, identityID, identity.IdentityAdminActor{UserID: 1})
		},
		"解綁並停用帳號": func(e *recTokenEnv, userID, identityID uint) error {
			return e.users.UnbindExternalIdentityAndDisable(userID, identityID, identity.IdentityAdminActor{UserID: 1})
		},
		"轉為僅外部登入": func(e *recTokenEnv, userID, _ uint) error {
			return e.users.ConvertToExternalOnly(userID, identity.IdentityAdminActor{UserID: 1})
		},
	}
	for label, op := range ops {
		t.Run(label, func(t *testing.T) {
			env := setupRecordingTokenEnv(t)
			pid := env.seedProvider(t, "cid-ident")
			uid, identityID := env.seedUserWithIdentity(t, "target", pid)
			otherUID, _ := env.seedUserWithIdentity(t, "bystander", pid)

			viaProvider := env.mustIssue(t, uid, 100, pid)
			viaLocal := env.mustIssue(t, uid, 101, 0) // 同一人的本地簽發亦須清掉
			bystander := env.mustIssue(t, otherUID, 102, pid)

			if err := op(env, uid, identityID); err != nil {
				t.Fatalf("%s: %v", label, err)
			}

			env.assertDead(t, viaProvider, label+"（經 provider 簽出）")
			env.assertDead(t, viaLocal, label+"（同一人本地簽出）")
			env.assertAlive(t, bystander, label+"：他人不受牽連")
		})
	}
}

// TestRecordingTokenRevokeIsNotWildcard 4.14i 的邊界：
// providerID=0 與 userID=0 皆非萬用字元。
//
// 0 是「本地／LDAP 登入」與「不適用」的既有零值語義；若被當成萬用字元，
// 任何一次 provider 撤銷都會清掉全體本地管理員正在播放的錄影
func TestRecordingTokenRevokeIsNotWildcard(t *testing.T) {
	env := setupRecordingTokenEnv(t)
	pid := env.seedProvider(t, "cid-wildcard")
	local := env.mustIssue(t, env.seedPlainUser(t, "u-local"), 100, 0)
	viaProvider := env.mustIssue(t, env.seedPlainUser(t, "u-provider"), 101, pid)

	if n := env.mgr.RevokeByProvider(0); n != 0 {
		t.Errorf("RevokeByProvider(0) 撤銷了 %d 張，0 不得為萬用字元", n)
	}
	if n := env.mgr.RevokeByUser(0); n != 0 {
		t.Errorf("RevokeByUser(0) 撤銷了 %d 張，0 不得為萬用字元", n)
	}
	env.assertAlive(t, local, "providerID=0 的 token")
	env.assertAlive(t, viaProvider, "其他 provider 的 token")
}

// TestRecordingTokenRevocationBeatsTTL 4.14i 的核心語義：
// 失效是**撤銷造成的**，不是等 TTL 到期。
//
// 若沒有這一格，一份「先撤銷、再 sleep 到 TTL 後才斷言」的測試也會全綠，
// 而那正是規格要禁止的 120 秒殘留窗口
func TestRecordingTokenRevocationBeatsTTL(t *testing.T) {
	env := setupRecordingTokenEnv(t)
	pid := env.seedProvider(t, "cid-ttl")
	tok := env.mustIssue(t, env.seedPlainUser(t, "u-ttl"), 100, pid)

	grant, ok := env.mgr.Resolve(tok)
	if !ok {
		t.Fatal("前提不成立：token 應可用")
	}
	remaining := time.Until(grant.ExpiresAt)
	if remaining <= 0 {
		t.Fatalf("前提不成立：token 已自然到期（剩餘 %v）", remaining)
	}

	enabled := false
	if _, err := env.providers.Update(pid, &identity.OIDCProviderRequest{Enabled: &enabled}); err != nil {
		t.Fatalf("停用 provider: %v", err)
	}

	env.assertDead(t, tok, "provider 停用後")
	// 撤銷發生時 TTL 還剩一大段——失效與到期是兩回事
	if left := time.Until(grant.ExpiresAt); left <= 0 {
		t.Fatalf("撤銷時 TTL 已到期（剩餘 %v），本測試未能證明是撤銷造成的失效", left)
	}
}
