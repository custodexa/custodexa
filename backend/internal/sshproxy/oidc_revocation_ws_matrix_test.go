package sshproxy

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/gorilla/websocket"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 撤銷收線的**真 WebSocket 端到端**（idp-oidc-integration tasks 4.14c／4.14g）。
//
// 與 monitor_revoke_test.go 的分工：該檔直接呼叫 hub 的三個 Disconnect 方法，
// 驗的是「匹配語義對不對」；service 層若漏接管道（根本沒呼叫），那些測試全綠。
// **本檔驗的是 service 的撤銷路徑真的把管道打出去**，且觀察者是真的被收線的
// WebSocket 而非計數器。
//
// 放在 sshproxy 而非 service：MonitorHub 在此包，而 service 不得反向依賴傳輸層
//（那是 ProviderSubscriptionTerminator／SubscriptionTerminator 兩個介面存在的理由）。
// sshproxy 已依賴 service，故只有本包能把兩端接成真的。

// --- fixture ---

// wsMatrixDB 單連線 :memory:（ff51836：第二條連線是另一個空 DB）
func wsMatrixDB(t *testing.T) *gorm.DB {
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
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{},
		&model.PasswordHistory{}, &model.RefreshToken{}, &model.OIDCProvider{},
		&model.UserExternalIdentity{}, &model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// wsMatrixProvider 建一個啟用中的 provider（issuer 各自不同以免撞唯一性）
func wsMatrixProvider(t *testing.T, db *gorm.DB, name, issuer, clientID string) *model.OIDCProvider {
	t.Helper()
	p := &model.OIDCProvider{
		Name: name, Issuer: issuer, ClientID: clientID, Scopes: "openid",
		AdmissionMode: model.AdmissionPreboundOnly, Enabled: true,
	}
	if err := db.Create(p).Error; err != nil {
		t.Fatalf("seed provider %s: %v", name, err)
	}
	// Enabled 帶 not null default:false，GORM 對零值交由 DB default 填；
	// 顯式回寫確保取值精確落庫（同 connect_generation_test.go 的處置）
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).
		Update("enabled", true).Error; err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	return p
}

// wsMatrixSession 一筆進行中會話；providerID 為 0 時 auth_provider_id 寫 NULL
// （本地／LDAP 登入的語義，按 provider 的掃描必須掃不到）
func wsMatrixSession(t *testing.T, db *gorm.DB, userID, providerID uint, tag string) *model.Session {
	t.Helper()
	assetID := uint(1)
	s := &model.Session{
		SessionID: tag, UserID: userID, AssetID: &assetID,
		Protocol: model.ProtocolSSH, Status: model.SessionStatusActive,
		StartTime: time.Now().Add(-time.Minute),
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

func wsMatrixReloadSession(t *testing.T, db *gorm.DB, id uint) *model.Session {
	t.Helper()
	var s model.Session
	if err := db.First(&s, id).Error; err != nil {
		t.Fatalf("reload session %d: %v", id, err)
	}
	return &s
}

func wsMatrixBool(v bool) *bool { return &v }

const wsMatrixSecret = "ws-matrix-test-secret"

// wsMatrixUser 一個啟用中的觀察者帳號（credential_epoch 為 DB 預設 0）
func wsMatrixUser(t *testing.T, db *gorm.DB, username string) *model.User {
	t.Helper()
	u := &model.User{Username: username, Password: "x", Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
	return u
}

// wsMatrixHandler 接上真 AuthService 的 Handler（其 Monitor 即被測 hub）
func wsMatrixHandler(t *testing.T, sessions *session.SessionService) *Handler {
	t.Helper()
	gin.SetMode(gin.TestMode)
	return NewHandler(nil, identity.NewAuthService(wsMatrixSecret, 15*time.Minute),
		nil, sessions, nil, "", nil)
}

// wsMatrixToken 與生產同形的 connection token（脈絡取 DB 現值；providerID=0 即本地登入）
func wsMatrixToken(t *testing.T, db *gorm.DB, u *model.User, providerID uint) string {
	t.Helper()
	var authCtx crypto.AuthContext
	if providerID != 0 {
		var p model.OIDCProvider
		if err := db.First(&p, providerID).Error; err != nil {
			t.Fatalf("load provider %d: %v", providerID, err)
		}
		authCtx = crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: providerID, AuthEpoch: p.AuthEpoch,
		}
	}
	tok, err := crypto.NewJWTManager(wsMatrixSecret, 15*time.Minute).
		GenerateToken(u.ID, u.Username, "", model.RoleAdmin, authCtx)
	if err != nil {
		t.Fatalf("簽發 connection token: %v", err)
	}
	return tok
}

// dialMonitorObserver 走**真** `/sessions/:id/monitor?token=`（不掛 AuthMiddleware，
// 與 main.go 一致）建立監看訂閱，並等到它確實進入 room.observers
func dialMonitorObserver(t *testing.T, db *gorm.DB, h *Handler, tap *monitorTap,
	sessionID uint, username string, providerID uint) *websocket.Conn {
	t.Helper()
	u := wsMatrixUser(t, db, username)
	r := gin.New()
	r.GET("/api/v1/sessions/:id/monitor", h.HandleMonitor)
	ws := dialWS(t, r, fmt.Sprintf("/api/v1/sessions/%d/monitor?token=%s",
		sessionID, wsMatrixToken(t, db, u, providerID)))
	waitRegistered(t, tap, ws, "監看訂閱 "+username)
	return ws
}

// dialShareObserver 同上，但走 `/sessions/share/:code/ws?token=`
func dialShareObserver(t *testing.T, db *gorm.DB, h *Handler, tap *monitorTap,
	sessionID uint, username string, providerID uint) *websocket.Conn {
	t.Helper()
	u := wsMatrixUser(t, db, username)
	code, _, err := h.Shares.Create(sessionID, 999, time.Minute)
	if err != nil {
		t.Fatalf("建立分享碼: %v", err)
	}
	r := gin.New()
	r.GET("/api/v1/sessions/share/:code/ws", h.HandleShareJoin)
	ws := dialWS(t, r, "/api/v1/sessions/share/"+code+"/ws?token="+
		wsMatrixToken(t, db, u, providerID))
	waitRegistered(t, tap, ws, "分享訂閱 "+username)
	return ws
}

// --- 4.14c 停用收線監看：按觀察者脈絡，不按被監看會話 ---

// TestProviderDisableCutsMonitorOfLocalSession 經 provider A 認證的管理者，
// 監看一條由**本地帳號**建立的會話；停用 A → 該監看被收線（tasks 4.14c）。
//
// 這是「按觀察者脈絡收線」與「按被監看會話收線」的分水嶺：被監看的會話
// auth_provider_id 是 NULL（本地登入建立），與 provider A 完全不匹配。若收線
// 邏輯是「掃 sessions 表命中 provider A 的列、關掉其上的觀察者」，本情境的訂閱
// 一個都掃不到——而該管理者的存取權正是由已被停用的 provider A 賦予的，
// 他能繼續即時讀取那條本地會話的終端內容。
//
// 同時驗其精準性：本地觀察者與經另一個 provider 認證的觀察者皆不得被誤殺，
// 被監看的本地會話本身也不得被 provider A 的會話掃描終斷。
func TestProviderDisableCutsMonitorOfLocalSession(t *testing.T) {
	db := wsMatrixDB(t)
	providerA := wsMatrixProvider(t, db, "corp", "https://idp-a.example.com", "cid-a")
	providerB := wsMatrixProvider(t, db, "okta", "https://idp-b.example.com", "cid-b")

	sessions := session.NewSessionService(nil)
	h := wsMatrixHandler(t, sessions)
	svc := identity.NewOIDCProviderService(db, nil,
		&identity.OIDCEgressPolicy{AllowInsecureHosts: []string{"127.0.0.1"}},
		nil, "https://bastion.example.com")
	// 真管道：service 停用路徑 → hub 收線 ／ → sessions 掃描
	svc.SetSubscriptionTerminator(h.Monitor)
	svc.SetSessionTerminator(sessions)

	// 被監看的會話由本地帳號建立（auth_provider_id = NULL）
	localSession := wsMatrixSession(t, db, 100, 0, "sess-local")
	tap := h.Monitor.OpenRoom(localSession.ID, 80, 24)

	// 三位觀察者一律走真 `?token=`（對抗審查 C1）：脈絡由 Handler.authenticate
	// 自 claims 解出，而非測試手工塞進 ObserverContext——後者測不到「脈絡有沒有真的來」
	viaA := dialMonitorObserver(t, db, h, tap, localSession.ID, "obs-via-a", providerA.ID)
	viaB := dialMonitorObserver(t, db, h, tap, localSession.ID, "obs-via-b", providerB.ID)
	localObs := dialMonitorObserver(t, db, h, tap, localSession.ID, "obs-local", 0)

	if _, err := svc.Update(providerA.ID, &identity.OIDCProviderRequest{
		Enabled: wsMatrixBool(false)}); err != nil {
		t.Fatalf("停用 provider A: %v", err)
	}

	expectClosed(t, viaA, "經被停用 provider 認證的監看者")
	expectAlive(t, viaB, "經另一 provider 認證的監看者")
	expectAlive(t, localObs, "本地登入的監看者")

	// 被監看的本地會話不得被牽連：它與 provider A 無關，
	// 誤殺等於停用一個 IdP 就切斷了本地帳號正在進行的維運作業
	if s := wsMatrixReloadSession(t, db, localSession.ID); s.Status != model.SessionStatusActive {
		t.Errorf("被監看的本地會話不應被 provider 停用終斷: status=%q end_reason=%q",
			s.Status, s.EndReason)
	}
}

// TestProviderDisableCutsSubscriptionsAcrossRooms 同一位經 provider A 認證的
// 觀察者同時持有監看與分享觀看兩條訂閱（不同 room），停用 A 須全數收線
// （tasks 4.14c／4.14e 共用的防「只改一處」斷言）。
//
// 監看與分享在 handler 走的是兩個入口，但都經 JoinWithGenerationGuard 落到同一個
// MonitorHub；只處理第一個命中的 room 會留下活著的訂閱
func TestProviderDisableCutsSubscriptionsAcrossRooms(t *testing.T) {
	db := wsMatrixDB(t)
	providerA := wsMatrixProvider(t, db, "corp", "https://idp-a.example.com", "cid-a")

	sessions := session.NewSessionService(nil)
	h := wsMatrixHandler(t, sessions)
	svc := identity.NewOIDCProviderService(db, nil,
		&identity.OIDCEgressPolicy{AllowInsecureHosts: []string{"127.0.0.1"}},
		nil, "https://bastion.example.com")
	svc.SetSubscriptionTerminator(h.Monitor)
	svc.SetSessionTerminator(sessions)

	watched := wsMatrixSession(t, db, 100, 0, "sess-watched")
	shared := wsMatrixSession(t, db, 101, 0, "sess-shared")
	watchedTap := h.Monitor.OpenRoom(watched.ID, 80, 24)
	sharedTap := h.Monitor.OpenRoom(shared.ID, 80, 24)

	// 兩條訂閱各走各的**真**入口（monitor 與 share 是兩份 handler 程式碼）
	monitor := dialMonitorObserver(t, db, h, watchedTap, watched.ID, "obs-monitor", providerA.ID)
	share := dialShareObserver(t, db, h, sharedTap, shared.ID, "obs-share", providerA.ID)

	if _, err := svc.Update(providerA.ID, &identity.OIDCProviderRequest{
		Enabled: wsMatrixBool(false)}); err != nil {
		t.Fatalf("停用 provider A: %v", err)
	}
	expectClosed(t, monitor, "監看訂閱")
	expectClosed(t, share, "分享觀看訂閱")
}

// --- 4.14g 鎖定不得成為斷線武器（WS 端到端） ---

// TestLockoutDoesNotCloseMonitorWebSocket 第三方觸發的自動鎖定 SHALL NOT 關閉
// 受害者既有的監看 WebSocket，也不得終斷其進行中的協議會話（tasks 4.14g）。
//
// service 層的對應斷言在 service/oidc_revocation_matrix_test.go
// （TestLockoutIsNotADisconnectWeapon，含 credential_epoch 與 refresh 的完整矩陣）；
// **本測試補的是傳輸層的事實**——連線是真的 WebSocket，收線與否可直接觀測，
// 不依賴假 hub 的呼叫計數。
//
// 末段的對照組不可省：直接呼叫 hub.DisconnectByUser 證明這條連線本來就是
// 可被收線的，否則「鎖定後連線還在」可能只是因為根本沒接上 room
func TestLockoutDoesNotCloseMonitorWebSocket(t *testing.T) {
	db := wsMatrixDB(t)
	policies := policy.NewSecurityPolicyService(db)
	if _, err := policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin"); err != nil {
		t.Fatalf("設定鎖定門檻: %v", err)
	}
	auth := identity.NewAuthService("test-secret", 15*time.Minute)
	auth.SetSecurityPolicies(policies)

	const password = "Str0ng-Passw0rd!x"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	now := time.Now()
	victim := &model.User{
		Username: "victim", Password: string(hash), Active: true,
		ProvisioningOrigin: model.AuthSourceLocal, PasswordChangedAt: &now,
	}
	if err := db.Create(victim).Error; err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	// 受害者進行中的協議會話與監看訂閱
	sess := wsMatrixSession(t, db, victim.ID, 0, "sess-victim")
	hub := NewMonitorHub()
	hub.OpenRoom(sess.ID, 80, 24)
	watching, _ := dialObserver(t, hub, sess.ID, ObserverContext{UserID: victim.ID})

	// 第三方連續輸錯密碼觸發鎖定（未認證者只要知道 username 即可辦到）
	var lastErr error
	for i := 0; i < 3; i++ {
		if _, lastErr = auth.Login(&identity.LoginRequest{
			Username: "victim", Password: "definitely-wrong"}); lastErr == nil {
			t.Fatalf("第 %d 次錯誤密碼不應成功", i+1)
		}
	}
	if !errors.Is(lastErr, identity.ErrAccountLocked) {
		t.Fatalf("達門檻應回 ErrAccountLocked，實得 %v", lastErr)
	}
	var locked model.User
	if err := db.First(&locked, victim.ID).Error; err != nil {
		t.Fatalf("reload victim: %v", err)
	}
	if locked.LockedUntil == nil {
		t.Fatal("應已觸發自動鎖定（前提不成立則本測試無意義）")
	}

	expectAlive(t, watching, "鎖定期間受害者既有的監看訂閱")
	if s := wsMatrixReloadSession(t, db, sess.ID); s.Status != model.SessionStatusActive {
		t.Errorf("鎖定不得終斷既有協議會話: status=%q end_reason=%q", s.Status, s.EndReason)
	}

	// 對照組：這條訂閱確實是可收線的（排除「本來就沒接上」的假綠）
	if n := hub.DisconnectByUser(victim.ID); n != 1 {
		t.Fatalf("對照組收線數 = %d, want 1", n)
	}
	expectClosed(t, watching, "管理者顯式收線後")
}
