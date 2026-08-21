package sshproxy

import (
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/gorilla/websocket"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 觀察者脈絡在**生產路徑**上真的存在（idp-oidc-integration 對抗審查 C1）。
//
// 與 share_revoke_parity_test.go 的分工：該檔以 `c.Set("authContext", …)` 注入脈絡，
// 等於替 handler 把它最該做的那件事先做完了——脈絡從哪來、有沒有來，那檔完全測不到。
// 而 `/sessions/:id/monitor` 與 `/sessions/share/:code/ws` **兩條路由都不掛
// AuthMiddleware**（main.go：手動處理認證，支援 WebSocket query token），故生產路徑上
// 唯一可能寫入 authContext 的位置是 Handler.authenticate；它若不寫，
// middleware.GetAuthContext(c) 恆回零值，而所有既有測試依然全綠。
//
// 本檔一律走**真** `?token=` 路徑（簽一張帶 AuthContext 的 connection token，
// 經 handler 的 authenticate 進入），不碰 gin context 的任何注入。
//
// 兩個後果各有一格：
//
//	安全   ProviderID 恆 0 → provider 停用時 DisconnectByProvider 匹配 0 筆，
//	       OIDC 使用者的監看／分享訂閱在其 IdP 已被停用後仍持續讀他人終端內容。
//	功能   CredEpoch 恆 0 → 對 credential_epoch > 0 的使用者（凡改過密、解過綁的）
//	       JoinWithGenerationGuard 恆拒，監看與分享對這些人直接壞掉。
//
// 突變自檢：把 authenticate 內的 `c.Set("authContext", claims.AuthContext)` 刪掉，
// 本檔兩個測試的四格全紅（既有測試無一轉紅）。

const wsTokenSecret = "ws-query-token-test-secret"

// wsTokenMonitoredSession 被監看／被分享的會話（seed 後 ID 恆為 1）
const wsTokenMonitoredSession = uint(1)

type wsTokenEnv struct {
	h   *Handler
	db  *gorm.DB
	tap *monitorTap
	pid uint // 觀察者所經的 provider
	oth uint // 另一個 provider（誤殺對照）
}

func setupWSTokenEnv(t *testing.T) *wsTokenEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// 單連線：ff51836 的「單獨跑綠、整包跑紅」防護
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.Asset{},
		&model.Session{}, &model.OIDCProvider{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	env := &wsTokenEnv{db: db}
	env.pid = seedWSTokenProvider(t, db, "cid-primary")
	env.oth = seedWSTokenProvider(t, db, "cid-other")

	if err := db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	assetID := uint(1)
	if err := db.Create(&model.Session{
		SessionID: "sess-ws-token", UserID: 999, AssetID: &assetID,
		Protocol: model.ProtocolSSH, Status: model.SessionStatusActive,
		StartTime: time.Now().Add(-time.Minute),
	}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// AuthService 與測試簽章共用同一把 secret：ValidateConnectionToken 才驗得過
	auth := identity.NewAuthService(wsTokenSecret, 15*time.Minute)
	env.h = NewHandler(nil, auth, nil, session.NewSessionService(nil), nil, "", nil)
	env.tap = env.h.Monitor.OpenRoom(wsTokenMonitoredSession, 80, 24)
	return env
}

func seedWSTokenProvider(t *testing.T, db *gorm.DB, clientID string) uint {
	t.Helper()
	p := model.OIDCProvider{
		Name: clientID, Issuer: "https://idp.example/" + clientID,
		ClientID: clientID, Enabled: true, AuthEpoch: 7,
	}
	if err := db.Create(&p).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	// Enabled 帶 not null default:false，GORM 對零值交由 DB default 填；顯式回寫
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).
		Update("enabled", true).Error; err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	return p.ID
}

// seedWSTokenUser 建一個啟用帳號並把 credential_epoch 落到指定值
func (e *wsTokenEnv) seedUser(t *testing.T, username string, credEpoch int) *model.User {
	t.Helper()
	u := &model.User{Username: username, Password: "x", Active: true}
	if err := e.db.Create(u).Error; err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
	if err := e.db.Model(&model.User{}).Where("id = ?", u.ID).
		UpdateColumn("credential_epoch", credEpoch).Error; err != nil {
		t.Fatalf("set credential_epoch: %v", err)
	}
	u.CredentialEpoch = credEpoch
	return u
}

// signConnectionToken 簽一張與生產同形的 connection token：脈絡取 DB 現值，
// 故其本身必然通過世代閘——通不過只可能是脈絡在 handler 內遺失
func (e *wsTokenEnv) signConnectionToken(t *testing.T, u *model.User, role string, providerID uint) string {
	t.Helper()
	var p model.OIDCProvider
	if err := e.db.First(&p, providerID).Error; err != nil {
		t.Fatalf("load provider %d: %v", providerID, err)
	}
	tok, err := crypto.NewJWTManager(wsTokenSecret, 15*time.Minute).GenerateToken(
		u.ID, u.Username, "", role, crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: providerID,
			AuthEpoch: p.AuthEpoch, CredEpoch: u.CredentialEpoch,
		})
	if err != nil {
		t.Fatalf("簽發 connection token: %v", err)
	}
	return tok
}

// --- 兩條「不掛 AuthMiddleware、走 ?token=」的生產路徑 ---

type wsTokenPath struct {
	name string
	// route 組出該路徑的 gin engine 與帶 token 的 URL（皆不掛 AuthMiddleware，與 main.go 一致）
	route func(t *testing.T, e *wsTokenEnv, token string) (*gin.Engine, string)
}

func allWSTokenPaths() []wsTokenPath {
	return []wsTokenPath{
		{name: "monitor", route: routeMonitorWithQueryToken},
		{name: "share", route: routeShareWithQueryToken},
	}
}

func routeMonitorWithQueryToken(t *testing.T, e *wsTokenEnv, token string) (*gin.Engine, string) {
	t.Helper()
	r := gin.New()
	// 與 main.go 完全一致：不掛 AuthMiddleware
	r.GET("/api/v1/sessions/:id/monitor", e.h.HandleMonitor)
	return r, "/api/v1/sessions/1/monitor?token=" + token
}

func routeShareWithQueryToken(t *testing.T, e *wsTokenEnv, token string) (*gin.Engine, string) {
	t.Helper()
	code, _, err := e.h.Shares.Create(wsTokenMonitoredSession, 999, time.Minute)
	if err != nil {
		t.Fatalf("建立分享碼: %v", err)
	}
	r := gin.New()
	r.GET("/api/v1/sessions/share/:code/ws", e.h.HandleShareJoin)
	return r, "/api/v1/sessions/share/" + code + "/ws?token=" + token
}

// dial 走該路徑建立連線（握手須成功；Join 被拒是升級**之後**的事，仍握手成功）
func (p wsTokenPath) dial(t *testing.T, e *wsTokenEnv, token string) *websocket.Conn {
	t.Helper()
	r, url := p.route(t, e, token)
	return dialWS(t, r, url)
}

// dialExpectHandshakeRejected 期待連線在 WS 升級**之前**即被 authenticate 擋下
func (p wsTokenPath) dialExpectHandshakeRejected(t *testing.T, e *wsTokenEnv, token, why string) {
	t.Helper()
	r, url := p.route(t, e, token)
	srv := httptest.NewServer(r)
	defer srv.Close()
	ws, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+url, nil)
	if err == nil {
		ws.Close()
		t.Fatalf("%s：%s 不應握手成功", p.name, why)
	}
	if resp == nil {
		t.Fatalf("%s：%s 無 HTTP 回應（err=%v）", p.name, why, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("%s：%s 狀態碼 = %d, want %d", p.name, why, resp.StatusCode, http.StatusUnauthorized)
	}
}

// --- C1 第一格：脈絡真的抵達 ObserverContext（安全） ---

// TestQueryTokenObserverCarriesProviderContext 經 `?token=` 進入的觀察者，
// 其 ObserverContext SHALL 帶 token 內的 providerID——否則 provider 停用時
// DisconnectByProvider 一筆都匹配不到，該訂閱在 IdP 已停用後仍持續讀終端內容。
//
// 三條斷言合起來才鎖得住「providerID 確實是 token 那一個」：錯的 provider 不命中、
// 錯的 user 不命中、對的組合命中；最後以 DisconnectByProvider 端到端收線收尾。
func TestQueryTokenObserverCarriesProviderContext(t *testing.T) {
	for _, p := range allWSTokenPaths() {
		t.Run(p.name, func(t *testing.T) {
			e := setupWSTokenEnv(t)
			u := e.seedUser(t, "obs-"+p.name, 0)
			ws := p.dial(t, e, e.signConnectionToken(t, u, model.RoleAdmin, e.pid))
			waitRegistered(t, e.tap, ws, p.name+" 訂閱")

			if n := e.h.Monitor.DisconnectByUserAndProvider(u.ID, e.oth); n != 0 {
				t.Fatalf("%s：錯誤的 provider 不應命中，實得 %d", p.name, n)
			}
			if n := e.h.Monitor.DisconnectByUserAndProvider(u.ID+1, e.pid); n != 0 {
				t.Fatalf("%s：錯誤的 user 不應命中，實得 %d", p.name, n)
			}
			if n := e.h.Monitor.DisconnectByProvider(e.pid); n != 1 {
				t.Fatalf("%s：provider 停用應收線該訂閱，實得 %d（脈絡遺失時 ProviderID=0，恆不匹配）",
					p.name, n)
			}
			expectClosed(t, ws, p.name+"：經被停用 provider 認證的訂閱")
		})
	}
}

// --- C1 第二格：credential_epoch > 0 的使用者仍可訂閱（功能迴歸） ---

// TestQueryTokenObserverWithAdvancedCredentialEpochCanJoin 凡改過密、解過綁的
// 使用者其 credential_epoch > 0；脈絡若在 handler 內遺失，JoinWithGenerationGuard
// 會拿零值世代去比對而**恆拒**，監看與分享對這群人直接壞掉。
//
// 對照組（epoch=0 的使用者可加入）不可省：少了它，「epoch>0 也能加入」無法排除
// 「這條路徑根本沒有世代閘」。
func TestQueryTokenObserverWithAdvancedCredentialEpochCanJoin(t *testing.T) {
	for _, p := range allWSTokenPaths() {
		t.Run(p.name, func(t *testing.T) {
			e := setupWSTokenEnv(t)

			baseline := e.seedUser(t, "epoch-zero-"+p.name, 0)
			bws := p.dial(t, e, e.signConnectionToken(t, baseline, model.RoleAdmin, e.pid))
			waitRegistered(t, e.tap, bws, p.name+" 對照組（epoch=0）訂閱")

			rotated := e.seedUser(t, "epoch-three-"+p.name, 3)
			rws := p.dial(t, e, e.signConnectionToken(t, rotated, model.RoleAdmin, e.pid))
			waitRegistered(t, e.tap, rws, p.name+" 訂閱（credential_epoch=3）")

			// 世代閘仍在：拿舊世代的 token 必須被拒（不是把閘拆了才變綠）。
			// 該判定在 ValidateConnectionToken 內，故連 WS 升級都到不了
			stale, err := crypto.NewJWTManager(wsTokenSecret, 15*time.Minute).GenerateToken(
				rotated.ID, rotated.Username, "", model.RoleAdmin, crypto.AuthContext{
					AuthMethod: crypto.AuthMethodOIDC, ProviderID: e.pid,
					AuthEpoch: 7, CredEpoch: 2,
				})
			if err != nil {
				t.Fatalf("簽發過期世代 token: %v", err)
			}
			p.dialExpectHandshakeRejected(t, e, stale, "credential_epoch 已過期的 token")
		})
	}
}
