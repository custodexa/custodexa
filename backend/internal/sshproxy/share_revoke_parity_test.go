package sshproxy

import (
	"github.com/custodexa/backend/internal/modules/identity"
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

// 分享觀看與監看同受撤銷治理。
//
// 兩條路徑各自升級 WebSocket、各自組出 ObserverContext、各自呼叫
// JoinWithGenerationGuard——**是兩份程式碼**（handler.go 的 HandleMonitor 與
// HandleShareJoin）。既有的 monitor_revoke_test.go 只驗 MonitorHub 本體，
// 對「分享端漏填 ObserverContext」或「分享端沒過世代閘」完全無感：那時
// 分享連結就是一條繞過撤銷的旁路，而 hub 層的測試依然全綠。
//
// 故本檔的**每一格都跑兩遍**（monitor／share），且一律走 HTTP handler 進入，
// 不直接呼叫 hub.Join——直接呼叫 hub 等於把被測的那段程式碼跳過去。
//
// **脈絡一律由真 `?token=` 帶入**：本檔原以
// `c.Set("authContext", …)` 注入，等於替 handler 把它最該做的那件事先做完了——
// 而生產路徑上這兩條路由都不掛 AuthMiddleware，authContext 若沒人寫入即恆為零值。
// 那正是最危險的形狀：實作壞掉、本檔全綠。唯一的例外是 TestSubscriptionJoinGuardParity
// （見該處說明：它要製造的競態在 token 閘之後）。
//
// 突變自檢（任一即應轉紅）：
//   - 把 HandleShareJoin 的 shareObs 改成只填 UserID（丟掉 ProviderID）：
//     share 的「provider 停用收線」格轉紅，monitor 仍綠——正是「只改一處」的形狀。
//   - 把 HandleShareJoin 的 JoinWithGenerationGuard 換回裸 h.Monitor.Join：
//     share 的「建立點世代閘」格轉紅。
//   - 把 Handler.authenticate 的 `c.Set("authContext", …)` 刪掉：
//     前三格的 monitor 與 share 皆轉紅。

// --- harness ---

type shareParityEnv struct {
	h   *Handler
	db  *gorm.DB
	tap *monitorTap
	pid uint // 啟用中的 provider
	oth uint // 另一個 provider（對照組）
}

const parityMonitoredSession = uint(1)

func setupShareParity(t *testing.T) *shareParityEnv {
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

	env := &shareParityEnv{db: db}
	env.pid = seedParityProvider(t, db, "cid-active")
	env.oth = seedParityProvider(t, db, "cid-other")

	// 觀察者三人皆 admin：monitor 需 admin/auditor，share 不限角色；
	// 兩條路徑用同一組身分，矩陣才真的是「同一份」
	for i, name := range []string{"obs-a", "obs-b", "obs-local"} {
		if err := db.Create(&model.User{Username: name, Password: "x", Active: true}).Error; err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		// 監看票的角色現查讀的是 DB 角色列，不是 JWT 快照
		grantDBRole(t, db, uint(i+1), model.RoleAdmin)
	}
	if err := db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	assetID := uint(1)
	if err := db.Create(&model.Session{
		SessionID: "sess-parity", UserID: 1, AssetID: &assetID,
		Protocol: model.ProtocolSSH, Status: model.SessionStatusActive,
		StartTime: time.Now().Add(-time.Minute),
	}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// AuthService 與本檔簽章共用同一把 secret：走真 `?token=` 路徑的前提
	env.h = NewHandler(nil, identity.NewAuthService(parityJWTSecret, 15*time.Minute),
		nil, session.NewSessionService(nil), nil, "", nil)
	env.tap = env.h.Monitor.OpenRoom(parityMonitoredSession, 80, 24)
	return env
}

const parityJWTSecret = "share-parity-test-secret"

// signParityToken 簽一張與生產同形的 connection token（脈絡即由此進入 handler）
func (e *shareParityEnv) signParityToken(t *testing.T, userID uint, role string,
	authCtx crypto.AuthContext) string {
	t.Helper()
	var u model.User
	if err := e.db.First(&u, userID).Error; err != nil {
		t.Fatalf("load user %d: %v", userID, err)
	}
	tok, err := crypto.NewJWTManager(parityJWTSecret, 15*time.Minute).
		GenerateToken(userID, u.Username, "", role, authCtx)
	if err != nil {
		t.Fatalf("簽發 connection token: %v", err)
	}
	return tok
}

func seedParityProvider(t *testing.T, db *gorm.DB, clientID string) uint {
	t.Helper()
	p := model.OIDCProvider{
		Name: clientID, Issuer: "https://idp.example/" + clientID,
		ClientID: clientID, Enabled: true, AuthEpoch: 0,
	}
	if err := db.Create(&p).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).
		Update("enabled", true).Error; err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	return p.ID
}

// oidcCtx 經指定 provider 認證的觀察者脈絡（世代取 DB 現值，故 Join 必過閘）
func (e *shareParityEnv) oidcCtx(t *testing.T, providerID uint) crypto.AuthContext {
	t.Helper()
	var p model.OIDCProvider
	if err := e.db.First(&p, providerID).Error; err != nil {
		t.Fatalf("load provider %d: %v", providerID, err)
	}
	return crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: providerID, AuthEpoch: p.AuthEpoch,
	}
}

// disableProvider 停用 provider 並推進世代（模擬 3.8 失效流程的 DB 效果）
func (e *shareParityEnv) disableProvider(t *testing.T, providerID uint) {
	t.Helper()
	if err := e.db.Model(&model.OIDCProvider{}).Where("id = ?", providerID).
		Updates(map[string]any{"enabled": false, "auth_epoch": gorm.Expr("auth_epoch + 1")}).
		Error; err != nil {
		t.Fatalf("disable provider: %v", err)
	}
}

// --- 兩條進入路徑 ---

// joinPath 一條「取得唯讀訂閱」的產品路徑。兩條路徑的差異只在 handler，
// 其餘（身分、脈絡、被觀察的會話）完全相同——差異一旦出現即是治理不一致
type joinPath struct {
	name string
	// prepare 走生產路徑取得一張一次性觀看票（含建路由與分享碼），
	// **尚未建立 WS 連線**——取票與建線之間的窗口是訂閱建立點世代閘的射程
	prepare func(t *testing.T, e *shareParityEnv, userID uint, authCtx crypto.AuthContext) joinAttempt
}

// joinAttempt 已取得票證、尚未建線的一次觀看嘗試
type joinAttempt struct {
	r     *gin.Engine
	wsURL string
}

// dial 以既有票證建立 WS 連線
func (a joinAttempt) dial(t *testing.T) *websocket.Conn {
	t.Helper()
	return dialWS(t, a.r, a.wsURL)
}

// dial 取票並建線（成功路徑的常用組合）
func (p joinPath) dial(t *testing.T, e *shareParityEnv, userID uint,
	authCtx crypto.AuthContext) *websocket.Conn {
	t.Helper()
	return p.prepare(t, e, userID, authCtx).dial(t)
}

func allJoinPaths() []joinPath {
	return []joinPath{
		{name: "monitor", prepare: prepareMonitorPath},
		{name: "share", prepare: prepareSharePath},
	}
}

func prepareMonitorPath(t *testing.T, e *shareParityEnv, userID uint,
	authCtx crypto.AuthContext) joinAttempt {
	t.Helper()
	// 與 main.go 完全一致：簽發掛 AuthMiddleware、WS 不掛
	r := observerTicketEngine(e.h, e.h.AuthService)
	ticket := mustObserverTicket(t, r, monitorTicketPath(parityMonitoredSession),
		e.signParityToken(t, userID, model.RoleAdmin, authCtx))
	return joinAttempt{r: r, wsURL: monitorWSPath(parityMonitoredSession, ticket)}
}

func prepareSharePath(t *testing.T, e *shareParityEnv, userID uint,
	authCtx crypto.AuthContext) joinAttempt {
	t.Helper()
	code := newParityShareCode(t, e)
	r := observerTicketEngine(e.h, e.h.AuthService)
	// 分享觀看不限角色，刻意用非 admin
	ticket := mustObserverTicket(t, r, shareTicketPath,
		e.signParityToken(t, userID, model.RoleUser, authCtx), shareTicketBody(code))
	return joinAttempt{r: r, wsURL: shareWSPath(code, ticket)}
}

// newParityShareCode 分享碼由會話擁有者建立；加入者是另一個已登入使用者（產品語義）
func newParityShareCode(t *testing.T, e *shareParityEnv) string {
	t.Helper()
	code, _, err := e.h.Shares.Create(parityMonitoredSession, 1, time.Minute)
	if err != nil {
		t.Fatalf("建立分享碼: %v", err)
	}
	return code
}

func dialWS(t *testing.T, r *gin.Engine, path string) *websocket.Conn {
	t.Helper()
	srv := httptest.NewServer(r)
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+path, nil)
	if err != nil {
		srv.Close()
		t.Fatalf("dial %s: %v", path, err)
	}
	t.Cleanup(func() {
		ws.Close()
		srv.Close()
	})
	return ws
}

// waitRegistered 等到該連線確實進入 room.observers。
//
// WS 握手完成早於 handler 完成 Join，直接收線會測到「還沒加入」而假綠。
// 以廣播探測資料為準：收得到廣播即證明已在 observers 集合內（那正是收線要掃的集合）
func waitRegistered(t *testing.T, tap *monitorTap, ws *websocket.Conn, why string) {
	t.Helper()
	const probe = "parity-probe"
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tap.WriteOutput([]byte(probe))
		_ = ws.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if isTimeout(err) {
				continue
			}
			t.Fatalf("%s：等待訂閱生效時連線已斷: %v", why, err)
		}
		if strings.Contains(string(msg), probe) {
			return
		}
	}
	t.Fatalf("%s：訂閱未於期限內生效", why)
}

func isTimeout(err error) bool {
	te, ok := err.(interface{ Timeout() bool })
	return ok && te.Timeout()
}

// join 走指定路徑建立訂閱並確認已生效
func (e *shareParityEnv) join(t *testing.T, p joinPath, userID uint, authCtx crypto.AuthContext) *websocket.Conn {
	t.Helper()
	ws := p.dial(t, e, userID, authCtx)
	waitRegistered(t, e.tap, ws, p.name+" 訂閱")
	return ws
}

// --- 4.14e 矩陣：每一格跑兩遍 ---

// TestSubscriptionRevocationParityProviderDisabled 4.14e：provider 停用時，
// 分享加入者與監看者一同被收線
func TestSubscriptionRevocationParityProviderDisabled(t *testing.T) {
	for _, p := range allJoinPaths() {
		t.Run(p.name, func(t *testing.T) {
			e := setupShareParity(t)
			victim := e.join(t, p, 1, e.oidcCtx(t, e.pid))
			control := e.join(t, p, 2, e.oidcCtx(t, e.oth))

			if n := e.h.Monitor.DisconnectByProvider(e.pid); n != 1 {
				t.Fatalf("收線數 = %d, want 1", n)
			}
			expectClosed(t, victim, p.name+"：經被停用 provider 認證的訂閱")
			expectAlive(t, control, p.name+"：經另一 provider 認證的訂閱")
		})
	}
}

// TestSubscriptionRevocationParityUserDisabled 4.14e：帳號停用（按-user 收線）時，
// 分享加入者與監看者一同被收線
func TestSubscriptionRevocationParityUserDisabled(t *testing.T) {
	for _, p := range allJoinPaths() {
		t.Run(p.name, func(t *testing.T) {
			e := setupShareParity(t)
			victim := e.join(t, p, 1, e.oidcCtx(t, e.pid))
			control := e.join(t, p, 2, e.oidcCtx(t, e.pid))

			if n := e.h.Monitor.DisconnectByUser(1); n != 1 {
				t.Fatalf("收線數 = %d, want 1", n)
			}
			expectClosed(t, victim, p.name+"：被停用帳號的訂閱")
			expectAlive(t, control, p.name+"：其他使用者的訂閱")
		})
	}
}

// TestSubscriptionRevocationParityLocalObserverNotWildcard 4.14e：
// 本地登入（providerID=0）的分享加入者不得被任何一次 provider 收線誤殺，
// 但按-user 收線必須掃得到——兩條路徑同標準
func TestSubscriptionRevocationParityLocalObserverNotWildcard(t *testing.T) {
	for _, p := range allJoinPaths() {
		t.Run(p.name, func(t *testing.T) {
			e := setupShareParity(t)
			local := e.join(t, p, 3, crypto.AuthContext{}) // 本地登入：providerID=0

			if n := e.h.Monitor.DisconnectByProvider(e.pid); n != 0 {
				t.Fatalf("本地訂閱不應被 provider 收線命中，實得 %d", n)
			}
			expectAlive(t, local, p.name+"：本地登入的訂閱")

			if n := e.h.Monitor.DisconnectByUser(3); n != 1 {
				t.Fatalf("按-user 收線數 = %d, want 1", n)
			}
			expectClosed(t, local, p.name+"：本地登入者被停用後的訂閱")
		})
	}
}

// TestSubscriptionJoinGuardParity 4.14e：訂閱**建立點**的世代閘兩條路徑同在。
//
// 收線只處理「已建立」的訂閱；provider 已停用之後才送達的 Join 請求，
// 若某條路徑沒過閘，就會建立出一個永遠掃不到（因為掃描已跑完）的長效訂閱。
//
// **本格刻意把停用夾在取票與建線之間**：那正是「認證已通過、Join 尚未完成」
// 那段窗口——票在 provider 仍啟用時簽出，停用發生於建線之前。簽發端的世代閘
// 在此擋不到（票已經在手上），能擋的只剩訂閱建立點的閘
func TestSubscriptionJoinGuardParity(t *testing.T) {
	for _, p := range allJoinPaths() {
		t.Run(p.name, func(t *testing.T) {
			e := setupShareParity(t)
			// 先取得停用前的脈絡（等同認證當下讀到的世代）
			authCtx := e.oidcCtx(t, e.pid)

			attempt := p.prepare(t, e, 1, authCtx)
			e.disableProvider(t, e.pid)
			ws := attempt.dial(t)
			expectClosed(t, ws, p.name+"：provider 已停用後的訂閱建立")

			// 且不得留下任何存活的訂閱（掃描已跑完，留下即是永久旁路）
			if n := e.h.Monitor.DisconnectByUser(1); n != 0 {
				t.Fatalf("%s：世代閘拒絕後仍留下 %d 個訂閱", p.name, n)
			}
		})
	}
}

// TestShareJoinCarriesObserverContext 4.14e 的直接斷言：
// 分享路徑填入的 ObserverContext 與監看路徑同構。
//
// 前四格是行為層斷言；這一格鎖住「脈絡欄位有沒有真的填」——UserID 之外的三欄
// 任一漏填，收線的判定依據就殘缺，而多數行為格仍可能因巧合而綠
func TestShareJoinCarriesObserverContext(t *testing.T) {
	e := setupShareParity(t)
	authCtx := e.oidcCtx(t, e.pid)
	e.join(t, joinPath{name: "share", prepare: prepareSharePath}, 1, authCtx)

	// 以「只有正確的 (user, provider) 組合才收得到」反推脈絡欄位確實填入
	if n := e.h.Monitor.DisconnectByUserAndProvider(1, e.oth); n != 0 {
		t.Fatalf("錯誤的 provider 不應命中分享訂閱，實得 %d", n)
	}
	if n := e.h.Monitor.DisconnectByUserAndProvider(2, e.pid); n != 0 {
		t.Fatalf("錯誤的 user 不應命中分享訂閱，實得 %d", n)
	}
	if n := e.h.Monitor.DisconnectByUserAndProvider(1, e.pid); n != 1 {
		t.Fatalf("正確的 (user, provider) 應命中分享訂閱，實得 %d", n)
	}
}
