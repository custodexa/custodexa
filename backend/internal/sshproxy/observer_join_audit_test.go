package sshproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 加入他人會話的唯讀觀看必須留痕。
//
// # 缺陷
//
// `/sessions/:id/monitor` 與 `/sessions/share/:code/ws` 兩條路由都不掛
// AuthMiddleware（`cmd/server/main.go`：WebSocket 只能以 query token 認證），
// `authenticate` 的 `?token=` 分支不寫 `userID`，而 `AuditLogMiddleware` 缺
// userID／username 即整筆跳過（`internal/middleware/audit_log.go`）。
// 修法前 `audit_logs` 對「誰旁觀了誰」為**零列**（實測 2026-08-13）。
//
// 在 PAM 產品裡這是最難向稽核解釋的一種無痕：管理員可即時看遍所有人的終端輸入
// （含跳板後鍵入的憑證），而系統對此毫無紀錄——與「沒有人看過」不可分辨。
//
// # 本檔守的四件事
//
//  1. 監看加入**必然**產生一列，且答得出「誰、何時、看了哪一場會話、哪台資產」。
//  2. 分享碼加入同樣產生一列，並以 `via` 與監看區分（同一個 hub、兩條入口）。
//  3. 無效分享碼的**拒絕**也留痕（反覆試碼是猜測攻擊的訊號）。
//  4. **恰好一列**：證明列來自 handler，且掛著的真 `AuditLogMiddleware` 確實跳過
//     這條路徑——若哪天有人把路由移進認證群組，列數變 2，本檔轉紅並提醒重新設計。
//
// # 突變自檢
//
// 拿掉 `HandleMonitor` 內的 `h.auditObserverJoin(...)` ⇒ 只有監看格轉紅；
// 拿掉 `HandleShareJoin` 內成功分支的呼叫 ⇒ 只有分享格轉紅；
// 拿掉無效碼分支的呼叫 ⇒ 只有拒絕格轉紅。三者互不掩蓋。

const observerAuditSecret = "observer-join-audit-secret"

// observerAuditSession 被觀看的會話（seed 後 ID 恆為 1）
const observerAuditSession = uint(1)

// observerAuditOwner 被觀看會話的擁有者（即「誰被看了」）
const observerAuditOwner = uint(999)

// observerAuditAsset 被觀看會話所在的資產
const observerAuditAsset = uint(1)

type observerAuditEnv struct {
	h   *Handler
	db  *gorm.DB
	tap *monitorTap
	pid uint
}

// setupObserverAuditEnv 與生產同構的最小鏈路：真 handler ＋ 真 audit service
// ＋ 真 sqlite ＋ 真 AuditLogMiddleware，斷言 `audit_logs` 實列。
//
// 審計服務刻意 `AsyncAuditEnabled: false`：生產走非同步 channel，測試若也走，
// 斷言就得靠輪詢等待，而「等不到」與「根本沒寫」在失敗訊息上無從分辨。
func setupObserverAuditEnv(t *testing.T) *observerAuditEnv {
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

	env := &observerAuditEnv{db: db}
	env.pid = seedWSTokenProvider(t, db, "cid-observer-audit")

	if err := db.Create(&model.Asset{Name: "target-host", Protocol: "ssh", Host: "h", Port: 22}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	assetID := observerAuditAsset
	if err := db.Create(&model.Session{
		SessionID: "sess-observer-audit", UserID: observerAuditOwner, AssetID: &assetID,
		Protocol: model.ProtocolSSH, Status: model.SessionStatusActive,
		StartTime: time.Now().Add(-time.Minute),
	}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// seed 的資產建立會經 GORM hook 落一筆自己的審計列（AP-23）：清空後起算，
	// 使本檔的「恰好一列」斷言指的是**觀看事件**的列數
	if err := db.Exec("DELETE FROM audit_logs").Error; err != nil {
		t.Fatalf("清空 seed 期審計列: %v", err)
	}

	auditService := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	auth := identity.NewAuthService(observerAuditSecret, 15*time.Minute)
	env.h = NewHandler(nil, auth, nil, session.NewSessionService(nil), nil, "", auditService)
	env.tap = env.h.Monitor.OpenRoom(observerAuditSession, 80, 24)
	return env
}

// seedObserver 建一個啟用的觀察者帳號
func (e *observerAuditEnv) seedObserver(t *testing.T, username string) *model.User {
	t.Helper()
	u := &model.User{Username: username, Password: "x", Active: true}
	if err := e.db.Create(u).Error; err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
	return u
}

// token 簽一張與生產同形的 connection token（脈絡取 DB 現值，必然通過世代閘）
func (e *observerAuditEnv) token(t *testing.T, u *model.User, role string) string {
	t.Helper()
	var p model.OIDCProvider
	if err := e.db.First(&p, e.pid).Error; err != nil {
		t.Fatalf("load provider: %v", err)
	}
	tok, err := crypto.NewJWTManager(observerAuditSecret, 15*time.Minute).GenerateToken(
		u.ID, u.Username, "", role, crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: e.pid,
			AuthEpoch: p.AuthEpoch, CredEpoch: u.CredentialEpoch,
		})
	if err != nil {
		t.Fatalf("簽發 connection token: %v", err)
	}
	return tok
}

// router 掛上與生產同一位置的真審計中介層（全域 r.Use，見 cmd/server/main.go），
// 使「中介層對這條路由確實零列」成為機器事實而非讀者的推論
func (e *observerAuditEnv) router() *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(e.h.AuditService))
	r.GET("/api/v1/sessions/:id/monitor", e.h.HandleMonitor)
	r.GET("/api/v1/sessions/share/:code/ws", e.h.HandleShareJoin)
	return r
}

// waitAuditRows 等到審計列達到期望筆數並回傳；逾時即視為未寫入。
// 加入事件寫在 Join 之後，與 WS 握手完成之間有微秒級的窗口，故用輪詢而非睡眠
func (e *observerAuditEnv) waitAuditRows(t *testing.T, want int, why string) []model.AuditLog {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var rows []model.AuditLog
	for {
		rows = nil
		if err := e.db.Order("id asc").Find(&rows).Error; err != nil {
			t.Fatalf("查 audit_logs: %v", err)
		}
		if len(rows) >= want {
			return rows
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s：期限內只等到 %d 列審計，want %d（零列＝留痕未寫入）",
				why, len(rows), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// assertObserverRow 逐欄檢查一列觀看留痕
func assertObserverRow(t *testing.T, row model.AuditLog, want observerRowExpect) {
	t.Helper()
	if row.UserID != want.userID {
		t.Errorf("%s：user_id = %d, want %d（誰在監看答不出來）", want.why, row.UserID, want.userID)
	}
	if row.Username != want.username {
		t.Errorf("%s：username = %q, want %q", want.why, row.Username, want.username)
	}
	if row.Action != model.ActionRead {
		t.Errorf("%s：action = %q, want %q", want.why, row.Action, model.ActionRead)
	}
	if row.Resource != model.ResourceSession {
		t.Errorf("%s：resource = %q, want %q", want.why, row.Resource, model.ResourceSession)
	}
	if row.Status != want.status {
		t.Errorf("%s：status = %q, want %q", want.why, row.Status, want.status)
	}
	if want.sessionID == 0 {
		if row.ResourceID != nil {
			t.Errorf("%s：resource_id = %v, want nil（碼解析不出目標會話）", want.why, *row.ResourceID)
		}
	} else {
		if row.ResourceID == nil || *row.ResourceID != want.sessionID {
			t.Errorf("%s：resource_id = %v, want %d（看的是哪一場會話答不出來）",
				want.why, row.ResourceID, want.sessionID)
		}
		if row.AssetID == nil || *row.AssetID != observerAuditAsset {
			t.Errorf("%s：asset_id = %v, want %d（看的是哪台資產答不出來，資產樞紐上等同沒發生）",
				want.why, row.AssetID, observerAuditAsset)
		}
	}
	if row.ClientIP == "" {
		t.Errorf("%s：client_ip 為空（來源位址是稽核比對的主要欄）", want.why)
	}
	if row.Path != want.path {
		t.Errorf("%s：path = %q, want %q", want.why, row.Path, want.path)
	}
	if !strings.Contains(row.Details, `"via":"`+want.via+`"`) {
		t.Errorf("%s：details = %q 未標記 via=%s（監看與分享兩條入口無從區分）",
			want.why, row.Details, want.via)
	}
	if want.targetUserID != 0 &&
		!strings.Contains(row.Details, `"target_user_id":`+itoa(want.targetUserID)) {
		t.Errorf("%s：details = %q 未記被監看者（「誰被看了」答不出來）", want.why, row.Details)
	}
	if row.CreatedAt.IsZero() {
		t.Errorf("%s：created_at 為零值（加入時間答不出來）", want.why)
	}
}

type observerRowExpect struct {
	why          string
	userID       uint
	username     string
	sessionID    uint
	targetUserID uint
	via          string
	status       model.AuditStatus
	path         string
}

func itoa(v uint) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// --- 格 1：監看加入留痕（本 change 的最高優先項）---

// TestMonitorJoinWritesAuditRow 稽核必須答得出「誰於何時監看了哪個會話與資產」。
func TestMonitorJoinWritesAuditRow(t *testing.T) {
	e := setupObserverAuditEnv(t)
	obs := e.seedObserver(t, "monitor-observer")

	ws := dialWS(t, e.router(), "/api/v1/sessions/1/monitor?token="+e.token(t, obs, model.RoleAdmin))
	waitRegistered(t, e.tap, ws, "監看訂閱")

	rows := e.waitAuditRows(t, 1, "監看加入")
	if len(rows) != 1 {
		t.Fatalf("監看加入應恰好一列（handler 寫、中介層跳過），實得 %d 列", len(rows))
	}
	assertObserverRow(t, rows[0], observerRowExpect{
		why: "監看加入", userID: obs.ID, username: obs.Username,
		sessionID: observerAuditSession, targetUserID: observerAuditOwner,
		via: observerViaMonitor, status: model.StatusSuccess,
		path: "/api/v1/sessions/:id/monitor",
	})
}

// --- 格 2：分享碼加入留痕 ---

// TestShareJoinWritesAuditRow 分享觀看與監看走同一個 hub，留痕必須同樣完整；
// `via` 是兩條入口在資料上唯一的區分。
func TestShareJoinWritesAuditRow(t *testing.T) {
	e := setupObserverAuditEnv(t)
	obs := e.seedObserver(t, "share-observer")
	code, _, err := e.h.Shares.Create(observerAuditSession, observerAuditOwner, time.Minute)
	if err != nil {
		t.Fatalf("建立分享碼: %v", err)
	}

	ws := dialWS(t, e.router(),
		"/api/v1/sessions/share/"+code+"/ws?token="+e.token(t, obs, model.RoleUser))
	waitRegistered(t, e.tap, ws, "分享訂閱")

	rows := e.waitAuditRows(t, 1, "分享加入")
	if len(rows) != 1 {
		t.Fatalf("分享加入應恰好一列，實得 %d 列", len(rows))
	}
	assertObserverRow(t, rows[0], observerRowExpect{
		why: "分享加入", userID: obs.ID, username: obs.Username,
		sessionID: observerAuditSession, targetUserID: observerAuditOwner,
		via: observerViaShare, status: model.StatusSuccess,
		path: "/api/v1/sessions/share/:code/ws",
	})
	// 分享碼是短期憑證，不得落進長期保存的審計表
	if strings.Contains(rows[0].Path, code) || strings.Contains(rows[0].Details, code) {
		t.Errorf("分享碼落入審計列（path=%q details=%q）", rows[0].Path, rows[0].Details)
	}
}

// --- 格 3：無效分享碼的拒絕留痕 ---

// TestInvalidShareCodeRejectionWritesAuditRow 反覆試碼是猜測攻擊的訊號；
// 不留痕即與「沒有人試過」無從分辨。
func TestInvalidShareCodeRejectionWritesAuditRow(t *testing.T) {
	e := setupObserverAuditEnv(t)
	obs := e.seedObserver(t, "share-guesser")

	srv := httptest.NewServer(e.router())
	defer srv.Close()
	url := srv.URL + "/api/v1/sessions/share/not-a-real-code/ws?token=" + e.token(t, obs, model.RoleUser)
	resp, err := http.Get(url) //nolint:gosec // 測試伺服器位址
	if err != nil {
		t.Fatalf("請求失效分享碼: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("失效分享碼狀態碼 = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	rows := e.waitAuditRows(t, 1, "失效分享碼拒絕")
	if len(rows) != 1 {
		t.Fatalf("失效分享碼拒絕應恰好一列，實得 %d 列", len(rows))
	}
	assertObserverRow(t, rows[0], observerRowExpect{
		why: "失效分享碼拒絕", userID: obs.ID, username: obs.Username,
		via: observerViaShare, status: model.StatusDenied,
		path: "/api/v1/sessions/share/:code/ws",
	})
	if rows[0].StatusCode != http.StatusNotFound {
		t.Errorf("失效分享碼拒絕：status_code = %d, want %d", rows[0].StatusCode, http.StatusNotFound)
	}
	if !strings.Contains(rows[0].Details, `"via":"`+observerViaShare+`"`) {
		t.Errorf("失效分享碼拒絕：details = %q 未標記入口", rows[0].Details)
	}
}

// --- 格 4：WebSocket 升級不吞掉留痕 ---

// TestMonitorJoinAuditSurvivesObserverDisconnect 觀察者立刻離線也不得吃掉留痕：
// 監看紀錄的價值在於「他曾經看過」，看多久是另一回事。
func TestMonitorJoinAuditSurvivesObserverDisconnect(t *testing.T) {
	e := setupObserverAuditEnv(t)
	obs := e.seedObserver(t, "drive-by-observer")

	ws := dialWS(t, e.router(), "/api/v1/sessions/1/monitor?token="+e.token(t, obs, model.RoleAuditor))
	waitRegistered(t, e.tap, ws, "監看訂閱")
	_ = ws.Close()

	rows := e.waitAuditRows(t, 1, "監看加入後立即離線")
	if rows[0].Status != model.StatusSuccess || rows[0].ResourceID == nil {
		t.Fatalf("監看加入後立即離線：留痕不完整 status=%q resource_id=%v",
			rows[0].Status, rows[0].ResourceID)
	}
}
