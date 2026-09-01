package main

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/observability"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/sshproxy"
)

// 封印閘與段 1 路由面。

// sealGateWhitelist 是封印期唯一可達的端點集合。
//
// 三項缺一不可：健康檢查（監控必須能探測到「服務在跑但未解封」）、
// 狀態查詢（管理員與監控無須猜測）、解封端點（否則封印無法解除）。
// 任何擴充 SHALL 先過設計——白名單每多一條，封印期的攻擊面就多一條。
//
// **第四項 `/metrics` 的設計依據**（已過設計）：
// 封印期若回 503，採集端的 `up` 指標歸零，「封印中待解封」與「行程當機」
// 在監控上不可區分，而這兩者的處置完全不同（前者要人去解封，後者要重啟）。
// 新增的攻擊面被限制在**縮減盤**：封印期 registry 內只有封印狀態與行程執行期
// 指標，段 2 服務的指標（含 HTTP）尚未註冊。這道縮減不是優化而是本列成立的前提
// ——段 1 註冊完整路由樹（見 sealedStageOneDeps 說明），若封印期曝光 HTTP 指標，
// 其 `path` 標籤即端點清單全集，等於在未解封狀態下洩漏整份路由表。
// 封印狀態本身不構成新洩漏：`/api/v1/seal/status` 已在本表內。
var sealGateWhitelist = map[[2]string]bool{
	{http.MethodGet, "/health"}:                 true,
	{http.MethodPost, "/health"}:                true,
	{http.MethodGet, "/healthz"}:                true,
	{http.MethodGet, observability.MetricsPath}: true,
	{http.MethodGet, "/api/v1/seal/status"}:     true,
	{http.MethodPost, "/api/v1/seal/unseal"}:    true,
	{http.MethodOptions, "/api/v1/seal/status"}: true,
	{http.MethodOptions, "/api/v1/seal/unseal"}: true,
}

// sealGateMiddleware 是 registerRoutes 的最外層閘。
//
// live 回報「本 router 的完整服務圖是否已就緒」。**不是直接讀狀態機**，
// 理由是兩段啟動用的是兩個 engine：段 1 的 engine 恆回 false（它的業務路由
// 只有佔位 handler，永遠不該被執行），段 2 的 engine 才依狀態機判定。
// 若段 1 的閘改讀狀態機，就會出現「狀態已 unsealed 但 router 尚未換手」的
// 撕裂窗，請求會打到佔位 handler。
//
// 非白名單一律 **503**＋機器碼——不是 500、不是 401：狀態必須可被外部監控
// 正確辨識。未匹配任何路由者（FullPath 為空）同樣走 503：封印期不對外
// 透露路由是否存在。
func sealGateMiddleware(live func() bool) gin.HandlerFunc {
	return (&sealGate{live: live}).Handle
}

// sealGate 是封印閘的具名承載體。
//
// **刻意不是匿名 closure**：gin 以 runtime 函式名記錄中間件鏈，而 closure 的
// 名稱含呼叫點與編譯器序號（`main.<呼叫者>.sealGateMiddleware.funcN`），
// 會隨內聯決策與呼叫位置改變——鏈比對 golden 因此會為了與路由無關的原因變紅。
// 具名方法的名稱是 `main.(*sealGate).Handle-fm`，與其他 handler 同形且穩定。
type sealGate struct {
	live func() bool
}

// Handle 是封印閘的中間件本體。
func (g *sealGate) Handle(c *gin.Context) {
	if g.live() || sealGateAllows(c) {
		c.Next()
		return
	}
	c.Abort()
	apierror.Respond(c, http.StatusServiceUnavailable, apierror.CodeSealServiceSealed, nil)
}

// sealGateAllows 判定本請求是否落在封印期白名單內。
//
// 一般路徑以 gin 的 FullPath 比對（樣板路徑，不受具體參數值影響）。
// **CORS 預檢另行處理**：專案未註冊任何 OPTIONS 路由，故預檢請求的 FullPath
// 為空字串，只比 FullPath 會把預檢一律擋成 503——瀏覽器隨即封鎖真正的解封
// 請求，跨源部署（dev 的前後端分離）下解封頁因此完全不能用。預檢不觸及任何
// 業務 handler，放行它不擴大封印期的攻擊面。
func sealGateAllows(c *gin.Context) bool {
	if sealGateWhitelist[[2]string{c.Request.Method, c.FullPath()}] {
		return true
	}
	return c.Request.Method == http.MethodOptions &&
		sealGateWhitelist[[2]string{http.MethodOptions, c.Request.URL.Path}]
}

// sealedStageOneDeps 組出段 1 的 routeDeps。
//
// **為何段 1 也註冊完整路由樹**：規格要求封印期「其餘一律 503＋機器碼」。
// 若段 1 只註冊白名單，非白名單路由會回 404——監控無從分辨「服務封印中」
// 與「這條 API 不存在」，而 404 恰恰是最容易被誤讀為「部署錯版本」的訊號。
//
// **為何佔位 handler 是安全的**：它們是零值結構、不持有任何服務，且閘在鏈首
// 無條件 Abort，故永不被執行。這與「先建全部服務再擋路由」相反——此處**沒有
// 任何服務被建構**，KEK 材料自始至終不在啟動期取得。零值結構足以完成註冊
// 的證據是既有的 golden 迴歸測試：它以同一手法擷取整份路由表。
func sealedStageOneDeps(cfg stageOneRouteConfig, sealHandler *api.SealHandler) routeDeps {
	return routeDeps{
		sealOnly: cfg.sealOnly,
		// 段 1 的閘恆封印：本 engine 於解封成功後即被換下，不存在「該放行」的時刻。
		sealGate:       sealGateMiddleware(func() bool { return false }),
		seal:           sealHandler,
		corsMiddleware: cfg.corsMiddleware,
		metrics:        cfg.metrics,
		metricsToken:   cfg.metricsToken,
		// 審計中間件於段 1 關閉：其寫入鏈依賴段 2 才建構的蓋章服務與
		// AuditLogService。封印期的留痕由 journal 承擔，不靠 DB 審計。
		auditLogEnabled: false,

		auth:                  &api.AuthHandler{},
		securityPolicy:        &api.SecurityPolicyHandler{},
		syslogSetting:         &api.SyslogSettingHandler{},
		auditIntegrity:        &api.AuditIntegrityHandler{},
		auditCheckpoint:       &api.AuditCheckpointHandler{},
		asset:                 &api.AssetHandler{},
		assetAccount:          &api.AssetAccountHandler{},
		session:               &api.SessionHandler{},
		myConnection:          &api.MyConnectionHandler{},
		sessionCommand:        &api.SessionCommandHandler{},
		alertRule:             &api.AlertRuleHandler{},
		commandAlert:          &api.CommandAlertHandler{},
		dailyReview:           &api.DailyReviewHandler{},
		auditFailure:          &api.AuditFailureHandler{},
		transmissionInventory: &api.TransmissionInventoryHandler{},
		notificationChannel:   &api.NotificationChannelHandler{},
		oidc:                  &api.OIDCHandler{},
		ldapDirectory:         &api.LDAPDirectoryHandler{},
		offsiteStorage:        &api.OffsiteStorageHandler{},
		instanceGuard:         &api.InstanceGuardHandler{},
		keyManagement:         &api.KeyManagementHandler{},
		snippet:               &api.SnippetHandler{},
		assetGroup:            &api.AssetGroupHandler{},
		userGroup:             &api.UserGroupHandler{},
		user:                  &api.UserHandler{},
		role:                  &api.RoleHandler{},
		authorization:         &api.AuthorizationHandler{},
		recording:             &api.RecordingHandler{},
		auditLog:              &api.AuditLogHandler{},
		exportSigning:         &api.ExportSigningHandler{},
		auditExport:           &api.AuditExportHandler{},
		accessReview:          &api.AccessReviewHandler{},
		hostKey:               &api.HostKeyHandler{},
		clipboard:             &api.ClipboardEventHandler{},
		auditTimeline:         &api.AuditTimelineHandler{},
		changeSecret:          &api.ChangeSecretHandler{},
		accessRequest:         &api.AccessRequestHandler{},
		sftp:                  &api.SFTPHandler{},

		conn: &proxy.ConnectionHandler{},
		ssh:  &sshproxy.Handler{},
	}
}

// stageOneRouteConfig 是段 1 註冊路由所需的最小組態。
type stageOneRouteConfig struct {
	corsMiddleware gin.HandlerFunc
	// metrics 段 1／段 2 共用的指標實例。
	// 共用而非各建一份：counter 在換 router 時歸零會被採集端讀成行程重啟。
	metrics *observability.Metrics
	// metricsToken 指標端點的 bearer token；空＝免認證
	metricsToken string
	// sealOnly 為真時只註冊 seal 端點群與健康檢查（獨立解封監聽）。
	//
	// **這是網段隔離之所以成立的關鍵**：獨立監聽若共用主 router，解封成功後
	// 換上的完整業務樹就會同時暴露在管理監聽上——部署方以為自己把解封端點
	// 收進管理網段，實際上是把整個產品多開了一個入口。
	sealOnly bool
}

// swappableHandler 是 http.Server 的固定 Handler，內部指向當前生效的 router。
//
// 兩段啟動需要在解封成功後把段 1 的最小 router 換成段 2 的完整 router，而
// http.Server.Handler 不可在 Serve 之後安全改寫。以一層 atomic 間接解決：
// 換手是單一指標交換，讀取端無鎖。
//
// **換手時機 SHALL 晚於 publish**：段 2 完成 → 寫 SUCCESS ＋同步 → publish CAS
// → 換手 → 回應。任何提前換手都會在 SUCCESS 未 durable 時放行服務。
type swappableHandler struct {
	current atomic.Pointer[http.Handler]
}

// Set 安裝當前生效的 handler。
func (s *swappableHandler) Set(h http.Handler) { s.current.Store(&h) }

// ServeHTTP 轉發至當前生效的 handler。
//
// 尚未安裝時回 503＋機器碼而非 panic：監聽開放與 handler 安裝之間即使只有
// 幾微秒，那也是一個真實可被打中的窗口，回 503 與封印期語義一致。
func (s *swappableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p := s.current.Load(); p != nil {
		(*p).ServeHTTP(w, r)
		return
	}
	// **只送機器碼、不送文字**：此處取不到 gin.Context，因而無法走
	// apierror.Respond；自行拼一段文字會成為一個新的裸文字錯誤出口
	// （sink 守衛會擋，而且該擋——同一個碼會就此有兩份可各自漂移的文案）。
	// 呼叫端一律由 code 取三語文案，缺 error 欄不影響其解讀。
	payload, err := json.Marshal(map[string]string{"code": string(apierror.CodeSealServiceSealed)})
	if err != nil {
		payload = []byte(`{"code":"` + string(apierror.CodeSealServiceSealed) + `"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(payload)
}
