package main

import (
	"context"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/branding"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/observability"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/internal/sshproxy"
)

// Version 產品版本號，**由建置時注入**：正式版於 docker/backend/Dockerfile 以
// `-ldflags -X main.Version=...` 帶入，值取自專案根 VERSION 檔（單一事實源，
// 與 CHANGELOG.md 的一致性由 TestVersionFileMatchesChangelog 釘住）；開發版由
// Air 於容器內建置時帶入（backend/.air.toml 讀 CUSTODEXA_VERSION）。
//
// **預設值刻意不是任何版本字面值**：本變數經 /health 對外揭露，手寫常數必然漂移
// ——它曾停在一個開發初期的握手版字面值而產品已發布 1.0.1，打健康檢查的人看到的
// 版本與 CHANGELOG／Release 不符。未注入的建置（go run、go test）自稱 dev，
// 不冒充任何已發布版本；該預設由 TestServerVersionIsBuildInjected 把關。
//
// **只揭露版號、不揭露 commit hash 或建置時間**（docs/security/
// vulnerability-response-process.md）：BuildTime 僅供啟動日誌，不進 /health。
var (
	Version   = "dev"
	BuildTime = time.Now().Format("2006-01-02 15:04:05")
)

// oidcIssuerDeclarationDigest 本副本所讀到的 `OIDC_DEDICATED_ISSUERS` 宣告指紋，
// 由段 1 於 config 載入後設定。
//
// 為套件層變數而非 routeDeps 成員：healthHandler SHALL 維持具名的
// func(*gin.Context)（見其註解——route characterization 以函式名比對，改成
// closure 會使鏈指紋隨所在函式漂移），故不能由註冊點以參數帶入。
// 寫入僅發生於啟動期單一位置，其後只讀。
//
// 預設為「空宣告」的指紋而非空字串：/health 的輸出形狀不隨設定有無而改變，
// 監控端才能無條件比對各副本的同一個欄位。
var oidcIssuerDeclarationDigest = identity.DedicatedIssuerDeclarationDigest(nil)

// 兩段啟動的組裝根。
//
//	段 1（stage1.go）  config 判定／DB＋migration＋seed／journal／封印閘／
//	                   健康檢查與 /seal/*／開監聽
//	段 2（stage2.go）  InitKeyManager＋policy／audit／通知／排程器／全部業務
//	                   handler／完整路由樹
//
// A／C 模式：兩段於啟動時連續完成，對外行為與現況相同（恆 unsealed）。
// B 模式：段 2 延後至解封成功後執行，且其失敗**不殺行程**——回機器碼給解封
// 請求並轉 sealed-faulted，管理員可讀狀態與重試。
//
// **同一份段 2 邏輯、兩種失敗處置**：分歧只落在本檔的呼叫端（下方兩個分支），
// runStage2 內不做模式分支。
func main() {
	s1 := runStage1()
	defer database.Close()

	// http.Server 的 Handler 固定為可換手層：監聽於段 1 即開放，
	// 解封成功後才把段 2 的完整 router 換上。
	swap := &swappableHandler{}
	srv := &http.Server{
		Addr:    ":" + s1.cfg.Server.Port,
		Handler: swap,
	}

	var (
		machine *seal.Machine
		graph   *appGraph
		// sealOnlyHandler 為獨立解封監聽的 handler；nil 代表不另開監聽。
		sealOnlyHandler http.Handler
		shutdown        func(context.Context)
	)

	// 來源網段組態在**任何模式下都要解析**：A／C 模式過去一律傳 nil，
	// 於是設了 SEAL_UNSEAL_ALLOWED_CIDRS 的部署以為來源受限、實際完全沒有生效，
	// 而打錯的網段也不會有人發現。解析失敗即拒絕啟動。
	allowedSources, err := s1.cfg.Seal.ParseAllowedCIDRs()
	if err != nil {
		log.Fatalf("解封端點的來源網段組態不合法（拒絕啟動）: %v", err)
	}

	if s1.sealedMode() {
		w, err := newSealMachine(s1, swap)
		if err != nil {
			log.Fatalf("建立封印狀態機失敗（拒絕開放監聽）: %v", err)
		}
		machine = w.machine
		r, err := newEngine(s1, true)
		if err != nil {
			log.Fatalf("建立段 1 router 失敗（拒絕開放監聽）: %v", err)
		}
		registerRoutes(r, sealedStageOneDeps(stageOneRouteConfig{
			corsMiddleware:    s1.corsMiddleware,
			metrics:           s1.metrics,
			metricsToken:      s1.cfg.Server.MetricsToken,
		}, w.main))
		swap.Set(r)
		if w.admin != nil {
			sr, err := newEngine(s1, true)
			if err != nil {
				log.Fatalf("建立解封端點獨立監聽的 router 失敗（拒絕開放監聽）: %v", err)
			}
			registerRoutes(sr, sealedStageOneDeps(stageOneRouteConfig{
				corsMiddleware:    s1.corsMiddleware,
				metrics:           s1.metrics,
				metricsToken:      s1.cfg.Server.MetricsToken,
				sealOnly:          true,
			}, w.admin))
			sealOnlyHandler = sr
		}
		shutdown = func(ctx context.Context) {
			// 解封後才有服務圖可收；未解封時只需關 journal。
			if snap := machine.Snapshot(); snap.Services != nil {
				_ = snap.Services.Release(ctx)
			}
			machine.WaitCleanup()
			if s1.journal != nil {
				_ = s1.journal.Close()
			}
		}
		log.Println("[Seal] KEK_PROVIDER=ui：已封印啟動，段 2 延後至解封成功後執行")
	} else {
		// A（env）／C（kms／hsm）模式：段 2 於啟動時連續執行，
		// 任一失敗即殺行程——啟動期無人可回覆，續存無意義。
		g, err := runStage2(context.Background(), s1, s1.kekProvider)
		if err != nil {
			log.Fatalf("初始化服務失敗: %v", err)
		}
		graph = g
		machine = seal.NewUnsealed(g)
		sealHandler := api.NewSealHandler(machine, nil)
		sealHandler.SetSourceControls(s1.cfg.Seal.TrustedProxyConfigured(), allowedSources, "")
		// **A／C 模式不建立獨立解封監聽**，且明說理由：該模式恆 unsealed，
		// 解封端點只會回 409，另開一個監聽面不會增加任何運維能力，
		// 卻會多一個對外開放的埠。組態被忽略時必須留下可查的一行。
		if addr := s1.cfg.Seal.UnsealBindAddr; addr != "" {
			log.Printf("[Seal] 已設 SEAL_UNSEAL_BIND_ADDR=%s，但目前為 %s 模式（恆解封）：不建立獨立解封監聽，該組態僅在 KEK_PROVIDER=ui 下生效",
				addr, s1.kekDecision.Mode)
		}
		r, err := newEngine(s1, false)
		if err != nil {
			log.Fatalf("建立 router 失敗（拒絕開放監聽）: %v", err)
		}
		deps := g.deps
		deps.sealGate = sealGateMiddleware(func() bool {
			return machine.Snapshot().State == seal.StateUnsealed
		})
		deps.seal = sealHandler
		// 金鑰清冊的封印狀態欄：A／C 模式恆 unsealed，解封時點即啟動時點
		// ——狀態查詢在各模式下形狀一致是 spec 明文要求，不因「本模式沒有封印期」
		// 而省略欄位（省略會逼前端寫兩套判斷）。
		startedAt := time.Now()
		deps.keyManagement.SetSealStateProbe(func() (string, time.Time) {
			return string(machine.Snapshot().State), startedAt
		})
		registerRoutes(r, deps)
		swap.Set(r)
		shutdown = func(ctx context.Context) { _ = graph.Release(ctx) }
	}

	// 封印狀態指標的資料源。
	//
	// **接在此處而非各分支內**：兩條路徑（B 模式的狀態機、A／C 模式的
	// NewUnsealed）到這裡都已產生 machine，一處接線即涵蓋全模式——
	// 分頭接線只要漏一邊，該模式的封印指標就會靜默缺席。
	//
	// 態的全集取自 `seal.AllStates()` 而非在此列舉：抄一份清單，日後對方
	// 新增態時這裡不會有任何訊號，採集端就永遠看不到新態。
	//
	// **只濾掉空字串**：那是 `stateBoot` 偽態（其定義即空字串），僅供遷移表窮舉
	// 測試使用、永不出現在 sealNode，曝光成 `state=""` 是一條無意義的序列。
	// 過濾條件精確對應該偽態的定義，不會連帶濾掉未來新增的真態。
	s1.metrics.SetSealStateSource(func() (string, []string) {
		all := seal.AllStates()
		names := make([]string, 0, len(all))
		for _, st := range all {
			if st == "" {
				continue
			}
			names = append(names, string(st))
		}
		return string(machine.Snapshot().State), names
	})

	// 啟動服務器
	log.Printf("==================================")
	log.Printf("%s 後端服務啟動成功", branding.Name)
	log.Printf("版本: %s", Version)
	log.Printf("構建時間: %s", BuildTime)
	log.Printf("==================================")
	log.Printf("監聽端口: %s", s1.cfg.Server.Port)
	log.Printf("==================================")

	// 明文傳輸告警（deployment-hardening）：後端以明文 HTTP 提供服務（設計為置於反向代理之後）。
	// 本專案採 external-ingress TLS 契約——TLS termination 為部署方職責。release 模式提醒務必以具
	// TLS termination 的 ingress/反代承載對外流量（TLS 1.2+、HTTP→HTTPS redirect、HSTS、WSS）。
	// 此為告警非 fail-close（不改變預設綁定），詳見部署指南。
	if s1.cfg.IsReleaseMode() {
		log.Println("release：後端以明文 HTTP 提供服務，須置於具 TLS termination 的反向代理/ingress 之後；stock 部署本身不提供 TLS")
	}

	// refresh cookie 的 Secure 歸因日誌**已移入段 2**：生效值住在安全政策服務裡，
	// 而封印啟動的段 2 要到解封後才跑——
	// 留在這裡只會在封印模式下永遠印不出來。落點見 stage2.go 的政策播種段。

	// 解封端點的獨立監聽（SHALL 支援繫結獨立監聽位址）。
	// **掛 seal-only handler**：只有 seal 端點群與健康檢查，解封後也不會長出
	// 業務樹——網段隔離的意義就在於此。
	var sealSrv *http.Server
	if sealOnlyHandler != nil {
		sealSrv = &http.Server{Addr: s1.cfg.Seal.UnsealBindAddr, Handler: sealOnlyHandler}
	}

	// **兩個監聽位址同步建立，任一失敗即 fail-close**（不在 goroutine 內才發現）。
	// 舊行為是把獨立監聽的 ListenAndServe 丟進 goroutine、失敗只記一行 log：
	// 位址被佔用或無權繫結時，行程照樣以「解封端點已隔離」的姿態提供服務，
	// 而解封實際上只能從主監聽進來——部署方相信的隔離根本沒有發生。
	listeners, err := openListeners(srv, sealSrv)
	if err != nil {
		log.Fatalf("開放監聽失敗（拒絕啟動）: %v", err)
	}
	if sealSrv != nil {
		log.Printf("[Seal] 解封端點另行繫結於 %s（僅 seal 端點與健康檢查；主監聽上的解封一律拒絕）",
			sealSrv.Addr)
	}
	serveAll(listeners)

	// 等待中斷信號（優雅關閉）
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("收到關閉信號，開始優雅關閉...")

	// 設定 5 秒超時
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 關閉 HTTP Server（含解封端點的獨立監聽）→ 再收束段 2 資源。
	// 順序不可倒：仍在處理中的請求可能還會產生審計列。
	steps := []shutdownStep{}
	if sealSrv != nil {
		steps = append(steps, shutdownStep{"解封端點獨立監聽", sealSrv.Shutdown})
	}
	steps = append(steps,
		shutdownStep{"主監聽", srv.Shutdown},
		shutdownStep{"段 2 資源", func(c context.Context) error { shutdown(c); return nil }})

	if code := runShutdown(ctx, steps); code != 0 {
		// **離開碼保留**：關閉逾時（仍有連線未收完、審計未 flush 完）是 supervisor
		// 與 CI 需要知道的事實。改用 Fatalf 會跳過後續資源收束，故錯誤只記錄、
		// 收束照跑，非零碼留到全部收束完成的最末端才生效。
		log.Println("服務器關閉過程有未完成項目，以非零碼結束")
		os.Exit(code)
	}
	log.Println("服務器已優雅關閉")
}

// openListeners 同步建立全部監聽位址；任一失敗即關閉已建立者並回錯。
//
// 分兩段（先 Listen 再 Serve）而非 ListenAndServe：後者把繫結失敗推遲到
// goroutine 內，呼叫端無從得知，於是「監聽建立失敗」與「服務正常啟動」在
// 行程行為上不可分辨。
func openListeners(servers ...*http.Server) ([]serverListener, error) {
	var out []serverListener
	for _, s := range servers {
		if s == nil {
			continue
		}
		ln, err := net.Listen("tcp", s.Addr)
		if err != nil {
			for _, o := range out {
				_ = o.ln.Close()
			}
			return nil, fmt.Errorf("繫結 %q 失敗: %w", s.Addr, err)
		}
		out = append(out, serverListener{srv: s, ln: ln})
	}
	return out, nil
}

// serverListener 是一組已繫結的監聽與其 server。
type serverListener struct {
	srv *http.Server
	ln  net.Listener
}

// serveAll 於各自的 goroutine 上開始服務。
// 監聽已成功建立，此後的錯誤只有「被 Shutdown 關閉」與真正的服務中斷兩種。
func serveAll(listeners []serverListener) {
	for _, l := range listeners {
		l := l
		go func() {
			if err := l.srv.Serve(l.ln); err != nil && err != http.ErrServerClosed {
				log.Fatalf("服務中斷（%s）: %v", l.srv.Addr, err)
			}
		}()
	}
}

// shutdownStep 是一個具名的收束步驟。
type shutdownStep struct {
	name string
	fn   func(context.Context) error
}

// runShutdown 依序執行全部收束步驟，回傳行程離開碼。
//
// **單步失敗不中斷後續**：跳過剩下的收束會讓資源永久洩漏，而那是比離開碼更糟的
// 結果。但失敗也**不得被吞掉**——回傳非零碼使 supervisor 與 CI 看得見。
func runShutdown(ctx context.Context, steps []shutdownStep) int {
	code := 0
	for _, s := range steps {
		if err := s.fn(ctx); err != nil {
			log.Printf("收束步驟 %q 未乾淨完成: %v", s.name, err)
			code = 1
		}
	}
	return code
}

// newEngine 建立一個帶專案全域設定的 gin engine。
//
// **可信代理只在顯式設定時才套用**：未設定時維持 gin 預設，
// 既有部署的 c.ClientIP() 行為零變化；per-source 退避與網段白名單則由解封端點
// 自行降級（前者退為全域退避，後者只採信 socket peer IP）——寧可影響可用性，
// 也不提供可被轉送標頭污染而繞過的假防線。
//
// **設定非法即回錯，SHALL NOT 續跑**：舊行為是記一行警告後保留 gin 預設的
// 「信任全部代理」，同時仍向來源控管回報「可信代理已設定」。那個組合是最壞的
// ——偽造的轉送標頭會同時繞過網段白名單與 per-source 退避，而部署方看到的是
// 一行早已捲走的警告。組態錯誤屬於啟動期問題，啟動期就該擋下。
//
// stageOne 為真時另關閉 gin 的自動 redirect：封印期的 301/307 會洩漏
// 「這條路由存在」（見 stageOneRedirectPolicy 的說明）。
//
// **不用 gin.Default()**（access log 憑證遮蔽）：它掛的是 gin 內建
// logger，會把 `path?rawquery` 原樣印出，於是 `?rtoken=`／`?token=`／
// `?connect_token=`／OIDC `?code=` 等憑證逐字進 access log。改用
// middleware.NewEngineWithAccessLog()：同樣是 New＋Logger＋Recovery、鏈名與
// 順序不變，只是敏感 query 值輸出為 `***`。
func newEngine(s1 *stage1, stageOne bool) (*gin.Engine, error) {
	r := middleware.NewEngineWithAccessLog()
	if stageOne {
		// **尾斜線與路徑修正的自動 redirect 發生在中間件鏈之前**：gin 於
		// 路由樹查無此路徑時，會在進入任何 handler／middleware 之前直接回
		// 301/307 導向修正後的路徑。封印期因此出現一個路由存在性 oracle：
		// `/api/v1/assets/` 回 301 代表 `/api/v1/assets` 真的存在，而不存在的
		// 路徑回 503——正是封印閘刻意要抹平的區別。
		r.RedirectTrailingSlash = false
		r.RedirectFixedPath = false
	}
	if proxies := s1.cfg.Seal.TrustedProxies; len(proxies) > 0 {
		if err := r.SetTrustedProxies(proxies); err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES 設定無效: %w", err)
		}
		log.Printf("可信代理：%v", proxies)
	}
	return r, nil
}

// refreshCookieSourceLabel 把政策來源分類轉成運維日誌看得懂的人話。
//
// 三類的差別是**該去哪裡改**：管理端設定過的鍵，改 .env 不會生效；
// 從未設定過的鍵才吃得到組態播種。指錯地方的歸因比不歸因更浪費時間。
func refreshCookieSourceLabel(source string) string {
	switch source {
	case policy.PolicySourceAdmin:
		return "管理端安全政策頁設定"
	case policy.PolicySourceSeed:
		return "首次啟動時自部署組態播種"
	case policy.PolicySourceDefault:
		return "出廠預設"
	default:
		return "來源不明（政策讀取失敗）"
	}
}

// logRefreshCookieSecurity 印出 refresh cookie 的 Secure **政策現值**
// 與其來源歸因。
//
// **本函式只做歸因，不承擔可見性**：沒有人會去讀一個運作正常的系統的啟動日誌。
// 防線在安全預設（決策 1）與登入頁／管理頁的說明（決策 3/4）；這裡是有人去查時
// 的第一條線索，僅此而已。
//
// 預設反轉後兩個狀態的角色互換：現在要留話的是**已關閉**那一側（憑證將經明文
// 傳輸），開啟側則是資訊性歸因＋為純 HTTP 誤入者指路。兩側的復原方向都指政策頁
// ——播種之後改 .env 不生效，把讀者指向 env 是指向一條死路。
func logRefreshCookieSecurity(policies *policy.SecurityPolicyService) {
	secure := policies.GetBool(policy.PolicyRefreshCookieSecure)
	source := refreshCookieSourceLabel(policies.ValueSource(policy.PolicyRefreshCookieSecure))
	if secure {
		log.Printf("refresh cookie：已標記 Secure（來源：%s）。純 HTTP 部署下瀏覽器不會保存"+
			"此 cookie，使用者每 15 分鐘須重新登入；確定走 HTTP 的部署請在管理端「安全政策」"+
			"頁關閉該設定", source)
		return
	}
	log.Printf("refresh cookie：未標記 Secure（來源：%s）——refresh 憑證將經明文 HTTP 傳輸。"+
		"若本站實際以 HTTPS 對外，請在管理端「安全政策」頁開啟「登入狀態僅在 https 連線保存」",
		source)
}

// buildCORSConfig 依 allowlist 與執行模式決定 CORS 設定（PCI 7.3）。
//
// 三種結果：
//   - 有顯式 allowlist：來源受限，故可安全帶憑證
//   - release 且無 allowlist：拒絕所有跨源（僅同源）
//   - dev 且無 allowlist：全開，便於本地前後端分離開發
//
// **release 分支必須顯式表達「拒絕所有跨源」，不能只是留空**：
// gin-contrib/cors 的 Validate（cors.go:132）對「AllowAllOrigins 為 false、
// 無 AllowOriginFunc、且 AllowOrigins 為空」判定為互斥衝突並 panic
// （"conflict settings: all origins disabled"）。留空並不等於「拒絕全部」，
// 該套件不接受兩者皆空。此處以恆回 false 的 AllowOriginFunc 表達拒絕，
// 使 Validate 通過且語義與註解一致。
//
// 選 AllowOriginFunc 而非「release 時不掛載 cors middleware」的理由：
// 後者會改變全域中間件鏈，違反 route-registration spec 的鏈契約
// （Logger → Recovery → SealGate → Metrics → CORS → audit）。
func buildCORSConfig(allowedOrigins []string, isRelease bool) cors.Config {
	c := cors.Config{
		AllowMethods:  []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:  []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders: []string{"Content-Length"},
		MaxAge:        12 * time.Hour,
	}
	switch {
	case len(allowedOrigins) > 0:
		c.AllowOrigins = allowedOrigins
		c.AllowCredentials = true
	case isRelease:
		// 拒絕所有跨源。不設 AllowCredentials——無跨源可帶憑證。
		c.AllowOriginFunc = func(string) bool { return false }
	default:
		c.AllowAllOrigins = true
		c.AllowCredentials = false // AllowAllOrigins 時必須 false
	}
	return c
}

// routeDeps 聚合 registerRoutes 所需的全部依賴。
//
// 所有成員 SHALL 於呼叫 registerRoutes 之前完成建構與注入——registerRoutes 是純註冊
// 函式，不負責建立任何東西。旗標與預先算好的設定（corsCfg）一併由此傳入，
// 使註冊過程不需存取 config、不需寫 log。
type routeDeps struct {
	// 全域設定與旗標
	//
	// corsMiddleware 為**已建構完成**的 gin.HandlerFunc，非設定物件：
	// cors.New() 內部會 Validate 並在設定非法時 panic，屬「可導致行程終止」的
	// 呼叫，依 route-registration 契約不得出現在 registerRoutes 內。
	corsMiddleware gin.HandlerFunc
	// sealGate 封印閘：註冊為**最外層**
	// 全域中間件。非白名單路由於封印期一律 503＋機器碼。
	sealGate          gin.HandlerFunc
	auditLogEnabled   bool
	// metrics 營運指標集合。**段 1 與段 2 共用同一個實例**
	// ——換 router 時若另建一份，封印期累計的計數會在解封當下歸零，
	// 而 counter 回退在採集端會被讀成「行程重啟」。
	metrics *observability.Metrics
	// metricsToken 指標端點的 bearer token；空＝免認證
	metricsToken string
	// sealOnly 為真時，registerRoutes 只註冊健康檢查與 seal 端點群
	// （解封端點的獨立監聽）。業務路由**完全不存在**於該 router，
	// 而不是「存在但被閘擋住」——後者在解封後就會全部活過來。
	sealOnly bool

	// 共用服務
	authService  *identity.AuthService
	auditService *audit.AuditLogService
	// authorizationService 逐資產可視守門（帳號讀取端點用）
	authorizationService *authz.AssetAuthorizationService

	// API handlers（依註冊順序排列，便於與 registerRoutes 對照）
	seal                  *api.SealHandler
	auth                  *api.AuthHandler
	securityPolicy        *api.SecurityPolicyHandler
	syslogSetting         *api.SyslogSettingHandler
	auditIntegrity        *api.AuditIntegrityHandler
	auditCheckpoint       *api.AuditCheckpointHandler
	asset                 *api.AssetHandler
	assetAccount          *api.AssetAccountHandler
	session               *api.SessionHandler
	myConnection          *api.MyConnectionHandler
	sessionCommand        *api.SessionCommandHandler
	alertRule             *api.AlertRuleHandler
	commandAlert          *api.CommandAlertHandler
	dailyReview           *api.DailyReviewHandler
	auditFailure          *api.AuditFailureHandler
	transmissionInventory *api.TransmissionInventoryHandler
	notificationChannel   *api.NotificationChannelHandler
	oidc                  *api.OIDCHandler
	ldapDirectory         *api.LDAPDirectoryHandler
	keyManagement         *api.KeyManagementHandler
	snippet               *api.SnippetHandler
	assetGroup            *api.AssetGroupHandler
	userGroup             *api.UserGroupHandler
	user                  *api.UserHandler
	role                  *api.RoleHandler
	authorization         *api.AuthorizationHandler
	recording             *api.RecordingHandler
	auditLog              *api.AuditLogHandler // 僅 auditLogEnabled 時註冊
	exportSigning         *api.ExportSigningHandler
	auditExport           *api.AuditExportHandler
	accessReview          *api.AccessReviewHandler
	hostKey               *api.HostKeyHandler
	clipboard             *api.ClipboardEventHandler
	auditTimeline         *api.AuditTimelineHandler
	changeSecret          *api.ChangeSecretHandler
	accessRequest         *api.AccessRequestHandler
	sftp                  *api.SFTPHandler

	// 連線層 handlers（WebSocket 與 token 簽發）
	conn *proxy.ConnectionHandler
	ssh  *sshproxy.Handler
}

// registerRoutes 是本服務唯一的路由註冊入口。
//
// 契約：只做 Use／Group／HTTP method 註冊與 handler 的 RegisterRoutes 呼叫。
// **不得**於此執行初始化、I/O、資料庫存取、scheduler 啟停，或任何可導致行程
// 終止的呼叫（log.Fatal*／os.Exit）——那些一律屬於 main()。
//
// production 與測試共用本函式，使測試觀察到的路由集合與實際註冊者同源；
// AST 結構守衛禁止在 cmd/server 的其他位置變更路由。
//
// 全域中間件順序為契約：Logger → Recovery（來自 newEngine，前者為
// middleware.AccessLogger()，見該處說明）→ **SealGate**
// → Metrics → CORS → audit。gin 於**註冊當下**由 combineHandlers 定鏈，其後的
// Use 不回溯既有路由——故本函式內不得有先於自訂全域中間件註冊的路由，否則該
// 路由的鏈會僅含 Logger → Recovery。此不變式由鏈比對迴歸保護。
//
// **封印閘必須在最外層**：它要擋的是「服務尚未上線」，若排在 Metrics
// 或 audit 之後，封印期的請求就會先經過那些依賴段 2 服務的中間件。
func registerRoutes(r *gin.Engine, d routeDeps) {
	// 全域中間件（順序為契約，見上方說明）
	r.Use(d.sealGate)
	r.Use(d.metrics.HTTPMiddleware())
	r.Use(d.corsMiddleware)
	if d.auditLogEnabled {
		r.Use(middleware.AuditLogMiddleware(d.auditService))
	}

	// Health check endpoint
	// 同時接受 POST：webhook 測試發送（alert-notifications E2E）需要一個
	// 無認證、冪等、可 POST 的收端來驗證投遞鏈路，health 無副作用最合適
	r.GET("/health", healthHandler)
	r.POST("/health", healthHandler)
	// /healthz 是規格指名的存活探針路徑，且在封印閘白名單內。
	// **與 /health 並存而非取代**：既有部署的探針指向 /health，改名等於在
	// 升級當下讓所有探針一起變紅。只收 GET——探針不需要 POST，而白名單每多
	// 一條，封印期的攻擊面就多一條。
	r.GET("/healthz", healthHandler)

	// 解封端點的獨立監聽：只註冊 seal 端點群與健康檢查即返回。
	// 早退出而非旗標分支：業務路由在此 router 上「不存在」是可被路由表直接
	// 觀察的事實，不必倚賴閘的判定是否正確。
	if d.sealOnly {
		sealOnlyV1 := r.Group("/api/v1")
		d.seal.RegisterRoutes(sealOnlyV1)
		return
	}

	// 指標曝光。**刻意註冊在根層、不在 `/api` 之下**：
	// 正式版 edge 只代理 `/api` 與 `/ws`，故此端點預設自外部不可達——安全性由
	// 拓撲保證，而非由「認證中介層有沒有被掛上」這種每次改路由都可能失手的人為保證。
	// 前身 `/api/v1/internal/metrics` 自稱「內部使用、無需認證」而落在被代理的
	// `/api` 段內，該前提在正式部署下並不成立。
	//
	// **落在 sealOnly 早退之後**：獨立解封監聽的用途是把解封操作收進管理網段，
	// 其路由面愈小愈好。封印期主監聽已提供本端點，監控照樣採得到，
	// 故在獨立監聽上再開一份不增加任何運維能力，只多一個未認證的對外面。
	// 與 /health 的差別在探針是每個監聽各自需要，而指標採集只需一個來源。
	r.GET(observability.MetricsPath, d.metrics.Handler(d.metricsToken))

	v1 := r.Group("/api/v1")
	{
		v1.GET("/ping", pingHandler)

		// 封印狀態與解封：兩條路徑都在封印閘
		// 白名單內，且**不要求 JWT**（要求 JWT 會在 admin 已開 MFA 時死鎖）。
		// 恆註冊而非僅 B 模式註冊：A／C 模式下狀態查詢同樣是有效的運維面，
		// 且解封端點在已解封時一律回 409、不重跑任何初始化。
		d.seal.RegisterRoutes(v1)

		d.auth.RegisterRoutes(v1, d.authService)
		d.securityPolicy.RegisterRoutes(v1, d.authService)
		d.syslogSetting.RegisterRoutes(v1, d.authService)
		d.auditIntegrity.RegisterRoutes(v1, d.authService)
		// 檢查點鏈（audit-checkpoint-chain）：緊鄰列級完整性驗證註冊——
		// 兩者是同一件事的兩個層次（列的內容真偽／序列的完整性），
		// 角色邊界亦相同（admin 或 auditor，唯讀）
		d.auditCheckpoint.RegisterRoutes(v1, d.authService)
		d.asset.RegisterRoutes(v1, d.authService)
		// 資產帳號：與 /assets 同前綴不同子路徑，
		// 讀取端沿用逐資產可視守門，故需授權服務
		d.assetAccount.RegisterRoutes(v1, d.authService, d.authorizationService)
		d.session.RegisterRoutes(v1, d.authService)
		d.myConnection.RegisterRoutes(v1, d.authService)
		d.sessionCommand.RegisterRoutes(v1, d.authService)
		d.alertRule.RegisterRoutes(v1, d.authService)
		d.commandAlert.RegisterRoutes(v1, d.authService)
		d.dailyReview.RegisterRoutes(v1, d.authService)
		d.auditFailure.RegisterRoutes(v1, d.authService)
		d.transmissionInventory.RegisterRoutes(v1, d.authService)
		d.notificationChannel.RegisterRoutes(v1, d.authService)
		d.oidc.RegisterRoutes(v1, d.authService)
		// LDAP 目錄設定：與 OIDC provider 同屬
		// 身分管理面的 admin-only 設定；singleton 資源（無 :id、無集合式建立）
		d.ldapDirectory.RegisterRoutes(v1, d.authService)
		d.keyManagement.RegisterRoutes(v1, d.authService)
		d.snippet.RegisterRoutes(v1, d.authService)
		d.assetGroup.RegisterRoutes(v1, d.authService)
		d.userGroup.RegisterRoutes(v1, d.authService)
		d.user.RegisterRoutes(v1, d.authService)
		d.role.RegisterRoutes(v1, d.authService)
		d.authorization.RegisterRoutes(v1, d.authService)
		d.recording.RegisterRoutes(v1, d.authService)

		// 審計日誌查詢：依 FEATURE_AUDIT_LOG_ENABLED 條件註冊，
		// 關閉時整組 3 條 /audit-logs 不存在
		if d.auditLogEnabled {
			d.auditLog.RegisterRoutes(v1, d.authService)
		}

		d.exportSigning.RegisterRoutes(v1, d.authService)
		d.auditExport.RegisterRoutes(v1, d.authService)
		d.accessReview.RegisterRoutes(v1, d.authService)

		// 連線路由（手動處理認證，支援 WebSocket query token）
		v1.GET("/connect", d.conn.HandleConnect)

		d.hostKey.RegisterRoutes(v1, d.authService)
		d.clipboard.RegisterRoutes(v1, d.authService)
		// 稽核調查工作台（auditor-workbench）：唯讀聚合端點兩支。
		// **不掛在 auditLogEnabled 條件內**——它聚合的是六類資料，
		// 關閉操作日誌不代表會話、指令、告警的調查面也該消失
		d.auditTimeline.RegisterRoutes(v1, d.authService)
		d.changeSecret.RegisterRoutes(v1, d.authService)

		// 原生 SSH 終端：只收 token + asset_id，憑證後端注入
		v1.GET("/ssh", d.ssh.HandleSSH)
		// SSH 會話即時監看：限 admin/auditor，唯讀
		v1.GET("/sessions/:id/monitor", d.ssh.HandleMonitor)
		// session-stats: SSH 會話即時指標（JWT middleware 認證）
		v1.GET("/ssh/sessions/:id/stats", middleware.AuthMiddleware(d.authService), d.ssh.HandleStats)
		// session-share: 會話分享（建立/撤銷需登入；加入走 WS query token）
		v1.POST("/sessions/:id/share", middleware.AuthMiddleware(d.authService), d.ssh.HandleCreateShare)
		v1.DELETE("/sessions/:id/share", middleware.AuthMiddleware(d.authService), d.ssh.HandleRevokeShare)
		v1.GET("/sessions/share/:code/ws", d.ssh.HandleShareJoin)
		// connect-token: 一次性連線 token（P2，取代 WS query JWT）
		v1.POST("/connect-tokens", middleware.AuthMiddleware(d.authService), d.ssh.HandleCreateConnectToken)

		d.accessRequest.RegisterRoutes(v1, d.authService)

		// 連線同意閘
		v1.POST("/transmission-consents", middleware.AuthMiddleware(d.authService), d.ssh.HandleCreateTransmissionConsent)

		// SSH 資產檔案管理：資產收口 + 全操作審計
		d.sftp.RegisterRoutes(v1, d.authService)
	}
}

// healthHandler 健康檢查端點。
// 同時接受 POST：webhook 測試發送（alert-notifications E2E）需要一個
// 無認證、冪等、可 POST 的收端來驗證投遞鏈路，health 無副作用最合適。
//
// 具名為套件層函式而非 main() 內 closure：route characterization 以 Handler
// 函式名比對，closure 的編譯器生成名（main.main.funcN）會隨所在函式改變，
// 路由註冊搬入 registerRoutes 後將變為 main.registerRoutes.funcN 而造成假紅。
//
// 輸出含 `oidc_dedicated_issuers_digest`（3.10a）：多副本部署下該宣告是部署層
// 設定，副本間分歧會使自動供應時靈時不靈而管理端畫面看不出異常。指紋放在這裡
// 是因為健康檢查是唯一「每個副本都會被外部逐一探測」的端點——分歧因此可被
// 監控直接比對出來，不需登入任一副本。輸出為指紋而非原文，見
// identity.DedicatedIssuerDeclarationDigest 的說明。
func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":                        "ok",
		"service":                       "custodexa-backend",
		"version":                       Version,
		"database":                      "connected",
		"oidc_dedicated_issuers_digest": oidcIssuerDeclarationDigest,
	})
}

// pingHandler 連通性探測端點。具名理由同 healthHandler。
func pingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}
