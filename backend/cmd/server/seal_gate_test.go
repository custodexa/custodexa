package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/observability"
)

// 封印閘守衛。
//
// 掃描的是**段 1 實際註冊的整份路由表**，不是抽樣清單：抽樣會在新增路由時
// 靜默漏掉，而漏掉的那一條正是封印期唯一可達的洞。

// stageOneRouter 建出與 production 段 1 完全相同的 router。
func stageOneRouter(t *testing.T) *gin.Engine {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	_, sealHandler := newTestSealSetup(t)
	r := newStageOneTestEngine(t, nil)
	registerRoutes(r, sealedStageOneDeps(stageOneRouteConfig{
		corsMiddleware:    cors.New(buildCORSConfig(nil, false)),
		metrics:           observability.New(),
	}, sealHandler))
	return r
}

// sealOnlyRouter 建出解封端點獨立監聽的 router。
func sealOnlyRouter(t *testing.T) *gin.Engine {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	_, sealHandler := newTestSealSetup(t)
	r := newStageOneTestEngine(t, nil)
	registerRoutes(r, sealedStageOneDeps(stageOneRouteConfig{
		corsMiddleware:    cors.New(buildCORSConfig(nil, false)),
		metrics:           observability.New(),
		sealOnly:          true,
	}, sealHandler))
	return r
}

// TestSealGateBlocksEveryNonWhitelistedRoute 逐路由掃描：封印期非白名單一律 503＋機器碼。
func TestSealGateBlocksEveryNonWhitelistedRoute(t *testing.T) {
	r := stageOneRouter(t)

	routes := r.Routes()
	if len(routes) < 100 {
		t.Fatalf("段 1 只註冊到 %d 條路由——路由表明顯不完整，逐路由掃描將形同虛設", len(routes))
	}

	var leaked []string
	whitelistSeen := map[[2]string]bool{}
	for _, rt := range routes {
		key := [2]string{rt.Method, rt.Path}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(rt.Method, concreteTestPath(rt.Path), strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if sealGateWhitelist[key] {
			whitelistSeen[key] = true
			if w.Code == http.StatusServiceUnavailable && bodyCode(t, w.Body.Bytes()) == string(apierror.CodeSealServiceSealed) {
				t.Errorf("白名單路由 %s %s 竟被封印閘擋下——管理員將無法解封", rt.Method, rt.Path)
			}
			continue
		}
		if w.Code != http.StatusServiceUnavailable {
			leaked = append(leaked, rt.Method+" "+rt.Path+"：狀態碼 "+http.StatusText(w.Code))
			continue
		}
		if got := bodyCode(t, w.Body.Bytes()); got != string(apierror.CodeSealServiceSealed) {
			leaked = append(leaked, rt.Method+" "+rt.Path+"：機器碼 "+got)
		}
	}
	sort.Strings(leaked)
	if len(leaked) > 0 {
		t.Errorf("封印期有 %d 條非白名單路由未回 503＋SEAL_SERVICE_SEALED：\n  %s",
			len(leaked), strings.Join(leaked, "\n  "))
	}

	// 白名單三項必須真的存在於路由表：否則上面的迴圈只是在「跳過不存在的東西」。
	for key := range sealGateWhitelist {
		if key[0] == http.MethodOptions {
			continue // OPTIONS 由 CORS 預檢處理，不是獨立註冊的路由
		}
		if !whitelistSeen[key] {
			t.Errorf("白名單項 %s %s 不存在於段 1 路由表——封印期無從解封", key[0], key[1])
		}
	}
}

// TestSealGateSealsPublicPreAuthReads 登入前可讀的公開端點於封印期一律 503。
//
// 逐路由掃描（上一支）已涵蓋這兩條，這裡再具名釘一次的理由是**失敗訊息**：
// 掃描紅的時候只說「某條路由洩漏了」，而這兩條是使用者在還沒登入時就會打到的
// 面，封印期它們若回 200，前端會把一個空的登入頁當成正常服務渲染出來。
func TestSealGateSealsPublicPreAuthReads(t *testing.T) {
	r := stageOneRouter(t)
	for _, path := range []string{"/api/v1/auth/banner", "/api/v1/auth/methods"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s 於封印期回 %d，期望 503", path, w.Code)
			continue
		}
		if got := bodyCode(t, w.Body.Bytes()); got != string(apierror.CodeSealServiceSealed) {
			t.Errorf("%s 於封印期的機器碼 = %q, want %q", path, got, apierror.CodeSealServiceSealed)
		}
	}
}

// TestSealGateSealsUnknownPaths 封印期不對外透露路由是否存在：未匹配路徑同樣 503。
func TestSealGateSealsUnknownPaths(t *testing.T) {
	r := stageOneRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/definitely-not-a-route", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("未匹配路徑於封印期回 %d，期望 503（回 404 會洩漏路由是否存在）", w.Code)
	}
}

// TestSealGatePassesWhenLive 閘放行的唯一條件是完整服務圖就緒。
func TestSealGatePassesWhenLive(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prev)

	live := false
	r := gin.New()
	r.Use(sealGateMiddleware(func() bool { return live }))
	r.GET("/api/v1/ping", pingHandler)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("封印期 /ping 回 %d，期望 503", w.Code)
	}

	live = true
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("解封後 /ping 回 %d，期望 200", w.Code)
	}
}

// stage2ServiceProbe 把段 2 服務對應到「若它存在就會活的路由」。
//
// **鍵集必須與 stage2ServiceInventory 完全相同**（由 TestStage1HasNoStage2Service
// 斷言）：早期版本只列了 34 項中的 18 項，未列名者靜默 continue——新增的服務
// 因此可以完全不被檢查而測試依然綠，那正是這類守衛最典型的假綠形態。
//
// 空字串＝該服務沒有專屬的對外端點（純內部設施：套件級單例、背景排程器、
// 快取、遷移佇列）。它們**不由本測試涵蓋**，而是由整合測試斷言「段 1 期間
// 服務圖為 nil、段 2 清單與實際建構逐項相符」來涵蓋
// （seal_integration_test.go 的 TestSealInitializeUnsealFullChain）。
// 這裡誠實標為空字串而不是假裝有覆蓋。
var stage2ServiceProbe = map[string]string{
	"keyManager":    "/api/v1/keys",
	"policyService": "/api/v1/security-policies",
	// LDAP 目錄設定服務：singleton 資源的讀取端點，
	// 封印期同樣須 503——設定面不得在服務未上線時可讀
	"ldapDirectoryService": "/api/v1/ldap-directory",
	// auditTxSink：純內部設施，無專屬端點——它是交易內審計的落地面，
	// 由 requireAuditTxSink 於段 2 建構期自檢，涵蓋見 seal_integration_test 的清單比對
	"auditTxSink":           "",
	"transmissionPolicy":    "",
	"auditFailureService":   "/api/v1/audit-failures",
	"syslogForwarder":       "/api/v1/syslog-settings",
	"auditIntegrity":        "/api/v1/audit-integrity/verify",
	"postUnsealMigrations":  "",
	"authService":           "/api/v1/auth/me",
	"assetService":          "/api/v1/assets",
	"connectionRegistry":    "",
	"sessionService":        "/api/v1/sessions",
	"reconciliationService": "",
	"recordingService":      "/api/v1/recordings/stats",
	"auditService":          "/api/v1/audit-logs",
	"dailyReviewService":    "/api/v1/daily-reviews",
	"connHandler":           "/api/v1/connect",
	"userService":           "/api/v1/users",
	// alertSink：純內部設施，無專屬端點——指令告警的落地面，
	// 由 requireAlertSink 於段 2 建構期自檢；其資料面的讀取端點即下方 alertMatcher 那條
	"alertSink":                  "",
	"alertMatcher":               "/api/v1/command-alerts",
	"alertNotifier":              "",
	"kekRetirementMonitor":       "",
	"notificationChannelService": "/api/v1/notification-channels",
	// OIDC 整合：登入方法清單是未認證可讀的公開端點，
	// 封印期同樣須 503——封印閘白名單只有 health 與 seal 三支。
	// 前端據此降級為只顯示本地表單（封印期本就只有本地 admin 能解封）
	"oidcServices":  "/api/v1/auth/methods",
	"exportSigning": "/api/v1/audit-export/public-key",
	// checkpointSigning（audit-checkpoint-chain 第 3／8 組）：公鑰端點於第 8 組
	// 接線完成，本項自空字串改填該路徑——封印期它必須同樣回 503
	"checkpointSigning":     "/api/v1/audit-checkpoints/public-key",
	"sshHandler":            "/api/v1/ssh",
	"hostKeyService":        "/api/v1/assets/:id/host-key",
	"changeSecretScheduler": "/api/v1/change-secret-plans",
	// 候選憑證重試排程，其對外面即候選清單端點
	"changeSecretRetryScheduler": "/api/v1/change-secret-candidates",
	"accessRequestScheduler":     "/api/v1/access-requests/pending",
	"apiHandlers":                "/api/v1/roles",
	"retentionScheduler":         "",
	"reviewReminderScheduler":    "",
	"inactivityScheduler":        "",
	"kekRetirementScheduler":     "",
	"reconcileScheduler":         "",
	"checkpointScheduler":        "",
	// chainVerifyScheduler：
	// 純背景排程，自動驗證狀態經既有 ChainReport 揭露、不新增路由，故無對外面
	"chainVerifyScheduler": "",
	// 離機儲存三項（evidence-offsite-storage）：設定服務與帳冊的對外面即管理端點，
	// 封印期須 503——那正是「服務尚未上線」的可觀察形式。
	// **上傳 worker 填空字串**：它是純背景設施，且未設定時本來就不建 goroutine，
	// 「它存不存在」無法由任何端點觀察；其設定面已由前兩項覆蓋
	"offsiteProfiles": "/api/v1/offsite-storage/settings",
	"offsiteLedger":   "/api/v1/offsite-storage/status",
	"offsiteUploader": "",
	// auditExportJobWorker：
	// 打包 worker 本身是純背景設施，其對外面即 job 發起／清單端點——封印期須 503
	"auditExportJobWorker": "/api/v1/audit-export/jobs",
	// metricsRefresher（接替 perfMonitor）：純背景刷新任務。
	// **對外面填空字串是刻意的**——`/metrics` 端點本身於段 1 即存在且刻意可達
	// （封印期須能區分「封印中」與「當機」），它不隨本服務出現或消失；
	// 本服務只負責填入段 2 才有的指標值。
	"metricsRefresher": "",
}

// TestStage1HasNoStage2Service 段 1 期間，段 2 清單上的每一項都不存在。
//
// **逐項斷言而非整體斷言**：整體只驗「服務圖為 nil」時，若日後有人把某個服務
// 提前建到段 1（例如為了讓某條路由能用），整體斷言依然綠。此處對清單逐項
// 檢查其對應的業務路由是否可達——服務不存在的可觀察形式就是「它的端點回 503」。
//
// **另有完備性斷言**：probe 表的鍵集必須與清單完全相同。缺此斷言時，
// 新增的段 2 服務只要沒被加進 probe 表就自動跳過——守衛的涵蓋率會隨清單成長
// 而單調下降，且下降過程完全無聲。
func TestStage1HasNoStage2Service(t *testing.T) {
	if len(stage2ServiceInventory) == 0 {
		t.Fatal("段 2 服務清單為空——本守衛將在空集合下假綠")
	}

	inventory := map[string]bool{}
	for _, name := range stage2ServiceInventory {
		if inventory[name] {
			t.Fatalf("段 2 服務清單有重複項 %q", name)
		}
		inventory[name] = true
		if _, ok := stage2ServiceProbe[name]; !ok {
			t.Errorf("段 2 服務 %q 未列於 probe 表——它於段 1 期間是否存在完全沒有被檢查（有對外端點請填路徑，純內部設施請填空字串）", name)
		}
	}
	for name := range stage2ServiceProbe {
		if !inventory[name] {
			t.Errorf("probe 表列了不存在於段 2 清單的 %q——表已與清單漂移", name)
		}
	}
	if t.Failed() {
		t.Fatal("probe 表與段 2 服務清單不一致（見上方逐項訊息）——守衛的涵蓋率已無法確定，不繼續")
	}

	// probe 路徑必須真的是一條已註冊的路由：段 1 對**未匹配路徑**同樣回 503，
	// 故一個打錯的路徑會讓斷言在「這條路由根本不存在」的情況下照樣通過。
	stage2Routes, _ := buildRouter(t, gin.TestMode, true)

	r := stageOneRouter(t)
	covered := 0
	for _, name := range stage2ServiceInventory {
		path := stage2ServiceProbe[name]
		if path == "" {
			continue
		}
		covered++
		if _, ok := stage2Routes[[2]string{http.MethodGet, path}]; !ok {
			t.Errorf("probe 表為段 2 服務 %q 指定的 GET %s 不是一條已註冊的路由——該項的斷言恆真（未匹配路徑同樣回 503）",
				name, path)
			continue
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("段 2 服務 %q 的端點 %s 於段 1 期間回 %d（期望 503）——該服務可能已被提前建構",
				name, path, w.Code)
		}
	}
	if covered == 0 {
		t.Fatal("probe 表全為空字串——本守衛實際上什麼都沒檢查")
	}
}

// bodyCode 取出回應信封的機器碼欄位。
func bodyCode(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "<非 JSON 回應>"
	}
	return env.Code
}

// TestSealGateAllowsCORSPreflightForUnseal 封印期必須放行解封端點的 CORS 預檢。
//
// 專案未註冊任何 OPTIONS 路由，故預檢的 FullPath 為空字串；只比 FullPath 的
// 閘會把預檢擋成 503，瀏覽器隨即封鎖真正的解封請求——跨源部署下解封頁完全
// 不能用，而且症狀（「解封按鈕沒反應」）與封印本身難以區分。
func TestSealGateAllowsCORSPreflightForUnseal(t *testing.T) {
	r := stageOneRouter(t)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/seal/unseal", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusServiceUnavailable {
		t.Fatalf("解封端點的 CORS 預檢於封印期被擋（回 503）——跨源部署將無法解封")
	}

	// 非白名單路徑的預檢仍應被擋：放行預檢不得成為繞過封印的側門。
	req = httptest.NewRequest(http.MethodOptions, "/api/v1/assets", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("非白名單路徑的預檢回 %d，期望 503", w.Code)
	}
}
