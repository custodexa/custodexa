package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/observability"
	"github.com/custodexa/backend/internal/seal"
)

// 兩段啟動與初始化解封的整合驗收（kek-provider-modularization 2.0／2.2a）。
//
// **跑真的段 2**：這些案例要驗的是「段 2 被延後、且延後後真的能起來」，
// 用假的段 2 驗不出任何一條。DB 走檔案型 sqlite（非 :memory:——後者的連線池
// 語義曾使本專案出現「單獨跑綠、整包跑紅」的假訊號）。
//
// 全部案例共用行程級全域（database.DB、各套件單例），故一律序列執行、
// 且於 Cleanup 收束服務圖。

const (
	testAdminUser     = "admin"
	testAdminPassword = "IntegrationPass!2026"
	// 32 字元、字元集合格、非出廠預設：滿足 D8 完整格式驗證。
	testInitialKEK = "aZ9bY8cX7dW6eV5fU4gT3hS2iR1jQ0kP"
	testOtherKEK   = "pK0jQ1iR2hS3gT4fU5eV6dW7cX8bY9aZ"
)

// sealIntegrationEnv 是一次整合案例的完整環境。
type sealIntegrationEnv struct {
	s1      *stage1
	wiring  *sealWiring
	machine *seal.Machine
	handler *api.SealHandler
	swap    *swappableHandler
	engine  *gin.Engine
}

// newSealIntegrationEnv 建出「段 1 已完成、段 2 尚未執行」的封印狀態。
//
// 刻意不呼叫 runStage1()：後者含 config.Load()、RunMigrations() 與多處
// log.Fatalf，在測試行程內既不可控也會殺掉整個測試二進位。此處以同樣的
// 產物（stage1 結構）交棒，驗的仍是段 1／段 2 的分界本身。
func newSealIntegrationEnv(t *testing.T, opts ...func(*config.SealConfig)) *sealIntegrationEnv {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	dir := t.TempDir()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "seal_test.db")),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("開啟測試 DB 失敗: %v", err)
	}
	prevDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = prevDB })

	// 以 model 清單建表而非跑 baseline：baseline 是 postgres 專屬 DDL，sqlite 跑不動。
	// 本測試驗的是段 1／段 2 的分界，不是 schema 形狀；schema 形狀由
	// internal/database 的 parity 守衛在真 pg 上把關（migration-baseline-compression D3）。
	if err := db.AutoMigrate(database.SchemaParityModels()...); err != nil {
		t.Fatalf("建表失敗: %v", err)
	}
	if err := database.SeedDatabase(testAdminPassword); err != nil {
		t.Fatalf("SeedDatabase 失敗: %v", err)
	}

	cfg := &config.Config{}
	cfg.Server.Port = "0"
	cfg.Server.Mode = gin.TestMode
	cfg.Security.JWTSecret = strings.Repeat("j", 48)
	cfg.Features.AuditLogEnabled = true
	// 同步審計寫入：非同步批次會讓「審計事件可區分」的斷言變成計時競賽。
	cfg.Features.AsyncAuditEnabled = false
	cfg.Seal = config.SealConfig{
		BackoffBase: time.Second, BackoffMax: 4 * time.Second,
		CooldownThreshold: 50, Cooldown: time.Minute, CooldownMax: time.Minute,
	}
	for _, o := range opts {
		o(&cfg.Seal)
	}

	env := &sealIntegrationEnv{
		s1: &stage1{
			cfg:            cfg,
			kekDecision:    &config.KEKDecision{Mode: config.KEKModeUI, MatrixRow: "test", Rationale: "整合測試"},
			corsMiddleware: cors.New(buildCORSConfig(nil, false)),
			journal:        testJournal(t),
			// 與 runStage1 一致：段 1 即建立，供封印期曝光與段 2 共用
			metrics: observability.New(),
		},
		swap: &swappableHandler{},
	}

	// 內建遷移的登記器自 W1 1.10 起由組裝根提供（4.9 環拆解）：整合測試自建
	// 段 1／段 2 環境而不經 main 的組裝順序，故 setup 顯式補上同一筆登記，
	// 讓封印期的佇列成員斷言看到與生產一致的佇列
	keyvault.RegisterPostUnsealBuiltin(identity.PostUnsealMigrationLDAPSeed, func() {
		identity.RegisterLDAPSeedMigration(audit.NewTxSink())
	})
	keyvault.ResetPostUnsealQueueForTest()
	keyvault.ResetPostUnsealRunCountsForTest()

	w, err := newSealMachine(env.s1, env.swap)
	if err != nil {
		t.Fatalf("建立封印狀態機失敗: %v", err)
	}
	env.wiring = w
	env.machine, env.handler = w.machine, w.main
	m := w.machine

	// **以 production 的段 1 engine 建構路徑建 router**：段 1 的 redirect 政策
	// （M2）與可信代理處理都掛在 newEngine 上，測試自己 gin.New() 等於驗一個
	// 不存在於 production 的 router。
	r := newStageOneTestEngine(t, env.s1)
	registerRoutes(r, sealedStageOneDeps(stageOneRouteConfig{
		corsMiddleware:    env.s1.corsMiddleware,
		// 取 s1 上的實例而非另建：production 路徑即以此共用，
		// 另建一份會讓封印期指標與解封後不是同一組序列
		metrics:           env.s1.metrics,
	}, w.main))
	env.engine = r
	env.swap.Set(r)

	t.Cleanup(func() {
		if snap := m.Snapshot(); snap.Services != nil {
			_ = snap.Services.Release(context.Background())
		}
		m.WaitCleanup()
		// hook 與單例是行程級的：不解掉會讓下一個案例的 GORM 寫入打到已釋放的物件。
		model.SetAuditCreateHooks(nil, nil)
		audit.ResetAuditFailureSingleton()
		audit.ResetAuditIntegritySingleton()
		audit.ResetAlertMatcherSingleton()
	})
	return env
}

// do 送一次請求至**當前生效**的 handler（換手後即為段 2 的完整 router）。
func (e *sealIntegrationEnv) do(method, path, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.swap.ServeHTTP(w, r)
	return w
}

// initPayload 組出初始化解封的請求體（含 paste-back 與初始管理員憑證）。
// **手工組出 wire 形式而非序列化 payload 結構**：秘密欄位已改為可覆寫的
// []byte，序列化它只會得到 base64；而測試要送的正是使用者實際送出的那份 JSON。
func initPayload(kek string) string {
	return fmt.Sprintf(`{"kek":%q,"kek_confirm":%q,"confirm_saved":true,"username":%q,"password":%q}`,
		kek, kek, testAdminUser, testAdminPassword)
}

// dataKeyCount 目前金鑰表筆數。
func dataKeyCount(t *testing.T) int64 {
	t.Helper()
	n, err := keyvault.CountDataKeys(database.DB)
	if err != nil {
		t.Fatalf("讀取金鑰表筆數失敗: %v", err)
	}
	return n
}

// sealAuditDetails 取出解封相關審計列的 details。
func sealAuditDetails(t *testing.T) []string {
	t.Helper()
	var rows []model.AuditLog
	if err := database.DB.Where("resource = ?", model.ResourceKeyManagement).
		Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("讀取審計列失敗: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Details)
	}
	return out
}

// TestSealInitializeUnsealFullChain 空庫 → B 模式封印 → 初始化解封 → 登入。
//
// 這是 2.2a 的存在理由：缺初始化解封路徑時，全新安裝的 B 模式對**任何**正確
// 輸入都無法解封（空 data_keys 沒有代表列可解包，而 bootstrap 又需要先有 KEK）。
func TestSealInitializeUnsealFullChain(t *testing.T) {
	env := newSealIntegrationEnv(t)

	// 段 1：金鑰表為空、業務路由 503、遷移佇列未執行。
	if n := dataKeyCount(t); n != 0 {
		t.Fatalf("段 1 金鑰表筆數為 %d，期望 0（段 1 不得建立任何金鑰）", n)
	}
	if w := env.do(http.MethodGet, "/api/v1/keys", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("封印期 /api/v1/keys 回 %d，期望 503", w.Code)
	}
	if got := keyvault.PostUnsealMigrationRunCounts()[identity.PostUnsealMigrationLDAPSeed]; got != 0 {
		t.Fatalf("sealed 期 ldap_seed 已執行 %d 次，期望 0", got)
	}

	// status 應指出這是初始化路徑。
	var st map[string]any
	w := env.do(http.MethodGet, "/api/v1/seal/status", "")
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("解析 status 失敗: %v", err)
	}
	if st["initialization_required"] != true {
		t.Fatalf("空庫時 initialization_required 為 %v，期望 true", st["initialization_required"])
	}

	// 初始化解封。
	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d（碼 %s）：%s", w.Code, bodyCode(t, w.Body.Bytes()), w.Body.String())
	}

	// 段 2 已完成：狀態 unsealed、金鑰表已 bootstrap、遷移佇列恰執行一次。
	if got := env.machine.Snapshot().State; got != seal.StateUnsealed {
		t.Fatalf("解封後狀態為 %s，期望 unsealed", got)
	}
	if n := dataKeyCount(t); n == 0 {
		t.Fatal("解封後金鑰表仍為空——bootstrap 未執行")
	}
	if got := keyvault.PostUnsealMigrationRunCounts()[identity.PostUnsealMigrationLDAPSeed]; got != 1 {
		t.Fatalf("解封後 ldap_seed 執行 %d 次，期望恰 1 次", got)
	}

	// 完整路由已換上：業務端點不再 503，且可實際登入。
	if w := env.do(http.MethodGet, "/api/v1/ping", ""); w.Code != http.StatusOK {
		t.Fatalf("解封後 /ping 回 %d，期望 200", w.Code)
	}
	login := fmt.Sprintf(`{"username":%q,"password":%q}`, testAdminUser, testAdminPassword)
	if w := env.do(http.MethodPost, "/api/v1/auth/login", login); w.Code != http.StatusOK {
		t.Fatalf("解封後登入回 %d：%s", w.Code, w.Body.String())
	}

	// **MustChangePassword 不因通過解封而被清除**：解封是一次性部署動作，
	// 不是登入，二者不得互相代償。
	var admin model.User
	if err := database.DB.Where("username = ?", testAdminUser).First(&admin).Error; err != nil {
		t.Fatalf("讀取初始管理員失敗: %v", err)
	}
	if !admin.MustChangePassword {
		t.Fatal("初始管理員的 MustChangePassword 已被清除——解封被誤當成一次登入")
	}

	// 段 2 服務清單完備性：實際建構的項目必須與宣告清單逐項相符。
	snap := env.machine.Snapshot()
	g, ok := snap.Services.(*appGraph)
	if !ok {
		t.Fatalf("服務圖型別為 %T，期望 *appGraph", snap.Services)
	}
	if got, want := strings.Join(g.ServiceNames(), ","), strings.Join(stage2ServiceInventory, ","); got != want {
		t.Errorf("段 2 實際建構的服務清單與宣告不符：\n  實際：%s\n  宣告：%s", got, want)
	}
}

// retryUnsealUntilOK 重試解封直到成功或逾時（退避與待收束屬預期中的暫時性拒絕）。
func retryUnsealUntilOK(t *testing.T, env *sealIntegrationEnv, body string) *httptest.ResponseRecorder {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var w *httptest.ResponseRecorder
	for time.Now().Before(deadline) {
		w = env.do(http.MethodPost, "/api/v1/seal/unseal", body)
		if w.Code == http.StatusOK {
			return w
		}
		time.Sleep(20 * time.Millisecond)
	}
	return w
}

// TestStage2RouterFailureIsRetryable 段 2 的 router 建構失敗必須是可重試的段 2 失敗（H1）。
//
// **這是 H1 的核心驗收**：router 若在 publish 之後才建構，此處的失敗會停在
// 「狀態已 unsealed、router 仍是段 1 的」——unsealed 沒有任何出邊，於是服務
// 對外恆 503 且**不可重試**，只能重啟行程。把建構移進段 2 之後，同一個失敗
// 走 sealed-faulted，修掉成因即可重試。
//
// 破壞方式選在「段 2 服務全部建成、router 建不出來」的縫隙：非法的
// TRUSTED_PROXIES 使 newEngine 回錯，而它是 buildStage2Engine 的第一步。
func TestStage2RouterFailureIsRetryable(t *testing.T) {
	env := newSealIntegrationEnv(t, func(c *config.SealConfig) {
		c.BackoffBase, c.BackoffMax = time.Millisecond, time.Millisecond
	})
	env.s1.cfg.Seal.TrustedProxies = []string{"not-a-cidr"}

	w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK))
	if w.Code != http.StatusInternalServerError ||
		bodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealInitFailed) {
		t.Fatalf("router 建構失敗回 %d/%s，期望 500/SEAL_INIT_FAILED：%s",
			w.Code, bodyCode(t, w.Body.Bytes()), w.Body.String())
	}
	if got := env.machine.Snapshot().State; got != seal.StateSealedFaulted {
		t.Fatalf("router 建構失敗後狀態為 %s，期望 sealed-faulted——若為 unsealed，服務已無法路由且無出邊可重試", got)
	}
	// 服務未被放行：業務路由仍是封印期的 503，而非「已解封但打不到」。
	if w := env.do(http.MethodGet, "/api/v1/keys", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("router 建構失敗後 /api/v1/keys 回 %d，期望 503", w.Code)
	}
	// 狀態端點仍可服務＝行程存活。
	if w := env.do(http.MethodGet, "/api/v1/seal/status", ""); w.Code != http.StatusOK {
		t.Fatalf("router 建構失敗後 /seal/status 回 %d——行程未存活", w.Code)
	}

	// 修掉成因後可重試（金鑰表已 bootstrap，故走一般解封的材料判準）。
	env.machine.WaitCleanup()
	env.s1.cfg.Seal.TrustedProxies = nil
	w = retryUnsealUntilOK(t, env, fmt.Sprintf(`{"kek":%q}`, testInitialKEK))
	if w.Code != http.StatusOK {
		t.Fatalf("修掉成因後重試回 %d（碼 %s），期望 200——router 建構失敗造成了不可恢復的鎖死",
			w.Code, bodyCode(t, w.Body.Bytes()))
	}
	if w := env.do(http.MethodGet, "/api/v1/ping", ""); w.Code != http.StatusOK {
		t.Fatalf("重試成功後 /ping 回 %d，期望 200——換手未發生", w.Code)
	}
	// 服務圖上必須帶著本世代的 router：換手回呼因此沒有任何可能失敗的建構工作。
	g, ok := env.machine.Snapshot().Services.(*appGraph)
	if !ok || g.engine == nil {
		t.Fatal("已發佈的服務圖沒有帶著段 2 router——換手回呼仍需自行建構，H1 的成因未被移除")
	}
}

// TestBootstrapPendingSurvivesStage2Failure 初始化事件不因段 2 失敗重試而降級為一般解封（M1）。
//
// 初始化解封的段 2 在 InitKeyManager 就把 bootstrap 金鑰持久化了。若段 2 於其後
// 失敗，重試時金鑰表已非空，分流會轉走一般解封——這次部署的初始化事件因此被
// 記成一筆普通 unseal，稽核從此無法回答「這個部署的 KEK 是何時、由誰初始化的」，
// 而那正是 D6.3 要求兩條路徑可區分的全部理由。
func TestBootstrapPendingSurvivesStage2Failure(t *testing.T) {
	env := newSealIntegrationEnv(t, func(c *config.SealConfig) {
		c.BackoffBase, c.BackoffMax = time.Millisecond, time.Millisecond
	})
	env.s1.cfg.Seal.TrustedProxies = []string{"not-a-cidr"}

	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusInternalServerError {
		t.Fatalf("第一次初始化解封回 %d，期望 500（本測試需要一次「bootstrap 已落地但段 2 失敗」）", w.Code)
	}
	if n := dataKeyCount(t); n == 0 {
		t.Fatal("前提不成立：段 2 失敗前未寫入任何金鑰，重試不會轉走一般解封路徑")
	}

	env.machine.WaitCleanup()
	env.s1.cfg.Seal.TrustedProxies = nil
	// 重試**不帶憑證**（金鑰表已非空，材料判準即一般解封的「能解包」）。
	if w := retryUnsealUntilOK(t, env, fmt.Sprintf(`{"kek":%q}`, testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("重試回 %d，期望 200", w.Code)
	}

	details := sealAuditDetails(t)
	initialize, normal := 0, 0
	for _, d := range details {
		if strings.Contains(d, `"`+sealAuditEventInitialize+`"`) {
			initialize++
		}
		if strings.Contains(d, `"`+sealAuditEventUnseal+`"`) {
			normal++
		}
	}
	if initialize != 1 {
		t.Fatalf("seal_initialize 事件有 %d 筆，期望恰 1 筆：%v", initialize, details)
	}
	if normal != 0 {
		t.Fatalf("重試竟產生 %d 筆一般解封事件——本次部署的初始化在審計上被降級：%v", normal, details)
	}
}

// TestSealJournalReplayIsAwaitedOnRelease 回灌 goroutine 納入服務圖的收束（B3）。
//
// 沒有主的 goroutine 不在 WaitCleanup／Release 的涵蓋範圍內：行程收尾與測試
// 清理都等不到它，實測形態是偶發的「TempDir RemoveAll: directory not empty」。
// 本測試在解封成功後**立刻**收束，並要求回灌的成果此時已經落地。
func TestSealJournalReplayIsAwaitedOnRelease(t *testing.T) {
	env := newSealIntegrationEnv(t)
	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d：%s", w.Code, w.Body.String())
	}

	snap := env.machine.Snapshot()
	if snap.Services == nil {
		t.Fatal("解封後沒有服務圖")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := snap.Services.Release(ctx); err != nil {
		t.Fatalf("收束服務圖失敗（回灌未於逾時內結束即為此形態）: %v", err)
	}

	var n int64
	if err := database.DB.Model(&model.AuditLog{}).
		Where("details LIKE ?", `%"seal_journal"%`).Count(&n).Error; err != nil {
		t.Fatalf("查詢回灌審計列失敗: %v", err)
	}
	if n == 0 {
		t.Fatal("收束返回時回灌尚未落地——回灌 goroutine 不在收束的涵蓋範圍內")
	}
}

// TestSealInitializeAuditEventDistinguishable 兩條路徑的審計事件可區分。
func TestSealInitializeAuditEventDistinguishable(t *testing.T) {
	env := newSealIntegrationEnv(t)
	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d", w.Code)
	}

	details := sealAuditDetails(t)
	found := false
	for _, d := range details {
		if strings.Contains(d, `"`+sealAuditEventInitialize+`"`) {
			found = true
			// 初始化事件 SHALL 記新 KEK 指紋與 bootstrap 產生的金鑰版本清單。
			if !strings.Contains(d, "kek_fingerprint") || !strings.Contains(d, "bootstrap_key_versions") {
				t.Errorf("seal_initialize 事件缺 KEK 指紋或金鑰版本清單：%s", d)
			}
		}
		if strings.Contains(d, `"`+sealAuditEventUnseal+`"`) {
			t.Errorf("初始化路徑竟產生了一般解封事件：%s", d)
		}
	}
	if !found {
		t.Fatalf("找不到 %s 審計事件（稽核將無法回答「KEK 何時由誰初始化」）：%v",
			sealAuditEventInitialize, details)
	}
}

// TestSealNormalUnsealAfterInitialize 既有金鑰表走一般解封：不要求憑證、不驗格式。
func TestSealNormalUnsealAfterInitialize(t *testing.T) {
	// 退避壓到最小：本案例要驗的是「錯材料被拒、對材料放行」這對語義，
	// 而預設退避會讓緊接著的第二次嘗試被限速擋下——那是 2.3 的驗收面，
	// 已由 seal_endpoint_test.go 單獨涵蓋，不該在此重複並干擾判讀。
	env := newSealIntegrationEnv(t, func(c *config.SealConfig) {
		c.BackoffBase = time.Millisecond
		c.BackoffMax = time.Millisecond
	})
	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d", w.Code)
	}
	// 收束第一代服務圖後，以同一個 DB 重新起一台「新實例」。
	if snap := env.machine.Snapshot(); snap.Services != nil {
		_ = snap.Services.Release(context.Background())
	}
	model.SetAuditCreateHooks(nil, nil)

	second := &sealIntegrationEnv{s1: env.s1, swap: &swappableHandler{}}
	w2, err := newSealMachine(second.s1, second.swap)
	if err != nil {
		t.Fatalf("重建封印狀態機失敗: %v", err)
	}
	m, h := w2.machine, w2.main
	second.machine, second.handler = m, h
	r := gin.New()
	registerRoutes(r, sealedStageOneDeps(stageOneRouteConfig{
		corsMiddleware: env.s1.corsMiddleware,
		metrics:        env.s1.metrics,
	}, h))
	second.swap.Set(r)
	t.Cleanup(func() {
		if snap := m.Snapshot(); snap.Services != nil {
			_ = snap.Services.Release(context.Background())
		}
		m.WaitCleanup()
	})

	// 錯的材料：拒絕。
	w := second.do(http.MethodPost, "/api/v1/seal/unseal", fmt.Sprintf(`{"kek":%q}`, testOtherKEK))
	if w.Code != http.StatusBadRequest || bodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealMaterialInvalid) {
		t.Fatalf("錯誤材料回 %d/%s，期望 400/SEAL_MATERIAL_INVALID", w.Code, bodyCode(t, w.Body.Bytes()))
	}

	time.Sleep(5 * time.Millisecond) // 跨過（已壓到毫秒級的）退避期

	// 對的材料：**不帶任何憑證**即可解封（要求 JWT 會在 admin 已開 MFA 時死鎖）。
	w = second.do(http.MethodPost, "/api/v1/seal/unseal", fmt.Sprintf(`{"kek":%q}`, testInitialKEK))
	if w.Code != http.StatusOK {
		t.Fatalf("一般解封回 %d（碼 %s）：%s", w.Code, bodyCode(t, w.Body.Bytes()), w.Body.String())
	}
	if got := m.Snapshot().State; got != seal.StateUnsealed {
		t.Fatalf("一般解封後狀態為 %s，期望 unsealed", got)
	}

	found := false
	for _, d := range sealAuditDetails(t) {
		if strings.Contains(d, `"`+sealAuditEventUnseal+`"`) {
			found = true
		}
	}
	if !found {
		t.Fatal("一般解封未產生 seal_unseal 審計事件")
	}
}

// TestInitializeUnsealRejectsIncompleteInput 缺 paste-back／格式不合／缺憑證各自被拒，
// 且**皆計入退避**——否則攻擊者可零成本重試。
func TestInitializeUnsealRejectsIncompleteInput(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"缺 paste-back", fmt.Sprintf(`{"kek":%q,"confirm_saved":true,"username":%q,"password":%q}`,
			testInitialKEK, testAdminUser, testAdminPassword)},
		{"paste-back 不符", fmt.Sprintf(`{"kek":%q,"kek_confirm":%q,"confirm_saved":true,"username":%q,"password":%q}`,
			testInitialKEK, testOtherKEK, testAdminUser, testAdminPassword)},
		{"未確認保存", fmt.Sprintf(`{"kek":%q,"kek_confirm":%q,"username":%q,"password":%q}`,
			testInitialKEK, testInitialKEK, testAdminUser, testAdminPassword)},
		{"格式不合", fmt.Sprintf(`{"kek":"short","kek_confirm":"short","confirm_saved":true,"username":%q,"password":%q}`,
			testAdminUser, testAdminPassword)},
		{"缺憑證", fmt.Sprintf(`{"kek":%q,"kek_confirm":%q,"confirm_saved":true}`,
			testInitialKEK, testInitialKEK)},
		{"憑證錯誤", fmt.Sprintf(`{"kek":%q,"kek_confirm":%q,"confirm_saved":true,"username":%q,"password":"wrong-password"}`,
			testInitialKEK, testInitialKEK, testAdminUser)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := newSealIntegrationEnv(t)
			w := env.do(http.MethodPost, "/api/v1/seal/unseal", c.body)
			if w.Code != http.StatusBadRequest || bodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealMaterialInvalid) {
				t.Fatalf("回 %d/%s，期望 400/SEAL_MATERIAL_INVALID：%s",
					w.Code, bodyCode(t, w.Body.Bytes()), w.Body.String())
			}
			if n := dataKeyCount(t); n != 0 {
				t.Fatalf("被拒的初始化解封竟寫入 %d 筆金鑰——材料可能已被固化", n)
			}
			// 計入退避：緊接著的第二次嘗試落在退避期內。
			w2 := env.do(http.MethodPost, "/api/v1/seal/unseal", c.body)
			if w2.Code != http.StatusTooManyRequests ||
				bodyCode(t, w2.Body.Bytes()) != string(apierror.CodeSealBackoffActive) {
				t.Fatalf("第二次嘗試回 %d/%s，期望 429/SEAL_BACKOFF_ACTIVE（本類拒絕未計入退避）",
					w2.Code, bodyCode(t, w2.Body.Bytes()))
			}
		})
	}
}

// TestStage2FailureKeepsProcessAliveAndRetryable 解封後 load 失敗 →
// 行程存活、回機器碼、狀態 sealed-faulted、可重試。
//
// 破壞方式刻意選在「驗證過得去、load 過不去」的縫隙：插一列 wrapped_key 為空的
// data v3。ProbeKEKUnwrap 只看非空的代表列故會通過，而 load 對該 slot 取代表列
// 時會落入「退役或空列不可解密」而 fail-close——這正是 D6.1 所指的
// 「材料正確但段 2 初始化失敗」。
func TestStage2FailureKeepsProcessAliveAndRetryable(t *testing.T) {
	env := newSealIntegrationEnv(t)
	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d", w.Code)
	}
	if snap := env.machine.Snapshot(); snap.Services != nil {
		_ = snap.Services.Release(context.Background())
	}
	model.SetAuditCreateHooks(nil, nil)

	var rep model.DataKey
	if err := database.DB.Where("purpose = ? AND kek_retired_at IS NULL", "data").
		Order("version desc").First(&rep).Error; err != nil {
		t.Fatalf("讀取代表列失敗: %v", err)
	}
	broken := model.DataKey{
		Purpose: "data", Version: rep.Version + 2, WrappedKey: "",
		KEKID: rep.KEKID, Status: model.DataKeyStatusActive,
	}
	if err := database.DB.Create(&broken).Error; err != nil {
		t.Fatalf("插入破壞列失敗: %v", err)
	}

	second := &sealIntegrationEnv{s1: env.s1, swap: &swappableHandler{}}
	w2, err := newSealMachine(second.s1, second.swap)
	if err != nil {
		t.Fatalf("重建封印狀態機失敗: %v", err)
	}
	m, h := w2.machine, w2.main
	second.machine = m
	r := gin.New()
	registerRoutes(r, sealedStageOneDeps(stageOneRouteConfig{
		corsMiddleware: env.s1.corsMiddleware,
		metrics:        env.s1.metrics,
	}, h))
	second.swap.Set(r)
	t.Cleanup(func() {
		if snap := m.Snapshot(); snap.Services != nil {
			_ = snap.Services.Release(context.Background())
		}
		m.WaitCleanup()
	})

	w := second.do(http.MethodPost, "/api/v1/seal/unseal", fmt.Sprintf(`{"kek":%q}`, testInitialKEK))
	if w.Code != http.StatusInternalServerError ||
		bodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealInitFailed) {
		t.Fatalf("段 2 失敗回 %d/%s，期望 500/SEAL_INIT_FAILED：%s",
			w.Code, bodyCode(t, w.Body.Bytes()), w.Body.String())
	}
	if got := m.Snapshot().State; got != seal.StateSealedFaulted {
		t.Fatalf("段 2 失敗後狀態為 %s，期望 sealed-faulted", got)
	}
	// 行程存活：狀態端點仍可服務，且暴露故障機器碼。
	sw := second.do(http.MethodGet, "/api/v1/seal/status", "")
	if sw.Code != http.StatusOK {
		t.Fatalf("段 2 失敗後 /seal/status 回 %d——行程未存活或閘擋錯了", sw.Code)
	}
	var st map[string]any
	_ = json.Unmarshal(sw.Body.Bytes(), &st)
	if st["fault_code"] != seal.CodeInitFailed {
		t.Fatalf("status 未暴露故障機器碼：%v", st)
	}

	// 可重試：修掉成因後，自 sealed-faulted 重試必須成功。
	m.WaitCleanup()
	if err := database.DB.Unscoped().Delete(&broken).Error; err != nil {
		t.Fatalf("移除破壞列失敗: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var last int
	for time.Now().Before(deadline) {
		w = second.do(http.MethodPost, "/api/v1/seal/unseal", fmt.Sprintf(`{"kek":%q}`, testInitialKEK))
		last = w.Code
		if last == http.StatusOK {
			break
		}
		// 退避與待收束是預期中的暫時性拒絕，重試即可——這正是「不需重啟」的內容。
		time.Sleep(50 * time.Millisecond)
	}
	if last != http.StatusOK {
		t.Fatalf("自 sealed-faulted 重試最終回 %d（碼 %s），期望 200",
			last, bodyCode(t, w.Body.Bytes()))
	}
}

// TestPostUnsealMigrationQueueBModeTiming 遷移佇列的 B 模式時序（具名驗收）。
//
// 三條斷言缺一不可：sealed 期不執行、解封後恰執行一次、
// **佇列不含任何過渡遷移項**（release-transitional-cleanup 3.8 的 B 模式側釘子
// ——service 層的佇列成員測試綠，不足以證明「B 模式解封時不會自動跑過渡遷移」）。
func TestPostUnsealMigrationQueueBModeTiming(t *testing.T) {
	env := newSealIntegrationEnv(t)

	names := keyvault.PostUnsealMigrationNames()
	hasSeed := false
	for _, n := range names {
		if n == identity.PostUnsealMigrationLDAPSeed {
			hasSeed = true
		}
		lower := strings.ToLower(n)
		if strings.Contains(lower, "aad") || strings.Contains(lower, "legacy") {
			t.Errorf("解封後遷移佇列出現過渡遷移項 %q——該類機制已整組拆除", n)
		}
	}
	if !hasSeed {
		t.Fatalf("佇列缺 %s，本測試的正向斷言將落空：%v", identity.PostUnsealMigrationLDAPSeed, names)
	}

	counts := keyvault.PostUnsealMigrationRunCounts()
	if counts[identity.PostUnsealMigrationLDAPSeed] != 0 {
		t.Fatalf("sealed 期 ldap_seed 已執行 %d 次，期望 0",
			counts[identity.PostUnsealMigrationLDAPSeed])
	}

	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d：%s", w.Code, w.Body.String())
	}

	counts = keyvault.PostUnsealMigrationRunCounts()
	if got := counts[identity.PostUnsealMigrationLDAPSeed]; got != 1 {
		t.Fatalf("解封後 ldap_seed 執行 %d 次，期望恰 1 次", got)
	}
	for name, n := range counts {
		lower := strings.ToLower(name)
		if (strings.Contains(lower, "aad") || strings.Contains(lower, "legacy")) && n > 0 {
			t.Errorf("解封觸發了過渡遷移 %q（%d 次）", name, n)
		}
	}
}

// TestConcurrentInitializeUnsealExactlyOneWins 空庫同時初始化恰一成功。
//
// 兩台「實例」（各自的狀態機，共用同一個 DB）以**不同材料**同時初始化：
// 必須恰一方成為部署主 KEK，且金鑰表內只存在單一 KEK 指紋——否則就是腦裂，
// 而腦裂的具體後果是「另一半資料以無人知曉的 KEK 落地」。
func TestConcurrentInitializeUnsealExactlyOneWins(t *testing.T) {
	env := newSealIntegrationEnv(t)

	other := &sealIntegrationEnv{s1: env.s1, swap: &swappableHandler{}}
	w2, err := newSealMachine(other.s1, other.swap)
	if err != nil {
		t.Fatalf("建立第二台狀態機失敗: %v", err)
	}
	m2, h2 := w2.machine, w2.main
	other.machine = m2
	r2 := gin.New()
	registerRoutes(r2, sealedStageOneDeps(stageOneRouteConfig{
		corsMiddleware: env.s1.corsMiddleware,
		metrics:        env.s1.metrics,
	}, h2))
	other.swap.Set(r2)
	t.Cleanup(func() {
		if snap := m2.Snapshot(); snap.Services != nil {
			_ = snap.Services.Release(context.Background())
		}
		m2.WaitCleanup()
	})

	var wg sync.WaitGroup
	codes := make([]int, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		codes[0] = env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)).Code
	}()
	go func() {
		defer wg.Done()
		codes[1] = other.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testOtherKEK)).Code
	}()
	wg.Wait()

	success := 0
	for _, c := range codes {
		if c == http.StatusOK {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("同時初始化的成功數為 %d，期望恰 1（回應碼 %v）", success, codes)
	}

	var keks []string
	if err := database.DB.Model(&model.DataKey{}).Distinct().Pluck("kek_id", &keks).Error; err != nil {
		t.Fatalf("讀取 kek_id 清單失敗: %v", err)
	}
	if len(keks) != 1 {
		t.Fatalf("金鑰表出現 %d 個 KEK 指紋（%v）——空庫同時初始化造成腦裂", len(keks), keks)
	}
}

// TestUIModeBootstrapMintsNoV0 `ui` 模式**初始化解封**路徑同樣只鑄 v1 active
// （release-transitional-cleanup D4）：bootstrap 不鑄 v0 的規範適用於**全部**
// 初始化路徑，env 模式的 service 層測試不足以涵蓋 B 模式這條入口。
func TestUIModeBootstrapMintsNoV0(t *testing.T) {
	env := newSealIntegrationEnv(t)
	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d：%s", w.Code, w.Body.String())
	}

	var rows []model.DataKey
	if err := database.DB.Order("purpose, version").Find(&rows).Error; err != nil {
		t.Fatalf("查詢金鑰表失敗: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("初始化解封應只鑄 2 列（data v1 + audit_integrity v1），得 %d: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.Version == 0 {
			t.Errorf("ui 模式初始化解封 MUST NOT 鑄造 v0 列: %+v", r)
		}
		if r.Status != model.DataKeyStatusActive {
			t.Errorf("初始化解封 MUST NOT 產生 retired 列: %+v", r)
		}
		if !strings.HasPrefix(r.WrappedKey, "wk:2:local:") {
			t.Errorf("wrapped_key MUST 為終態格式 wk:2:local:，得 %.16q", r.WrappedKey)
		}
	}
}

// TestSealJournalReplayRowsAreStamped 封印期審計事實的回歸釘子
// （release-transitional-cleanup D4／design Context 錨點）。
//
// 封印期**不寫 audit_logs**：事件走檔案 journal，解封後由 sealwire 回灌並走
// 一般審計路徑——回灌發生於 SetAuditCreateHooks 之後，故**全部帶正常蓋章**。
// 全新安裝因此不存在任何 key_version=0 或空 HMAC 的基準後列；v0 快照得以拆除
// 正是踩在這個事實上，故以測試釘住它。
func TestSealJournalReplayRowsAreStamped(t *testing.T) {
	env := newSealIntegrationEnv(t)
	// 封印期的解封嘗試本身即入 journal，解封成功後回灌
	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d：%s", w.Code, w.Body.String())
	}
	snap := env.machine.Snapshot()
	if snap.Services == nil {
		t.Fatal("解封後沒有服務圖")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := snap.Services.Release(ctx); err != nil {
		t.Fatalf("收束服務圖失敗: %v", err)
	}

	var rows []model.AuditLog
	if err := database.DB.Where("details LIKE ?", `%"seal_journal"%`).Find(&rows).Error; err != nil {
		t.Fatalf("查詢回灌審計列失敗: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("無回灌列——本測試的正向斷言將由空集合假綠")
	}
	for _, r := range rows {
		if r.KeyVersion < 1 {
			t.Errorf("回灌列 key_version MUST >=1（回灌晚於蓋章 hook 註冊），得 %d（id=%d）", r.KeyVersion, r.ID)
		}
		if r.IntegrityHMAC == "" {
			t.Errorf("回灌列 HMAC MUST 非空（id=%d）", r.ID)
		}
	}
}
