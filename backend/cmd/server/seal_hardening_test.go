package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/apierror"
)

// 組裝根的 fail-close 驗收（kek-provider-modularization D6.1／D6.4／D6.6）。

// TestStageOneEngineDisablesRedirects 封印期不得以 redirect 洩漏路由是否存在（M2）。
//
// gin 的尾斜線／路徑修正 redirect 發生在中間件鏈之前：封印閘根本沒有機會執行。
// 於是 `/api/v1/assets/` 回 301 而 `/api/v1/not-a-route/` 回 503，
// 兩者的差異剛好把封印閘刻意抹平的「路由是否存在」還原回來。
func TestStageOneEngineDisablesRedirects(t *testing.T) {
	r := stageOneRouter(t)

	for _, path := range []string{"/api/v1/assets/", "/api/v1/users/", "/health/"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusMovedPermanently || w.Code == http.StatusTemporaryRedirect {
			t.Errorf("封印期 %s 回 %d（Location: %s）——redirect 洩漏了該路由存在",
				path, w.Code, w.Header().Get("Location"))
			continue
		}
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("封印期 %s 回 %d，期望 503", path, w.Code)
		}
	}

	// 對照：不存在的路徑同樣 503——兩者不可區分才是本項要保住的性質。
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/definitely-not-a-route/", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("不存在的路徑回 %d，期望 503", w.Code)
	}
}

// TestHealthzProbeIsWhitelisted D6.1 指名的探針路徑於封印期可用（M3）。
//
// 依設計文件配置探針的部署，過去在封印期收到的是 503——不是因為服務真的不健康，
// 而是因為那條路徑根本沒被註冊。
func TestHealthzProbeIsWhitelisted(t *testing.T) {
	r := stageOneRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("封印期 GET /healthz 回 %d，期望 200（依設計配置的存活探針將永遠是紅的）", w.Code)
	}
	// /health 保留相容：既有部署的探針不得因本次新增而變紅。
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("封印期 GET /health 回 %d，期望 200", w.Code)
	}
}

// TestSealOnlyRouterHasNoBusinessRoutes 獨立解封監聽只有 seal 端點群（H2）。
//
// 主 router 與獨立監聽若共用同一份路由表，解封成功後換上的完整業務樹就會
// **同時**出現在管理監聽上：部署方以為把解封端點收進管理網段，
// 實際上是把整個產品多開了一個入口。
func TestSealOnlyRouterHasNoBusinessRoutes(t *testing.T) {
	r := sealOnlyRouter(t)

	allowed := map[string]bool{
		"/health": true, "/healthz": true,
		"/api/v1/seal/status": true, "/api/v1/seal/unseal": true,
	}
	var extra []string
	for _, rt := range r.Routes() {
		if !allowed[rt.Path] {
			extra = append(extra, rt.Method+" "+rt.Path)
		}
	}
	if len(extra) > 0 {
		t.Fatalf("解封端點的獨立監聽出現 %d 條非 seal 路由：%s", len(extra), strings.Join(extra, ", "))
	}
	// 正向：解封與狀態必須在
	for _, want := range [][2]string{
		{http.MethodPost, "/api/v1/seal/unseal"},
		{http.MethodGet, "/api/v1/seal/status"},
	} {
		found := false
		for _, rt := range r.Routes() {
			if rt.Method == want[0] && rt.Path == want[1] {
				found = true
			}
		}
		if !found {
			t.Errorf("獨立監聽缺 %s %s——管理網段將無從解封", want[0], want[1])
		}
	}
	// 業務路徑在此 router 上不存在（回 503 是因為未匹配，而非被閘擋下的既有路由）。
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("獨立監聽上的 /api/v1/assets 回 %d，期望 503", w.Code)
	}
}

// TestSealOnlyRoutesAreStrictSubset sealOnly 只做減法（支撐旗標矩陣守衛的豁免）。
//
// TestRouteDepsFlagsCoveredByMatrix 對 sealOnly 的豁免建立在「它不可能引入
// 未被索引的端點」之上。那不是口頭承諾——此處以機器檢查該前提：
// sealOnly 的路由集合必須是完整路由集合的真子集。
func TestSealOnlyRoutesAreStrictSubset(t *testing.T) {
	full, _ := buildRouter(t, gin.TestMode, true)

	sealOnly := map[[2]string]bool{}
	for _, rt := range sealOnlyRouter(t).Routes() {
		sealOnly[[2]string{rt.Method, rt.Path}] = true
	}
	if len(sealOnly) == 0 {
		t.Fatal("sealOnly router 沒有任何路由——本測試的前提不成立")
	}
	if len(sealOnly) >= len(full) {
		t.Fatalf("sealOnly 有 %d 條路由、完整路由表有 %d 條——sealOnly 已不是真子集，旗標矩陣的豁免前提消失",
			len(sealOnly), len(full))
	}
	for k := range sealOnly {
		if _, ok := full[k]; !ok {
			t.Errorf("sealOnly 引入了完整路由表沒有的 %s %s——該端點不會進入索引", k[0], k[1])
		}
	}
}

// TestNewEngineRejectsInvalidTrustedProxies 可信代理設定非法即拒絕，不得靜默沿用 gin 預設（H4）。
//
// 舊行為的組合是最壞的：保留 gin 預設的「信任全部代理」，同時向來源控管回報
// 「可信代理已設定」。偽造的轉送標頭因此可同時繞過網段白名單與 per-source 退避，
// 而部署方看到的只是一行早已捲走的警告。
func TestNewEngineRejectsInvalidTrustedProxies(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	bad := &stage1{cfg: &config.Config{}}
	bad.cfg.Seal.TrustedProxies = []string{"10.0.0.0/8", "not-a-cidr"}
	if _, err := newEngine(bad, false); err == nil {
		t.Fatal("非法的 TRUSTED_PROXIES 竟建出 engine——服務會以 trust-all 續跑並回報「已設定」")
	}
	if err := validateTrustedProxies(bad.cfg.Seal.TrustedProxies); err == nil {
		t.Fatal("啟動期驗證放行了非法的 TRUSTED_PROXIES")
	}

	good := &stage1{cfg: &config.Config{}}
	good.cfg.Seal.TrustedProxies = []string{"10.0.0.0/8", "192.168.1.1"}
	if err := validateTrustedProxies(good.cfg.Seal.TrustedProxies); err != nil {
		t.Fatalf("合法的 TRUSTED_PROXIES 被拒: %v", err)
	}
	if _, err := newEngine(good, false); err != nil {
		t.Fatalf("合法設定建 engine 失敗: %v", err)
	}
	// 未設定＝不啟用，合法。
	if err := validateTrustedProxies(nil); err != nil {
		t.Fatalf("未設定 TRUSTED_PROXIES 竟被拒: %v", err)
	}
}

// TestOpenListenersFailsClosed 任一監聽位址建立失敗即整體失敗（H3）。
//
// 舊行為把獨立監聽的 ListenAndServe 丟進 goroutine、失敗只記一行 log：
// 位址被佔用或無權繫結時，行程照樣以「解封端點已隔離」的姿態提供服務，
// 而解封實際上只能從主監聽進來——部署方相信的隔離根本沒有發生。
func TestOpenListenersFailsClosed(t *testing.T) {
	// 佔用一個位址，使第二個 server 必然繫結失敗。
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("準備佔用位址失敗: %v", err)
	}
	defer occupied.Close()

	main := &http.Server{Addr: "127.0.0.1:0"}
	sealed := &http.Server{Addr: occupied.Addr().String()}

	if _, err := openListeners(main, sealed); err == nil {
		t.Fatal("其中一個監聽位址被佔用，openListeners 竟成功——隔離失效不會被任何人發現")
	}

	// 已建立的監聽必須被關閉，否則失敗路徑會留下佔用中的埠。
	// 以「同一個埠可再次繫結」證明：main 的位址是 :0，故改用可控位址重試一次。
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取得可控位址失敗: %v", err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	first := &http.Server{Addr: addr}
	if _, err := openListeners(first, sealed); err == nil {
		t.Fatal("第二個位址被佔用時 openListeners 竟成功")
	}
	again, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("失敗路徑未關閉已建立的監聽（%s 仍被佔用）: %v", addr, err)
	}
	_ = again.Close()

	// 正向：全部位址可繫結時成功，且回傳的監聽可被關閉。
	ok, err := openListeners(&http.Server{Addr: "127.0.0.1:0"}, &http.Server{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("全部位址可用時仍失敗: %v", err)
	}
	if len(ok) != 2 {
		t.Fatalf("回傳 %d 個監聽，期望 2 個", len(ok))
	}
	for _, l := range ok {
		_ = l.ln.Close()
	}
}

// TestRunShutdownKeepsExitCode 收束失敗不中斷後續，但離開碼必須保留。
//
// 兩個性質缺一不可：跳過剩下的收束會讓資源永久洩漏；而把錯誤吞掉（只記 log、
// 離開碼 0）會讓「關閉逾時、審計未 flush 完」在 supervisor 與 CI 眼中完全消失。
func TestRunShutdownKeepsExitCode(t *testing.T) {
	var ran []string
	steps := []shutdownStep{
		{"第一步", func(context.Context) error { ran = append(ran, "1"); return nil }},
		{"第二步", func(context.Context) error { ran = append(ran, "2"); return errors.New("測試：收束逾時") }},
		{"第三步", func(context.Context) error { ran = append(ran, "3"); return nil }},
	}
	code := runShutdown(context.Background(), steps)
	if code == 0 {
		t.Fatal("收束有失敗項但離開碼為 0——關閉未乾淨完成的事實被吞掉了")
	}
	if strings.Join(ran, ",") != "1,2,3" {
		t.Fatalf("實際執行順序 %v——單步失敗不得中斷後續收束（否則剩餘資源永久洩漏）", ran)
	}

	if code := runShutdown(context.Background(), steps[:1]); code != 0 {
		t.Fatalf("全部成功時離開碼為 %d，期望 0", code)
	}
}

// TestSealMaterialFailuresShareOneResponse 材料類失敗共用同一回應；限速類刻意可區分。
//
// D6.6 的承諾範圍是**材料類五種**（格式／材料驗證失敗／初始化憑證錯／
// paste-back 不符／保存確認未勾）：狀態碼、機器碼、body 與 headers 全部相同。
// 憑證錯必須併入——否則攻擊者可探得「密碼對但 KEK 錯」這個極有價值的區分。
//
// **限速類（退避／冷卻）刻意可區分**：D6.4 要求冷卻可被管理員與監控觀測，
// 若連 429 都要偽裝成 400，運維就無從得知「現在只是在等冷卻」。
func TestSealMaterialFailuresShareOneResponse(t *testing.T) {
	env := newSealIntegrationEnv(t, func(c *config.SealConfig) {
		// 退避壓到最小，使每一種材料失敗都真的走到驗證。
		c.BackoffBase, c.BackoffMax = time.Nanosecond, time.Nanosecond
		c.CooldownThreshold = 1000
	})

	bodies := map[string]string{
		"格式不合": fmt.Sprintf(`{"kek":"short","kek_confirm":"short","confirm_saved":true,"username":%q,"password":%q}`,
			testAdminUser, testAdminPassword),
		"請求體無法解析": `not json at all`,
		"paste-back 不符": fmt.Sprintf(`{"kek":%q,"kek_confirm":%q,"confirm_saved":true,"username":%q,"password":%q}`,
			testInitialKEK, testOtherKEK, testAdminUser, testAdminPassword),
		"未勾保存確認": fmt.Sprintf(`{"kek":%q,"kek_confirm":%q,"username":%q,"password":%q}`,
			testInitialKEK, testInitialKEK, testAdminUser, testAdminPassword),
		"初始化憑證錯": fmt.Sprintf(`{"kek":%q,"kek_confirm":%q,"confirm_saved":true,"username":%q,"password":"wrong-password"}`,
			testInitialKEK, testInitialKEK, testAdminUser),
	}

	type shape struct {
		status  int
		body    string
		headers string
	}
	var baseline *shape
	var baselineName string
	for name, body := range bodies {
		w := env.do(http.MethodPost, "/api/v1/seal/unseal", body)
		got := shape{status: w.Code, body: w.Body.String(), headers: canonicalHeaders(w)}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s 回 %d，期望 400", name, w.Code)
		}
		if baseline == nil {
			baseline, baselineName = &got, name
			continue
		}
		if got != *baseline {
			t.Fatalf("「%s」與「%s」的回應可被區分：\n  %s → %+v\n  %s → %+v",
				name, baselineName, name, got, baselineName, *baseline)
		}
	}
	if baseline == nil {
		t.Fatal("沒有任何案例被執行——本測試的前提不成立")
	}

	// 限速類必須**可**區分：冷卻／退避有專屬碼與 429。
	slow := newSealIntegrationEnv(t)
	if w := slow.do(http.MethodPost, "/api/v1/seal/unseal", `{"kek":"bad"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("首次材料失敗回 %d，期望 400", w.Code)
	}
	w := slow.do(http.MethodPost, "/api/v1/seal/unseal", `{"kek":"bad"}`)
	if w.Code != http.StatusTooManyRequests ||
		bodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealBackoffActive) {
		t.Fatalf("退避期內回 %d/%s，期望 429/SEAL_BACKOFF_ACTIVE（限速必須可觀測）",
			w.Code, bodyCode(t, w.Body.Bytes()))
	}
}

// canonicalHeaders 取出可比較的回應標頭（排序後串接）。
func canonicalHeaders(w *httptest.ResponseRecorder) string {
	keys := make([]string, 0, len(w.Header()))
	for k := range w.Header() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+strings.Join(w.Header().Values(k), ","))
	}
	return strings.Join(parts, "\n")
}
