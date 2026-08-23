package main

import (
	"encoding/json"
	"flag"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/observability"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/sshproxy"
)

// 路由與中間件鏈迴歸守衛（route-registration spec Requirement 4）。
//
// 對照 A-0 擷取並入庫的 golden baseline，逐格比對路由三元組與中間件鏈。
// golden 於 registerRoutes 重構「之前」以真實啟動路徑擷取，是不可竄改的基準；
// 本測試使 baseline 與現況之間有可重跑的自動橋樑——否則 golden 只是歷史文件，
// 任何人改動路由註冊都不會有測試變紅。
//
// 為何非 nil zero-value handler：多個 RegisterRoutes 於註冊期即解參考 receiver 欄位
// （asset_handler.go、host_key_handler.go、access_request_handler.go），nil 指標會 panic。
// 註冊期只執行 Group/Use/METHOD 與立即回傳 closure 的 middleware 工廠，故 zero-value
// instance 足夠且不觸及任何 service。

// goldenDir：golden baseline 所在。
//
// 置於 testdata/ 而非 openspec change 目錄——**change 一旦 archive，
// openspec 會把整個目錄搬到 archive/<date>-<name>/，測試路徑與任何指向它的
// docker 掛載會同時失效，等於「歸檔即壞」**。testdata 是 Go 工具鏈慣例的
// 忽略目錄，隨 package 存在，且位於 backend/ 內故容器可直接讀，不需額外掛載。
const goldenDir = "testdata/route-golden"

// probeMarkerFunc 是本測試 probe 的識別片段，比對前自鏈中剔除。
// probe 為 buildRouter 內的匿名 closure，runtime 名稱形如 main.buildRouter.funcN，
// 故以所在函式名為 marker（不可假設 probe 位於鏈首——gin.Default() 已預掛
// Logger 與 Recovery，probe 實際是第三段）。
const probeMarkerFunc = "buildRouter"

type goldenRoute struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Handler string `json:"handler"`
}

type goldenChain struct {
	Method string `json:"method"`
	Path   string `json:"path"`

	// Chain 是 A-0 characterization 擷取當時的**原始** runtime 名，例如
	// main.main.Metrics.func24——工廠 closure 的 runtime 名含呼叫點，故 registerRoutes
	// 重構後現況已是 main.registerRoutes.Metrics.funcN，**此欄無法由現況重現**。
	//
	// 它是歷史證據而非現況快照，且無任何程式消費者（比對一律走 ChainStable）。
	// 故 -update **原樣沿用**既有值、不重寫；被移除的路由連同本欄一併刪除，
	// 重構後新增的路由則無此欄（omitempty）——混入不同世代的名稱只會讓證據失真。
	Chain []string `json:"chain,omitempty"`

	ChainStable []string `json:"chain_stable"`
}

type goldenFile struct {
	State  string        `json:"state"`
	Routes []goldenRoute `json:"routes"`
	Chains []goldenChain `json:"chains"`
}

// testDeps 組出非 nil 的 zero-value handler 集合。
func testDeps(isRelease, auditLogEnabled bool) routeDeps {
	return routeDeps{
		corsMiddleware: cors.New(buildCORSConfig(nil, isRelease)),
		// 封印閘以「已解封」形態注入：golden 記錄的是正常服務期的路由面。
		// 封印期的行為（非白名單一律 503）由 seal_gate_test.go 的逐路由掃描守衛。
		sealGate:          sealGateMiddleware(func() bool { return true }),
		auditLogEnabled:   auditLogEnabled,

		seal:                  &api.SealHandler{},
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
		ldapDirectory:         &api.LDAPDirectoryHandler{},
		keyManagement:         &api.KeyManagementHandler{},
		snippet:               &api.SnippetHandler{},
		assetGroup:            &api.AssetGroupHandler{},
		userGroup:             &api.UserGroupHandler{},
		user:                  &api.UserHandler{},
		role:                  &api.RoleHandler{},
		authorization:         &api.AuthorizationHandler{},
		recording:             &api.RecordingHandler{},
		// 指標實例不可為 nil：registerRoutes 以 d.metrics 掛全域 middleware
		// 並註冊曝光端點，零值指標會在建構路由時 panic
		metrics:  observability.New(),
		auditLog: &api.AuditLogHandler{},
		exportSigning:         &api.ExportSigningHandler{},
		auditExport:           &api.AuditExportHandler{},
		accessReview:          &api.AccessReviewHandler{},
		hostKey:               &api.HostKeyHandler{},
		clipboard:             &api.ClipboardEventHandler{},
		changeSecret:          &api.ChangeSecretHandler{},
		accessRequest:         &api.AccessRequestHandler{},
		sftp:                  &api.SFTPHandler{},

		conn: &proxy.ConnectionHandler{},
		ssh:  &sshproxy.Handler{},
	}
}

// normalizeHandlerName 消除測試套件與 production 二進位的套件路徑差異。
// golden 由 production 擷取，main package 的符號為 `main.X`；測試套件編譯時
// 同一符號變成 `github.com/.../cmd/server.X`。兩者指同一函式，非路由差異。
func normalizeHandlerName(n string) string {
	return strings.ReplaceAll(n, "github.com/custodexa/backend/cmd/server.", "main.")
}

// stableName 與 A-0 擷取時的正規化規則一致：只收窄 main package 內、
// 由工廠在 main()／registerRoutes() 建立的 closure（名稱含呼叫點與編譯器序號）。
func stableName(full string) string {
	full = normalizeHandlerName(full)
	const fromMain, fromRegister = "main.main.", "main.registerRoutes."
	var rest string
	switch {
	case strings.HasPrefix(full, fromMain):
		rest = strings.TrimPrefix(full, fromMain)
	case strings.HasPrefix(full, fromRegister):
		rest = strings.TrimPrefix(full, fromRegister)
	default:
		return full
	}
	parts := strings.Split(rest, ".")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.HasPrefix(p, "func") && len(p) > len("func") {
			continue
		}
		if p != "" {
			kept = append(kept, p)
		}
	}
	return "main." + strings.Join(kept, ".")
}

// concreteTestPath 將 gin 樣板路徑具體化，使 httptest 請求能命中該路由。
func concreteTestPath(tmpl string) string {
	segs := strings.Split(tmpl, "/")
	for i, s := range segs {
		switch {
		case strings.HasPrefix(s, ":"):
			segs[i] = "1"
		case strings.HasPrefix(s, "*"):
			segs[i] = "x"
		}
	}
	return strings.Join(segs, "/")
}

// buildRouter 以指定組態建 router 並取得路由與鏈。
// probe 必須早於 registerRoutes 內的任何 Use——gin 於註冊當下即定鏈，事後 Use 不回溯。
func buildRouter(t *testing.T, mode string, auditLogEnabled bool) (map[[2]string]string, map[[2]string][]string) {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(mode)
	defer gin.SetMode(prev)

	r := gin.Default()
	chains := map[[2]string][]string{}
	r.Use(func(c *gin.Context) {
		key := [2]string{c.Request.Method, c.FullPath()}
		var stable []string
		for _, n := range c.HandlerNames() {
			if strings.Contains(n, probeMarkerFunc) {
				continue // 剔除 probe 自身（不假設其位於鏈首）
			}
			stable = append(stable, stableName(n))
		}
		chains[key] = stable
		c.Abort() // 不執行真 handler：zero-value deps 會 panic
	})
	registerRoutes(r, testDeps(mode == gin.ReleaseMode, auditLogEnabled))

	routes := map[[2]string]string{}
	for _, rt := range r.Routes() {
		routes[[2]string{rt.Method, rt.Path}] = normalizeHandlerName(rt.Handler)
		req := httptest.NewRequest(rt.Method, concreteTestPath(rt.Path), nil)
		r.ServeHTTP(httptest.NewRecorder(), req)
	}
	return routes, chains
}

func loadGolden(t *testing.T, state string) goldenFile {
	t.Helper()
	path := filepath.Join(cmdServerDir(t), goldenDir, state+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("找不到 golden %s：%v\n"+
			"baseline 讀不到即等於沒有迴歸保護，故 fail 而非 skip", state, err)
	}
	var g goldenFile
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("解析 golden %s 失敗: %v", state, err)
	}
	validateGolden(t, state, g)
	return g
}

// validateGolden 驗證 baseline 自身的完整性。
//
// 僅驗「非空」不足以防假綠：若有人自 golden 刪掉某條 chains，比對迴圈只迭代
// golden 內現存項目，該路由的中間件鏈就再也不會被檢查，而測試依然全綠。
// 故須斷言 routes 與 chains 的鍵集**完全相等**、無重複鍵、已排序、欄位非空。
func validateGolden(t *testing.T, state string, g goldenFile) {
	t.Helper()
	if g.State != state {
		t.Fatalf("golden %s 的 state 欄為 %q，與檔名不符——可能複製自其他組態", state, g.State)
	}
	if len(g.Routes) == 0 || len(g.Chains) == 0 {
		t.Fatalf("golden %s 為空——baseline 無效（防假綠）", state)
	}

	routeKeys := map[[2]string]bool{}
	var routeOrder []string
	for _, r := range g.Routes {
		if r.Method == "" || r.Path == "" || r.Handler == "" {
			t.Fatalf("golden %s 有欄位為空的 route：%+v", state, r)
		}
		k := [2]string{r.Method, r.Path}
		if routeKeys[k] {
			t.Fatalf("golden %s 有重複的 route 鍵：%v", state, k)
		}
		routeKeys[k] = true
		routeOrder = append(routeOrder, r.Method+" "+r.Path)
	}

	chainKeys := map[[2]string]bool{}
	var chainOrder []string
	for _, c := range g.Chains {
		if c.Method == "" || c.Path == "" {
			t.Fatalf("golden %s 有欄位為空的 chain：%+v", state, c)
		}
		if len(c.ChainStable) == 0 {
			t.Fatalf("golden %s 的 %s %s 鏈為空——不可能有路由沒有 handler", state, c.Method, c.Path)
		}
		k := [2]string{c.Method, c.Path}
		if chainKeys[k] {
			t.Fatalf("golden %s 有重複的 chain 鍵：%v", state, k)
		}
		chainKeys[k] = true
		chainOrder = append(chainOrder, c.Method+" "+c.Path)
	}

	// 鍵集完全相等：任一側缺項都會使該路由失去對應面向的保護
	var onlyRoutes, onlyChains []string
	for k := range routeKeys {
		if !chainKeys[k] {
			onlyRoutes = append(onlyRoutes, k[0]+" "+k[1])
		}
	}
	for k := range chainKeys {
		if !routeKeys[k] {
			onlyChains = append(onlyChains, k[0]+" "+k[1])
		}
	}
	sort.Strings(onlyRoutes)
	sort.Strings(onlyChains)
	if len(onlyRoutes) > 0 {
		t.Fatalf("golden %s 有 %d 條 route 缺對應的 chain（其中間件鏈將不受保護）：\n  %s",
			state, len(onlyRoutes), strings.Join(onlyRoutes, "\n  "))
	}
	if len(onlyChains) > 0 {
		t.Fatalf("golden %s 有 %d 條 chain 缺對應的 route：\n  %s",
			state, len(onlyChains), strings.Join(onlyChains, "\n  "))
	}

	// 排序：擷取器保證按 method+path 排序，亂序代表檔案曾被手改
	if !sort.StringsAreSorted(routeOrder) {
		t.Errorf("golden %s 的 routes 未按 method+path 排序——檔案可能曾被手動編輯", state)
	}
	if !sort.StringsAreSorted(chainOrder) {
		t.Errorf("golden %s 的 chains 未按 method+path 排序——檔案可能曾被手動編輯", state)
	}
}

// updateFlag 是 package main 測試共用的 -update 旗標。
//
// **只能定義一次**：Go 的 flag 註冊於 package 層級，同一 package 內第二次
// flag.Bool("update", ...) 會於 init 期 panic（flag redefined）。故 golden 重生與
// API 索引重生共用本變數，由 -run 決定實際執行哪個生成器。
var updateFlag = flag.Bool("update", false,
	"重新生成 testdata golden 與 docs/API_SPEC.md 的端點索引（依 -run 決定對象）")

// writeGolden 以現況重新生成單格 golden。
//
// **取捨明載**：加入 -update 使 golden 從「不可竄改的基準」降為「可重新
// 生成的快照」。這是有意識的降級——本測試的價值自此依賴流程而非機制：
// golden 的 diff **必須在 commit 中被逐條審視**，與任何 snapshot 測試相同。
// 若審視被省略，重新生成就成了「使測試變綠」的捷徑，而非記錄真實變動。
//
// 之所以仍為淨改善：替代方案是永久保留 build-tagged characterization hook 與
// 專用 compose 檔，而那正是路由組裝收斂時判定應移除的攻擊面。
func writeGolden(t *testing.T, state string, routes map[[2]string]string, chains map[[2]string][]string) {
	t.Helper()

	path := filepath.Join(cmdServerDir(t), goldenDir, state+".json")

	// 沿用既有的 chain 歷史欄（見 goldenChain.Chain）。首次生成時檔案不存在，
	// 此表為空、所有條目皆無 chain 欄——那是正確的：沒有擷取過就沒有歷史。
	prevChain := map[[2]string][]string{}
	if data, err := os.ReadFile(path); err == nil {
		var prev goldenFile
		if err := json.Unmarshal(data, &prev); err != nil {
			t.Fatalf("解析既有 golden %s 失敗，無法沿用 chain 歷史欄: %v", state, err)
		}
		for _, c := range prev.Chains {
			if len(c.Chain) > 0 {
				prevChain[[2]string{c.Method, c.Path}] = c.Chain
			}
		}
	}

	g := goldenFile{State: state}
	for k, h := range routes {
		g.Routes = append(g.Routes, goldenRoute{Method: k[0], Path: k[1], Handler: h})
	}
	for k, c := range chains {
		g.Chains = append(g.Chains, goldenChain{
			Method: k[0], Path: k[1], Chain: prevChain[k], ChainStable: c,
		})
	}
	// 排序鍵與 validateGolden 的檢查一致（method+path 的字串序）
	sort.Slice(g.Routes, func(i, j int) bool {
		return g.Routes[i].Method+" "+g.Routes[i].Path < g.Routes[j].Method+" "+g.Routes[j].Path
	})
	sort.Slice(g.Chains, func(i, j int) bool {
		return g.Chains[i].Method+" "+g.Chains[i].Path < g.Chains[j].Method+" "+g.Chains[j].Path
	})

	// 先自驗再落檔：產物若不滿足 baseline 的結構不變式，寫出去只會製造假綠
	validateGolden(t, state, g)

	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		t.Fatalf("序列化 golden %s 失敗: %v", state, err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("寫入 golden %s 失敗: %v", state, err)
	}
	t.Logf("已重新生成 golden %s（%d routes / %d chains）——請於 commit 中逐條審視其 diff",
		state, len(g.Routes), len(g.Chains))
}

// TestRoutesMatchGolden 六格組態的路由三元組與中間件鏈皆須與 baseline 相同。
//
// 不含 release × permission-off：release 模式於 main.go 無條件強制啟用權限檢查，
// 該組態於真實環境不可達，故 baseline 亦不含。
//
// 以 -update 執行時改為重新生成 baseline（取捨見 writeGolden）。
func TestRoutesMatchGolden(t *testing.T) {
	cases := []struct {
		state           string
		mode            string
		auditLogEnabled bool
	}{
		// permission 維度已退場：權限檢查無旗標，
		// 原本的 *-permoff 三格不再是可達組態，其 golden 檔一併刪除
		{"dev-auditon", gin.DebugMode, true},
		{"dev-auditoff", gin.DebugMode, false},
		{"release-auditon", gin.ReleaseMode, true},
		// release-auditoff：**生產路徑不可達**（release 模式於旗標決定處強制啟用
		// 審計，見 config.EnforceReleaseSecurityFloor）。
		// 保留本格是因為 buildRouter 直接以旗標值呼叫 registerRoutes、不經 Config，
		// 故它記錄的是「registerRoutes 在此輸入下的輸出」這一純函式事實，仍有迴歸
		// 價值；但 SHALL NOT 被讀成「生產支援此組態」。生產面的真實斷言在
		// release_audit_floor_guard_test.go。
		{"release-auditoff", gin.ReleaseMode, false},
	}

	for _, c := range cases {
		t.Run(c.state, func(t *testing.T) {
			if *updateFlag {
				routes, chains := buildRouter(t, c.mode, c.auditLogEnabled)
				writeGolden(t, c.state, routes, chains)
				return
			}

			g := loadGolden(t, c.state)
			routes, chains := buildRouter(t, c.mode, c.auditLogEnabled)

			// 層 1：路由三元組
			want := map[[2]string]string{}
			for _, r := range g.Routes {
				want[[2]string{r.Method, r.Path}] = r.Handler
			}
			if len(routes) != len(want) {
				t.Errorf("路由數不符：現況 %d，baseline %d", len(routes), len(want))
			}
			var missing, extra, changed []string
			for k, v := range want {
				got, ok := routes[k]
				switch {
				case !ok:
					missing = append(missing, k[0]+" "+k[1])
				case got != v:
					changed = append(changed, k[0]+" "+k[1]+"：baseline "+v+" → 現況 "+got)
				}
			}
			for k := range routes {
				if _, ok := want[k]; !ok {
					extra = append(extra, k[0]+" "+k[1])
				}
			}
			sort.Strings(missing)
			sort.Strings(extra)
			sort.Strings(changed)
			if len(missing) > 0 {
				t.Errorf("baseline 有但現況缺少 %d 條：\n  %s", len(missing), strings.Join(missing, "\n  "))
			}
			if len(extra) > 0 {
				t.Errorf("現況多出 baseline 沒有的 %d 條：\n  %s", len(extra), strings.Join(extra, "\n  "))
			}
			if len(changed) > 0 {
				t.Errorf("handler 綁定變更 %d 條：\n  %s", len(changed), strings.Join(changed, "\n  "))
			}

			// 層 2：中間件鏈。先斷言數量相等——validateGolden 已保證 golden 內部
			// routes↔chains 鍵集一致，此處再確認現況的鏈數與之相符
			if len(chains) != len(g.Chains) {
				t.Errorf("鏈數不符：現況 %d，baseline %d", len(chains), len(g.Chains))
			}
			var chainDiff []string
			for _, gc := range g.Chains {
				k := [2]string{gc.Method, gc.Path}
				got, ok := chains[k]
				if !ok {
					chainDiff = append(chainDiff, k[0]+" "+k[1]+"：現況無此路由的鏈")
					continue
				}
				if strings.Join(got, "|") != strings.Join(gc.ChainStable, "|") {
					chainDiff = append(chainDiff,
						k[0]+" "+k[1]+"\n      baseline: "+strings.Join(gc.ChainStable, " → ")+
							"\n      現況    : "+strings.Join(got, " → "))
				}
			}
			if len(chainDiff) > 0 {
				sort.Strings(chainDiff)
				shown := chainDiff
				if len(shown) > 8 {
					shown = shown[:8]
				}
				t.Errorf("中間件鏈與 baseline 不符 %d 條（僅列前 %d）：\n    %s\n\n"+
					"鏈變動代表 middleware 掛載被更動——例如權限旗標若被寫死，"+
					"路由集合完全不變但鏈會少一段 RequirePermission。",
					len(chainDiff), len(shown), strings.Join(shown, "\n    "))
			}
		})
	}
}

