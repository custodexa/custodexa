package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 環境變數漂移守衛（deployment-configuration spec）。
//
// 掃 backend/ 所有產品 .go（排除 _test.go、vendor、testdata、scripts）收集傳給
// 「已知 env 讀取函式」的字串字面 key，組成「產品碼實際消費的環境變數集合」，
// 斷言其為專案根 .env.example（唯一環境變數範本）∪ allowlist 的子集。
// allowlist 含 compose 拓撲/模式常數（由 compose environment: 提供，不入使用者 .env）。
// scripts/ 全為 //go:build ignore 獨立開發工具，其 env 讀取非部署契約故排除。
// 新增消費變數而未同步範本即失敗——防範本與程式碼脫節（本 change 的根因）。
//
// 已知讀取函式與取 key 的參數位置：
//   - os.Getenv / os.LookupEnv（selector）：第 1 參數
//   - getEnv / getEnvInt / getEnvBool / lookupRaw（config 套件 helper，Ident）：第 1 參數
//   - SeedFromEnv（政策播種，selector）：第 2 參數
// config.go 的變數皆經上述 helper 讀取（非直接 os.Getenv），故 helper 必須納入掃描。
// lookupRaw 是「無出廠預設值」鍵的讀取器（ENCRYPTION_KEY、DB_DRIVER）；未列入時，
// 經它讀取的 key 會自 consumed 集合整個消失，守衛對這些鍵形同不存在。
//
// 無法字面掃描的間接讀取（如局部閉包包裝 os.Getenv 且 key 非字面傳入上述函式）
// 需將 key 補入 knownIndirectKeys；現含 sshproxy 動態讀的 SSH_IDLE/MAX_*_MINUTES
// （詳見該常數註解）。

var selectorReaderArg0 = map[string]bool{"Getenv": true, "LookupEnv": true}
var identReaderArg0 = map[string]bool{"getEnv": true, "getEnvInt": true, "getEnvBool": true, "lookupRaw": true}

// driftAllowlist：不該出現在使用者面 .env 範本的 key。
// 分兩類：系統/測試專用；compose 拓撲——後者由 docker-compose 的 environment: 提供
// （純拓撲/模式常數，非運維旋鈕），故不列於 .env.example 而列於此。
var driftAllowlist = map[string]bool{
	// 系統 / 測試專用
	"HOME":                true,
	"PATH":                true,
	"APIERROR_LOCALE_DIR": true, // apiError 完備性測試 locale 定位（dev 掛載）
	"SSH_TEST_HOST":       true, // sshproxy 整合測試目標
	// 整合測試 gating（internal/testgate；非部署契約，故不入 .env.example）。
	// testgate 是**非測試套件**（三個測試套件共用同一份 gating 語義），
	// 故其 os.Getenv 會被本守衛掃到——列此為刻意登記，不是漏網。
	"REQUIRE_INTEGRATION": true, // 設 1 時整合測試的 skip 轉 fail（CI 開啟，消滅假綠）
	"TEST_PG_DSN":         true, // postgres 靶機 DSN
	"TEST_KMS_ENDPOINT":   true, // KMS 模擬器（localstack）端點
	// compose 拓撲/模式常數（由 compose environment: 提供，見 docker-compose.yml 與 docker-compose.dev.yml）
	"PORT":     true,
	"GIN_MODE": true,
	// DB_DRIVER 自 fail-close 化（無出廠預設值、缺值即拒絕啟動）後**仍屬本類**，
	// 不上移至 .env.example。理由是分類判準看的是「誰供給、使用者調不調得動」而非
	// 「必不必填」：兩份 compose 的 backend environment: 都寫死 postgres，而
	// environment: 優先於 env_file，使用者在 .env 裡填任何值都不會生效——列入範本
	// 只會製造一個看得到、改了沒用的假旋鈕（config-env-drift-sync 明列的反模式）。
	// 且它沒有第二個合法部署值：postgres 是唯一正式目標，sqlite 只服務單元測試。
	// 真正需要自己供給它的是裸二進位／自製編排的部署者，那條路徑由
	// config.ValidateDatabaseDriver 的拒絕啟動訊息當場指路，而非靠範本。
	"DB_DRIVER":      true,
	"DB_HOST":        true,
	"DB_PORT":        true,
	"GUACD_HOST":     true,
	"GUACD_PORT":     true,
	"AUDIT_LOG_PATH": true, // 容器內審計路徑；host 側落點由 DATA_PATH 決定
	"RECORDING_PATH": true, // 容器內錄影路徑；host 側落點由 DATA_PATH 決定
}

// knownIndirectKeys：經無法字面掃描的間接路徑讀取的 key（安全網）。
// sshproxy sessionTimeoutsFromEnv 以區域閉包 `os.Getenv(key)` 動態讀取（handler.go），
// key 傳給區域 parse 函式而非上述已知讀取函式，字面掃描看不到。
// 這兩個 key 目前雖也由 main.go SeedFromEnv 字面冗餘覆蓋，但列此確保即使播種被移除，
// 完備性核對仍要求其記載於範本。新增此類間接讀取時，務必同步此清單。
var knownIndirectKeys = []string{
	"SSH_IDLE_TIMEOUT_MINUTES",
	"SSH_MAX_SESSION_MINUTES",
	// KEK 來源模式判定（kek-provider-modularization D2）：config/kek.go 一律經
	// 可注入的 EnvLookup 讀取，且 key 以具名常數（EnvKeyKEKProvider 等）傳入，
	// 字面掃描看不到。可注入是矩陣「十一格逐格測試」的前提（不得污染行程 env），
	// 故此處以安全網登記；新增金鑰類鍵時務必同步本清單與 .env.example。
	"KEK_PROVIDER",
	"KEK_KMS_PROVIDER",
	"KEK_KMS_KEY_ID",
	"KEK_KMS_REGION",
	"KEK_HSM_MODULE",
	"KEK_HSM_TOKEN_LABEL",
	"KEK_HSM_KEY_LABEL",
	"KEK_HSM_PIN",
	"KEK_HSM_PIN_FILE",
}

// commentedAssignment 註解掉的賦值行（`# KEY=` 形式）。
//
// 為何需要（kek-provider-modularization 1.1b）：金鑰類鍵改為三值語義且無
// 出廠預設值注入後，範本若帶生效賦值即等於「所有部署共用一把公開已知的
// KEK」。故 KEK 材料鍵在範本中**必須是註解掉的佔位**（＝未設），
// 使 `cp .env.example .env` 後必須顯式填值才起得來。
// 本形態仍是**明示的鍵宣告**（只是被停用），故計入「已記載」——
// 僅在註解中「提到」鍵名不算（不匹配 `#\s*KEY=` 形態）。
var commentedAssignment = regexp.MustCompile(`^#\s*([A-Za-z_][A-Za-z0-9_]*)\s*=`)

// collectKeysFromAST 從單一 AST 收集消費的 env key。
// Ident 型 helper（getEnv 系列）僅在 config 套件內採信，避免誤收同名函式。
func collectKeysFromAST(f *ast.File, into map[string]bool) {
	pkg := f.Name.Name
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		argIdx := -1
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if selectorReaderArg0[fun.Sel.Name] {
				argIdx = 0
			} else if fun.Sel.Name == "SeedFromEnv" {
				argIdx = 1
			}
		case *ast.Ident:
			if pkg == "config" && identReaderArg0[fun.Name] {
				argIdx = 0
			}
		}
		if argIdx < 0 || argIdx >= len(call.Args) {
			return true
		}
		if lit, ok := call.Args[argIdx].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil && s != "" {
				into[s] = true
			}
		}
		return true
	})
}

// envDriftModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const envDriftModulePath = "github.com/custodexa/backend"

// minEnvDriftScannedFiles 全 backend 掃描的檔數下限（防空集合假綠）。
// 2026-08-09 實測 292 檔（見 TestEnvExampleNoDrift 的 t.Logf），門檻取 260。
const minEnvDriftScannedFiles = 260

// backendRoot 定位 backend module 根。
//
// **原以 runtime.Caller + 固定 2 層 Dir 推算**：那與「本 package 住在樹的第幾層」
// 綁死，package 下移一層即把掃描根指向 config/（而非 backend/），Walk 照樣成功、
// 只是掃到錯的子樹——消費的 env key 集合縮成近乎空集合，於是「沒有漂移」
// （modular-architecture W1 1.20）。改以「向上找 go.mod 並核對 module 行」為錨點。
func backendRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			want := "module " + envDriftModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				filepath.Join(dir, "go.mod"), envDriftModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位",
				filepath.Dir(self), envDriftModulePath)
		}
		dir = parent
	}
}

// collectConsumedKeys 掃 backend 下所有非測試 .go，收集消費的 env key。
func collectConsumedKeys(t *testing.T, root string) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	scanned := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			// scripts：全為 //go:build ignore 的獨立開發/smoke 工具，非產品碼，
			// 其 env 讀取（如 retention_smoke.go 的 envOr）不屬部署 env 契約。
			case "vendor", "testdata", "scripts", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		scanned++
		collectKeysFromAST(f, keys)
		return nil
	})
	if err != nil {
		t.Fatalf("掃描 backend 失敗: %v", err)
	}
	if scanned < minEnvDriftScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下限 %d，掃描根 %s）：掃描範圍已失真，"+
			"守衛將在近乎空的 consumed 集合下宣稱「範本無漂移」。"+
			"若目錄結構改變，改的是掃描根而不是下限", scanned, minEnvDriftScannedFiles, root)
	}
	t.Logf("env 漂移守衛掃描檔數=%d（下限 %d）", scanned, minEnvDriftScannedFiles)
	for _, k := range knownIndirectKeys {
		keys[k] = true
	}
	return keys
}

// parseEnvExampleKeys 解析 .env.example 的 KEY（忽略註解與空行）。
func parseEnvExampleKeys(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀 %s 失敗: %v", path, err)
	}
	keys := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			// 註解掉的賦值佔位仍屬明示宣告（見 commentedAssignment 註解）
			if m := commentedAssignment.FindStringSubmatch(line); m != nil {
				keys[m[1]] = true
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		if k := strings.TrimSpace(line[:eq]); k != "" {
			keys[k] = true
		}
	}
	return keys
}

// envExamplePath 定位專案根 .env.example（唯一環境變數範本）。
//
// 容器內（backend 測試環境）：根 .env.example 唯讀掛載於 config/testdata/.env.example。
// **掛載點位於 module 內是必要條件**：go test 的結果快取只追蹤 module 內被開啟的檔案，
// 掛在 module 外（原本的 /opt/custodexa）時，只改範本而不動 Go 碼會讓 `go test` 回報
// (cached) 通過而根本不執行本守衛——看似有保護，實則從未執行。
// host 直跑：backendRoot=<proj>/backend，範本在 backendRoot/../.env.example（<proj>/.env.example）。
func envExamplePath(t *testing.T, root string) string {
	t.Helper()
	// 兩個候選都相對 **module 根**（root 由 go.mod 錨定），非相對本 package 位置：
	// 掛載點在 module 內、host 範本在 module 上一層，兩者都不隨 package 下移而失效。
	for _, p := range []string{
		filepath.Join(root, "config", "testdata", ".env.example"), // 容器唯讀掛載點（module 內）
		filepath.Join(root, "..", ".env.example"),                 // host 專案根
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatalf("找不到專案根 .env.example（容器內應唯讀掛於 config/testdata/.env.example；見 docker-compose.dev.yml backend volumes）")
	return ""
}

// TestEnvExampleNoDrift 斷言後端產品碼消費的每個 env 變數，皆記載於專案根 .env.example
// 或屬 allowlist（系統/測試/compose 拓撲），否則失敗——防範本與程式碼脫節。
func TestEnvExampleNoDrift(t *testing.T) {
	root := backendRoot(t)
	consumed := collectConsumedKeys(t, root)
	documented := parseEnvExampleKeys(t, envExamplePath(t, root))

	var missing []string
	for k := range consumed {
		if driftAllowlist[k] || documented[k] {
			continue
		}
		missing = append(missing, k)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("以下 %d 個消費中的環境變數未記載於專案根 .env.example（或加入 driftAllowlist）：\n  %s\n"+
			"若為運維可調設定：補入 .env.example；若為 compose 拓撲/測試/系統專用：加入 driftAllowlist。",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// TestEnvExampleNoInlineComments 防回歸：.env.example 作 compose env_file 消費時，
// docker compose 對「空值」的行內註解不剝除——`KEY=   # c`（值本為空）整個 `# c` 會成為值，
// 實測（compose v2.39.4）會使 CORS `panic: bad origin`、政策值非法。
// （非空值 `KEY=v  # c` 的行內註解則會被剝除，但為避免上述空值坑並保持格式一致，
//
//	本檔一律不用行內註解，說明置於獨立註解行。）
func TestEnvExampleNoInlineComments(t *testing.T) {
	path := envExamplePath(t, backendRoot(t))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀 %s 失敗: %v", path, err)
	}
	var bad []string
	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue // 空行 / 整行註解
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		value := line[eq+1:]
		// 行內註解形態：值中出現「空白後接 #」或（空值時）僅為 # 註解。
		if strings.Contains(value, " #") || strings.Contains(value, "\t#") ||
			strings.HasPrefix(strings.TrimSpace(value), "#") {
			bad = append(bad, "  L"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
		}
	}
	if len(bad) > 0 {
		t.Errorf("以下 %d 行值帶行內 # 註解（空值行內註解 compose 不剝除、會使值含註解導致啟動失敗；"+
			"本檔一律不用行內註解）；請把說明移到獨立註解行：\n%s", len(bad), strings.Join(bad, "\n"))
	}
}

// TestEnvDriftScannerSelfCheck 驗證掃描器認得各讀取函式形態、且不誤收變數 key。
func TestEnvDriftScannerSelfCheck(t *testing.T) {
	// 樣本套件名設為 config，使 Ident helper（getEnv 系列）被採信。
	src := `package config
import "os"
func sample() {
	_ = os.Getenv("SC_GETENV")
	_, _ = os.LookupEnv("SC_LOOKUP")
	_ = getEnv("SC_HELPER", "d")
	_ = getEnvInt("SC_HELPER_INT", 1)
	_ = getEnvBool("SC_HELPER_BOOL", false)
	_ = lookupRaw("SC_LOOKUP_RAW")
	s.SeedFromEnv(KeyX, "SC_SEED")
	_ = os.Getenv(dynamicVar)
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sample.go", src, 0)
	if err != nil {
		t.Fatalf("解析樣本失敗: %v", err)
	}
	got := map[string]bool{}
	collectKeysFromAST(f, got)

	for _, w := range []string{"SC_GETENV", "SC_LOOKUP", "SC_HELPER", "SC_HELPER_INT", "SC_HELPER_BOOL", "SC_LOOKUP_RAW", "SC_SEED"} {
		if !got[w] {
			t.Errorf("掃描器漏掉字面 key %s", w)
		}
	}
	if got["dynamicVar"] {
		t.Error("掃描器誤收變數 key dynamicVar")
	}
}

// TestEnvExampleKEKMaterialKeysArePlaceholders 出貨值佔位化守衛
// （kek-provider-modularization 1.1b）。
//
// 為何是硬閘：範本原值 `ENCRYPTION_KEY=dev-key-for-testing-only-ok32bts` 與
// config.DefaultEncryptionKey 逐字相同；金鑰類鍵廢除預設注入後，照抄該值等於
// 所有部署共用一把公開已知的 KEK。本測試釘住三件事——
// (1) KEK 材料鍵在範本中一律為**註解掉的佔位**（＝未設，使部署必須顯式填值，
// 不會照抄一個帶值或空值的生效賦值）；
// (2) 範本任一處都不得再出現出廠預設 KEK 材料字面；
// (3) 強 KEK 生成指引（CSPRNG 指令）仍在，且為全行註解（不觸發行內註解守衛）。
func TestEnvExampleKEKMaterialKeysArePlaceholders(t *testing.T) {
	path := envExamplePath(t, backendRoot(t))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀 %s 失敗: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")

	// **LEGACY_ENCRYPTION_KEY 已自本集合移除**（release-transitional-cleanup D3）：
	// 該鍵不再被任何產品碼消費，對它施加「必須有註解佔位」的要求會迫使範本
	// 永遠保留一個死鍵。此為機制拆除的一部分，非放寬守衛——集合其餘鍵不動。
	materialKeys := map[string]bool{
		"ENCRYPTION_KEY": true,
	}
	declaredLive := map[string]int{}
	declaredCommented := map[string]bool{}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if m := commentedAssignment.FindStringSubmatch(line); m != nil && materialKeys[m[1]] {
				declaredCommented[m[1]] = true
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		if k := strings.TrimSpace(line[:eq]); materialKeys[k] {
			declaredLive[k] = i + 1
		}
	}
	for k := range materialKeys {
		if ln, live := declaredLive[k]; live {
			t.Errorf(".env.example L%d 的 %s 為生效賦值：KEK 材料鍵 MUST 為註解掉的佔位。"+
				"空字串等同無材料（env 模式將拒絕啟動）；"+
				"帶值則使部署照抄公開已知材料。", ln, k)
		}
		if !declaredCommented[k] {
			t.Errorf(".env.example 缺少 %s 的註解佔位（`# %s=` 形式）："+
				"env 漂移守衛與部署引導都依賴該宣告", k, k)
		}
	}

	if strings.Contains(string(data), DefaultEncryptionKey) {
		t.Errorf(".env.example 仍含出廠預設 KEK 材料字面 %q：MUST 移除（照抄即所有部署共用同一把 KEK）",
			DefaultEncryptionKey)
	}

	// 強 KEK 生成指引（既有 spec「強 KEK 生成指引」）：CSPRNG 指令須存在且為全行註解。
	// **比對 KEKGenerateCommands 集合而非字面**：範本、列 3b 錯誤訊息、介面的指令參考
	// 與實跑驗證測試共用同一事實源，任一處漂移即紅——原先把
	// `openssl rand -base64 24` 硬編在守衛裡，反而把一條會讓部署起不來的指令釘死在範本中。
	// **逐條要求**：只驗「至少有一條」會讓集合擴充時範本靜默落後
	for _, cmd := range KEKGenerateCommandLines() {
		found := false
		for _, raw := range lines {
			line := strings.TrimSpace(raw)
			if strings.HasPrefix(line, "#") && strings.Contains(line, cmd) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf(".env.example 缺少全行註解形式的 CSPRNG KEK 生成指令（須與 config.KEKGenerateCommands 逐條一致）：%s",
				cmd)
		}
	}

	// 反向：**KEK 材料段內**不得再出現舊的 `openssl rand -base64 24`。
	// 接受 base64 之後它**仍然**是壞指令，只是壞法變了：它產出的是 24 個隨機
	// 位元組的 base64（32 個字元），既不是 43／44 字元的「32 位元組 base64」，
	// 含 `+` `/` 時又過不了原字元形態的字元集政策——約六成機率拒啟動，
	// 剩下四成則把一把只有 192 bit 熵的值當成 256 bit 金鑰用。
	// 正解是 `openssl rand -base64 32`（已在 KEKGenerateCommands 內）。
	// 刻意只掃該段而非全檔——`ADMIN_INITIAL_PASSWORD` 等無字元集約束的鍵用
	// base64 生成完全合理，全檔比對會製造假紅
	// 段落界定：自 ENCRYPTION_KEY 佔位行往上回溯至該段落開頭（第一個非註解行為界）
	placeholder := -1
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") && strings.Contains(line, EnvKeyEncryptionKey+"=") {
			placeholder = i
			break
		}
	}
	if placeholder < 0 {
		t.Fatalf(".env.example 找不到 %s 的註解佔位行——KEK 生成指引段落界定失效，"+
			"本守衛將在無法定位段落的情況下形同虛設", EnvKeyEncryptionKey)
	}
	for i := placeholder; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" && !strings.HasPrefix(line, "#") {
			break // 上一個賦值行＝段落起點
		}
		if strings.Contains(line, "openssl rand -base64 24") {
			t.Errorf(".env.example 的 %s 生成指引仍指示 openssl rand -base64 24："+
				"它產出 24 個隨機位元組的 base64（32 字元），約六成機率被字元集政策擋下，"+
				"其餘四成則以 192 bit 熵充當 256 bit 金鑰。請改用 openssl rand -base64 32"+
				"（第 %d 行：%s）",
				EnvKeyEncryptionKey, i+1, line)
		}
	}
}
