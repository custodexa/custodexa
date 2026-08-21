package sealjournal

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// productionSources 回傳本套件非測試原始碼「去除註解後」的程式碼本體。
// 以 go/parser + printer 剝掉註解，守衛才是打在真實程式碼上而非文字提及
// （否則說明「本套件不受某旗標控制」的註解會誤觸守衛）。
func productionSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("讀取套件目錄失敗: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("讀取 %s 失敗: %v", name, err)
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, b, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("解析 %s 失敗: %v", name, err)
		}
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, file); err != nil {
			t.Fatalf("輸出 %s 失敗: %v", name, err)
		}
		out[name] = buf.String()
	}
	if len(out) == 0 {
		t.Fatal("未掃到任何產品原始碼，守衛失效")
	}
	return out
}

// TestJournalIsNotControlledByFeatureFlag 驗收（守衛）：
// journal 不受 FEATURE_AUDIT_FALLBACK_TO_FILE 或任何 feature flag 控制、不可關閉。
func TestJournalIsNotControlledByFeatureFlag(t *testing.T) {
	for name, src := range productionSources(t) {
		if strings.Contains(src, "FEATURE_AUDIT_FALLBACK_TO_FILE") {
			t.Errorf("%s 引用了 FEATURE_AUDIT_FALLBACK_TO_FILE：留痕不得可被 feature flag 關閉", name)
		}
		if strings.Contains(src, "FeatureFlags") || strings.Contains(src, "AuditFallbackToFile") {
			t.Errorf("%s 依賴 feature flag 設定：journal 必須無條件啟用", name)
		}
	}
}

// TestNoNewEnvKeys 驗收（守衛）：落點沿用既有 AUDIT_LOG_PATH 所在目錄，不新增 env 鍵。
func TestNoNewEnvKeys(t *testing.T) {
	re := regexp.MustCompile(`os\.Getenv\("([^"]+)"\)`)
	allowed := map[string]bool{"AUDIT_LOG_PATH": true}
	for name, src := range productionSources(t) {
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			if !allowed[m[1]] {
				t.Errorf("%s 讀取了未允許的 env 鍵 %q：本套件不得新增 env 鍵", name, m[1])
			}
		}
		if strings.Contains(src, "os.LookupEnv") {
			t.Errorf("%s 使用 os.LookupEnv：env 讀取一律收斂於 ResolveDir", name)
		}
	}
}

// sealjournalModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const sealjournalModulePath = "github.com/custodexa/backend"

// sealjournalPkgPath 本套件的 import path（判定「自己」用，非掃描根推算）。
const sealjournalPkgPath = sealjournalModulePath + "/internal/sealjournal"

// minSealjournalClosurePkgs 相依閉包的載入下限（防空集合假綠）。
// 2026-08-09 實測 108 包（go list -deps），門檻取 80。
const minSealjournalClosurePkgs = 80

// sealjournalModuleRoot 由本測試檔位置向上找 go.mod，並核對 module 行。
// 不用 cwd 相對或固定層數 `..`：那與本 package 的樹深綁死（W1 1.20）。
func sealjournalModuleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			want := "module " + sealjournalModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				filepath.Join(dir, "go.mod"), sealjournalModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位",
				filepath.Dir(self), sealjournalModulePath)
		}
		dir = parent
	}
}

// TestReplayCannotWriteDatabaseDirectly 驗收（守衛）：
// 回灌 MUST 經既有審計寫入路徑（同一序列化入口），MUST NOT 另開直寫。
// 本套件因此不得依賴任何 DB 存取套件——落地一律經呼叫端提供的 Sink。
//
// **判定自字串比對改為結構性斷言**（modular-architecture W1 1.20，R4 D-5 實證）：
// 原先掃自家原始碼是否出現 "internal/repository"／"internal/service" 等**具名
// import 路徑**。那種寫法在包被改名或搬遷的當下就恆綠——`repository` 一旦更名
// 為 `database`，禁令字串再也匹配不到任何東西，守衛從此永遠通過，而「直寫 DB」
// 這件事一點都沒被擋住。改為判「相依閉包裡有沒有 DB 存取能力」：任何名字的
// DB 層都必然（直接或間接）觸及 gorm 或 database/sql，故以那兩者為判準，
// 對包名與位置完全免疫。
func TestReplayCannotWriteDatabaseDirectly(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedImports | packages.NeedDeps,
		Dir:  sealjournalModuleRoot(t),
	}
	pkgs, err := packages.Load(cfg, sealjournalPkgPath)
	if err != nil {
		t.Fatalf("packages.Load 失敗（守衛無法在無視野下宣稱通過）: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].PkgPath != sealjournalPkgPath {
		t.Fatalf("未載入目標包 %s（實載 %d 個）：守衛掃不到目標即等於沒跑",
			sealjournalPkgPath, len(pkgs))
	}

	// 走訪整個相依閉包（含間接），沿途攔 pkg.Errors：帶著載入／型別錯誤的樹
	// 其 import 資訊可能殘缺，「查不到 DB 相依」會被誤當成「沒有 DB 相依」。
	closure := map[string]bool{}
	reached := map[string][]string{} // 違規包 → 由哪個直接 import 進來
	var visit func(parent string, p *packages.Package)
	visit = func(parent string, p *packages.Package) {
		if closure[p.PkgPath] {
			return
		}
		closure[p.PkgPath] = true
		if len(p.Errors) > 0 {
			t.Fatalf("包 %s 有 %d 個載入錯誤（首個：%v）：守衛拒絕在殘缺的相依資訊上作判定",
				p.PkgPath, len(p.Errors), p.Errors[0])
		}
		if isDatabaseAccessPkg(p.PkgPath) {
			reached[p.PkgPath] = append(reached[p.PkgPath], parent)
		}
		for _, imp := range p.Imports {
			visit(p.PkgPath, imp)
		}
	}
	visit("<root>", pkgs[0])

	if len(closure) < minSealjournalClosurePkgs {
		t.Fatalf("相依閉包只有 %d 個包（下限 %d）：載入範圍已失真，"+
			"守衛將在近乎空集合下宣稱「沒有 DB 相依」", len(closure), minSealjournalClosurePkgs)
	}
	t.Logf("sealjournal 相依閉包包數=%d（下限 %d）", len(closure), minSealjournalClosurePkgs)

	if len(reached) > 0 {
		var lines []string
		for pkg, via := range reached {
			sort.Strings(via)
			lines = append(lines, "  "+pkg+"（經 "+strings.Join(via, "、")+"）")
		}
		sort.Strings(lines)
		t.Fatalf("sealjournal 的相依閉包觸及 DB 存取能力：\n%s\n\n"+
			"回灌不得繞過既有審計序列化入口直寫 DB——落地一律經呼叫端提供的 Sink。\n"+
			"（本守衛判的是能力而非套件名：任何名字的 DB 層都會落在此判準內。）",
			strings.Join(lines, "\n"))
	}
}

// isDatabaseAccessPkg 回報 import path 是否代表「DB 存取能力」。
//
// `database/sql/driver` 刻意**不算**：它是 driver 介面宣告（github.com/google/uuid
// 為了實作 Scanner/Valuer 就會帶進來），本身不具備開連線或下語句的能力。
// 故 database/sql 採**精確比對**而非前綴比對。
func isDatabaseAccessPkg(path string) bool {
	return path == "database/sql" || strings.HasPrefix(path, "gorm.io/")
}

// TestAdmissionUsesMonotonicClock 驗收（守衛）：
// admission 間隔以單調時鐘度量，SHALL NOT 使用牆鐘
// （否則 NTP 校時或手動改時可瞬間繞過或無限延長間隔）。
func TestAdmissionUsesMonotonicClock(t *testing.T) {
	s, ok := productionSources(t)["admission.go"]
	if !ok {
		t.Fatal("找不到 admission.go，守衛失效")
	}
	if !strings.Contains(s, "time.Since(") {
		t.Error("admission 必須以 time.Since（單調時鐘讀數）度量間隔")
	}
	for _, wall := range []string{".Unix()", ".UnixNano()", ".UnixMilli()", "time.Now().Format"} {
		if strings.Contains(s, wall) {
			t.Errorf("admission 使用了牆鐘表述 %q：可被校時繞過", wall)
		}
	}
	// 配額語義（扣減／重置／視窗）不得以任何名目回流。
	for _, quota := range []string{"quota", "Quota", "tokensLeft", "window", "Window"} {
		if strings.Contains(s, quota) {
			t.Errorf("admission 出現配額語義字樣 %q：間隔須為固定最小值，無扣減與重置", quota)
		}
	}
}

// TestJournalNeverContainsMaterialOrCredentials 驗收：
// journal 不含 KEK 材料或其片段、不含認證憑證或其衍生值、不含請求體。
// 斷言打在真實檔案位元上。
func TestJournalNeverContainsMaterialOrCredentials(t *testing.T) {
	const (
		kekMaterial = "SUPER-SECRET-KEK-MATERIAL-0123456789abcdef"
		credential  = "Bearer eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.c2ln"
		requestBody = `{"kek":"SUPER-SECRET-KEK-MATERIAL-0123456789abcdef","confirm":true}`
	)
	dir := t.TempDir()
	j := openTestJournal(t, dir)
	ctx := context.Background()

	// 唯一的自由字串欄位只接受十六進位摘要：原始材料在建構上無法寫入。
	for _, bad := range []string{kekMaterial, credential, requestBody, "Z", strings.Repeat("a", 65)} {
		if _, err := j.WriteReceived(ctx, 1, bad); !errors.Is(err, ErrInvalidSourceDigest) {
			t.Fatalf("非摘要輸入 %.20q 必須被拒，得 %v", bad, err)
		}
	}

	writeAttempt(t, j, 1, OutcomeMaterialFailure)
	for i := 0; i < 20; i++ {
		j.RecordRejected(RejectedConflict)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("Close 失敗: %v", err)
	}

	raw, err := os.ReadFile(journalPath(dir))
	if err != nil {
		t.Fatalf("讀檔失敗: %v", err)
	}
	for _, secret := range []string{kekMaterial, credential, requestBody, "kek", "Bearer", "password"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("journal 位元中出現不得記錄的內容: %q", secret)
		}
	}
	if !bytes.Contains(raw, []byte(testDigest)) {
		t.Fatal("測試前提：來源摘要應確實寫入 journal")
	}
}

// TestJournalPathFollowsAuditLogPathDirectory 驗收：
// 落點沿用既有 AUDIT_LOG_PATH 所在目錄，另立固定檔名。
func TestJournalPathFollowsAuditLogPathDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AUDIT_LOG_PATH", dir)
	if got := ResolveDir(); got != dir {
		t.Fatalf("ResolveDir 應採 AUDIT_LOG_PATH=%q，得 %q", dir, got)
	}

	j, err := Open("", testOptions()...)
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	defer j.Close()
	want := filepath.Join(dir, DefaultFileName)
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("journal 應落在 %q: %v", want, err)
	}

	t.Setenv("AUDIT_LOG_PATH", "")
	if got := ResolveDir(); got != filepath.Join("logs", "audit_fallback") {
		t.Fatalf("未設 AUDIT_LOG_PATH 時應退回內建相對路徑，得 %q", got)
	}
}
