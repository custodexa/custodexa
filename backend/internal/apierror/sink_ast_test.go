package apierror

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 全域裸文字錯誤出口守衛（backend-i18n-unification D1）
//
// 語義：後端「使用者可見文字直寫」的出口必須全部走 apierror 出口。既有出口以
// hash 制 allowlist 凍結（燒盡制），新出口一律紅。
//
// 為什麼是 hash 而不是 file:line：行號會因無關改動漂移，漂移後的 allowlist 條目
// 會意外赦免新出口（移位假綠）。條目改為「檔名 + sink 運算式正規化後的 hash」，
// 對 gofmt 重排免疫，且刪掉出口後 stale 條目會直接紅。
//
// 測試語義＝掃描結果集與 allowlist **集合相等**（新 hash 紅、stale hash 紅）。
// 不設「只准縮減」的單調閘：集合相等已雙向，燒盡紀律由 commit diff 人審承擔
// （與 cmd/server 的 routes golden 同級）。
// ---------------------------------------------------------------------------

// updateSinkAllowlist 重新生成 allowlist golden。
//
// 用法（唯一文件化指令）：
//
//	docker compose exec -T backend go test ./internal/apierror/ -run TestNoRawErrorSinks -update
//
// 與 routes golden 同一取捨：-update 使清單從「不可竄改基準」降為「可重生快照」，
// 其價值自此依賴流程——**每次 -update 的 diff 必須在 commit 中逐條審視**，
// 尤其新增條目（新增即代表又多了一個裸文字出口，正常情況只該減不該增）。
var updateSinkAllowlist = flag.Bool("update", false,
	"重新生成 internal/apierror/testdata/raw_sink_allowlist.txt")

// sinkScanDirs 是掃描範圍（相對 backend/），非測試 .go 全部納入（遞迴，略過 testdata）。
//
// 清單由 sinkCoverageRoots 的涵蓋斷言把關：任何 import gin 的非測試套件
// 必須落在本清單內，否則測試紅——堵「在清單外套件寫 handler」的規避路徑。
var sinkScanDirs = []string{
	"internal/api",
	"internal/middleware",
	"internal/sshproxy",
	"internal/proxy",
	"internal/k8sproxy",
	"internal/dbproxy",
	"internal/sourceip",
	// internal/observability 的指標曝光端點 import gin（observability-lite）。
	// **納入掃描而非加入豁免**：豁免等於在該套件內放棄監管，而它確實有一條
	// 錯誤回應路徑（token 不符的 401）。納入後守衛即持續保證該路徑不裸寫錯誤體。
	"internal/observability",
	"cmd/server",
}

// sinkCoverageRoots 是涵蓋斷言的搜尋根。
var sinkCoverageRoots = []string{"internal", "cmd"}

// sinkCoverageExempt 是涵蓋斷言的**具名豁免**（唯一一筆，需理由）。
//
// internal/apierror 自己 import gin：它就是 apierror 出口的實作套件，
// Write/WriteLegacy 內部必然有 c.JSON(gin.H{...})。把實作套件納入掃描等於
// 要求出口實作自我豁免，無意義。WriteLegacy 的消滅由「刪函式」保證
// （編譯期不可回潮），不由本守衛保證。
var sinkCoverageExempt = map[string]bool{
	"internal/apierror": true,
}

// sinkKeys 是偵測鍵：map 字面量帶這些字串鍵即視為使用者可見文字出口。
//
// "message" 與 "error" 同樣直達使用者（成功回應的 message 亦然）。
// **"reason"/"policy" 刻意不在內**——它們是機器欄，前端據以做控制流分支
// （connect.js 依 reason 彈框），本就該保留。
var sinkKeys = []string{"error", "message"}

const (
	// minScannedFiles 是掃描檔數下限（防假綠）：若掃描目錄設定被誤改成只剩
	// 少數檔案，測試會綠得毫無意義。實測 66 檔，門檻取 60。
	minScannedFiles = 60

	// sinkAllowlistRel 是 allowlist golden 相對本套件目錄的路徑。
	sinkAllowlistRel = "testdata/raw_sink_allowlist.txt"

	// sinkHashLen 是 hash 十六進位字元數（sha256 前 12 hex）。
	sinkHashLen = 12
)

// legacyCodeAllowlist lists documented out-of-system lowercase codes that are
// written directly (not via apierror) and are exempt from grammar/registry.
// backend-i18n-unification 收尾後應保持為空：break_glass_disabled 已改
// RULE_BREAK_GLASS_DISABLED、ack_required/strict_reject 已改
// VALIDATION_TRANSMISSION_*（前後端同步收斂）。新條目須附書面理由。
var legacyCodeAllowlist = map[string]bool{}

// writerFuncs are the apierror response writers whose code argument must be a
// registry constant reference (selector/ident), never a bare string or conversion.
var writerFuncs = map[string]bool{"Respond": true, "RespondInternal": true, "Write": true}

// apierrorModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const apierrorModulePath = "github.com/custodexa/backend"

// backendRoot 定位 backend module 根（本套件三個守衛的共用掃描根）。
//
// **不用固定層數 `..`**（modular-architecture W1 1.20）：`Dir(caller)/../..`
// 與「本 package 住在樹的第幾層」綁死，package 一下移就指向 internal/（而非
// backend/），Walk 照樣成功、只是掃到錯的子樹或空目錄——守衛於是掃空而照樣綠。
// 改以「自本測試檔位置向上找 go.mod 並核對 module 行」為身分錨點。
// 錨點失效時 panic 而非回傳錯路徑：本函式無 *testing.T，靜默回錯根才是最壞結果。
func backendRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(file)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			want := "module " + apierrorModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			panic("在 " + dir + "/go.mod 找到 go.mod，但 module 行不是 \"" + want +
				"\"：掃描根定位錨點失效，守衛可能正在掃錯的樹")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("自 " + filepath.Dir(file) + " 向上找不到 go.mod（module " +
				apierrorModulePath + "）：掃描根無從定位")
		}
		dir = parent
	}
}

func apierrorDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// ---------------------------------------------------------------------------
// 掃描
// ---------------------------------------------------------------------------

// sinkEntry 是單一裸文字出口：檔案（相對 backend/，斜線分隔）＋正規化 hash。
// Line 僅用於錯誤訊息可讀性，不參與比對。
type sinkEntry struct {
	File string
	Hash string
	Line int
}

func (e sinkEntry) key() string { return e.File + "\x00" + e.Hash }

// normalizedHash 以 go/printer 標準化列印節點後取 sha256 前 12 hex。
//
// 正規化定義：以**空的 FileSet** 呼叫 go/printer——節點位置在該 FileSet 中無法
// 解析，printer 因此忽略原始碼的換行／縮排，輸出唯一的緊湊表述（多行寫法的
// 尾逗號也隨之消失）；再把殘餘空白序列壓成單一空格。結果對 gofmt 重排、
// 單行↔多行改寫、巢狀層級變動免疫，只對「寫了什麼」敏感。
// 見 TestSinkHashNormalization（排版免疫＋內容敏感的雙向證明）。
//
// **fail-closed**：列印失敗一律回 error 並由呼叫端上拋至 t.Fatal。舊版退回
// 「printerr<len>」的假 hash——長度相同的兩個節點會碰撞成同一條目，等於讓
// allowlist 誤赦真實出口（假綠）。守衛寧可整個掛掉也不可假裝算出 hash。
// 見 TestNormalizedHashFailsClosed。
func normalizedHash(n ast.Node) (string, error) {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, token.NewFileSet(), n); err != nil {
		return "", fmt.Errorf("go/printer 無法列印 %T（守衛 fail-closed）: %w", n, err)
	}
	norm := strings.Join(strings.Fields(buf.String()), " ")
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])[:sinkHashLen], nil
}

// compositeHasAnySinkKey reports whether cl carries any of the detection keys.
func compositeHasAnySinkKey(cl *ast.CompositeLit) bool {
	for _, k := range sinkKeys {
		if compositeHasStringKey(cl, k) {
			return true
		}
	}
	return false
}

func isSinkKeyLiteral(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return false
	}
	for _, k := range sinkKeys {
		if s == k {
			return true
		}
	}
	return false
}

// scanErrorSinks walks a parsed file and returns the three violation classes:
//
//  1. sinks：帶偵測鍵的 map 字面量（同時涵蓋 c.JSON(gin.H{...}) 直寫與
//     `body := gin.H{...}; c.JSON(body)` 的變數中轉）＋ `x["error"] = v` 的
//     index 賦值型；
//  2. badCodeArgs：apierror writer 的 code 引數不是 registry 常數
//     （裸字串／ErrCode(...) 轉換）；
//  3. badCodeWrites：allowlist 外的直寫 "code" 字串。
//
// hash 計算失敗即回 error（fail-closed），呼叫端一律 t.Fatal。
func scanErrorSinks(fset *token.FileSet, f *ast.File, rel string) (sinks []sinkEntry, badCodeArgs, badCodeWrites []string, hashErr error) {
	loc := func(n ast.Node) string { return rel + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) }
	entry := func(n ast.Node) sinkEntry {
		h, err := normalizedHash(n)
		if err != nil && hashErr == nil {
			hashErr = fmt.Errorf("%s: %w", loc(n), err)
		}
		return sinkEntry{File: rel, Hash: h, Line: fset.Position(n.Pos()).Line}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if cl, ok := n.(*ast.CompositeLit); ok {
			// (1) 帶偵測鍵的 map 字面量＝裸文字出口
			if compositeHasAnySinkKey(cl) {
				sinks = append(sinks, entry(cl))
			}
			// (3) 直寫 "code" 字串必須是文件化的 legacy 碼
			if v, ok := stringValueForKey(cl, "code"); ok && !legacyCodeAllowlist[v] {
				badCodeWrites = append(badCodeWrites, loc(cl)+" ("+v+")")
			}
		}
		// (2) apierror writer 的 code 引數必須解析為 registry 常數
		if call, ok := n.(*ast.CallExpr); ok {
			if codeExpr, ok := writerCodeArg(call); ok && !isRegistryConstRef(codeExpr) {
				badCodeArgs = append(badCodeArgs, loc(call))
			}
		}
		// (1b) index 賦值型出口：`x["error"] = raw`
		if as, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range as.Lhs {
				if ix, ok := lhs.(*ast.IndexExpr); ok && isSinkKeyLiteral(ix.Index) {
					sinks = append(sinks, entry(as))
					break
				}
			}
		}
		return true
	})
	return
}

// collectScanFiles 回傳 dirs 下所有非測試 .go（相對 root，斜線分隔，排序穩定）。
// 略過 testdata/vendor（Go 工具鏈慣例）。
func collectScanFiles(root string, dirs []string) ([]string, error) {
	var out []string
	for _, d := range dirs {
		abs := filepath.Join(root, filepath.FromSlash(d))
		err := filepath.Walk(abs, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if name := info.Name(); path != abs && (name == "testdata" || name == "vendor") {
					return filepath.SkipDir
				}
				return nil
			}
			name := info.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// ginPackagesOutsideScan 是涵蓋斷言的實作：回傳 roots 下所有「有非測試 .go
// 且 import gin」但不在 dirs 掃描範圍（也不在具名豁免）內的套件目錄。
// 回傳非空即代表有 handler 寫在守衛視野外。
func ginPackagesOutsideScan(root string, roots, dirs []string, exempt map[string]bool) ([]string, error) {
	covered := func(rel string) bool {
		for _, d := range dirs {
			if rel == d || strings.HasPrefix(rel, d+"/") {
				return true
			}
		}
		return exempt[rel]
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range roots {
		abs := filepath.Join(root, filepath.FromSlash(r))
		if _, err := os.Stat(abs); os.IsNotExist(err) {
			continue
		}
		err := filepath.Walk(abs, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if name := info.Name(); name == "testdata" || name == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			name := info.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if perr != nil {
				return fmt.Errorf("parse imports %s: %w", path, perr)
			}
			if !importsGin(f) {
				return nil
			}
			relDir, rerr := filepath.Rel(root, filepath.Dir(path))
			if rerr != nil {
				return rerr
			}
			pkg := filepath.ToSlash(relDir)
			if covered(pkg) || seen[pkg] {
				return nil
			}
			seen[pkg] = true
			out = append(out, pkg)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

func importsGin(f *ast.File) bool {
	for _, imp := range f.Imports {
		if imp.Path != nil && imp.Path.Value == `"github.com/gin-gonic/gin"` {
			return true
		}
	}
	return false
}

// checkScanStats 防假綠：掃描檔數下限（抽成純函式以便單測）。
// 註：初版另有「掃到 0 個出口即紅」的 tripwire——大掃除歸零後該預設反轉
// （0 即目標狀態），偵測器健康改由 TestSinkScannerDetects 的樣本正向控制保證
// （樣本掃不出必紅），不再以生產碼殘量當偵測器健康指標。
func checkScanStats(fileCount, sinkCount int) []string {
	var problems []string
	if fileCount < minScannedFiles {
		problems = append(problems, fmt.Sprintf(
			"掃描檔數 %d < 下限 %d——掃描範圍設定可能被誤縮，本測試已失去意義", fileCount, minScannedFiles))
	}
	_ = sinkCount
	return problems
}

// ---------------------------------------------------------------------------
// allowlist golden 讀寫
// ---------------------------------------------------------------------------

// multiset 以 "file\x00hash" 為鍵計數（同檔同構出口可能多筆）。
type multiset map[string]int

func sinkMultiset(entries []sinkEntry) multiset {
	m := multiset{}
	for _, e := range entries {
		m[e.key()]++
	}
	return m
}

func loadSinkAllowlist(path string) (multiset, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := multiset{}
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s:%d 格式錯誤（需 `path hash count`）：%q", path, line, text)
		}
		n, err := strconv.Atoi(fields[2])
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("%s:%d count 非正整數：%q", path, line, fields[2])
		}
		m[fields[0]+"\x00"+fields[1]] += n
	}
	return m, sc.Err()
}

func renderSinkAllowlist(m multiset) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# 裸文字錯誤出口 allowlist（backend-i18n-unification D1，機器生成勿手改）\n")
	b.WriteString("# 格式：<相對 backend/ 的檔案路徑> <sink 運算式正規化 hash> <同檔同 hash 筆數>\n")
	b.WriteString("# 重生：docker compose exec -T backend go test ./internal/apierror/ -run TestNoRawErrorSinks -update\n")
	b.WriteString("# 語義：燒盡制。條目只該減不該增；-update 的 diff 須在 commit 中逐條審視。\n")
	for _, k := range keys {
		parts := strings.SplitN(k, "\x00", 2)
		fmt.Fprintf(&b, "%s %s %d\n", parts[0], parts[1], m[k])
	}
	return b.String()
}

// diffMultiset 回傳 got 相對 want 的新增／缺漏（含計數差）。
func diffMultiset(got, want multiset) (added, stale []string) {
	for k, n := range got {
		if d := n - want[k]; d > 0 {
			added = append(added, formatMultisetKey(k, d))
		}
	}
	for k, n := range want {
		if d := n - got[k]; d > 0 {
			stale = append(stale, formatMultisetKey(k, d))
		}
	}
	sort.Strings(added)
	sort.Strings(stale)
	return
}

func formatMultisetKey(k string, n int) string {
	parts := strings.SplitN(k, "\x00", 2)
	return fmt.Sprintf("%s %s x%d", parts[0], parts[1], n)
}

// ---------------------------------------------------------------------------
// 主守衛
// ---------------------------------------------------------------------------

// TestNoRawErrorSinks 是「後端不再新增裸文字錯誤出口」的長久守衛。
func TestNoRawErrorSinks(t *testing.T) {
	root := backendRoot()

	files, err := collectScanFiles(root, sinkScanDirs)
	if err != nil {
		t.Fatalf("collect scan files: %v", err)
	}

	fset := token.NewFileSet()
	var sinks []sinkEntry
	var badCodeArgs, badCodeWrites []string
	for _, rel := range files {
		f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		s, ba, bw, herr := scanErrorSinks(fset, f, rel)
		if herr != nil {
			t.Fatalf("hash 計算失敗（守衛 fail-closed，不接受假 hash）: %v", herr)
		}
		sinks = append(sinks, s...)
		badCodeArgs = append(badCodeArgs, ba...)
		badCodeWrites = append(badCodeWrites, bw...)
	}

	// 防假綠 1/2：掃描檔數下限與「掃到 0 個出口」。
	for _, p := range checkScanStats(len(files), len(sinks)) {
		t.Error(p)
	}

	// 防假綠 3：涵蓋斷言——import gin 的套件不得落在掃描清單外。
	uncovered, err := ginPackagesOutsideScan(root, sinkCoverageRoots, sinkScanDirs, sinkCoverageExempt)
	if err != nil {
		t.Fatalf("coverage scan: %v", err)
	}
	if len(uncovered) > 0 {
		t.Errorf("下列套件 import gin 但不在 sinkScanDirs 內（handler 寫在守衛視野外）：\n  %s\n"+
			"請把它們加進 sinkScanDirs（或以理由加入 sinkCoverageExempt）", strings.Join(uncovered, "\n  "))
	}

	got := sinkMultiset(sinks)
	allowlistPath := filepath.Join(apierrorDir(), filepath.FromSlash(sinkAllowlistRel))

	if *updateSinkAllowlist {
		if err := os.MkdirAll(filepath.Dir(allowlistPath), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(allowlistPath, []byte(renderSinkAllowlist(got)), 0o644); err != nil {
			t.Fatalf("write allowlist: %v", err)
		}
		t.Logf("已重生 %s：%d 個條目 / %d 個出口 / 掃描 %d 檔——請逐條審視 diff",
			sinkAllowlistRel, len(got), len(sinks), len(files))
	} else {
		want, err := loadSinkAllowlist(allowlistPath)
		if err != nil {
			t.Fatalf("load allowlist（首次請以 -update 生成）: %v", err)
		}
		added, stale := diffMultiset(got, want)
		if len(added) > 0 {
			t.Errorf("新增的裸文字錯誤出口（%d 筆，未在 allowlist）：\n  %s\n"+
				"新出口一律不接受——請改走 apierror.Respond/RespondInternal/Write。\n"+
				"對照行號：%s", len(added), strings.Join(added, "\n  "), locateHashes(sinks, added))
		}
		if len(stale) > 0 {
			t.Errorf("allowlist 中已不存在的條目（%d 筆，stale）：\n  %s\n"+
				"出口已消滅是好事——請跑 -update 更新清單（燒盡進度）", len(stale), strings.Join(stale, "\n  "))
		}
	}

	if len(badCodeArgs) > 0 {
		t.Errorf("apierror writer with non-constant code arg (bare string / conversion) (%d):\n  %v", len(badCodeArgs), badCodeArgs)
	}
	if len(badCodeWrites) > 0 {
		t.Errorf("direct \"code\" writes outside legacy allowlist (%d):\n  %v", len(badCodeWrites), badCodeWrites)
	}
}

// locateHashes 把「file hash xN」條目對回實際行號，讓錯誤訊息可直接定位。
func locateHashes(sinks []sinkEntry, entries []string) string {
	wanted := map[string]bool{}
	for _, e := range entries {
		fields := strings.Fields(e)
		if len(fields) >= 2 {
			wanted[fields[0]+"\x00"+fields[1]] = true
		}
	}
	var locs []string
	for _, s := range sinks {
		if wanted[s.key()] {
			locs = append(locs, fmt.Sprintf("%s:%d", s.File, s.Line))
		}
	}
	sort.Strings(locs)
	return strings.Join(locs, ", ")
}

// ---------------------------------------------------------------------------
// 守衛自身的守衛（防假綠分支各自可觸發）
// ---------------------------------------------------------------------------

// TestNoRawErrorSinksDetectors 證明掃描器確實抓得到每一類違規（含新加的
// "message" 鍵），並證明 hash 對排版變動免疫、對內容變動敏感。
func TestNoRawErrorSinksDetectors(t *testing.T) {
	// 反引號鍵的案例必須以字串串接嵌入（樣本本身是 raw string，不能巢狀反引號）。
	bad := `package sample
import "github.com/custodexa/backend/internal/apierror"
func f(c interface{ JSON(int, any) }) {
	c.JSON(400, ginH{"error": "raw sink"})              // (1) 直寫
	raw := ginH{"error": "indirect"}                     // (1) 變數中轉
	c.JSON(400, raw)
	body := ginH{}
	body["error"] = "assigned"                           // (1b) index 賦值
	c.JSON(400, body)
	c.JSON(200, ginH{"message": "刪除成功"})              // (1) message 鍵
	c.JSON(200, ginH{"reason": "policy_denied"})         // OK: 機器欄不在偵測鍵內
	apierror.Respond(c, 400, "BARE_STRING", nil)         // (2) 裸字串碼
	apierror.Respond(c, 400, apierror.ErrCode("X"), nil) // (2) ErrCode 轉換
	c.JSON(403, ginH{"code": "unlisted_lowercase"})      // (3) allowlist 外的直寫碼
	apierror.Respond(c, 401, apierror.CodeUnauthenticated, nil) // OK: registry 常數
	c.JSON(403, ginH{"code": "break_glass_disabled"})    // (3) legacy allowlist 已清空，同樣違規
	c.JSON(400, ginH{` + "`error`" + `: "raw-string key"})    // (1) 反引號鍵繞過
	c.JSON(403, ginH{` + "`code`" + `: "raw_key_code"})       // (3) 反引號鍵的直寫碼
	body[` + "`message`" + `] = "raw-string index key"        // (1b) 反引號 index 鍵
}
type ginH map[string]any
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sample.go", bad, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sinks, ba, bw, herr := scanErrorSinks(fset, f, "sample.go")
	if herr != nil {
		t.Fatalf("hash 失敗: %v", herr)
	}
	if len(sinks) != 6 {
		t.Errorf("sinks: got %d %v, want 6 (2 composite error + 1 index-assign + 1 message + 1 反引號鍵 + 1 反引號 index 鍵)", len(sinks), sinks)
	}
	if len(ba) != 2 {
		t.Errorf("bad code args: got %d %v, want 2", len(ba), ba)
	}
	if len(bw) != 3 {
		t.Errorf("bad code writes: got %d %v, want 3 (legacy allowlist 已清空，含反引號鍵)", len(bw), bw)
	}
	for _, s := range sinks {
		if len(s.Hash) != sinkHashLen {
			t.Errorf("hash 長度 %d != %d: %+v", len(s.Hash), sinkHashLen, s)
		}
	}
}

// TestSinkHashNormalization 證明 hash 對排版免疫、對內容敏感（hash 制的前提）。
func TestSinkHashNormalization(t *testing.T) {
	hashOf := func(t *testing.T, src string) string {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "s.go", src, 0)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		s, _, _, herr := scanErrorSinks(fset, f, "s.go")
		if herr != nil {
			t.Fatalf("hash 失敗: %v", herr)
		}
		if len(s) != 1 {
			t.Fatalf("want exactly 1 sink, got %d", len(s))
		}
		return s[0].Hash
	}
	compact := hashOf(t, "package s\nfunc f(c C) { c.JSON(400, ginH{\"error\": \"帳號已停用\"}) }\ntype C interface{ JSON(int, any) }\ntype ginH map[string]any\n")
	spread := hashOf(t, "package s\nfunc f(c C) {\n\tc.JSON(400, ginH{\n\t\t\"error\":   \"帳號已停用\",\n\t})\n}\ntype C interface{ JSON(int, any) }\ntype ginH map[string]any\n")
	other := hashOf(t, "package s\nfunc f(c C) { c.JSON(400, ginH{\"error\": \"帳號已鎖定\"}) }\ntype C interface{ JSON(int, any) }\ntype ginH map[string]any\n")

	if compact != spread {
		t.Errorf("排版變動改變了 hash（移位假綠風險反向）：%s vs %s", compact, spread)
	}
	if compact == other {
		t.Errorf("不同訊息卻同 hash：%s", compact)
	}
}

// TestNormalizedHashFailsClosed 證明 hash 計算失敗會回 error 而非退成假 hash。
//
// 可構造性：go/printer 的 printNode 只認 ast.Expr/Stmt/Decl/Spec/*ast.File
// （及其切片與 CommentedNode），其餘 ast.Node 一律回
// "unsupported node type"。*ast.Comment 正好是 ast.Node 但不屬上列任一類，
// 因此是可穩定構造的失敗輸入。
//
// 為什麼舊實作是假綠風險：它回傳 "printerr"+len 的四位十六進位，長度相同的
// 不同節點會得到**同一個** hash——allowlist 上一筆這種條目即可赦免任意數量的
// 真實出口。守衛的失敗模式必須是「整個紅」，不是「悄悄算出一個值」。
func TestNormalizedHashFailsClosed(t *testing.T) {
	if _, err := normalizedHash(&ast.Comment{Text: "// x"}); err == nil {
		t.Fatal("列印不支援的節點型別應回 error（fail-closed），實得 nil")
	}

	// 正常節點仍須算得出 hash（證明上面的紅不是因為函式整個壞掉）。
	h, err := normalizedHash(&ast.BasicLit{Kind: token.STRING, Value: `"ok"`})
	if err != nil {
		t.Fatalf("正常節點不該失敗: %v", err)
	}
	if len(h) != sinkHashLen {
		t.Errorf("hash 長度 %d != %d", len(h), sinkHashLen)
	}
}

// TestSinkScanStatsGuards 證明檔數下限分支會觸發。
// （零出口 tripwire 已隨大掃除歸零移除——0 即目標狀態；偵測器健康由
// TestSinkScannerDetects 的樣本正向控制保證。）
func TestSinkScanStatsGuards(t *testing.T) {
	if p := checkScanStats(minScannedFiles, 300); len(p) != 0 {
		t.Errorf("正常情況不該有問題，got %v", p)
	}
	if p := checkScanStats(minScannedFiles, 0); len(p) != 0 {
		t.Errorf("零出口是目標狀態，不該有問題，got %v", p)
	}
	if p := checkScanStats(minScannedFiles-1, 300); len(p) != 1 {
		t.Errorf("檔數低於下限應觸發 1 條，got %v", p)
	}
}

// TestSinkCoverageAssertion 證明涵蓋斷言抓得到「在掃描清單外的套件寫 gin handler」。
func TestSinkCoverageAssertion(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const ginSrc = "package p\nimport \"github.com/gin-gonic/gin\"\nfunc H(c *gin.Context) {}\n"
	write("internal/api/h.go", ginSrc)                         // 在掃描範圍內
	write("internal/sneaky/h.go", ginSrc)                      // 規避路徑：清單外套件
	write("internal/apierror/w.go", ginSrc)                    // 具名豁免
	write("internal/service/s.go", "package s\nfunc F() {}\n") // 不 import gin
	write("internal/api/h_test.go", ginSrc)                    // 測試檔不算

	dirs := []string{"internal/api"}
	got, err := ginPackagesOutsideScan(root, []string{"internal", "cmd"}, dirs, sinkCoverageExempt)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	want := []string{"internal/sneaky"}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("涵蓋斷言結果錯誤：got %v, want %v", got, want)
	}

	// 把它納入掃描清單後應轉綠。
	got2, err := ginPackagesOutsideScan(root, []string{"internal", "cmd"}, append(dirs, "internal/sneaky"), sinkCoverageExempt)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got2) != 0 {
		t.Errorf("納入清單後應無殘留，got %v", got2)
	}
}

// TestSinkAllowlistRoundTrip 證明 golden 的讀寫與集合相等比對語義。
func TestSinkAllowlistRoundTrip(t *testing.T) {
	base := multiset{
		"internal/api/a.go\x00aaaaaaaaaaaa": 2,
		"internal/api/b.go\x00bbbbbbbbbbbb": 1,
	}
	path := filepath.Join(t.TempDir(), "raw_sink_allowlist.txt")
	if err := os.WriteFile(path, []byte(renderSinkAllowlist(base)), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadSinkAllowlist(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != len(base) {
		t.Fatalf("round-trip 條目數不符：got %d want %d", len(got), len(base))
	}
	if added, stale := diffMultiset(got, base); len(added) != 0 || len(stale) != 0 {
		t.Fatalf("round-trip 應相等：added=%v stale=%v", added, stale)
	}

	// 新 hash → added；缺 hash → stale；同 hash 增量 → added。
	plus := multiset{
		"internal/api/a.go\x00aaaaaaaaaaaa": 3,
		"internal/api/c.go\x00cccccccccccc": 1,
	}
	added, stale := diffMultiset(plus, base)
	if len(added) != 2 {
		t.Errorf("added: got %v, want 2 (a.go 增量 + c.go 新條目)", added)
	}
	if len(stale) != 1 {
		t.Errorf("stale: got %v, want 1 (b.go)", stale)
	}
}

// ---------------------------------------------------------------------------
// AST 小工具
// ---------------------------------------------------------------------------

// compositeHasStringKey reports whether cl has a KeyValueExpr with the given string key.
func compositeHasStringKey(cl *ast.CompositeLit, key string) bool {
	_, ok := findKV(cl, key)
	return ok
}

// stringValueForKey returns the unquoted string value for a string-literal key, if the value is a string literal.
func stringValueForKey(cl *ast.CompositeLit, key string) (string, bool) {
	v, ok := findKV(cl, key)
	if !ok {
		return "", false
	}
	if lit, ok := v.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		if s, err := strconv.Unquote(lit.Value); err == nil {
			return s, true
		}
	}
	return "", false
}

// findKV 找出 composite literal 中鍵為 key 的值運算式。
//
// 鍵一律經 strconv.Unquote 後比對**字串值**，不比對原始 token 文字：`"error"` 與
// 反引號 raw string 的鍵是同一個 map 鍵，卻是兩種 token 寫法。舊版直接比
// `"`+key+`"` 的原始文字，於是 gin.H{`error`: "x"} 這種寫法完全繞過守衛
// （index 賦值路徑的 isSinkKeyLiteral 一直是對的，此處對齊之）。
func findKV(cl *ast.CompositeLit, key string) (ast.Expr, bool) {
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		lit, ok := kv.Key.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		if s, err := strconv.Unquote(lit.Value); err == nil && s == key {
			return kv.Value, true
		}
	}
	return nil, false
}

// writerCodeArg returns the code-argument expression of an apierror writer call.
// For Respond/RespondInternal the code is arg[2]; for Write it is the Code field
// of the ErrorResponse composite literal (arg[2]).
func writerCodeArg(call *ast.CallExpr) (ast.Expr, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !writerFuncs[sel.Sel.Name] {
		return nil, false
	}
	if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "apierror" {
		return nil, false
	}
	if len(call.Args) < 3 {
		return nil, false
	}
	arg := call.Args[2]
	if sel.Sel.Name == "Write" {
		cl, ok := arg.(*ast.CompositeLit)
		if !ok {
			return nil, false
		}
		if code, ok := fieldValue(cl, "Code"); ok {
			return code, true
		}
		return nil, false
	}
	return arg, true
}

// fieldValue returns the value of a struct-literal field with the given identifier name.
func fieldValue(cl *ast.CompositeLit, name string) (ast.Expr, bool) {
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == name {
			return kv.Value, true
		}
	}
	return nil, false
}

// isRegistryConstRef reports whether e is an acceptable code argument: a
// registry constant selector (apierror.CodeXxx), a local identifier bound to one
// (e.g. `code := apierror.CodeScopedTokenDenied`), or a helper call that returns
// an ErrCode (e.g. mfaSentinelCode(err)). It rejects bare string literals and
// ErrCode(...) type conversions that would smuggle an unregistered code past
// the type system.
// Scope note: without go/types this gate cannot prove that an identifier/selector
// (e.g. a local `code` var, or a struct field like `violation.Code`) resolves to a
// *registered* constant — those legitimate indirections are accepted. It reliably
// rejects the clear-cut smuggling paths: bare string literals and ErrCode(...)
// conversions. The residual (a var/field bound to an unregistered code) is backstopped
// at runtime (Write logs + generic on unregistered code) and by the bijection test.
func isRegistryConstRef(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return true // apierror.CodeXxx or a field of ErrCode type (e.g. violation.Code)
	case *ast.Ident:
		return v.Name != "nil"
	case *ast.CallExpr:
		// a helper call returning ErrCode is fine; an ErrCode(...) conversion is not
		return !isErrCodeConversion(v)
	default:
		return false // BasicLit (string), etc.
	}
}

// isErrCodeConversion reports whether call is `ErrCode(x)` or `apierror.ErrCode(x)`.
func isErrCodeConversion(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name == "ErrCode"
	case *ast.SelectorExpr:
		return fun.Sel.Name == "ErrCode"
	}
	return false
}
