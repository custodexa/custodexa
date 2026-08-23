package apierror

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// ---------------------------------------------------------------------------
// 串流出口中文字面量守衛
//
// 語義：`internal/sshproxy`、`internal/proxy` 的**非測試碼**中，中文字面量只允許
// 出現在三種位置——
//
//	1. log 系呼叫（log.Printf / log.Println / log.Fatalf / …）：伺服端日誌，不出站；
//	2. fmt.Errorf / errors.New：內部 error 值，由上層決定如何呈現；
//	3. 註解（不是 BasicLit，天然不在掃描面內）。
//
// 其餘一律紅——使用者可見文字必須走 apierror registry 的碼（送碼、前端查譯）。
//
// 為什麼是「callee 名稱」而非「字串內容」：v2 版守衛以內容啟發式判斷，被審出
// 「先賦值給變數再送出」即可繞過。改看呼叫點後，`msg := "中文"; c.JSON(...)` 的
// 中轉寫法在賦值當下就紅，沒有可繞路徑。
//
// allowlist 與 sink 守衛同一套 hash 燒盡制（檔名＋字面量正規化 hash＋筆數），
// 集合相等比對：新字面量紅、已消滅的條目 stale 也紅。行號不參與比對（漂移假綠）。
//
// 重生（沿用 sink 守衛的 -update 旗標，同套件共用）：
//
//	docker compose exec -T backend go test ./internal/apierror/ \
//	  -run TestNoChineseLiteralsInStreamExits -update
//
// 初始清單的主體是 sshproxy/proxy 兩個 handler 的 HTTP JSON 直寫殘量，
// 隨這些出口改走 apierror 碼而歸零。
// ---------------------------------------------------------------------------

// streamScanDirs 是本守衛的掃描範圍（相對 backend/）。
var streamScanDirs = []string{"internal/sshproxy", "internal/proxy"}

const (
	// streamAllowlistRel 是 allowlist golden 相對本套件目錄的路徑。
	streamAllowlistRel = "testdata/stream_literal_allowlist.txt"

	// minStreamScannedFiles 是掃描檔數下限（防假綠）：兩個套件實測 20 檔，門檻取 15。
	minStreamScannedFiles = 15
)

// exemptCallDesc 描述一種豁免呼叫形態，供錯誤訊息與自測引用。
var exemptCallDesc = "log.*／fmt.Errorf／errors.New"

// isExemptCall 判斷 call 是否為豁免呼叫（其整個子樹內的中文字面量都放行）。
//
// 子樹放行而非僅直接引數：`log.Printf("%s", fmt.Sprintf("中文 %v", err))` 這類
// 巢狀組字仍是日誌路徑。代價是 `log.Printf("x", f(gin.H{"error": "中文"}))` 會被
// 誤赦——該形態在本兩套件不存在，且真要出口也會被 sink 守衛攔下。
func isExemptCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch pkg.Name {
	case "log": // 整個標準 log 套件：Print/Printf/Println/Fatal*/Panic*
		return true
	case "fmt":
		return sel.Sel.Name == "Errorf"
	case "errors":
		return sel.Sel.Name == "New"
	}
	return false
}

// containsHan 回報字串是否含漢字。
//
// 守衛盲區：只擋中文。英文的使用者可見字面量攔不到——
// 本專案的裸文字歷史包袱全是中文，先解決可機器判定的那半。
func containsHan(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// scanChineseLiterals 回傳檔內所有「不在豁免呼叫子樹內」的中文字面量。
//
// 兩種寫法變體由 strconv.Unquote／逐節點掃描天然涵蓋，並由
// TestStreamLiteralDetector 的樣本鎖住（防日後解析邏輯退化）：
//   - 反引號 raw string：Unquote 同樣解得出內容，照抓；
//   - `"中" + "文"` 串接：兩段各自是 BasicLit，各記一筆（都得進 allowlist）。
//
// hash 計算失敗即回 error（fail-closed，見 normalizedHash）。
func scanChineseLiterals(fset *token.FileSet, f *ast.File, rel string) ([]sinkEntry, error) {
	type span struct{ start, end token.Pos }
	var exempt []span
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isExemptCall(call) {
			exempt = append(exempt, span{call.Pos(), call.End()})
		}
		return true
	})
	inExempt := func(p token.Pos) bool {
		for _, s := range exempt {
			if p >= s.start && p < s.end {
				return true
			}
		}
		return false
	}

	var out []sinkEntry
	var hashErr error
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil || !containsHan(s) {
			return true
		}
		if inExempt(lit.Pos()) {
			return true
		}
		h, herr := normalizedHash(lit)
		if herr != nil && hashErr == nil {
			hashErr = fmt.Errorf("%s:%d: %w", rel, fset.Position(lit.Pos()).Line, herr)
		}
		out = append(out, sinkEntry{
			File: rel,
			Hash: h,
			Line: fset.Position(lit.Pos()).Line,
		})
		return true
	})
	if hashErr != nil {
		return nil, hashErr
	}
	return out, nil
}

// renderStreamAllowlist 產生 golden 內容（格式與 sink allowlist 一致，
// 標頭另述以免兩份清單被混淆）。
func renderStreamAllowlist(m multiset) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# 串流出口中文字面量 allowlist（機器生成勿手改）\n")
	b.WriteString("# 範圍：internal/sshproxy、internal/proxy 的非測試碼；log 系呼叫與 fmt.Errorf/errors.New 已豁免。\n")
	b.WriteString("# 格式：<相對 backend/ 的檔案路徑> <字面量正規化 hash> <同檔同 hash 筆數>\n")
	b.WriteString("# 重生：docker compose exec -T backend go test ./internal/apierror/ -run TestNoChineseLiteralsInStreamExits -update\n")
	b.WriteString("# 語義：燒盡制。條目只該減不該增；-update 的 diff 須在 commit 中逐條審視。\n")
	for _, k := range keys {
		parts := strings.SplitN(k, "\x00", 2)
		fmt.Fprintf(&b, "%s %s %d\n", parts[0], parts[1], m[k])
	}
	return b.String()
}

// TestNoChineseLiteralsInStreamExits 是串流出口的字面量守衛。
func TestNoChineseLiteralsInStreamExits(t *testing.T) {
	root := backendRoot()

	files, err := collectScanFiles(root, streamScanDirs)
	if err != nil {
		t.Fatalf("collect scan files: %v", err)
	}
	if len(files) < minStreamScannedFiles {
		t.Errorf("掃描檔數 %d < 下限 %d——掃描範圍設定可能被誤縮，本測試已失去意義",
			len(files), minStreamScannedFiles)
	}

	fset := token.NewFileSet()
	var lits []sinkEntry
	for _, rel := range files {
		f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		got, herr := scanChineseLiterals(fset, f, rel)
		if herr != nil {
			t.Fatalf("hash 計算失敗（守衛 fail-closed，不接受假 hash）: %v", herr)
		}
		lits = append(lits, got...)
	}

	got := sinkMultiset(lits)
	allowlistPath := filepath.Join(apierrorDir(), filepath.FromSlash(streamAllowlistRel))

	if *updateSinkAllowlist {
		if err := os.MkdirAll(filepath.Dir(allowlistPath), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(allowlistPath, []byte(renderStreamAllowlist(got)), 0o644); err != nil {
			t.Fatalf("write allowlist: %v", err)
		}
		t.Logf("已重生 %s：%d 個條目 / %d 個字面量 / 掃描 %d 檔——請逐條審視 diff",
			streamAllowlistRel, len(got), len(lits), len(files))
		return
	}

	want, err := loadSinkAllowlist(allowlistPath)
	if err != nil {
		t.Fatalf("load allowlist（首次請以 -update 生成）: %v", err)
	}
	added, stale := diffMultiset(got, want)
	if len(added) > 0 {
		t.Errorf("新增的中文字面量（%d 筆，未在 allowlist）：\n  %s\n"+
			"串流出口的使用者可見文字一律走 apierror 碼；只有 %s 可帶中文。\n"+
			"對照行號：%s", len(added), strings.Join(added, "\n  "), exemptCallDesc, locateHashes(lits, added))
	}
	if len(stale) > 0 {
		t.Errorf("allowlist 中已不存在的條目（%d 筆，stale）：\n  %s\n"+
			"字面量已消滅是好事——請跑 -update 更新清單（燒盡進度）", len(stale), strings.Join(stale, "\n  "))
	}
}

// TestStreamLiteralDetector 證明豁免規則與偵測器雙向正確：
// 該放行的放行、該抓的抓（含變數中轉這條 v2 被審出的繞過路徑，
// 以及反引號 raw string 與字串串接這兩種寫法變體）。
func TestStreamLiteralDetector(t *testing.T) {
	// 反引號案例必須以字串串接嵌入（樣本本身是 raw string，不能巢狀反引號）。
	src := `package sample

import (
	"errors"
	"fmt"
	"log"
)

func f(c C) {
	log.Printf("[SSHProxy] 連線失敗: %v", nil)          // 豁免：log
	log.Println("已關閉")                                // 豁免：log 全套件
	log.Printf("%s", fmt.Sprintf("巢狀組字 %d", 1))      // 豁免：子樹放行
	_ = fmt.Errorf("訊息格式錯誤: %w", nil)              // 豁免：內部 error
	_ = errors.New("未知的訊息類型")                      // 豁免：內部 error
	_ = "ascii only"                                     // 非中文不計

	c.JSON(400, ginH{"error": "資產已停用"})              // 紅：直寫出口
	msg := "本資產的存取政策要求填寫事由後連線"           // 紅：變數中轉
	c.JSON(403, ginH{"error": msg})
	_ = fmt.Sprintf("已阻斷 %s", "rule")                 // 紅：Sprintf 不在豁免清單
	_ = ` + "`反引號原始字串`" + `                        // 紅：raw string 寫法變體
	_ = "串" + "接"                                      // 紅：串接兩段各記一筆
}

type C interface{ JSON(int, any) }
type ginH map[string]any
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sample.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, herr := scanChineseLiterals(fset, f, "sample.go")
	if herr != nil {
		t.Fatalf("hash 失敗: %v", herr)
	}

	wantLits := []string{
		"資產已停用", "本資產的存取政策要求填寫事由後連線", "已阻斷 %s",
		"反引號原始字串", "串", "接",
	}
	if len(got) != len(wantLits) {
		var lines []string
		for _, e := range got {
			lines = append(lines, fmt.Sprintf("%s:%d", e.File, e.Line))
		}
		t.Fatalf("違規數 = %d %v, want %d（豁免規則或偵測器有誤）", len(got), lines, len(wantLits))
	}
	for _, e := range got {
		if len(e.Hash) != sinkHashLen {
			t.Errorf("hash 長度 %d != %d: %+v", len(e.Hash), sinkHashLen, e)
		}
	}

	// hash 對內容敏感：同一位置換一個字就是不同條目（allowlist 不會誤赦）。
	hashOf := func(lit string) string {
		one := "package s\nfunc g() { _ = []string{" + strconv.Quote(lit) + "} }\n"
		ff, perr := parser.ParseFile(token.NewFileSet(), "s.go", one, 0)
		if perr != nil {
			t.Fatalf("parse: %v", perr)
		}
		e, herr := scanChineseLiterals(token.NewFileSet(), ff, "s.go")
		if herr != nil {
			t.Fatalf("hash 失敗: %v", herr)
		}
		if len(e) != 1 {
			t.Fatalf("want 1 literal, got %d", len(e))
		}
		return e[0].Hash
	}
	if hashOf("帳號已停用") == hashOf("帳號已鎖定") {
		t.Error("不同文案卻同 hash——hash 對內容不敏感")
	}
}

// TestStreamScanDirsAreReal 釘掃描範圍確實存在（設定被改成不存在的路徑時，
// collectScanFiles 會直接錯，但這裡多一道明確語義的斷言）。
func TestStreamScanDirsAreReal(t *testing.T) {
	root := backendRoot()
	for _, d := range streamScanDirs {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(d))); err != nil {
			t.Errorf("掃描目錄不存在: %s (%v)", d, err)
		}
	}
}
