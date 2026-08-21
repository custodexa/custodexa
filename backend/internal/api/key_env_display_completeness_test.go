package api

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
)

// 金鑰清冊 env 側顯示碼的三語完備性守衛。
//
// **為何既有的三語對齊守衛擋不住這件事**：那類守衛比對「三份 locale 的鍵集合
// 是否相等」，而漏譯的典型形態是後端新增一個 `NameCode`／`NoteCode` 而三份
// locale **同時**都沒有——集合仍相等，守衛全綠。實際後果是 en-US／ja-JP 的
// 使用者看到 `keyDisplay.js` 降級回傳的後端 zh 字串（wire fallback），
// 畫面上出現中文而沒有任何測試轉紅。audit-checkpoint-chain 的
// `audit_checkpoint` 兩碼即以此形態漏掉，由歸檔期的 spec 同步者冷讀發現。
//
// 本守衛改從**後端字面**出發：掃 handler 中所有 `NameCode:`／`NoteCode:` 的值，
// 要求每一個都在三語有對應譯文。方向相反，故能擋住三語同缺。

// keyEnvHandlerRel 產生 env 側清冊項的檔案（相對本測試檔）
const keyEnvHandlerRel = "key_management_handler.go"

// keyEnvLocaleEnv locale 目錄的環境覆寫鍵（容器內走唯讀掛載，同 policy 域慣例）
const keyEnvLocaleEnv = "APIERROR_LOCALE_DIR"

// keyEnvLocaleRel locale 目錄相對專案根（backend module 根的上一層）的路徑
const keyEnvLocaleRel = "frontend/src/i18n/locales"

var keyEnvLocales = []string{"zh-TW", "en-US", "ja-JP"}

// minKeyEnvCodes 後端字面掃描結果的下限（防「掃不到＝無違規」的空集合假綠）。
// 2026-08-12 現況：NameCode 2 個（audit_export、audit_checkpoint）、
// NoteCode 4 個（另有 encryption_key、jwt_secret）。門檻取 5 保留一格餘裕
const minKeyEnvCodes = 5

func keyEnvLocaleDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv(keyEnvLocaleEnv); d != "" {
		return d
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("取工作目錄失敗: %v", err)
	}
	// internal/api → backend → 專案根
	root := filepath.Join(wd, "..", "..", "..")
	dir := filepath.Join(root, filepath.FromSlash(keyEnvLocaleRel))
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("locale 目錄不可達（%s 未設且 %s 不存在）：跳過而非假綠", keyEnvLocaleEnv, dir)
	}
	return dir
}

// keyEnvCodesFromBackend 掃出 handler 中所有 NameCode／NoteCode 的字面值。
//
// 以 AST 而非字串比對：欄位可能換行、可能與其他欄位同列，
// 字串比對會在「格式一改就漏掉整個欄位」時靜默放行
func keyEnvCodesFromBackend(t *testing.T) (nameCodes, noteCodes map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, keyEnvHandlerRel, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗：守衛拒絕在殘缺的 AST 上作判定: %v", keyEnvHandlerRel, err)
	}
	nameCodes, noteCodes = map[string]bool{}, map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		ident, ok := kv.Key.(*ast.Ident)
		if !ok {
			return true
		}
		lit, ok := kv.Value.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val, err := strconv.Unquote(lit.Value)
		if err != nil || val == "" {
			return true
		}
		switch ident.Name {
		case "NameCode":
			nameCodes[val] = true
		case "NoteCode":
			noteCodes[val] = true
		}
		return true
	})
	return nameCodes, noteCodes
}

func keyEnvLocaleNamespace(t *testing.T, dir, locale, ns string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, locale+".json"))
	if err != nil {
		t.Fatalf("讀 %s locale 失敗: %v", locale, err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 %s locale 失敗: %v", locale, err)
	}
	body, ok := doc[ns]
	if !ok {
		t.Fatalf("%s 缺少 namespace %q：清冊顯示碼將整段降級為後端 zh 字串", locale, ns)
	}
	out := map[string]string{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("解析 %s 的 %s 失敗: %v", locale, ns, err)
	}
	return out
}

// diffKeyEnvCodes 比對「後端碼集合」與「單一 locale 的 namespace」。
//
// 抽成純函式**是為了讓偵測力本身可被測試**：對真實 locale 做突變需要改動
// 共用檔案，而本專案的 locale 同時被多個並行工作者寫入，突變還原會覆蓋
// 他人改動。合成輸入使自證不需碰任何真實檔案
func diffKeyEnvCodes(codes map[string]bool, got map[string]string) (missing, stale []string) {
	for code := range codes {
		if v, ok := got[code]; !ok || v == "" {
			missing = append(missing, code)
		}
	}
	for code := range got {
		if !codes[code] {
			stale = append(stale, code)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	return missing, stale
}

// TestKeyEnvDisplayCodesTranslated 後端每個顯示碼在三語皆有譯文。
//
// 兩個方向都驗：後端有而 locale 缺＝使用者看到中文；locale 有而後端已無＝
// 清冊腐爛（下一個人會以為那個碼還在用而照抄）
func TestKeyEnvDisplayCodesTranslated(t *testing.T) {
	nameCodes, noteCodes := keyEnvCodesFromBackend(t)
	total := len(nameCodes) + len(noteCodes)
	if total < minKeyEnvCodes {
		t.Fatalf("只掃到 %d 個顯示碼（現況至少 %d）：AST 比對條件已失真，本守衛正在放行一切",
			total, minKeyEnvCodes)
	}
	dir := keyEnvLocaleDir(t)

	for _, tc := range []struct {
		ns    string
		codes map[string]bool
	}{
		{"keyEnvName", nameCodes},
		{"keyEnvNote", noteCodes},
	} {
		for _, locale := range keyEnvLocales {
			got := keyEnvLocaleNamespace(t, dir, locale, tc.ns)
			missing, stale := diffKeyEnvCodes(tc.codes, got)
			for _, code := range missing {
				t.Errorf("%s 的 %s 缺 %q：該語系使用者會看到後端回傳的中文（keyDisplay.js 的 wire fallback）",
					locale, tc.ns, code)
			}
			for _, code := range stale {
				t.Errorf("%s 的 %s 登記了 %q 但後端已無此碼：譯文腐爛，請刪除該條目",
					locale, tc.ns, code)
			}
		}
	}
}

// TestKeyEnvDiffDetectsBothDirections 比對器的偵測力自證（合成輸入，不碰真實 locale）。
//
// 沒有這一支，`TestKeyEnvDisplayCodesTranslated` 的綠只證明「現況沒違規」，
// 不證明「有違規時會紅」——比對器若寫成恆回空清單，兩者外觀完全相同
func TestKeyEnvDiffDetectsBothDirections(t *testing.T) {
	codes := map[string]bool{"audit_export": true, "audit_checkpoint": true}

	// 方向一：後端有而 locale 缺（en-US／ja-JP 顯示中文的那個形態）
	missing, stale := diffKeyEnvCodes(codes, map[string]string{"audit_export": "Export Signing Key"})
	if len(missing) != 1 || missing[0] != "audit_checkpoint" {
		t.Fatalf("漏譯未被偵測：missing=%v（want [audit_checkpoint]）", missing)
	}
	if len(stale) != 0 {
		t.Fatalf("誤報腐爛：stale=%v", stale)
	}

	// 方向二：locale 有而後端已無（清冊腐爛）
	missing, stale = diffKeyEnvCodes(codes, map[string]string{
		"audit_export": "x", "audit_checkpoint": "y", "retired_key": "z"})
	if len(stale) != 1 || stale[0] != "retired_key" {
		t.Fatalf("腐爛條目未被偵測：stale=%v（want [retired_key]）", stale)
	}
	if len(missing) != 0 {
		t.Fatalf("誤報漏譯：missing=%v", missing)
	}

	// 空字串譯文等同缺譯：JSON 上有鍵但值為空時畫面仍是空白
	missing, _ = diffKeyEnvCodes(codes, map[string]string{"audit_export": "x", "audit_checkpoint": ""})
	if len(missing) != 1 || missing[0] != "audit_checkpoint" {
		t.Fatalf("空字串譯文未被當成缺譯：missing=%v", missing)
	}
}
