package audit

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 時間軸摘要碼（`SummaryCode`）的三語完備性守衛。
//
// **為何既有守衛擋不住**：i18n.spec.js 那類守衛比對「三份 locale 的鍵集合是否
// 相等」，漏譯的典型形態卻是後端新增一個碼、三語**同時**都沒有——集合仍相等、
// 全綠。enum-locale-completeness.spec.js 雖然對 `enum.auditAction.*` 做了值域 ×
// locale 的檢查，但時間軸摘要走的是**另一個 namespace**
// （`auditorWorkbench.summary.audit_log.<action>`），不在其射程內：新增一個
// AuditAction 時 `enum.auditAction` 會紅，`auditorWorkbench.summary` 不會，
// 使用者在稽核工作台看到的是 `summary.fallback`（「未知事件（timeline.xxx）」）。
//
// 本守衛方向相反：從**後端字面**（timeline_service.go 的 SummaryCode 賦值
// ＋ model/audit_log.go 的 AuditAction 常數）展開全部可能碼，要求三語皆有譯文。

// timelineServiceRel 產生 SummaryCode 的檔案（相對本測試檔）
const timelineServiceRel = "timeline_service.go"

// auditLogModelRel AuditAction 常數所在（相對本 package 目錄）。
// 只讀不寫——本守衛不擁有 model 檔
const auditLogModelRel = "../../model/audit_log.go"

// summaryLocaleEnv locale 目錄的環境覆寫鍵（容器內走唯讀掛載，沿 apierror 慣例）
const summaryLocaleEnv = "APIERROR_LOCALE_DIR"

// summaryLocaleRel locale 目錄相對專案根的路徑
const summaryLocaleRel = "frontend/src/i18n/locales"

// summaryPrefix 前端 timelineSummary.js 剝除的前綴（SUMMARY_PREFIX）
const summaryPrefix = "timeline."

var summaryLocales = []string{"zh-TW", "en-US", "ja-JP"}

// minSummaryCodes 展開後碼數下限（防「掃不到＝無違規」的空集合假綠）。
// 2026-08-13 現況：21 個 audit_log.<action> ＋ session.start ＋ command.executed
// ＋ alert.triggered ＋ clipboard.send/recv ＝ 26。門檻取 24 保留餘裕
const minSummaryCodes = 24

// summaryDynamicDomains 動態摘要碼的前綴 → 值域。
//
// **未登記的前綴一律 Fatal**：新增一族動態碼卻沒有登記值域時，本守衛若默默略過，
// 就退化成「只驗得到靜態碼」的假綠。clipboard 的 direction 是 DB 自由欄
// （clipboard_event.go 註記 send=入遠端／recv=回拷），無 Go 常數可錨，故此處
// 為唯一硬編值域；audit_log 的值域由 model 原始碼即時解析，不硬拷
var summaryDynamicDomains = map[string]func(t *testing.T) []string{
	"timeline.audit_log.": auditActionValues,
	"timeline.clipboard.": func(*testing.T) []string { return []string{"send", "recv"} },
}

// summaryLocaleDir 定位三語 locale 目錄：env 覆寫優先，否則自 cwd 逐層上溯找
// 含 frontend/src/i18n/locales 的根（不寫死層數，package 移位不會指到錯目錄）
func summaryLocaleDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv(summaryLocaleEnv); d != "" {
		return d
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("取工作目錄失敗: %v", err)
	}
	for dir := wd; ; {
		cand := filepath.Join(dir, filepath.FromSlash(summaryLocaleRel))
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("locale 目錄不可達（%s 未設且自 %s 上溯找不到 %s）：跳過而非假綠",
		summaryLocaleEnv, wd, summaryLocaleRel)
	return ""
}

// auditActionValues 由 model/audit_log.go 的 AST 抽出全部 AuditAction 常數值。
//
// 以 AST 而非正則：常數區塊的排版、註解、對齊都可能變，正則失效時會靜默回空集合
func auditActionValues(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, auditLogModelRel, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗：守衛拒絕在殘缺的 AST 上作判定: %v", auditLogModelRel, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		ident, ok := vs.Type.(*ast.Ident)
		if !ok || ident.Name != "AuditAction" {
			return true
		}
		for _, v := range vs.Values {
			lit, ok := v.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			if s, err := strconv.Unquote(lit.Value); err == nil && s != "" {
				out = append(out, s)
			}
		}
		return true
	})
	if len(out) == 0 {
		t.Fatalf("未從 %s 抽到任何 AuditAction 常數：AST 條件已失真，本守衛正在放行一切", auditLogModelRel)
	}
	sort.Strings(out)
	return out
}

// summaryCodeLiterals 掃出 timeline_service.go 中所有 SummaryCode 賦值的字面部位。
//
// 回傳 static＝完整字面碼；prefixes＝`"字面前綴" + 動態值` 形態的前綴。
// 兩類都必須收——只收 static 會漏掉 audit_log／clipboard 這兩族（正是碼數最多的兩族）
func summaryCodeLiterals(t *testing.T) (static, prefixes []string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, timelineServiceRel, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗：守衛拒絕在殘缺的 AST 上作判定: %v", timelineServiceRel, err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		ident, ok := kv.Key.(*ast.Ident)
		if !ok || ident.Name != "SummaryCode" {
			return true
		}
		switch v := kv.Value.(type) {
		case *ast.BasicLit:
			if s, err := strconv.Unquote(v.Value); err == nil && s != "" {
				static = append(static, s)
			}
		case *ast.BinaryExpr:
			lit, ok := v.X.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s 有 SummaryCode 以非字面開頭的運算式組成：無法靜態展開值域，"+
					"請改成 `\"前綴\" + 動態值` 或靜態字面", timelineServiceRel)
				return true
			}
			if s, err := strconv.Unquote(lit.Value); err == nil && s != "" {
				prefixes = append(prefixes, s)
			}
		default:
			t.Errorf("%s 有 SummaryCode 既非字面亦非字面前綴串接（%T）：本守衛無法展開其值域",
				timelineServiceRel, kv.Value)
		}
		return true
	})
	sort.Strings(static)
	sort.Strings(prefixes)
	return static, prefixes
}

// expandSummaryCodes 把靜態碼與（前綴 × 值域）展開成完整碼集合，並剝除 timeline. 前綴
// ——前端 timelineSummary.js 查的是 `auditorWorkbench.summary.<剝前綴後的碼>`
func expandSummaryCodes(t *testing.T) map[string]bool {
	t.Helper()
	static, prefixes := summaryCodeLiterals(t)
	out := map[string]bool{}
	add := func(code string) {
		out[strings.TrimPrefix(code, summaryPrefix)] = true
	}
	for _, s := range static {
		add(s)
	}
	for _, p := range prefixes {
		domain, ok := summaryDynamicDomains[p]
		if !ok {
			t.Fatalf("SummaryCode 出現未登記的動態前綴 %q：請在 summaryDynamicDomains 補上其值域，"+
				"否則該族的漏譯永遠不會被本守衛偵測到", p)
		}
		for _, v := range domain(t) {
			add(p + v)
		}
	}
	return out
}

// summaryLocaleLeaves 讀 locale 的 auditorWorkbench.summary 子樹，攤平成「點分鍵 → 值」
func summaryLocaleLeaves(t *testing.T, dir, locale string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, locale+".json"))
	if err != nil {
		t.Fatalf("讀 %s locale 失敗: %v", locale, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 %s locale 失敗: %v", locale, err)
	}
	node, ok := doc["auditorWorkbench"].(map[string]any)
	if !ok {
		t.Fatalf("%s 缺 auditorWorkbench：時間軸摘要將整段退回 fallback 文案", locale)
	}
	sum, ok := node["summary"].(map[string]any)
	if !ok {
		t.Fatalf("%s 缺 auditorWorkbench.summary：時間軸摘要將整段退回 fallback 文案", locale)
	}
	out := map[string]string{}
	flattenSummary(sum, "", out)
	return out
}

func flattenSummary(node map[string]any, prefix string, out map[string]string) {
	for k, v := range node {
		switch tv := v.(type) {
		case map[string]any:
			flattenSummary(tv, prefix+k+".", out)
		case string:
			out[prefix+k] = tv
		default:
			out[prefix+k] = ""
		}
	}
}

// diffSummaryCodes 比對「後端展開碼集合」與「單一 locale 攤平後的鍵」。
//
// 抽成純函式**是為了讓偵測力本身可被測試**：對真實 locale 做突變需要改動共用
// 檔案，而本專案的 locale 同時被多個並行工作者寫入，突變還原會覆蓋他人改動。
// 合成輸入使自證不需碰任何真實檔案。
// exempt＝不對應後端碼、但本來就該存在的鍵（fallback）
func diffSummaryCodes(codes map[string]bool, got map[string]string, exempt map[string]bool) (missing, stale []string) {
	for code := range codes {
		if v, ok := got[code]; !ok || v == "" {
			missing = append(missing, code)
		}
	}
	for key, v := range got {
		if codes[key] || exempt[key] {
			continue
		}
		_ = v
		stale = append(stale, key)
	}
	sort.Strings(missing)
	sort.Strings(stale)
	return missing, stale
}

// summaryExemptKeys 非碼對應但必存在的鍵（未知碼降級文案）
var summaryExemptKeys = map[string]bool{"fallback": true}

// TestTimelineSummaryCodesTranslated 後端每個時間軸摘要碼在三語皆有譯文。
//
// 兩個方向都驗：後端有而 locale 缺＝該語系使用者看到「未知事件（timeline.xxx）」；
// locale 有而後端已無＝譯文腐爛（下一個人會以為那個碼還在用而照抄）
func TestTimelineSummaryCodesTranslated(t *testing.T) {
	codes := expandSummaryCodes(t)
	if len(codes) < minSummaryCodes {
		t.Fatalf("只展開出 %d 個摘要碼（現況至少 %d）：AST 比對條件已失真，本守衛正在放行一切",
			len(codes), minSummaryCodes)
	}
	dir := summaryLocaleDir(t)
	for _, locale := range summaryLocales {
		got := summaryLocaleLeaves(t, dir, locale)
		if got["fallback"] == "" {
			t.Errorf("%s 缺 auditorWorkbench.summary.fallback：未知碼將顯示為空白而非降級文案", locale)
		}
		missing, stale := diffSummaryCodes(codes, got, summaryExemptKeys)
		for _, code := range missing {
			t.Errorf("%s 的 auditorWorkbench.summary 缺 %q：該語系使用者在稽核工作台看到的是 fallback 文案（未知事件＋原碼）",
				locale, code)
		}
		for _, key := range stale {
			t.Errorf("%s 的 auditorWorkbench.summary 登記了 %q 但後端已無此碼：譯文腐爛，請刪除該條目",
				locale, key)
		}
	}
	if !t.Failed() {
		t.Logf("時間軸摘要碼 %d 個，三語皆有譯文", len(codes))
	}
}

// TestSummaryDiffDetectsBothDirections 比對器的偵測力自證（合成輸入，不碰真實 locale）。
//
// 沒有這一支，`TestTimelineSummaryCodesTranslated` 的綠只證明「現況沒違規」，
// 不證明「有違規時會紅」——比對器若寫成恆回空清單，兩者外觀完全相同
func TestSummaryDiffDetectsBothDirections(t *testing.T) {
	codes := map[string]bool{"audit_log.review": true, "session.start": true}
	exempt := map[string]bool{"fallback": true}

	// 方向一：後端有而 locale 缺（三語同缺＝對齊守衛全綠的那個形態）
	missing, stale := diffSummaryCodes(codes,
		map[string]string{"session.start": "Session started", "fallback": "Unknown"}, exempt)
	if len(missing) != 1 || missing[0] != "audit_log.review" {
		t.Fatalf("漏譯未被偵測：missing=%v（want [audit_log.review]）", missing)
	}
	if len(stale) != 0 {
		t.Fatalf("誤報腐爛：stale=%v", stale)
	}

	// 方向二：locale 有而後端已無（譯文腐爛）
	missing, stale = diffSummaryCodes(codes, map[string]string{
		"audit_log.review": "x", "session.start": "y", "audit_log.retired": "z", "fallback": "u"}, exempt)
	if len(stale) != 1 || stale[0] != "audit_log.retired" {
		t.Fatalf("腐爛條目未被偵測：stale=%v（want [audit_log.retired]）", stale)
	}
	if len(missing) != 0 {
		t.Fatalf("誤報漏譯：missing=%v", missing)
	}

	// 空字串譯文等同缺譯：JSON 上有鍵但值為空時畫面仍是空白
	missing, _ = diffSummaryCodes(codes,
		map[string]string{"audit_log.review": "", "session.start": "y", "fallback": "u"}, exempt)
	if len(missing) != 1 || missing[0] != "audit_log.review" {
		t.Fatalf("空字串譯文未被當成缺譯：missing=%v", missing)
	}

	// fallback 不得被誤報為腐爛（它不對應任何後端碼）
	_, stale = diffSummaryCodes(codes,
		map[string]string{"audit_log.review": "x", "session.start": "y", "fallback": "u"}, exempt)
	if len(stale) != 0 {
		t.Fatalf("fallback 被誤報為腐爛：stale=%v", stale)
	}
}

// TestSummaryDynamicPrefixesAreRegistered 後端每個動態前綴都有登記值域。
//
// 這是「新族漏登記」的專屬防線：expandSummaryCodes 在展開時會 Fatal，但那條路徑
// 只有在 locale 可達時才走得到；本測試不依賴 locale，任何環境都會紅
func TestSummaryDynamicPrefixesAreRegistered(t *testing.T) {
	static, prefixes := summaryCodeLiterals(t)
	if len(static) == 0 || len(prefixes) == 0 {
		t.Fatalf("AST 掃描結果可疑（static=%d、prefixes=%d）：條件已失真", len(static), len(prefixes))
	}
	for _, p := range prefixes {
		if _, ok := summaryDynamicDomains[p]; !ok {
			t.Errorf("動態前綴 %q 未登記值域：該族的漏譯不會被偵測", p)
		}
	}
	for p := range summaryDynamicDomains {
		found := false
		for _, got := range prefixes {
			if got == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("summaryDynamicDomains 登記了 %q 但後端已無此前綴：登記表腐爛", p)
		}
	}
	// 全部碼都應帶 timeline. 前綴（前端剝前綴後才查譯，漏前綴會查到錯的鍵）
	for _, s := range append(append([]string{}, static...), prefixes...) {
		if !strings.HasPrefix(s, summaryPrefix) {
			t.Errorf("SummaryCode %q 未以 %q 開頭：前端剝前綴邏輯會查到錯的 i18n 鍵", s, summaryPrefix)
		}
	}
}
