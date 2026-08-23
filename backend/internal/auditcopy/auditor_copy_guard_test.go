// Package auditcopy 只承載「稽核可讀文案」的機械層守衛。
//
// # 掃描對象
//
// 三份 locale 的**對外 namespace**（checkpointVerification、auditorWorkbench、
// policyNote、policyLabel），**不是原始碼**——原始碼的識別字本來就該是英文技術詞，
// 掃原始碼只會製造誤報並逼人加豁免。
//
// # 為什麼是獨立 package
//
// 守衛的輸入是前端 locale JSON，對後端任何 package 皆零相依。放獨立目錄可使它
// 不被其他 package 進行中的改動連坐（編譯不過 ＝ 守衛跑不起來 ＝ 靜默失效）。
// 本目錄刻意只有測試檔。
//
// # 與前端 CheckpointVerification.spec.js 那支守衛的關係（併存，分工明確）
//
// 前端那支掃 checkpointVerification 全 namespace ＋ policyNote/policyLabel 的
// audit_checkpoint_* 兩鍵，射程是本檔的**子集**；但它另外守著 Go 到不了的東西：
// 渲染後 DOM 的段落順序（spec.js「保護範圍 data-test 出現在 honest-limits 之前」）
// 與元件行為。故裁決為**併存**：
//
//   - 前端 = DOM／元件層 ＋ 編輯 Vue 時的快速回饋（vitest 秒級）
//   - 後端 = locale 內容層的完整射程（四個 namespace × 三語 × 全部葉鍵）
//
// 防漂移的約束寫死在這裡：**本檔的詞表必須是前端詞表的超集**。extendedLatinTerms
// 與 extendedCJKTerms 就是照前端 JARGON／CJK_JARGON 逐字搬過來的（2026-08-13 對齊），
// coreLatinTerms／coreCJKTerms 則是前端沒有、由對外文案的術語禁列要求的部分。
// 兩檔互有交叉引用註解；改任一邊的詞表都須同步另一邊。
//
// 註：無法把這件事機械化成測試——backend 容器只掛得到 locale 目錄
// （./frontend/src/i18n/locales:/app/testdata/locales:ro），掛不到 spec.js，
// 於容器內讀它只會得到一個永遠 skip 的測試（skip 不算驗過）。此處誠實記為
// 人工約束，不假裝它是機械保證。
package auditcopy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// localeEnv locale 目錄的環境覆寫鍵（沿 apierror／timeline_summary 既有慣例，
// dev compose 於 backend 容器內設為 /app/testdata/locales）
const localeEnv = "APIERROR_LOCALE_DIR"

// localeRel locale 目錄相對專案根的路徑（host 直跑時的 fallback）
const localeRel = "frontend/src/i18n/locales"

var locales = []string{"zh-TW", "en-US", "ja-JP"}

// managedNamespaces 受管的對外 namespace（固定順序，錯誤訊息才穩定）
var managedNamespaces = []string{
	"checkpointVerification",
	"auditorWorkbench",
	"policyNote",
	"policyLabel",
}

// namespaceMinLeaves 各 namespace 的葉鍵數下限——**空集合假綠的防線**。
// namespace 改名或結構調整導致選取為空時，守衛必須 Fatal 而非默默通過。
// 括號內為 2026-08-13 實測值，門檻取其八成留改寫餘裕
var namespaceMinLeaves = map[string]int{
	"checkpointVerification": 70, // 實測 84
	"auditorWorkbench":       85, // 實測 101
	"policyNote":             8,  // 實測 10
	"policyLabel":            40, // 實測 47
}

// coreLatinTerms 核心黑名單（拉丁字，全 namespace 適用）。
// 來源：對外文案的實作術語禁列逐字列舉。以 ASCII 詞界比對
var coreLatinTerms = []string{
	"seq",
	"hmac",
	"hash",
	"payload",
	"watermark",
	"cursor",
	"tombstone",
	"purge tombstone",
	"writeToFile",
	"extra_rows_valid_hmac",
}

// coreCJKTerms 核心黑名單（中日文，全 namespace 適用）。
// CJK 無 ASCII 詞界，一律以子字串比對
var coreCJKTerms = []string{
	"水位",
	"游標",
	"聚合雜湊",
	"封章",
	"時間窗",
	"入列",
	"條帶",
	"主體",
	"樞紐",
	"クエリ",
	"ワークベンチ",
}

// extendedLatinTerms 延伸黑名單（拉丁字），射程限稽核頁面文案。
//
// **為什麼不套用到 policy 全族**：policyLabel 四十餘鍵合法帶有協定專名
// （syslog／RDP／VNC／LDAP／Kubernetes／MFA），那是這些東西**本來的名字**，
// 稽核讀「syslog 傳輸層級」比讀任何改寫都準確。把它們列黑名單只能靠一份
// 逐鍵豁免清單成立，而「豁免清單只驗刪除不驗放寬」正是 docs/dev/testing.md §5
// 點名的假綠形態。故延伸詞表按 namespace 分層，而非按鍵開豁免——
// 分層是規則層的一次性判斷（改動看得見），豁免是可逐鍵長大的清單
var extendedLatinTerms = []string{
	"kek",
	"udp",
	"tcp",
	"syslog",
	"grace",
	"sql",
	"api",
	"json",
	"nonce",
	// enqueue 族逐形列舉：前端那支寫成 `enqueue[a-z]*`，本檔以字面詞表比對，
	// 少列一形即等於後端不再是前端的超集（2026-08-13 驗收實測：
	// "enqueues"／"enqueueing" 前端攔得下、後端漏接）。改動前端該詞表時，
	// 此處須補齊對應詞形
	"enqueue",
	"enqueued",
	"enqueues",
	"enqueueing",
	"dequeue",
}

// extendedCJKTerms 延伸黑名單（中日文），射程同 extendedLatinTerms
var extendedCJKTerms = []string{
	"列級",
	"聚合",
	"蓋章",
	"機器碼",
	"行レベル",
	"キュー投入",
}

// policyExtendedKeyPrefix policy 兩族中適用延伸詞表的鍵前綴（封章門檻兩鍵）
const policyExtendedKeyPrefix = "audit_checkpoint_"

// snakeCasePat 狀態機器碼形態（extra_rows_valid_hmac、anchor_status）
var snakeCasePat = regexp.MustCompile(`[a-z0-9]+_[a-z0-9_]+`)

// camelCasePat 內部函式名形態（writeToFile、sealCheckpoint）
var camelCasePat = regexp.MustCompile(`\b[a-z]+[A-Z][A-Za-z]*`)

var (
	coreLatinPat     = latinPattern(coreLatinTerms)
	extendedLatinPat = latinPattern(extendedLatinTerms)
)

func latinPattern(terms []string) *regexp.Regexp {
	quoted := make([]string, 0, len(terms))
	for _, t := range terms {
		quoted = append(quoted, regexp.QuoteMeta(t))
	}
	return regexp.MustCompile(`(?i)\b(` + strings.Join(quoted, "|") + `)\b`)
}

// jargonExemptions 逐鍵豁免：key = "<locale>|<namespace>.<路徑>|<命中詞>"，value = 理由。
//
// **目前刻意為空**：2026-08-13 全掃四個 namespace × 三語 × 242 葉鍵，核心與延伸
// 詞表皆零命中，故不需要任何豁免。空清單是本守衛可信度的來源之一——
// 見 TestAuditorCopyExemptionListStaysPinned 的上限釘定
var jargonExemptions = map[string]string{}

// maxJargonExemptions 豁免總數上限（反向守衛）。
//
// **調高此值即為放寬守衛**：這行是刻意設置的絆線，任何人要新增豁免都必須同時
// 改動這裡，讓「放寬」在 diff 中無法偽裝成「補一筆資料」。調高前請先確認
// 該命中詞是不是真該從詞表分層調整，而不是逐鍵挖洞
const maxJargonExemptions = 0

// pinnedExemptionCap 上限本身的釘定值——擋「連上限一起改掉」的無聲放寬
const pinnedExemptionCap = 0

// ---------------------------------------------------------------------------
// 有序 JSON 解析（順序守衛需要鍵序，encoding/json 解進 map 會丟失）
// ---------------------------------------------------------------------------

type ordObj struct {
	keys []string
	vals map[string]any
}

func (o *ordObj) get(k string) (any, bool) {
	v, ok := o.vals[k]
	return v, ok
}

func (o *ordObj) obj(k string) (*ordObj, bool) {
	v, ok := o.vals[k]
	if !ok {
		return nil, false
	}
	c, ok := v.(*ordObj)
	return c, ok
}

func (o *ordObj) str(k string) (string, bool) {
	v, ok := o.vals[k]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// index 回傳鍵在檔案中的出現序（不存在為 -1）
func (o *ordObj) index(k string) int {
	for i, kk := range o.keys {
		if kk == k {
			return i
		}
	}
	return -1
}

func decodeValue(dec *json.Decoder, tok json.Token) (any, error) {
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	switch d {
	case '{':
		o := &ordObj{vals: map[string]any{}}
		for {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if dd, ok := kt.(json.Delim); ok && dd == '}' {
				return o, nil
			}
			key, _ := kt.(string)
			vt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			v, err := decodeValue(dec, vt)
			if err != nil {
				return nil, err
			}
			if _, dup := o.vals[key]; !dup {
				o.keys = append(o.keys, key)
			}
			o.vals[key] = v
		}
	case '[':
		arr := []any{}
		for {
			vt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if dd, ok := vt.(json.Delim); ok && dd == ']' {
				return arr, nil
			}
			v, err := decodeValue(dec, vt)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// 載入
// ---------------------------------------------------------------------------

// localeDir 定位三語 locale 目錄：env 覆寫優先，否則自 cwd 逐層上溯找含
// frontend/src/i18n/locales 的專案根（不寫死層數，package 移位不會指到錯目錄）。
//
// **找不到一律 Fatal 而非 Skip**：掛載點改名或 env 掉了時，
// skip 與 pass 在 CI 輸出裡幾乎沒有差別，守衛等於自願失效
func localeDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv(localeEnv); d != "" {
		return d
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("取工作目錄失敗: %v", err)
	}
	for dir := wd; ; {
		cand := filepath.Join(dir, filepath.FromSlash(localeRel))
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("locale 目錄不可達（%s 未設，且自 %s 上溯找不到 %s）："+
		"守衛在此情況下不得通過", localeEnv, wd, localeRel)
	return ""
}

func loadLocale(t *testing.T, dir, name string) *ordObj {
	t.Helper()
	path := filepath.Join(dir, name+".json")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("開啟 locale %s 失敗: %v", path, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("解析 locale %s 失敗: %v", path, err)
	}
	v, err := decodeValue(dec, tok)
	if err != nil {
		t.Fatalf("解析 locale %s 失敗: %v", path, err)
	}
	root, ok := v.(*ordObj)
	if !ok {
		t.Fatalf("locale %s 頂層不是物件", path)
	}
	return root
}

type entry struct {
	// full 含 namespace 的完整鍵（錯誤訊息用）
	full string
	// path namespace 內的相對鍵路徑（分層判定用）
	path string
	// text 剝除插值變數後的可讀文字
	text string
}

// placeholderPat 插值變數是程式碼契約而非可讀文案，掃描前剝除
var placeholderPat = regexp.MustCompile(`\{[^}]*\}`)

func flatten(ns string, o *ordObj, prefix string, out []entry) []entry {
	for _, k := range o.keys {
		v := o.vals[k]
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		switch tv := v.(type) {
		case *ordObj:
			out = flatten(ns, tv, p, out)
		case string:
			out = append(out, entry{
				full: ns + "." + p,
				path: p,
				text: placeholderPat.ReplaceAllString(tv, ""),
			})
		}
	}
	return out
}

// extendedApplies 延伸詞表的射程：兩個稽核頁面 namespace 全部，
// 加上 policy 兩族中的封章門檻鍵
func extendedApplies(ns, path string) bool {
	switch ns {
	case "checkpointVerification", "auditorWorkbench":
		return true
	case "policyNote", "policyLabel":
		return strings.HasPrefix(path, policyExtendedKeyPrefix)
	}
	return false
}

type hit struct {
	kind string
	term string
}

// scanText 回傳一段文字命中的全部黑名單詞
func scanText(ns, path, text string) []hit {
	var hits []hit
	for _, m := range coreLatinPat.FindAllString(text, -1) {
		hits = append(hits, hit{kind: "核心術語", term: strings.ToLower(m)})
	}
	for _, term := range coreCJKTerms {
		if strings.Contains(text, term) {
			hits = append(hits, hit{kind: "核心術語", term: term})
		}
	}
	if extendedApplies(ns, path) {
		for _, m := range extendedLatinPat.FindAllString(text, -1) {
			hits = append(hits, hit{kind: "延伸術語", term: strings.ToLower(m)})
		}
		for _, term := range extendedCJKTerms {
			if strings.Contains(text, term) {
				hits = append(hits, hit{kind: "延伸術語", term: term})
			}
		}
	}
	if m := snakeCasePat.FindString(text); m != "" {
		hits = append(hits, hit{kind: "狀態機器碼", term: m})
	}
	if m := camelCasePat.FindString(text); m != "" {
		hits = append(hits, hit{kind: "內部函式名", term: m})
	}
	return hits
}

func exemptionKey(locale, fullKey, term string) string {
	return locale + "|" + fullKey + "|" + term
}

// namespaceObj 取受管 namespace；缺席即 Fatal（namespace 改名不得靜默掃空）
func namespaceObj(t *testing.T, root *ordObj, locale, ns string) *ordObj {
	t.Helper()
	o, ok := root.obj(ns)
	if !ok {
		t.Fatalf("locale %s 缺 namespace %q：受管範圍已失真，"+
			"此時通過等同於掃到空集合仍綠", locale, ns)
	}
	return o
}

// ---------------------------------------------------------------------------
// 2.1 術語黑名單守衛
// ---------------------------------------------------------------------------

// TestAuditorCopyNoImplementationJargon 對外文案不得出現內部函式名、狀態機器碼、
// 實作術語。射程＝四個對外 namespace × 三語 × 全部葉鍵。
//
// 人工審查曾在對外文案累計抓到四處「把防不了的說成防得了」，靠的是有人逐句回去讀碼；
// 往後未必有人這樣做。本守衛守的是可機械化的那一半（術語），判斷層仍只能靠人讀
func TestAuditorCopyNoImplementationJargon(t *testing.T) {
	dir := localeDir(t)
	used := map[string]bool{}
	for _, loc := range locales {
		root := loadLocale(t, dir, loc)
		total := 0
		for _, ns := range managedNamespaces {
			entries := flatten(ns, namespaceObj(t, root, loc, ns), "", nil)
			if min := namespaceMinLeaves[ns]; len(entries) < min {
				t.Fatalf("locale %s 的 %s 只掃到 %d 個葉鍵（下限 %d，目錄 %s）："+
					"選取範圍已失真，此時的綠是空集合假綠", loc, ns, len(entries), min, dir)
			}
			total += len(entries)
			for _, e := range entries {
				for _, h := range scanText(ns, e.path, e.text) {
					key := exemptionKey(loc, e.full, h.term)
					if _, ok := jargonExemptions[key]; ok {
						used[key] = true
						continue
					}
					t.Errorf("%s 的 %s 出現%s %q：%s\n"+
						"（修文案，不要把詞從黑名單拿掉；若確為合法專名，"+
						"加豁免鍵 %q 並附理由，同時調整 maxJargonExemptions）",
						loc, e.full, h.kind, h.term, e.text, key)
				}
			}
		}
		t.Logf("locale %s 受管 namespace 葉鍵數合計=%d", loc, total)
	}
	for k := range jargonExemptions {
		if !used[k] {
			t.Errorf("豁免 %q 已無對應違規：陳舊豁免＝預留給下一次放寬的空位，請刪除", k)
		}
	}
}

// TestAuditorCopyJargonMatcherIsWired 詞表自檢：每個列入黑名單的詞都必須真的
// 攔得下來。CJK 沒有 ASCII 詞界、latin 有，兩條路徑分開實作，任一條寫錯都會
// 讓整組詞靜默失效（詞在清單裡、卻永遠不命中）——那是最難察覺的假綠
func TestAuditorCopyJargonMatcherIsWired(t *testing.T) {
	check := func(ns, path, sample, term string) {
		t.Helper()
		found := false
		for _, h := range scanText(ns, path, sample) {
			if h.term == strings.ToLower(term) || h.term == term {
				found = true
			}
		}
		if !found {
			t.Errorf("黑名單詞 %q 在樣本 %q（%s）中未被攔下：該詞形同不存在", term, sample, ns)
		}
	}
	for _, term := range coreLatinTerms {
		check("policyLabel", "some_key", "前段 "+term+" 後段", term)
	}
	for _, term := range coreCJKTerms {
		check("policyLabel", "some_key", "前段"+term+"後段", term)
	}
	for _, term := range extendedLatinTerms {
		check("checkpointVerification", "x.y", "前段 "+term+" 後段", term)
		check("policyNote", policyExtendedKeyPrefix+"interval_seconds", "前段 "+term+" 後段", term)
	}
	for _, term := range extendedCJKTerms {
		check("auditorWorkbench", "x.y", "前段"+term+"後段", term)
	}
	// 分層必須真的分層：延伸詞不得對 policy 全族生效（否則就退化成需要豁免清單）
	if hits := scanText("policyLabel", "transport_syslog_level", "syslog 傳輸層級"); len(hits) > 0 {
		t.Errorf("延伸詞表誤及 policyLabel 一般鍵：%+v", hits)
	}
	// 反向：插值變數剝除後不得成為漏洞（{seq} 是契約，seq 是文案）
	if hits := scanText("checkpointVerification", "x", placeholderPat.ReplaceAllString("第 {seq} 號", "")); len(hits) > 0 {
		t.Errorf("插值變數剝除後仍誤報：%+v", hits)
	}
}

// ---------------------------------------------------------------------------
// 2.6 豁免清單的反向守衛
// ---------------------------------------------------------------------------

// TestAuditorCopyExemptionListStaysPinned 防「只驗刪除、不驗放寬」：
// 新增豁免鍵使總數超過釘定上限即紅，且上限本身也被釘死，
// 要放寬必須動兩個常數——放寬因此無法偽裝成補資料
func TestAuditorCopyExemptionListStaysPinned(t *testing.T) {
	if maxJargonExemptions > pinnedExemptionCap {
		t.Errorf("豁免上限已被調高（%d > 釘定值 %d）：這是放寬守衛的動作，"+
			"須在 change 中說明理由並重新釘定", maxJargonExemptions, pinnedExemptionCap)
	}
	if len(jargonExemptions) > maxJargonExemptions {
		keys := make([]string, 0, len(jargonExemptions))
		for k := range jargonExemptions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Errorf("豁免鍵數 %d 超過上限 %d：%v", len(jargonExemptions), maxJargonExemptions, keys)
	}
	for k, reason := range jargonExemptions {
		if len([]rune(strings.TrimSpace(reason))) < 10 {
			t.Errorf("豁免 %q 的理由過短（%q）：逐鍵理由是豁免可被審查的唯一憑據", k, reason)
		}
		if strings.Count(k, "|") != 2 {
			t.Errorf("豁免鍵 %q 格式錯誤：須為 <locale>|<namespace>.<路徑>|<命中詞>", k)
		}
	}
}

// ---------------------------------------------------------------------------
// 2.2 邊界結構守衛
// ---------------------------------------------------------------------------

// boundaryCodePat 邊界聲明的編碼（R0…R6）
var boundaryCodePat = regexp.MustCompile(`^R\d+$`)

// minBoundaryCodes 邊界條數下限：改寫前後事實條數不得減少
// （R0–R6 七條）。少一條即紅，不管少的那條是被刪還是被併
const minBoundaryCodes = 7

// minProtectionCodes 保護範圍條數下限（P1–P3）
const minProtectionCodes = 3

// minPartRunes 「情境」「承擔」兩段各自的最短長度：擋以佔位字元湊出結構的空殼
const minPartRunes = 12

// TestAuditorCopyBoundaryDeclarationsHaveBothParts 邊界聲明每一條都須具備
// 「情境」與「由什麼承擔」兩部分，缺一即紅
//（對得上 audit-checkpoint-chain 既有 scenario「邊界聲明以稽核可理解的語言撰寫」）。
//
// 缺「承擔」的邊界＝把讀者留在恐慌裡，而且是靜默的：版面上看起來仍是一條邊界
func TestAuditorCopyBoundaryDeclarationsHaveBothParts(t *testing.T) {
	dir := localeDir(t)
	var codeSets []string
	for _, loc := range locales {
		limits := limitsObj(t, loadLocale(t, dir, loc), loc)

		var codes []string
		for _, k := range limits.keys {
			if boundaryCodePat.MatchString(k) {
				codes = append(codes, k)
			}
		}
		if len(codes) < minBoundaryCodes {
			t.Fatalf("locale %s 只找到 %d 條邊界聲明（下限 %d，實際鍵：%v）："+
				"事實條數不得減少，且掃不到＝不能算通過", loc, len(codes), minBoundaryCodes, limits.keys)
		}
		sort.Strings(codes)
		codeSets = append(codeSets, strings.Join(codes, ","))

		for _, code := range codes {
			c, ok := limits.obj(code)
			if !ok {
				t.Errorf("%s 的 %s 不是「情境／承擔」兩段結構（扁平字串會讓結構守衛掃不到）", loc, code)
				continue
			}
			for _, part := range []struct{ key, label string }{
				{"scenario", "情境"},
				{"mitigation", "由什麼承擔"},
			} {
				s, ok := c.str(part.key)
				s = strings.TrimSpace(s)
				if !ok || s == "" {
					t.Errorf("%s 的 %s 缺「%s」段", loc, code, part.label)
					continue
				}
				if len([]rune(s)) < minPartRunes {
					t.Errorf("%s 的 %s 的「%s」段只有 %d 字（下限 %d）：%q",
						loc, code, part.label, len([]rune(s)), minPartRunes, s)
				}
			}
			sc, _ := c.str("scenario")
			mi, _ := c.str("mitigation")
			if sc != "" && sc == mi {
				t.Errorf("%s 的 %s 兩段內容相同：那是湊結構，不是承擔說明", loc, code)
			}
		}

		prot, ok := limits.obj("protection")
		if !ok {
			t.Fatalf("locale %s 缺保護範圍段（limits.protection）", loc)
		}
		if len(prot.keys) < minProtectionCodes {
			t.Fatalf("locale %s 的保護範圍只有 %d 條（下限 %d）", loc, len(prot.keys), minProtectionCodes)
		}
		for _, k := range prot.keys {
			s, ok := prot.str(k)
			if !ok || len([]rune(strings.TrimSpace(s))) < minPartRunes {
				t.Errorf("%s 的保護範圍 %s 內容過短或缺席：%q", loc, k, s)
			}
		}
		for _, k := range []string{"protectionTitle", "boundaryTitle", "scenarioLabel", "mitigationLabel"} {
			if s, ok := limits.str(k); !ok || strings.TrimSpace(s) == "" {
				t.Errorf("%s 缺標題／欄名 %s：兩部分的版面可見性靠它", loc, k)
			}
		}
	}
	for i := 1; i < len(codeSets); i++ {
		if codeSets[i] != codeSets[0] {
			t.Errorf("三語的邊界條數不一致：%s=%q vs %s=%q",
				locales[0], codeSets[0], locales[i], codeSets[i])
		}
	}
}

func limitsObj(t *testing.T, root *ordObj, locale string) *ordObj {
	t.Helper()
	cv := namespaceObj(t, root, locale, "checkpointVerification")
	limits, ok := cv.obj("limits")
	if !ok {
		t.Fatalf("locale %s 缺 checkpointVerification.limits：邊界聲明的選取為空，不得通過", locale)
	}
	return limits
}

// ---------------------------------------------------------------------------
// 2.3 順序守衛
// ---------------------------------------------------------------------------

// TestAuditorCopyProtectionScopePrecedesBoundaries 保護範圍段的位置必須早於
// 第一條邊界（只列「防不了什麼」會使讀者誤判整體控制失效）。
//
// **本守衛看的是 locale 檔中的鍵序**，那是譯者與改寫者實際編輯時看到的順序，
// 也是檔頭「掃描對象」界定的範圍（locale，不是原始碼）。渲染後 DOM 的順序由前端
// CheckpointVerification.spec.js 守（`data-test="protection-scope"` 必須出現在
// `data-test="honest-limits"` 之前）——Go 到不了 DOM，兩層各守一半，缺一都不完整
func TestAuditorCopyProtectionScopePrecedesBoundaries(t *testing.T) {
	dir := localeDir(t)
	for _, loc := range locales {
		limits := limitsObj(t, loadLocale(t, dir, loc), loc)

		firstBoundary := -1
		for i, k := range limits.keys {
			if boundaryCodePat.MatchString(k) {
				firstBoundary = i
				break
			}
		}
		if firstBoundary < 0 {
			t.Fatalf("locale %s 找不到任何邊界聲明鍵：順序無從比較，不得通過", loc)
		}
		for _, k := range []string{"protectionTitle", "protection"} {
			idx := limits.index(k)
			if idx < 0 {
				t.Fatalf("locale %s 缺 %s：保護範圍段不存在時，邊界會被讀成控制全面失效", loc, k)
			}
			if idx > firstBoundary {
				t.Errorf("locale %s 的 %s 排在第一條邊界 %q 之後（%d > %d）："+
					"先讀到邊界的稽核會把它讀成「一堆洞」",
					loc, k, limits.keys[firstBoundary], idx, firstBoundary)
			}
		}
		if bt := limits.index("boundaryTitle"); bt >= 0 && bt > firstBoundary {
			t.Errorf("locale %s 的 boundaryTitle 排在第一條邊界之後（%d > %d）", loc, bt, firstBoundary)
		}
	}
}
