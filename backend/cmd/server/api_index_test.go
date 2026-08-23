package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// docs/API_SPEC.md 端點索引的生成與完備性守衛（api-docs spec）。
//
// 為何需要本守衛：API_SPEC.md 是人與 AI 查 API 的實際入口，但它全靠人工維護，
// 沒有任何機制防止與實碼漂移——本 change 開工前已可指認至少兩處實質錯誤。
// 索引改由 registerRoutes 的實際註冊結果生成，消滅「人工抄寫路徑」這個錯誤類別。
//
// 信任邊界：一般測試容器以**唯讀**掛載取得 docs/，故守衛不具備修改
// 其驗證對象的能力——否則「重新生成使測試變綠」會成為掩蓋真實漂移的捷徑。
// 重新生成須以可寫掛載的一次性容器執行，指令見 updateIndexCmd。

const (
	apiIndexBegin = "<!-- BEGIN API-INDEX -->"
	apiIndexEnd   = "<!-- END API-INDEX -->"

	apiIndexHeader    = "| 方法 | 路徑 | 註冊條件 |"
	apiIndexSeparator = "|---|---|---|"

	// apiSpecRODir 是一般測試容器的唯讀掛載點（docker-compose.dev.yml backend volumes）。
	//
	// **位於 /app（Go module 根）內是必要條件，不是風格選擇**：go test 的結果快取
	// 只追蹤 module 內被開啟的檔案。掛在 module 外（如 /opt/custodexa/docs）時，
	// 純手改 API_SPEC.md 不會使快取失效——`go test` 回報 (cached) 綠而根本沒執行
	// 守衛，漂移完全不會被發現（實測確認）。掛進 testdata/ 後改文件即使快取失效。
	// 路徑相對於 cmd/server（與 route-golden 同層），實際位置由 cmdServerDir 解出。
	apiSpecRODir = "testdata/docs"

	// apiSpecRWDir 是 -update 專用的可寫掛載點，**刻意與唯讀點不同路徑**。
	//
	// 為何不能沿用同一路徑：`docker compose run -v ./docs:<唯讀點>` 無法覆蓋 compose
	// 檔中同目標的 :ro 掛載——compose 的 service 定義優先，實測仍為唯讀（設計文件
	// 原指令的錯誤，實作時修正）。改用獨立掛載點後，一般容器沒有這個點、寫入必失敗，
	// 信任邊界反而更明確：可寫能力只存在於刻意加掛的一次性容器。
	apiSpecRWDir = "testdata/docs-rw"

	// updateIndexCmd 是重新生成索引的唯一文件化指令。
	// --no-deps 不啟動 postgres／guacd（路由 dump 走 zero-value deps、不連 DB）；
	// compose run 不發布 ports，故不干擾既有的 backend service。
	updateIndexCmd = "docker compose run --rm --no-deps " +
		"-v ./docs:/app/cmd/server/" + apiSpecRWDir + " backend " +
		"go test ./cmd/server -run '^TestAPIIndex$' -update"
)

// 註冊條件的值域。
//
// 刻意為枚舉而非自由文字：若日後新增「依旗標條件註冊」的機制，deriveCondition
// 會因無法歸類而 fail，迫使新增者檢視文件並擴充此值域——而不是讓新端點悄悄
// 以錯誤的條件混入索引。
const (
	condAlways    = "always"
	condAuditFlag = "FEATURE_AUDIT_LOG_ENABLED"
)

// indexEntry 是索引的一列，三欄（不含「文件章節」第四欄）。
type indexEntry struct {
	Method    string
	Path      string
	Condition string
}

func (e indexEntry) sortKey() string { return e.Path + " " + e.Method }

// apiSpecPath 定位 docs/API_SPEC.md。
//
// 容器內：專案根 docs/ 唯讀掛載於 apiSpecRODir（**目錄**掛載，見 docker-compose.dev.yml
// backend volumes 對單檔 inode 陷阱與 module 內位置的說明）。
// host 直跑：cmd/server 往上三層即專案根。
//
// 找不到時 Fatal 而非 skip——讀不到被驗證對象就等於沒有守衛，skip 只會製造假綠。
func apiSpecPath(t *testing.T) string {
	t.Helper()
	// host fallback 不再由 cmd/server 往上數三層（與「組裝根住在樹的第幾層」綁死，
	// 且 cmdServerDir 本身已改為 module 錨點定位）：改由 module 根上溯一層取專案根。
	// 那一層是相對 go.mod 錨定的 module 根，package 下移不影響。
	for _, p := range []string{
		filepath.Join(cmdServerDir(t), apiSpecRODir, "API_SPEC.md"),            // 容器唯讀掛載點
		filepath.Join(filepath.Dir(guardModuleRoot(t)), "docs", "API_SPEC.md"), // host 專案根
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatalf("找不到 docs/API_SPEC.md（容器內應唯讀掛於 %s；"+
		"見 docker-compose.dev.yml backend volumes）——讀不到被驗證對象即等於沒有守衛，故 fail 而非 skip",
		apiSpecRODir)
	return ""
}

// apiSpecWritePath 定位 -update 的寫入目標。
//
// 一般測試容器沒有 apiSpecRWDir，故退回讀取路徑（唯讀）並必然寫入失敗——
// 那正是信任邊界要的結果。host 直跑時讀寫本就是同一個檔。
func apiSpecWritePath(t *testing.T, readPath string) string {
	t.Helper()
	if p := filepath.Join(cmdServerDir(t), apiSpecRWDir, "API_SPEC.md"); fileExists(p) {
		return p
	}
	return readPath
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// deployConfigs 是兩組可達的部署組態，順序即 membership bitmask 的位序。
//
// 順序為契約：maskAlways／maskAuditFlag 的常數值依賴它，改順序必須同步改常數。
//
// **permission 維度已退場**：權限檢查不再有旗標，
// 路由一律帶 RequirePermission。原本的四格（audit × permission）笛卡兒積收斂為兩格
var deployConfigs = []struct {
	auditLogEnabled bool
}{
	{true},  // bit 0
	{false}, // bit 1
}

const (
	// maskAlways：兩格全有 → 無條件註冊
	maskAlways = 0b11
	// maskAuditFlag：僅 audit-on 格有（bit 0）→ 受 audit 旗標控制
	maskAuditFlag = 0b01
)

// routeUniverse 以 registerRoutes 於各可達部署組態下的註冊結果取聯集，
// 並依「該路由出現於哪些組態」推導其註冊條件。
//
// **membership 必須逐組態保留，不可壓縮成單一布林**：壓縮會遺失「某端點只在
// 部分組態出現」的事實，使條件註冊的端點被誤標為 always，守衛全綠而事實消失
// （審查 Finding 1）。目前唯一維度是 audit，但結構保留 bitmask 形式——
// 新增任何條件註冊旗標時擴充 deployConfigs 即可，TestRouteDepsFlagsCoveredByMatrix
// 會在有人新增 routeDeps bool 欄位而未擴充矩陣時打紅。
func routeUniverse(t *testing.T) []indexEntry {
	t.Helper()

	membership := map[[2]string]int{}
	for bit, c := range deployConfigs {
		routes, _ := buildRouter(t, gin.DebugMode, c.auditLogEnabled)
		for k := range routes {
			membership[k] |= 1 << bit
		}
	}

	var entries []indexEntry
	for k, mask := range membership {
		entries = append(entries, indexEntry{
			Method:    k[0],
			Path:      k[1],
			Condition: deriveCondition(t, k, mask),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].sortKey() < entries[j].sortKey()
	})
	return entries
}

// deriveCondition 由完整的兩格 membership bitmask 推導註冊條件欄的值。
//
// 只認兩種 pattern，其餘一律 fail——包含「僅 audit-off 才出現」「只在單一組態出現」
// 「受 permission 影響」等。這是刻意的封閉值域：任何新的條件註冊機制都會在此撞牆，
// 迫使新增者檢視文件與枚舉，而不是讓端點以錯誤的條件悄悄混入索引。
func deriveCondition(t *testing.T, k [2]string, mask int) string {
	t.Helper()
	cond, err := conditionForMask(mask)
	if err != nil {
		t.Fatalf("%s %s：%v——出現了新的條件註冊機制，"+
			"須同步擴充此枚舉與 docs/API_SPEC.md 的索引", k[0], k[1], err)
	}
	return cond
}

// conditionForMask 是 deriveCondition 的純函式核心，抽出以便直接對各種 mask
// 斷言（t.Fatalf 會中止測試，無法在表格測試中逐項驗證拒絕行為）。
func conditionForMask(mask int) (string, error) {
	switch mask {
	case maskAlways:
		return condAlways, nil
	case maskAuditFlag:
		return condAuditFlag, nil
	default:
		return "", fmt.Errorf("註冊條件無法歸入已知值域（兩組態 membership=%02b）", mask)
	}
}

// assertFlagSemantics 複核旗標語義，防止索引在錯誤前提上生成。
//
// 這些斷言與索引本身無關，但若它們失效，索引的「註冊條件」欄就會建立在錯誤的
// 前提上——例如 audit 旗標若開始增減 /audit-logs 以外的端點，聯集會悄悄多出條目。
//
// 原有的 permission 旗標語義斷言已隨旗標退場移除；
// 「權限不得條件註冊」改由 TestNoConditionalPermissionRegistration 以結構檢查承擔。
func assertFlagSemantics(t *testing.T) {
	t.Helper()

	auditOn, _ := buildRouter(t, gin.DebugMode, true)
	auditOff, _ := buildRouter(t, gin.DebugMode, false)
	var delta []string
	for k := range auditOn {
		if _, ok := auditOff[k]; !ok {
			delta = append(delta, k[0]+" "+k[1])
		}
	}
	sort.Strings(delta)
	if len(delta) != 3 {
		t.Errorf("audit 旗標增減的端點數為 %d（預期 3 條 /audit-logs）：\n  %s",
			len(delta), strings.Join(delta, "\n  "))
	}
	for _, d := range delta {
		if !strings.Contains(d, "/audit-logs") {
			t.Errorf("audit 旗標增減了非 /audit-logs 的端點：%s", d)
		}
	}

	// gin mode 不再影響路由集合——/swagger 曾是唯一的 mode-dependent 路由，
	// 其退場使此不變式成立。若哪天有人重新引入 mode-dependent 路由，索引會漏掉它：
	// routeUniverse 只跑 DebugMode，release 專屬的端點根本不會進入宇宙。
	//
	// **必須比對完整鍵集，不可只比數量**：release 註冊 /prod-only、debug 註冊
	// /dev-only 時兩邊數量相同，只比長度會通過，而 /dev-only 被標成 always、
	// /prod-only 從索引徹底消失——production 端點無人守護（審查 Finding 2）。
	//
	// **且必須逐格比對，不可只驗一格**：若某路由的條件是 `release && !auditLogEnabled`，
	// 只比 {audit=on, perm=on} 那一格根本看不到它（同上）。
	// 這裡遍歷全部 deployConfigs——registerRoutes 本就不讀 gin mode，故「mode 完全
	// 不影響路由集合」是可主張的強契約，比只驗 release 可達組態更早攔截。
	for _, c := range deployConfigs {
		dev, _ := buildRouter(t, gin.DebugMode, c.auditLogEnabled)
		rel, _ := buildRouter(t, gin.ReleaseMode, c.auditLogEnabled)

		var onlyRelease, onlyDev []string
		for k := range rel {
			if _, ok := dev[k]; !ok {
				onlyRelease = append(onlyRelease, k[0]+" "+k[1])
			}
		}
		for k := range dev {
			if _, ok := rel[k]; !ok {
				onlyDev = append(onlyDev, k[0]+" "+k[1])
			}
		}
		sort.Strings(onlyRelease)
		sort.Strings(onlyDev)

		if len(onlyRelease) > 0 {
			t.Errorf("組態 audit=%v：以下 %d 條端點僅於 release 模式註冊，"+
				"而索引只取 DebugMode——它們完全不在索引中，production 端點無人守護：\n  %s",
				c.auditLogEnabled, len(onlyRelease), strings.Join(onlyRelease, "\n  "))
		}
		if len(onlyDev) > 0 {
			t.Errorf("組態 audit=%v：以下 %d 條端點僅於 dev 模式註冊，"+
				"卻會被索引標為 always：\n  %s",
				c.auditLogEnabled, len(onlyDev), strings.Join(onlyDev, "\n  "))
		}
	}
}

// renderIndex 產生索引區塊的內容（不含 marker 本身）。
func renderIndex(entries []indexEntry) string {
	var b strings.Builder
	b.WriteString(apiIndexHeader + "\n")
	b.WriteString(apiIndexSeparator + "\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "| %s | `%s` | %s |\n", e.Method, e.Path, e.Condition)
	}
	return b.String()
}

// parseAPIIndex 自文件內容取出索引區塊並解析為條目。
//
// 強制的結構不變式（各配 fixture，見 TestAPIIndexParserInvariants）：
//   - 恰好一組 BEGIN／END，且 BEGIN 先於 END
//   - 不存在第二個 marker 區塊
//   - 區塊內每一非表頭列都須成功解析（**不得靜默略過**）
//   - 解析結果為 0 列即為失敗
//
// 最後一條尤其關鍵：若表頭被微調致使所有資料列都解析不出來，雙向比對就會退化成
// 「空集合 == 空集合」而靜默通過——守衛看似全綠，實則什麼都沒檢查。
func parseAPIIndex(content string) ([]indexEntry, error) {
	if n := strings.Count(content, apiIndexBegin); n != 1 {
		return nil, fmt.Errorf("BEGIN marker 出現 %d 次（須恰好 1 次）", n)
	}
	if n := strings.Count(content, apiIndexEnd); n != 1 {
		return nil, fmt.Errorf("END marker 出現 %d 次（須恰好 1 次）", n)
	}
	begin := strings.Index(content, apiIndexBegin)
	end := strings.Index(content, apiIndexEnd)
	if begin > end {
		return nil, fmt.Errorf("BEGIN marker 位於 END marker 之後")
	}

	block := content[begin+len(apiIndexBegin) : end]

	var entries []indexEntry
	for i, raw := range strings.Split(block, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line == apiIndexHeader || line == apiIndexSeparator {
			continue
		}
		e, err := parseIndexRow(line)
		if err != nil {
			// 不得靜默略過：無法解析的列若被忽略，等同於該端點失去保護
			return nil, fmt.Errorf("索引區塊第 %d 列無法解析（%v）：%q", i+1, err, line)
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("索引區塊解析出 0 列——" +
			"表頭或格式可能已被改動，比對將退化為空集合對空集合而靜默通過")
	}
	return entries, nil
}

// parseIndexRow 解析單列 `| 方法 | 路徑 | 註冊條件 |`。
func parseIndexRow(line string) (indexEntry, error) {
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
		return indexEntry{}, fmt.Errorf("不是表格列")
	}
	cols := strings.Split(strings.Trim(line, "|"), "|")
	if len(cols) != 3 {
		return indexEntry{}, fmt.Errorf("欄數為 %d（須為 3）", len(cols))
	}
	method := strings.TrimSpace(cols[0])
	path := strings.Trim(strings.TrimSpace(cols[1]), "`")
	cond := strings.TrimSpace(cols[2])
	if method == "" || path == "" || cond == "" {
		return indexEntry{}, fmt.Errorf("有空欄位")
	}
	if !strings.HasPrefix(path, "/") {
		return indexEntry{}, fmt.Errorf("路徑 %q 不以 / 開頭", path)
	}
	if cond != condAlways && cond != condAuditFlag {
		return indexEntry{}, fmt.Errorf("註冊條件 %q 不在值域內（%s／%s）", cond, condAlways, condAuditFlag)
	}
	return indexEntry{Method: method, Path: path, Condition: cond}, nil
}

// replaceIndexBlock 以新內容取代 marker 區塊，marker 以外的文件內容**逐字不動**。
func replaceIndexBlock(content, rendered string) (string, error) {
	if n := strings.Count(content, apiIndexBegin); n != 1 {
		return "", fmt.Errorf("BEGIN marker 出現 %d 次（須恰好 1 次）", n)
	}
	if n := strings.Count(content, apiIndexEnd); n != 1 {
		return "", fmt.Errorf("END marker 出現 %d 次（須恰好 1 次）", n)
	}
	begin := strings.Index(content, apiIndexBegin)
	end := strings.Index(content, apiIndexEnd)
	if begin > end {
		return "", fmt.Errorf("BEGIN marker 位於 END marker 之後")
	}
	return content[:begin+len(apiIndexBegin)] + "\n" + rendered + content[end:], nil
}

// minRouteUniverse 路由宇宙（四格組態聯集）的條數下限（防空集合假綠）。
// 2026-08-09 實測 184 條（見 TestAPIIndex 的 t.Logf），門檻取 160。
const minRouteUniverse = 160

// TestAPIIndex 端點索引的完備性守衛，並於 -update 時重新生成。
//
// 雙向相等：索引缺少任一實際路由會紅，索引含有不存在的路由亦會紅。
func TestAPIIndex(t *testing.T) {
	assertFlagSemantics(t)

	want := routeUniverse(t)
	// 防空集合假綠：雙向相等在「兩邊都空」時同樣成立。路由宇宙一旦
	// 因組裝根被拆散而縮水，索引比對會安靜地什麼都不比。下限使其當場轉紅。
	if len(want) < minRouteUniverse {
		t.Fatalf("路由宇宙只有 %d 條（下限 %d）：四格組態的路由列舉已失真，"+
			"雙向相等比對將在近乎空集合下假綠", len(want), minRouteUniverse)
	}
	t.Logf("路由宇宙條數=%d（下限 %d）", len(want), minRouteUniverse)

	path := apiSpecPath(t)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取 %s 失敗: %v", path, err)
	}
	content := string(data)

	if *updateFlag {
		// assertFlagSemantics 以 t.Errorf 報告（不中止），故此處必須顯式攔截：
		// 旗標語義若已失效，生成出來的索引就建立在錯誤前提上（例如漏掉 release
		// 專屬路由）。測試雖會是紅的，但檔案已被覆寫——只看檔案的人會拿到一份
		// 看似完整的錯誤索引。寧可不寫。
		if t.Failed() {
			t.Fatalf("旗標語義斷言已失敗，中止生成——不得在錯誤前提上重寫索引")
		}

		// 讀寫都走可寫點：兩者指向同一 host 檔，但同源可避免「讀 A 寫 B」的錯位
		writePath := apiSpecWritePath(t, path)
		if writePath != path {
			data, err := os.ReadFile(writePath)
			if err != nil {
				t.Fatalf("讀取可寫掛載點 %s 失敗: %v", writePath, err)
			}
			content = string(data)
		}

		updated, err := replaceIndexBlock(content, renderIndex(want))
		if err != nil {
			t.Fatalf("無法定位索引區塊：%v\n"+
				"請先於 docs/API_SPEC.md 插入一組 %s ... %s marker——"+
				"生成器不擅自決定索引在文件中的位置", err, apiIndexBegin, apiIndexEnd)
		}
		if err := os.WriteFile(writePath, []byte(updated), 0o644); err != nil {
			t.Fatalf("寫入 %s 失敗: %v\n"+
				"一般測試容器只有唯讀的 %s（信任邊界：守衛不得修改其驗證對象）。\n"+
				"重新生成請用：%s", writePath, err, apiSpecRODir, updateIndexCmd)
		}
		t.Logf("已重新生成端點索引（%d 條）→ %s", len(want), writePath)
		return
	}

	got, err := parseAPIIndex(content)
	if err != nil {
		t.Fatalf("解析 %s 的端點索引失敗：%v\n重新生成請用：%s", path, err, updateIndexCmd)
	}

	gotByKey := map[[2]string]indexEntry{}
	for _, e := range got {
		k := [2]string{e.Method, e.Path}
		if _, dup := gotByKey[k]; dup {
			t.Errorf("索引有重複條目：%s %s", e.Method, e.Path)
		}
		gotByKey[k] = e
	}
	wantByKey := map[[2]string]indexEntry{}
	for _, e := range want {
		wantByKey[[2]string{e.Method, e.Path}] = e
	}

	var missing, ghost, wrongCond []string
	for k, w := range wantByKey {
		g, ok := gotByKey[k]
		switch {
		case !ok:
			missing = append(missing, k[0]+" "+k[1])
		case g.Condition != w.Condition:
			wrongCond = append(wrongCond, fmt.Sprintf("%s %s：索引記 %s，實際 %s",
				k[0], k[1], g.Condition, w.Condition))
		}
	}
	for k := range gotByKey {
		if _, ok := wantByKey[k]; !ok {
			ghost = append(ghost, k[0]+" "+k[1])
		}
	}
	sort.Strings(missing)
	sort.Strings(ghost)
	sort.Strings(wrongCond)

	if len(missing) > 0 {
		t.Errorf("實際註冊但索引缺少 %d 條端點：\n  %s\n重新生成請用：%s",
			len(missing), strings.Join(missing, "\n  "), updateIndexCmd)
	}
	if len(ghost) > 0 {
		t.Errorf("索引含有 %d 條實際不存在的幽靈端點：\n  %s\n重新生成請用：%s",
			len(ghost), strings.Join(ghost, "\n  "), updateIndexCmd)
	}
	if len(wrongCond) > 0 {
		t.Errorf("註冊條件欄與實際不符 %d 條：\n  %s",
			len(wrongCond), strings.Join(wrongCond, "\n  "))
	}

	// 排序穩定性：索引若非固定序，diff 會混入與真實變動無關的雜訊
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].sortKey() < got[j].sortKey() }) {
		t.Errorf("索引未按「路徑 + 方法」排序——請以 %s 重新生成", updateIndexCmd)
	}
}
