package gatewayapi

// pkg/gatewayapi 型別純淨守衛（任務 1.7）。
//
// **釘住什麼**：
//
//	1. pkg/gatewayapi 的**傳遞相依閉包**內零 internal/model、零 gorm、零 gin，
//	   且不相依本 module 的任何 internal/... 包（訂正後無例外項）。
//	2. TxSink SHALL NOT 出現在 pkg/gatewayapi——它帶 *gorm.DB，宣告在公開包等於
//	   整包相依 GORM。放錯位置即紅。
//	3. TxSink 的簽名是 WriteInTx(tx *gorm.DB, ev AuditEvent) error：**不得帶額外
//	   ctx**（額外的取消來源會讓原本不會回滾的交易回滾，是行為變更）。
//	4. 契約型別清單逐項存在，且 SessionLimits 不含 RecordingRequired
//	   （未拍板，寫入即固化未定案行為）。
//
// **為何第 4 項也在這個守衛裡**：掃描式守衛的頭號死法是「掃描範圍靜默縮小 → 空集合
// → 全綠」。若只驗「沒有壞相依」，把整個 pkg/gatewayapi 刪空即完美通過。要求清單內
// 每個型別都在，才使「零違規」有意義。這是 minScannedFiles 慣例在型別層的等價物。
//
// **掃描根定位**：以 go.mod 的 module 行為身分錨點，不用檔案深度推算、不用 cwd 相對
// 路徑（已實證 17 處既有守衛因此在搬檔後掃空仍綠）。
//
// **突變自檢**：在 pkg/gatewayapi 暫加一個 internal/model 引用，本守衛須變紅。

import (
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/packages"
)

// ── 受管常數 ──────────────────────────────────────────────────────────────

// gwModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const gwModulePath = "github.com/custodexa/backend"

// gwAPIPkgPath 公開契約包。
const gwAPIPkgPath = gwModulePath + "/pkg/gatewayapi"

// gwAuditPortPkgPath audit 模組的同行程 internal port（TxSink 的唯一合法住所）。
const gwAuditPortPkgPath = gwModulePath + "/internal/modules/audit/port"

// minGatewayGuardPackages packages.Load 的載入包數下限。
// 兩個 pattern 各至少一個包；載入數低於此即代表 pattern 掃空（包被搬走／改名），
// 守衛將在空集合下假綠。**這兩個包不會消失**（後續只往 audit 模組加東西），
// 故下限恆有效。
const minGatewayGuardPackages = 2

// minGatewayAPIFiles pkg/gatewayapi 的非測試 .go 檔下限（現況 5：doc/policy/audit/
// alert/token，取 4 為下界）。檔案被清空時要當場紅，而不是「零違規」。
const minGatewayAPIFiles = 4

// gwForbiddenImports pkg/gatewayapi 相依閉包內的禁止項（前綴比對）。逐條附理由，
// **無例外清單**——訂正後 TxSink 已移出本包，故不再有任何具名障礙例外。
var gwForbiddenImports = []struct {
	Prefix string
	Reason string
}{
	{gwModulePath + "/internal/", "公開契約包不得相依本 module 的 internal 實作（含 internal/model）；" +
		"相依即代表這些型別無法在 gateway 行程獨立成立"},
	{"gorm.io/", "型別一旦帶 GORM，整個公開包就把 ORM 拖進未來的 gateway 行程；" +
		"需要 *gorm.DB 的介面一律放 internal/modules/audit/port"},
	{"github.com/gin-gonic/", "HTTP 框架語義屬邊界 adapter，判定結果只帶 apierror 機器碼（P2）"},
}

// gwRequiredTypes 契約型別清單。key＝型別名，value＝該型別必須具備的
// 成員（struct 欄位或 interface 方法）。空 slice 代表只驗型別存在。
var gwRequiredTypes = map[string][]string{
	"AsyncSink": {"Submit"},
	// PolicyValue 已於閘道接線時自 PolicyGate 移除：全庫零實作零消費者，
	// 且 r4-adversarial-security §272 已標其為「對 36 鍵政策的無允許清單通用讀取面」
	// ——留著就是契約描述未實作能力，且是一個尚未被守衛覆蓋的讀取面。
	"PolicyGate": {"AuthorizePreResolve", "AuthorizeResolvedAccount"},
	"Denial":     {"Gate", "Decision", "Status", "Meta", "Internal"},
	"Stage":      {},
	"ConnectSubject": {"UserID", "ClaimedRole", "AuthMethod", "ProviderID",
		"AuthEpoch", "CredEpoch", "ClientIP"},
	"ConnectObjectRef":      {"AssetID", "AccountID", "Protocol", "Channel"},
	"ResolvedConnectObject": {"ConnectObjectRef", "Username"},
	"Decision": {"Allowed", "AdminExemption", "Code", "Params", "Reason", "Policy",
		"Risks", "MaxDurationMinutes", "PendingRequestID", "Limits", "ResolvedRole", "Hints"},
	"RiskDetail":    {"Key", "Label"},
	"SessionLimits": {"IdleTimeout", "MaxDuration"},
	// 閘道接線時拆分：VerifySession 歸 SessionVerifier（identity.AuthService 實作），
	// 簽發／兌換歸 TokenService（proxy.ConnectTokenManager 實作）——現實中沒有任何
	// 型別同時擔任兩者，合成單一介面只能靠一層為滿足介面而生的合成器。
	"SessionVerifier": {"VerifySession"},
	"TokenService":    {"IssueConnectToken", "RedeemConnectToken"},
	"Principal":       {"UserID", "Username", "Role", "Scope", "AuthMethod", "ProviderID", "AuthEpoch", "CredEpoch"},
	// ConnectGrant 客體改平鋪：現行票證只帶 asset_id／account_id 兩個選擇器，
	// 嵌 ConnectObjectRef 等於宣稱票證帶著 Protocol／Channel 而實作永遠填不了。
	// Limits 一併移除（零生產者零消費者，未拍板）。
	"ConnectGrant": {"UserID", "AssetID", "AccountID", "AuthMethod", "ProviderID", "AuthEpoch", "CredEpoch", "ExpiresAt"},
	"AlertSink":    {"RecordAlert", "RecordAlerts"},
	// Kind／ReasonCode 為降級告警而設：降級告警不掛規則，
	// 缺這兩欄則「這筆告警為何存在」只能塞回 RuleName 那個字串欄——
	// 那正是 payload 衛生禁止的形態（把分類混進顯示欄）
	"CommandAlert": {"OccurredAt", "SessionID", "Actor", "AssetID", "Command",
		"RuleID", "RuleName", "Kind", "ReasonCode", "Level", "Disposition", "Blocked"},
	// AssetID 為 auditor-workbench 新增：資產主體鍵必須能經 sink 傳到落地面，
	// 否則經 sink 的產生點無法表達主體，工作台的資產樞紐會少掉整批事件
	"AuditEvent": {"OccurredAt", "Actor", "Action", "Resource", "ResourceID",
		"Status", "AssetID", "Request", "Details", "ErrorMsg"},
	"Actor":       {"UserID", "Username"},
	"RequestMeta": {"Method", "Path", "ClientIP", "StatusCode", "DurationMS", "RequestID", "Body"},
}

// gwRequiredStageConsts Stage 的四個值，缺一即無法表達現況三處入口的閘序差異。
var gwRequiredStageConsts = []string{
	"StageIssue", "StageRedeemTerminal", "StageRedeemGraphical", "StageData",
}

// gwRequiredFieldTypes 指標型別必須維持指標的欄位（值型分不出 NULL 與 0）。
var gwRequiredFieldTypes = map[string]map[string]string{
	// RuleID 同 AssetID 的理由：降級類告警無規則可指，值型會把 NULL 寫成 0，
	// 而 0 不是任何一筆規則的 ID 卻在查詢與 JOIN 上看起來像個值
	"CommandAlert": {"AssetID": "*uint", "RuleID": "*uint"},
	"Decision":     {"PendingRequestID": "*uint"},
	"AuditEvent":   {"ResourceID": "*uint", "AssetID": "*uint"},
}

// gwExactFieldSets **欄位白名單**：這幾個型別的欄位集合必須與清單**精確相等**，
// 多一個未登記欄位即紅。
//
// **為什麼黑名單不夠**：
// 原本只有 gwForbiddenMembers 的名稱黑名單（禁 `ConnectGrant.ClaimedRole`、
// `ConnectSubject.Role`、`SessionLimits.RecordingRequired` 三個字面名）。審查時在
// `ConnectGrant` 加一欄 `Role string`——三個守衛全 PASS。`Role`／`UserRole`／
// `RoleSnapshot` 任意別名都能把角色帶進 token 快照，而「快照 SHALL NOT 攜帶角色」
// （`internal/proxy/connect_token.go:11-14`）正是同一條安全性質。
//
// 白名單把防線由「禁這幾個名字」改為「只准這些欄位」，任意命名的新欄位一律紅。
// **代價是日後新增欄位必須同時改本清單**——這是刻意的：token 快照的形狀是
// 安全契約，增欄應該在 PR diff 裡被看見並被質問「這欄會不會變成授權判定依據」。
//
// **界定（不誇大）**：這仍是**守衛強制**而非編譯器強制。有 commit 權者可以連同本清單
// 一起改；它擋的是「順手加一欄」的意外，不是有意繞過。故此處的措辭是
// 「不嵌入＋守衛欄位白名單」，不是「編譯期不可能」。
var gwExactFieldSets = map[string][]string{
	// 客體平鋪＋去 Limits（理由見 gwRequiredTypes 同名項）。
	// **白名單守的安全性質未變**：仍無任何角色欄——ConnectGrant 加 Role／UserRole／
	// RoleSnapshot 之類任意命名的欄位一律紅。
	"ConnectGrant": {"UserID", "AssetID", "AccountID", "AuthMethod", "ProviderID",
		"AuthEpoch", "CredEpoch", "ExpiresAt"},
	"ConnectSubject": {"UserID", "ClaimedRole", "AuthMethod", "ProviderID",
		"AuthEpoch", "CredEpoch", "ClientIP"},
	"SessionLimits": {"IdleTimeout", "MaxDuration"},
}

// gwForbiddenMembers 明確不得存在的成員（逐條附理由）。
//
// 與 gwExactFieldSets 並存而非被取代：白名單擋任意命名的新欄位，黑名單保留這三個
// **具名**形態的專屬失敗訊息（改名、回填未拍板欄位），讓犯錯者讀到的是為他而寫的理由。
var gwForbiddenMembers = map[string]map[string]string{
	"SessionLimits": {"RecordingRequired": "未拍板：兌換側現況零強制，無生產者無消費者，" +
		"寫入契約即固化未定案行為"},
	"ConnectSubject": {"Role": "已更名 ClaimedRole：舊名讀起來像權威角色，" +
		"新名讓「這是呼叫端自陳的」寫在型別上"},
	"ConnectGrant": {"ClaimedRole": "connect-token 快照 SHALL NOT 攜帶角色" +
		"（internal/proxy/connect_token.go:11-14），使憑角色快照判定成為編譯期不可能"},
}

// ── 掃描根定位 ────────────────────────────────────────────────────────────

// gwModuleRoot 由本測試檔位置向上找 go.mod，並核對 module 行。
// 不用「Dir(Caller)/../..」的層數推算：那在守衛檔搬家時會靜默指到別處。
func gwModuleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if body, err := os.ReadFile(gomod); err == nil {
			want := "module " + gwModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				gomod, gwModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位", filepath.Dir(self), gwModulePath)
		}
		dir = parent
	}
}

// gwScan 一次載入的產物。
//
// Err 承載失敗原因而非就地 t.Fatalf：載入結果由本包三支守衛共用單次執行，
// 而 sync.Once 內拿到的 `t` 屬於第一個進入的測試。在其中 Fatal 只會讓那一支紅，
// 其餘兩支拿到零值（nil map）並在空集合上全綠——守衛看似都在，射程卻是零。
type gwScan struct {
	ByPath map[string]*packages.Package
	Err    error
}

var (
	gwLoadOnce  sync.Once
	gwLoadCache gwScan
)

// gwLoad 取（並快取）兩個目標包的載入結果，本包三支守衛共用。
//
// 三支守衛看的是同一份型別事實且都不改動它，重複載入純屬浪費。
//
// **modroot 定位刻意留在 Once 之外**：gwModuleRoot 失敗時會 t.Fatal，若在 Once 內
// 觸發，Goexit 會讓 Once 記為已執行而快取停在零值，後續測試取到 nil map 且 Err 為
// nil——正是本檔要防的假綠。它只是往上找 go.mod，成本可忽略，各自呼叫即可。
func gwLoad(t *testing.T) map[string]*packages.Package {
	t.Helper()
	root := gwModuleRoot(t)
	gwLoadOnce.Do(func() { gwLoadCache = runGwLoad(root) })
	if gwLoadCache.Err != nil {
		t.Fatalf("%v", gwLoadCache.Err)
	}
	return gwLoadCache.ByPath
}

// runGwLoad 實際載入兩個目標包（含傳遞相依），並施加載入下限與 pkg.Errors 檢查。
//
// 不接 *testing.T（理由見 gwScan）。三道防假綠管線——載入下限、pkg.Errors、
// 目標包必須在實載清單內——**判準值與時機一律不變**，只是每包執行一次而非三次。
func runGwLoad(root string) gwScan {
	fail := func(format string, args ...any) gwScan {
		return gwScan{Err: fmt.Errorf(format, args...)}
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedTypes | packages.NeedImports | packages.NeedDeps,
		Dir:   root,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, gwAPIPkgPath+"/...", gwAuditPortPkgPath+"/...")
	if err != nil {
		return fail("packages.Load 失敗（守衛無法在無視野下宣稱通過）: %v", err)
	}
	if len(pkgs) < minGatewayGuardPackages {
		return fail("只載入 %d 個包（下限 %d）：掃描範圍已失真，守衛將在近乎空集合下假綠。"+
			"若包被搬移／改名，改守衛常數而非降低下限", len(pkgs), minGatewayGuardPackages)
	}
	// pkg.Errors 非空即失敗：帶著載入／型別錯誤的樹，其型別資訊可能殘缺，
	// 「查不到禁止的相依」會被誤當成「沒有禁止的相依」。遷移中途編譯最不穩，
	// 這一條是這類守衛在十波期間最重要的防線。
	byPath := map[string]*packages.Package{}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			return fail("包 %s 有 %d 個載入／型別錯誤（首個：%v）：守衛拒絕在殘缺的型別資訊上作判定",
				p.PkgPath, len(p.Errors), p.Errors[0])
		}
		byPath[p.PkgPath] = p
	}
	for _, want := range []string{gwAPIPkgPath, gwAuditPortPkgPath} {
		if byPath[want] == nil {
			return fail("目標包 %s 未被載入（實載：%v）：守衛掃不到目標即等於沒跑", want, sortedKeys(byPath))
		}
	}
	return gwScan{ByPath: byPath}
}

func sortedKeys(m map[string]*packages.Package) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── 守衛 1：型別純淨（傳遞相依閉包） ──────────────────────────────────────

func TestGatewayAPITypePurity(t *testing.T) {
	byPath := gwLoad(t)
	api := byPath[gwAPIPkgPath]

	if n := len(api.GoFiles); n < minGatewayAPIFiles {
		t.Fatalf("pkg/gatewayapi 只有 %d 個非測試 .go 檔（下限 %d）：契約被清空時本守衛"+
			"也會「零違規」，故以檔數下限擋住空集合假綠", n, minGatewayAPIFiles)
	}

	// BFS 走傳遞相依閉包：只驗直接 import 擋不住「經由一層轉手拖進 GORM」。
	type node struct {
		pkg   *packages.Package
		trail []string
	}
	seen := map[string]bool{gwAPIPkgPath: true}
	queue := []node{{pkg: api, trail: []string{gwAPIPkgPath}}}
	var violations []string
	visited := 0

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		visited++

		imps := make([]string, 0, len(cur.pkg.Imports))
		for p := range cur.pkg.Imports {
			imps = append(imps, p)
		}
		sort.Strings(imps)

		for _, path := range imps {
			for _, rule := range gwForbiddenImports {
				if strings.HasPrefix(path, rule.Prefix) {
					violations = append(violations, fmt.Sprintf(
						"  相依鏈 %s -> %s\n    命中禁令前綴 %q：%s",
						strings.Join(cur.trail, " -> "), path, rule.Prefix, rule.Reason))
				}
			}
			if seen[path] {
				continue
			}
			seen[path] = true
			queue = append(queue, node{pkg: cur.pkg.Imports[path], trail: append(append([]string{}, cur.trail...), path)})
		}
	}

	if visited == 0 {
		t.Fatal("相依閉包走訪了 0 個包：掃描失效")
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("pkg/gatewayapi 的相依閉包出現 %d 個禁止相依（走訪 %d 個包）：\n%s",
			len(violations), visited, strings.Join(violations, "\n"))
	}
	t.Logf("pkg/gatewayapi 相依閉包乾淨：走訪 %d 個包、%d 個非測試檔", visited, len(api.GoFiles))
}

// ── 守衛 2：型別清單完備＋禁止成員 ────────────────────────────────────────

func TestGatewayAPIContractSurface(t *testing.T) {
	byPath := gwLoad(t)
	scope := byPath[gwAPIPkgPath].Types.Scope()

	var missing []string
	for name, members := range gwRequiredTypes {
		obj := scope.Lookup(name)
		if obj == nil {
			missing = append(missing, fmt.Sprintf("  型別 %s 不存在（gwRequiredTypes 登記的契約型別）", name))
			continue
		}
		if !obj.Exported() {
			missing = append(missing, fmt.Sprintf("  型別 %s 未匯出：跨模組共用的契約型別必須匯出", name))
		}
		have := gwMemberSet(obj.Type())
		for _, m := range members {
			if !have[m] {
				missing = append(missing, fmt.Sprintf("  型別 %s 缺成員 %s（實有：%v）", name, m, sortedSet(have)))
			}
		}
	}

	for _, name := range gwRequiredStageConsts {
		obj := scope.Lookup(name)
		if obj == nil {
			missing = append(missing, fmt.Sprintf("  Stage 常數 %s 不存在：四值缺一即表達不了三處入口的閘序差異", name))
			continue
		}
		if _, ok := obj.(*types.Const); !ok {
			missing = append(missing, fmt.Sprintf("  %s 不是常數（實為 %T）", name, obj))
		}
	}

	for tname, fields := range gwRequiredFieldTypes {
		obj := scope.Lookup(tname)
		if obj == nil {
			continue // 上面已記
		}
		st, ok := obj.Type().Underlying().(*types.Struct)
		if !ok {
			missing = append(missing, fmt.Sprintf("  %s 不是 struct，無法驗欄位型別", tname))
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			want, tracked := fields[f.Name()]
			if !tracked {
				continue
			}
			if got := f.Type().String(); got != want {
				missing = append(missing, fmt.Sprintf(
					"  %s.%s 型別為 %s，應為 %s：值型分不出 NULL 與 0，會把 NULL 靜默寫成 0",
					tname, f.Name(), got, want))
			}
		}
	}

	// 欄位白名單：精確集合比對（多一欄即紅，少一欄也紅）。
	for tname, allowed := range gwExactFieldSets {
		obj := scope.Lookup(tname)
		if obj == nil {
			continue // 上面已記「型別不存在」
		}
		st, ok := obj.Type().Underlying().(*types.Struct)
		if !ok {
			missing = append(missing, fmt.Sprintf("  %s 不是 struct，無法作欄位白名單比對", tname))
			continue
		}
		want := map[string]bool{}
		for _, f := range allowed {
			want[f] = true
		}
		have := map[string]bool{}
		for i := 0; i < st.NumFields(); i++ {
			have[st.Field(i).Name()] = true
		}
		for f := range have {
			if !want[f] {
				missing = append(missing, fmt.Sprintf(
					"  %s 出現未登記欄位 %s：本型別採**欄位白名單**（gwExactFieldSets），"+
						"任何新增欄位一律紅。若確有必要，改守衛白名單並在 PR 說明該欄不會成為授權判定依據——"+
						"名稱黑名單擋不住 Role／UserRole／RoleSnapshot 這類別名（對抗審查實證）",
					tname, f))
			}
		}
		for f := range want {
			if !have[f] {
				missing = append(missing, fmt.Sprintf(
					"  %s 缺白名單欄位 %s：欄位被刪除時白名單也必須同步，否則白名單會在縮水的型別上假綠", tname, f))
			}
		}
	}

	for tname, banned := range gwForbiddenMembers {
		obj := scope.Lookup(tname)
		if obj == nil {
			continue
		}
		have := gwMemberSet(obj.Type())
		for m, reason := range banned {
			if have[m] {
				missing = append(missing, fmt.Sprintf("  %s 不得有成員 %s：%s", tname, m, reason))
			}
		}
	}

	// TxSink 不得出現在公開包——它帶 *gorm.DB，位置本身就是契約的一部分。
	if obj := scope.Lookup("TxSink"); obj != nil {
		missing = append(missing, "  pkg/gatewayapi 宣告了 TxSink：它的簽名帶 *gorm.DB，"+
			"放在公開包會讓整包相依 GORM。唯一合法住所是 "+gwAuditPortPkgPath)
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("gateway 契約面不符本檔登記的契約規格，共 %d 項：\n%s",
			len(missing), strings.Join(missing, "\n"))
	}
	t.Logf("契約面完備：%d 個型別、%d 個 Stage 常數逐項到位", len(gwRequiredTypes), len(gwRequiredStageConsts))
}

// gwMemberSet 取型別的成員名集合：interface 取方法，struct 取欄位（嵌入取型別名）。
func gwMemberSet(t types.Type) map[string]bool {
	out := map[string]bool{}
	switch u := t.Underlying().(type) {
	case *types.Interface:
		for i := 0; i < u.NumMethods(); i++ {
			out[u.Method(i).Name()] = true
		}
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			out[u.Field(i).Name()] = true
		}
	}
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── 守衛 3：TxSink 的位置與簽名 ───────────────────────────────────────────

func TestAuditTxSinkPortShape(t *testing.T) {
	byPath := gwLoad(t)
	obj := byPath[gwAuditPortPkgPath].Types.Scope().Lookup("TxSink")
	if obj == nil {
		t.Fatalf("%s 未宣告 TxSink：交易內 fail-close 審計失去唯一合法落地面", gwAuditPortPkgPath)
	}
	iface, ok := obj.Type().Underlying().(*types.Interface)
	if !ok {
		t.Fatalf("TxSink 不是 interface（實為 %s）", obj.Type().Underlying())
	}
	if n := iface.NumMethods(); n != 1 {
		t.Fatalf("TxSink 有 %d 個方法，應為 1（WriteInTx）", n)
	}
	m := iface.Method(0)
	if m.Name() != "WriteInTx" {
		t.Fatalf("TxSink 的方法名為 %s，應為 WriteInTx", m.Name())
	}
	sig := m.Type().(*types.Signature)

	const wantTx = "*gorm.io/gorm.DB"
	const wantEv = gwAPIPkgPath + ".AuditEvent"
	if got := sig.Params().Len(); got != 2 {
		var ps []string
		for i := 0; i < sig.Params().Len(); i++ {
			ps = append(ps, sig.Params().At(i).Type().String())
		}
		t.Fatalf("WriteInTx 有 %d 個參數（%v），應為 2：(tx *gorm.DB, ev AuditEvent)。"+
			"**不得帶額外 ctx**——現況 fail-close 函式本就無 ctx，補一個會引入額外的取消來源，"+
			"交易期間該 ctx 被取消將導致原本不會回滾的交易回滾，是行為變更",
			got, ps)
	}
	if got := sig.Params().At(0).Type().String(); got != wantTx {
		t.Fatalf("WriteInTx 第 1 參數為 %s，應為 %s", got, wantTx)
	}
	// types.Unalias：port.AuditEvent 是 gatewayapi.AuditEvent 的型別別名，Go 1.22+ 的
	// materialized alias 會讓 String() 回別名路徑。解別名後比對，才是在驗「同一個型別」
	// 而不是在驗「同一個名字」——別名合法，另立一份複製品不合法。
	if got := types.Unalias(sig.Params().At(1).Type()).String(); got != wantEv {
		t.Fatalf("WriteInTx 第 2 參數為 %s，應為 %s（與 AsyncSink 共用同一事件形狀，"+
			"不得另立一份而在收口時製造轉換失真點）", got, wantEv)
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if strings.Contains(sig.Params().At(i).Type().String(), "context.Context") {
			t.Fatalf("WriteInTx 第 %d 參數是 context.Context：額外的取消來源會改變回滾行為", i+1)
		}
	}
	if sig.Results().Len() != 1 || sig.Results().At(0).Type().String() != "error" {
		t.Fatalf("WriteInTx 的回傳不是單一 error：回 error 是 fail-close 得以成立的全部理由")
	}
	t.Log("TxSink 位置與簽名正確：internal port、WriteInTx(tx *gorm.DB, ev AuditEvent) error、無額外 ctx")
}
