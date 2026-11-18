package managedapi

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/middleware"
)

// 結構面守衛（不需資料庫）：
//   - 每個「資源乘規則」的格子都有值，值在封閉列舉內，例外對應的規則正確，不適用與待查有理由且合乎條件。
//   - 初始名單凍結；初始名單以外的列不得引用僅限初始名單的例外，也不得使用待查；哪些例外僅限初始名單同樣凍結。
//   - 登錄表引用的每條路由存在於路由清冊，在 API token 路由登錄內為開放且已分類，性質與操作相符。
//   - 路由歸屬表與 API token 路由登錄雙向一致：每條開放路由恰有一個歸屬；歸到非資源與唯讀家族的路由性質必須是讀。
//   - 兩張表的機器可讀副本與程式一致（-update 重生）。
//
// 檢查邏輯寫成接收資料的函式，另有自檢以壞資料餵入，證明檢查不是恆真。

var update = flag.Bool("update", false, "重生 testdata/managed-api-registry.json")

const modulePath = "github.com/custodexa/backend"

var routeGoldenStates = []string{"dev-auditoff", "dev-auditon", "release-auditoff", "release-auditon"}

// routeGoldenLowerBound 聯集路由數下界：讀檔或解析退化成空集合時，比對會假綠。
const routeGoldenLowerBound = 300

// frozenInitialNamesCopy 初始名單的第二份副本：registry.go 的初始名單一旦增減，這裡會失敗。
var frozenInitialNamesCopy = []string{
	"asset", "asset_account", "asset_node", "authorization", "credential", "group_role_mapping",
	"group_user_group_mapping", "role_definition", "user", "user_group", "user_group_role_binding",
}

// frozenInitialOnlyCopy 「僅限初始名單」例外的第二份副本：把某個例外改成不限初始名單，新資源就能引用它，
// 這裡會失敗。新增一個僅限初始名單的例外時兩處同步加上；新增不限初始名單的例外是規則的變更，不列在這裡。
var frozenInitialOnlyCopy = []Exception{
	"concurrent_write_retriable_conflict", "create_returns_200", "delete_response_shape", "detail_projection_differs",
	"identity_unique_within_kind", "list_without_total", "lookup_not_unique", "no_exact_lookup", "no_single_read",
	"no_time_fields", "response_envelope_mixed", "resend_advances_time_or_version", "secret_no_clear_path",
	"secret_state_implicit", "secret_without_fingerprint", "server_rewrites_input", "time_field_format",
	"update_full_replace", "update_reissues_identity", "write_response_shape_differs",
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("無法取得本檔路徑")
	}
	dir := filepath.Dir(self)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == "module "+modulePath {
					return dir
				}
			}
			t.Fatalf("%s 的 go.mod 不是 %s", dir, modulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("找不到 go.mod")
		}
		dir = parent
	}
}

// registeredRoutes 四種組態路由 golden 的「方法 樣板路徑」聯集（伺服端實際註冊的路由）。
func registeredRoutes(t *testing.T) map[string]bool {
	t.Helper()
	root := moduleRoot(t)
	out := map[string]bool{}
	for _, state := range routeGoldenStates {
		raw, err := os.ReadFile(filepath.Join(root, "cmd", "server", "testdata", "route-golden", state+".json"))
		if err != nil {
			t.Fatalf("讀取路由 golden %s 失敗：%v", state, err)
		}
		var doc struct {
			Routes []struct {
				Method string `json:"method"`
				Path   string `json:"path"`
			} `json:"routes"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("解析路由 golden %s 失敗：%v", state, err)
		}
		for _, r := range doc.Routes {
			out[r.Method+" "+r.Path] = true
		}
	}
	if len(out) < routeGoldenLowerBound {
		t.Fatalf("路由聯集只有 %d 條（下界 %d）", len(out), routeGoldenLowerBound)
	}
	return out
}

// naAllowed 規則在這一列可否填「不適用」：只在規則依賴的操作或欄位不存在時可以。
func naAllowed(res Resource, rule Rule) bool {
	switch rule {
	case RuleSingleMatchesList:
		return len(res.Read) == 0 || len(res.List) == 0
	case RuleHiddenTargetNotFound:
		return len(res.Read) == 0
	case RuleListDataTotal, RuleExactLookup:
		return len(res.List) == 0
	case RuleListPaging:
		return !res.Paged
	case RuleCreate201:
		return len(res.Create) == 0
	case RuleSameEnvelope, RuleWriteEqualsRead:
		return len(res.Create) == 0 && len(res.Update) == 0
	case RuleUpdatePartial, RuleUpdateKeepsIdentity, RuleResendNoChange:
		return len(res.Update) == 0
	case RuleDelete204, RuleRecreateSameName:
		return len(res.Delete) == 0
	case RuleSecretWriteOnly, RuleSecretClearPath:
		return len(res.Secrets) == 0
	}
	return false
}

// checkCells 登錄表格子的檢查：回傳每一處問題。initial 判定一列是否在初始名單。
func checkCells(resources []Resource, specs map[Exception]ExceptionSpec, initial func(string) bool) []string {
	var probs []string
	add := func(format string, a ...any) { probs = append(probs, fmt.Sprintf(format, a...)) }
	known := map[Rule]bool{}
	for _, r := range Rules() {
		known[r] = true
	}
	seen := map[string]bool{}
	for _, res := range resources {
		if res.Name == "" {
			add("有一列沒有名稱")
			continue
		}
		if seen[res.Name] {
			add("%s：名稱重複", res.Name)
		}
		seen[res.Name] = true
		for rule := range res.Cells {
			if !known[rule] {
				add("%s：格子引用不存在的規則 %q", res.Name, rule)
			}
		}
		for _, rule := range Rules() {
			cell, ok := res.Cells[rule]
			if !ok {
				add("%s × %s：格子留空", res.Name, rule)
				continue
			}
			switch cell.Status {
			case StatusConforms:
				if cell.Exception != "" {
					add("%s × %s：符合的格子不得帶例外", res.Name, rule)
				}
			case StatusException:
				spec, ok := specs[cell.Exception]
				if !ok {
					add("%s × %s：例外 %q 不在封閉列舉內", res.Name, rule, cell.Exception)
					break
				}
				if spec.Rule != rule {
					add("%s × %s：例外 %q 屬於規則 %s", res.Name, rule, cell.Exception, spec.Rule)
				}
				if spec.InitialOnly && !initial(res.Name) {
					add("%s × %s：初始名單以外的列不得引用僅限初始名單的例外 %q", res.Name, rule, cell.Exception)
				}
				if strings.TrimSpace(cell.Note) == "" {
					add("%s × %s：例外要附說明", res.Name, rule)
				}
			case StatusNotApplicable:
				if cell.Exception != "" || strings.TrimSpace(cell.Note) == "" {
					add("%s × %s：不適用要附理由且不帶例外", res.Name, rule)
				}
				if !naAllowed(res, rule) {
					add("%s × %s：規則依賴的操作或欄位存在，不得填不適用", res.Name, rule)
				}
			case StatusPending:
				if cell.Exception != "" || strings.TrimSpace(cell.Note) == "" {
					add("%s × %s：待查要附理由且不帶例外", res.Name, rule)
				}
				if !initial(res.Name) {
					add("%s × %s：初始名單以外的列不得使用待查", res.Name, rule)
				}
			default:
				add("%s × %s：狀態 %q 不在列舉內", res.Name, rule, cell.Status)
			}
		}
		probs = append(probs, checkRowShape(res)...)
	}
	return probs
}

// checkRowShape 一列的形狀與格子互相一致：沒有單筆讀取就要登錄例外、沒有查找參數就要登錄例外、
// 有查找參數時為符合或登錄「查找不能唯一定位」、共同欄位或列表獨有欄位只伴隨「詳情投影不同」且二擇一、
// 沒有秘密欄位或不分頁時對應規則必為不適用。
func checkRowShape(res Resource) []string {
	var probs []string
	add := func(format string, a ...any) { probs = append(probs, fmt.Sprintf(format, a...)) }
	cell := func(r Rule) Cell { return res.Cells[r] }
	if len(res.Read) == 0 && !(cell(RuleSingleRead).Status == StatusException && cell(RuleSingleRead).Exception == ExcNoSingleRead) {
		add("%s：沒有單筆讀取路由，必須登錄例外 %s", res.Name, ExcNoSingleRead)
	}
	if len(res.Read) > 0 && cell(RuleSingleRead).Status != StatusConforms {
		add("%s：有單筆讀取路由，單筆讀取規則應為符合", res.Name)
	}
	if len(res.List) > 0 && len(res.Lookup.Params) == 0 &&
		!(cell(RuleExactLookup).Status == StatusException && cell(RuleExactLookup).Exception == ExcNoExactLookup) {
		add("%s：沒有精確查找參數，必須登錄例外 %s", res.Name, ExcNoExactLookup)
	}
	notUnique := cell(RuleExactLookup).Status == StatusException && cell(RuleExactLookup).Exception == ExcLookupNotUnique
	if notUnique && len(res.Lookup.Params) == 0 {
		add("%s：登錄 %s 時必須列出查找參數", res.Name, ExcLookupNotUnique)
	}
	if len(res.Lookup.Params) > 0 {
		if cell(RuleExactLookup).Status != StatusConforms && !notUnique {
			add("%s：有精確查找參數，精確查找規則應為符合，或登錄例外 %s", res.Name, ExcLookupNotUnique)
		}
		if res.Lookup.Match != MatchExact && res.Lookup.Match != MatchTrimmed {
			add("%s：精確查找的比對規則 %q 不在列舉內", res.Name, res.Lookup.Match)
		}
	}
	differs := cell(RuleSingleMatchesList).Status == StatusException && cell(RuleSingleMatchesList).Exception == ExcDetailProjectionDiffers
	listed := 0
	for _, fields := range [][]string{res.CommonFields, res.ListOnlyFields} {
		if len(fields) > 0 {
			listed++
		}
	}
	if differs != (listed > 0) {
		add("%s：登錄「詳情投影不同」時必須列出共同欄位或列表獨有欄位，反之不得列", res.Name)
	}
	if listed > 1 {
		add("%s：共同欄位與列表獨有欄位只能二擇一", res.Name)
	}
	if len(res.Secrets) == 0 {
		for _, r := range []Rule{RuleSecretWriteOnly, RuleSecretClearPath} {
			if cell(r).Status != StatusNotApplicable {
				add("%s × %s：沒有秘密欄位時應為不適用", res.Name, r)
			}
		}
	}
	if !res.Paged && cell(RuleListPaging).Status != StatusNotApplicable {
		add("%s：列表不分頁時分頁規則應為不適用", res.Name)
	}
	if strings.TrimSpace(res.IdentityScope) == "" || strings.TrimSpace(res.Title) == "" {
		add("%s：識別範圍與名稱必填", res.Name)
	}
	if len(res.List)+len(res.Read) == 0 {
		add("%s：沒有任何讀取路由", res.Name)
	}
	return probs
}

func TestRegistryCellsComplete(t *testing.T) {
	resources := Resources()
	if len(resources) < len(frozenInitialNamesCopy) {
		t.Fatalf("登錄表只有 %d 列", len(resources))
	}
	for _, p := range checkCells(resources, ExceptionSpecs(), IsInitial) {
		t.Error(p)
	}
	// 例外列舉本身：每個值都有對應的規則與說明
	known := map[Rule]bool{}
	for _, r := range Rules() {
		known[r] = true
	}
	for e, spec := range ExceptionSpecs() {
		if !known[spec.Rule] || strings.TrimSpace(spec.Description) == "" {
			t.Errorf("例外 %q 的規則或說明不完整", e)
		}
	}
	n := 0
	for _, res := range resources {
		n += len(res.Cells)
	}
	t.Logf("登錄表 %d 列 × %d 條規則，格子 %d 個", len(resources), len(Rules()), n)
}

// checkInitialOnlyFrozen 「僅限初始名單」的例外集合與凍結副本相同。
func checkInitialOnlyFrozen(specs map[Exception]ExceptionSpec, frozen []Exception) []string {
	var probs []string
	want := map[Exception]bool{}
	for _, e := range frozen {
		want[e] = true
	}
	for e, spec := range specs {
		switch {
		case spec.InitialOnly && !want[e]:
			probs = append(probs, fmt.Sprintf("例外 %q 僅限初始名單，但不在凍結副本內（新增時兩處同步）", e))
		case !spec.InitialOnly && want[e]:
			probs = append(probs, fmt.Sprintf("例外 %q 在凍結副本內卻改成不限初始名單（新資源將可引用它）", e))
		}
	}
	for e := range want {
		if _, ok := specs[e]; !ok {
			probs = append(probs, fmt.Sprintf("凍結副本的例外 %q 已不在列舉內", e))
		}
	}
	sort.Strings(probs)
	return probs
}

func TestInitialOnlyExceptionsFrozen(t *testing.T) {
	for _, p := range checkInitialOnlyFrozen(ExceptionSpecs(), frozenInitialOnlyCopy) {
		t.Error(p)
	}
}

func TestInitialNamesFrozen(t *testing.T) {
	got := InitialNames()
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(frozenInitialNamesCopy, ",") {
		t.Errorf("初始名單已改變（初始名單凍結，新資源列在 laterResources）：\n  現在 %v\n  凍結 %v", got, frozenInitialNamesCopy)
	}
	var initialRows []string
	for _, res := range initialResources {
		initialRows = append(initialRows, res.Name)
	}
	sort.Strings(initialRows)
	if strings.Join(initialRows, ",") != strings.Join(frozenInitialNamesCopy, ",") {
		t.Errorf("initialResources 的列與初始名單不一致：%v", initialRows)
	}
	for _, res := range laterResources {
		if IsInitial(res.Name) {
			t.Errorf("%s 在初始名單內，不得列在 laterResources", res.Name)
		}
	}
}

// checkRegistryRoutes 登錄表引用的路由：存在、開放且已分類、性質與操作相符，且每條路由只屬於一個資源的一個操作。
func checkRegistryRoutes(resources []Resource, routes map[string]bool,
	classOf func(string) (middleware.APITokenRouteClass, bool), lookup func(method, path string) middleware.APITokenRouteVerdict) []string {
	var probs []string
	add := func(format string, a ...any) { probs = append(probs, fmt.Sprintf(format, a...)) }
	owner := map[string]string{}
	for _, res := range resources {
		for op, keys := range res.Routes() {
			for _, k := range keys {
				where := res.Name + " " + string(op)
				if prev, dup := owner[k]; dup {
					add("%s：同時屬於 %s 與 %s", k, prev, where)
				}
				owner[k] = where
				if !routes[k] {
					add("%s（%s）：路由清冊沒有這條路由", k, where)
					continue
				}
				class, ok := classOf(k)
				if !ok {
					add("%s（%s）：不在 API token 路由登錄內", k, where)
					continue
				}
				method, path, _ := strings.Cut(k, " ")
				v := lookup(method, path)
				if class.Access != middleware.RouteAccessOpen || !class.Classified() || !v.Open {
					add("%s（%s）：在 API token 路由登錄內不是開放且已分類", k, where)
					continue
				}
				wantRead := op == OpList || op == OpRead
				if wantRead != (v.Nature == middleware.RouteNatureRead) {
					add("%s（%s）：路由性質為 %s，與操作不符", k, where, v.Nature)
				}
				if wantRead && method != http.MethodGet {
					add("%s（%s）：讀取操作的方法必須是 GET", k, where)
				}
			}
		}
	}
	return probs
}

func TestRegistryRoutesOpenAndClassified(t *testing.T) {
	routes := registeredRoutes(t)
	probs := checkRegistryRoutes(Resources(), routes, middleware.APITokenRouteClassOf, middleware.LookupAPITokenRoute)
	for _, p := range probs {
		t.Error(p)
	}
	t.Logf("登錄表引用路由 %d 條", len(ManagedRouteOwners()))
}

// openRoutes API token 路由登錄內登錄為開放的路由（原值，不經執行期判定）。
func openRoutes() map[string]bool {
	out := map[string]bool{}
	for _, k := range middleware.APITokenRouteRegistryKeys() {
		if c, ok := middleware.APITokenRouteClassOf(k); ok && c.Access == middleware.RouteAccessOpen {
			out[k] = true
		}
	}
	return out
}

// checkAttribution 路由歸屬與開放路由雙向一致：每條開放路由恰有一個歸屬（納管資源或歸屬表其中之一），
// 歸屬表與納管資源不含未開放的路由；家族類別的家族名合乎規定；唯讀家族的路由性質都是讀；凍結名單沒有過時的家族。
func checkAttribution(open map[string]bool, managed map[string][]string, attrs map[string]Attribution,
	frozen map[string]string, natureOf func(string) middleware.APITokenRouteNature) []string {
	var probs []string
	add := func(format string, a ...any) { probs = append(probs, fmt.Sprintf(format, a...)) }
	for k := range open {
		_, inManaged := managed[k]
		_, inAttr := attrs[k]
		switch {
		case !inManaged && !inAttr:
			add("%s：對 API token 開放但沒有歸屬（要列入納管資源登錄表，或在歸屬表標明類別與家族）", k)
		case inManaged && inAttr:
			add("%s：同時屬於納管資源 %v 與歸屬表 %s", k, managed[k], attrs[k].Category)
		}
	}
	for k := range managed {
		if !open[k] {
			add("%s：納管資源引用了未開放的路由", k)
		}
	}
	used := map[string]bool{}
	for k, a := range attrs {
		if !open[k] {
			add("%s：歸屬表登錄了未開放或不存在的路由", k)
		}
		switch a.Category {
		case CategoryNonResource:
			if a.Family != "" {
				add("%s：非資源類別不帶家族", k)
			}
			// 可寫的路由不能以「非資源」避開納管規則：會改變保存資料的請求一定屬於某個資源家族
			if natureOf(k) != middleware.RouteNatureRead {
				add("%s：歸在非資源類別，但路由性質不是讀（可寫的路由要歸到納管資源或尚未納管的家族）", k)
			}
		case CategoryReadOnlyFamily:
			if a.Family == "" {
				add("%s：唯讀家族要標明家族", k)
			}
			if natureOf(k) != middleware.RouteNatureRead {
				add("%s：歸在唯讀家族 %s，但路由性質不是讀", k, a.Family)
			}
		case CategoryUnmanagedFamily:
			if _, ok := frozen[a.Family]; !ok {
				add("%s：家族 %q 不在尚未納管家族的凍結名單內（新增家族要改凍結名單）", k, a.Family)
			}
			used[a.Family] = true
		case CategoryManaged:
			add("%s：納管資源的路由由登錄表導出，不在歸屬表手填", k)
		default:
			add("%s：類別 %q 不在列舉內", k, a.Category)
		}
	}
	for f := range frozen {
		if !used[f] {
			add("凍結名單的家族 %q 已沒有任何路由（家族納管後要從名單移除）", f)
		}
	}
	return probs
}

func natureOfRegistry(k string) middleware.APITokenRouteNature {
	method, path, _ := strings.Cut(k, " ")
	return middleware.LookupAPITokenRoute(method, path).Nature
}

func TestRouteAttributionMatchesTokenRegistry(t *testing.T) {
	open := openRoutes()
	if len(open) < 100 {
		t.Fatalf("開放路由只有 %d 條，登錄讀取已退化", len(open))
	}
	probs := checkAttribution(open, ManagedRouteOwners(), Attributions(), FrozenUnmanagedFamilies(), natureOfRegistry)
	for _, p := range probs {
		t.Error(p)
	}
	counts := map[Category]int{CategoryManaged: len(ManagedRouteOwners())}
	for _, a := range Attributions() {
		counts[a.Category]++
	}
	t.Logf("開放路由 %d 條：納管資源 %d、非資源 %d、唯讀家族 %d、尚未納管家族 %d", len(open),
		counts[CategoryManaged], counts[CategoryNonResource], counts[CategoryReadOnlyFamily], counts[CategoryUnmanagedFamily])
}

// triple 一個已知例外的「資源、規則、例外」三元組。
type triple struct {
	Resource  string    `json:"resource"`
	Rule      Rule      `json:"rule"`
	Exception Exception `json:"exception"`
}

type registryCopy struct {
	Rules             []Rule                      `json:"rules"`
	Exceptions        map[Exception]ExceptionSpec `json:"exceptions"`
	InitialNames      []string                    `json:"initial_names"`
	Resources         []Resource                  `json:"resources"`
	ExceptionTriples  []triple                    `json:"exception_triples"`
	PendingCells      []triple                    `json:"pending_cells"`
	UnmanagedFamilies map[string]string           `json:"unmanaged_families"`
	RouteAttribution  map[string]Attribution      `json:"route_attribution"`
}

// renderRegistryCopy 兩張表的機器可讀副本：歸屬含由登錄表導出的納管路由（家族欄為「資源 操作」）。
func renderRegistryCopy() ([]byte, error) {
	doc := registryCopy{
		Rules: Rules(), Exceptions: ExceptionSpecs(), InitialNames: InitialNames(), Resources: Resources(),
		UnmanagedFamilies: FrozenUnmanagedFamilies(), RouteAttribution: Attributions(),
	}
	for k, owners := range ManagedRouteOwners() {
		doc.RouteAttribution[k] = Attribution{Category: CategoryManaged, Family: strings.Join(owners, "; ")}
	}
	for _, res := range doc.Resources {
		for _, rule := range Rules() {
			c := res.Cells[rule]
			switch c.Status {
			case StatusException:
				doc.ExceptionTriples = append(doc.ExceptionTriples, triple{res.Name, rule, c.Exception})
			case StatusPending:
				doc.PendingCells = append(doc.PendingCells, triple{Resource: res.Name, Rule: rule})
			}
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestRegistryJSONCopyUpToDate(t *testing.T) {
	got, err := renderRegistryCopy()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "managed-api-registry.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("寫入 %s：%v", path, err)
		}
		t.Logf("已重生 %s（%d 位元組），diff 要逐條審視", path, len(got))
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取 %s：%v（以 -update 產生）", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s 與登錄表不一致：改動登錄表或歸屬表後要以 -update 重生副本並逐條審視 diff", path)
	}
	var doc registryCopy
	if err := json.Unmarshal(want, &doc); err != nil {
		t.Fatalf("解析副本：%v", err)
	}
	if len(doc.ExceptionTriples) == 0 || len(doc.Resources) == 0 || len(doc.RouteAttribution) == 0 {
		t.Errorf("副本內容退化：資源 %d、例外 %d、歸屬 %d", len(doc.Resources), len(doc.ExceptionTriples), len(doc.RouteAttribution))
	}
}
