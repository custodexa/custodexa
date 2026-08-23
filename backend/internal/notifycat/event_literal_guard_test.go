package notifycat

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/packages"
)

// Event 字面量守衛。
//
// **以 go/types 判定，不以識別字名稱猜測。** Go 的未定型字串常數可隱式轉換為
// 具名型別——`NotifyEvent("access_reqeust.created")` 不產生任何轉換節點，
// 「掃顯式轉換 notifycat.Event(...)」的守衛擋不住最自然（也最容易打錯字）的寫法。
//
// 判準（v2，比 v1 的「字串字面量」嚴格）：凡「型別為 notifycat.Event **且為常數**
// 的運算式」，除非它就是 notifycat 的匯出常數識別字（Ident／SelectorExpr 解析到
// 本套件的 exported *types.Const），否則一律違規。
//
// 為什麼從「字面量」擴到「常數運算式」：v1 只看 *ast.BasicLit，兩條常數摺疊路徑
// 因此可繞——
//
//	NotifyEvent("audit" + "_failure")            // BinaryExpr，非 BasicLit
//	const e = "audit_failure"; NotifyEvent(e)    // Ident，非 BasicLit
//
// 兩者都是編譯期常數、都能寫錯字、都繞過「必用匯出常數」的意圖。改看
// types.Info.Types[expr].Value（untyped／typed 常數皆有值）後兩條路一併堵死。
// 這條規則同時涵蓋參數位置、變數宣告/賦值右值、struct 欄位、map 鍵值、
// return 值與顯式轉換——它們的共同末端都是一個被賦予 Event 型別的常數運算式。
//
// 非常數的 Event 運算式（如 Event 型別的變數）不在管轄：無法靜態判定其值，
// 由 registry 查表在執行期擋下（ErrUnregisteredEvent）。
//
// 防假綠：
//   - 載入失敗、型別資訊缺失、掃描套件數過少一律 Fatal（不靜默跳過）。
//   - **正向控制**：notifycat 套件自身的事件常數就是 Event 型別常數運算式；
//     掃描它必須抓到 ≥ registry 數量的違規。抓不到＝偵測器已失效，測試紅。
//   - **繞法樣本**：TestEventGuardCatchesConstFolding 以合成套件鎖住上述兩條
//     繞過路徑（把判準改回 v1 即紅）。

const notifycatPkgPath = "github.com/custodexa/backend/internal/notifycat"

// minScannedPackages 掃描涵蓋率下限。backend 現有 22 個 package（go list ./...）；
// 顯著低於此值代表載入 pattern 失效，守衛實際上什麼都沒看。
const minScannedPackages = 20

// mustScanPackages 必須進入掃描的套件——通知呼叫端所在與可能新增呼叫端之處。
// 數量門檻擋不住「載入器只回傳無關套件」，具名清單才擋得住。
var mustScanPackages = []string{
	// **七模組逐一具名**：掃描本身走 `./...` 故一直
	// 涵蓋得到，但具名清單是「必須在場」的下界——不列的話，該包被排除在載入結果
	// 外時不會有任何東西轉紅。**七個模組（全數搬包完成）逐條列出**。
	"github.com/custodexa/backend/internal/modules/keyvault",
	"github.com/custodexa/backend/internal/modules/policy",
	// authz 搬包後 `access_request_service.go` 的通知事件字面量住在此包
	"github.com/custodexa/backend/internal/modules/authz",
	"github.com/custodexa/backend/internal/modules/audit",
	"github.com/custodexa/backend/internal/modules/asset",
	// identity 搬包後 OIDC／LDAP／使用者生命週期的通知呼叫端住在此包
	"github.com/custodexa/backend/internal/modules/identity",
	// session 搬包後，會話／錄影／SFTP 的通知呼叫端住在此包
	"github.com/custodexa/backend/internal/modules/session",
	"github.com/custodexa/backend/internal/api",
	"github.com/custodexa/backend/internal/scheduler",
	"github.com/custodexa/backend/internal/proxy",
	"github.com/custodexa/backend/internal/sshproxy",
	"github.com/custodexa/backend/cmd/server",
}

const guardLoadMode = packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
	packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps

var (
	loadOnce sync.Once
	loadPkgs []*packages.Package
	loadErr  error
)

// notifycatModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const notifycatModulePath = "github.com/custodexa/backend"

// backendRoot 定位 backend module 根（packages.Load 的 Dir）。
//
// **不用固定層數 `..`**：`Dir(caller)/../..`
// 與「本 package 住在樹的第幾層」綁死，package 下移一層即把 Dir 指向 internal/，
// 而 packages.Load 在非 module 根目錄下的 "./..." 只會載到該子樹——守衛的
// 「全 backend」宣稱靜默縮成一小塊。改以「向上找 go.mod 並核對 module 行」為錨點。
func backendRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(file)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			want := "module " + notifycatModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			panic("在 " + dir + "/go.mod 的 module 行不是 \"" + want +
				"\"：掃描根定位錨點失效，守衛可能正在掃錯的樹")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("自 " + filepath.Dir(file) + " 向上找不到 go.mod（module " +
				notifycatModulePath + "）：掃描根無從定位")
		}
		dir = parent
	}
}

// loadBackend 型別檢查整個 backend module（一次載入，多測試共用）。
func loadBackend(t *testing.T) []*packages.Package {
	t.Helper()
	loadOnce.Do(func() {
		loadPkgs, loadErr = packages.Load(&packages.Config{
			Mode: guardLoadMode, Dir: backendRoot(), Tests: false,
		}, "./...")
	})
	if loadErr != nil {
		t.Fatalf("載入 backend 失敗: %v", loadErr)
	}
	if len(loadPkgs) < minScannedPackages {
		t.Fatalf("只載入 %d 個 package（下限 %d）——守衛涵蓋率失效，視同未掃描",
			len(loadPkgs), minScannedPackages)
	}
	var errs []string
	for _, p := range loadPkgs {
		for _, e := range p.Errors {
			errs = append(errs, p.PkgPath+": "+e.Error())
		}
	}
	if len(errs) > 0 {
		t.Fatalf("型別檢查有錯，守衛無法信任其結果:\n  %s", strings.Join(errs, "\n  "))
	}
	return loadPkgs
}

// eventTypeOf 自載入結果取得 notifycat.Event 的具名型別。
func eventTypeOf(t *testing.T, pkgs []*packages.Package) types.Type {
	t.Helper()
	var found types.Type
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.PkgPath != notifycatPkgPath || p.Types == nil || found != nil {
			return
		}
		if tn, ok := p.Types.Scope().Lookup("Event").(*types.TypeName); ok {
			found = tn.Type()
		}
	})
	if found == nil {
		t.Fatal("找不到 notifycat.Event 型別——守衛的唯一判準缺失（防假綠）")
	}
	return found
}

type literalHit struct {
	file string
	line int
	text string
}

// isExportedEventConstRef 回報 e 是否為「notifycat 匯出常數」的引用
// （唯一被允許的 Event 常數寫法）。
func isExportedEventConstRef(e ast.Expr, info *types.Info, constPkgPath string) bool {
	var id *ast.Ident
	switch v := e.(type) {
	case *ast.Ident:
		id = v
	case *ast.SelectorExpr:
		id = v.Sel
	default:
		return false // BasicLit / BinaryExpr / CallExpr(轉換) / ParenExpr …
	}
	c, ok := info.Uses[id].(*types.Const)
	if !ok || c.Pkg() == nil {
		return false
	}
	return c.Pkg().Path() == constPkgPath && c.Exported()
}

// scanEventConstExprs 回傳「型別為 eventType 的常數運算式，且非 constPkgPath
// 匯出常數識別字」的所有位置。
//
// 命中後即停止下鑽（回 false）：`"a" + "b"` 的兩個運算元在 go/types 的常數
// 定型傳播後也可能帶 Event 型別，只報最外層一次即可，避免同一處重複計數。
func scanEventConstExprs(fset *token.FileSet, files []*ast.File, info *types.Info,
	eventType types.Type, constPkgPath string) []literalHit {
	if info == nil {
		return nil
	}
	var hits []literalHit
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			expr, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			tv, ok := info.Types[expr]
			if !ok || tv.Type == nil || !types.Identical(tv.Type, eventType) {
				return true
			}
			if tv.Value == nil {
				return true // 非常數（如 Event 型別變數）：不在靜態管轄內
			}
			if isExportedEventConstRef(expr, info, constPkgPath) {
				return false // 合法：notifycat 匯出常數
			}
			pos := fset.Position(expr.Pos())
			hits = append(hits, literalHit{file: pos.Filename, line: pos.Line, text: types.ExprString(expr)})
			return false
		})
	}
	return hits
}

// scanEventLiterals 是 scanEventConstExprs 對 *packages.Package 的包裝。
func scanEventLiterals(pkg *packages.Package, eventType types.Type) []literalHit {
	if pkg.TypesInfo == nil {
		return nil
	}
	return scanEventConstExprs(pkg.Fset, pkg.Syntax, pkg.TypesInfo, eventType, notifycatPkgPath)
}

// TestNoEventStringLiterals 全 backend（notifycat 自身除外）不得出現 Event 字面量。
func TestNoEventStringLiterals(t *testing.T) {
	pkgs := loadBackend(t)
	eventType := eventTypeOf(t, pkgs)

	var violations []string
	seen := map[string]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.PkgPath == notifycatPkgPath || len(p.Syntax) == 0 {
			return
		}
		if !strings.HasPrefix(p.PkgPath, "github.com/custodexa/backend/") {
			return // 第三方相依不在管轄範圍
		}
		seen[p.PkgPath] = true
		for _, h := range scanEventLiterals(p, eventType) {
			violations = append(violations,
				h.file+":"+strconv.Itoa(h.line)+" "+h.text)
		}
	})

	if len(seen) < minScannedPackages {
		t.Fatalf("只掃到 %d 個自家 package（下限 %d）——守衛涵蓋率失效", len(seen), minScannedPackages)
	}
	for _, must := range mustScanPackages {
		if !seen[must] {
			t.Fatalf("%s 未進入掃描——守衛涵蓋率失效（防假綠）", must)
		}
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("偵測到 %d 處 notifycat.Event 常數運算式（字面量／串接／本地常數皆算；必須改用 notifycat 匯出常數）:\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// pkgImporter 以已載入的 *types.Package 餵給 go/types，讓合成套件能引用真正的
// notifycat 型別與常數（型別同一性是本守衛的唯一判準，不能用複製品）。
type pkgImporter map[string]*types.Package

func (m pkgImporter) Import(path string) (*types.Package, error) {
	if p, ok := m[path]; ok && p != nil {
		return p, nil
	}
	return nil, fmt.Errorf("合成套件不該引用 %q", path)
}

// TestEventGuardCatchesConstFolding 鎖住兩條常數摺疊繞法。
//
// 紅→綠敏感度：把 scanEventConstExprs 的判準改回 v1（只認 *ast.BasicLit）後，
// 串接與本地常數中轉這兩筆會消失，數量斷言即紅。
//
// 樣本用真的 notifycat 型別（Importer 餵已載入的 *types.Package），不另造替身：
// types.Identical 是判準，替身型別會讓測試量到別的東西。
func TestEventGuardCatchesConstFolding(t *testing.T) {
	pkgs := loadBackend(t)
	eventType := eventTypeOf(t, pkgs)

	imports := pkgImporter{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Types != nil {
			imports[p.PkgPath] = p.Types
		}
	})
	if imports[notifycatPkgPath] == nil {
		t.Fatal("找不到已載入的 notifycat *types.Package（樣本無法型別檢查）")
	}

	src := `package sample

import "` + notifycatPkgPath + `"

const localEvent = "audit_failure"

func sink(e notifycat.Event) {}

func f(runtimeEvent notifycat.Event) {
	sink(notifycat.EventAuditFailure)     // OK：匯出常數
	sink(runtimeEvent)                    // 不管轄：非常數
	sink("audit_failure")                 // 紅 1：直接字面量（v1 也抓得到）
	sink("audit" + "_failure")            // 紅 2：串接繞過（v1 抓不到）
	sink(localEvent)                      // 紅 3：本地常數中轉（v1 抓不到）
	_ = notifycat.Event("a" + "b")        // 紅 4：顯式轉換 + 串接
	var v notifycat.Event = localEvent    // 紅 5：宣告右值
	_ = v
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sample.go", src, 0)
	if err != nil {
		t.Fatalf("parse 樣本: %v", err)
	}
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Defs:  map[*ast.Ident]types.Object{},
		Uses:  map[*ast.Ident]types.Object{},
	}
	conf := types.Config{Importer: imports}
	if _, err := conf.Check("sample", fset, []*ast.File{f}, info); err != nil {
		t.Fatalf("型別檢查樣本失敗（樣本本身必須可編譯）: %v", err)
	}

	hits := scanEventConstExprs(fset, []*ast.File{f}, info, eventType, notifycatPkgPath)
	var texts []string
	for _, h := range hits {
		texts = append(texts, strconv.Itoa(h.line)+" "+h.text)
	}
	if len(hits) != 5 {
		t.Fatalf("偵測數 = %d, want 5（字面量／串接／本地常數／轉換+串接／宣告右值）:\n  %s",
			len(hits), strings.Join(texts, "\n  "))
	}

	// 合法寫法不得被誤報（守衛若對匯出常數也紅，全 backend 立刻不可用）。
	for _, h := range hits {
		if strings.Contains(h.text, "EventAuditFailure") {
			t.Errorf("誤報 notifycat 匯出常數: %s", h.text)
		}
		if h.text == "runtimeEvent" {
			t.Errorf("誤報非常數變數: %s", h.text)
		}
	}
}

// TestEventLiteralGuardSensitivity 正向控制：notifycat 自身的事件常數即
// Event 型別字面量，偵測器必須抓得到。抓不到代表 TypesInfo 判準失效，
// 此時 TestNoEventStringLiterals 的「零違規」是假綠。
func TestEventLiteralGuardSensitivity(t *testing.T) {
	pkgs := loadBackend(t)
	eventType := eventTypeOf(t, pkgs)

	var self *packages.Package
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.PkgPath == notifycatPkgPath && len(p.Syntax) > 0 {
			self = p
		}
	})
	if self == nil {
		t.Fatal("找不到 notifycat 套件本體（正向控制無法進行）")
	}
	hits := scanEventLiterals(self, eventType)
	if len(hits) < len(registry) {
		t.Fatalf("正向控制失敗：notifycat 自身應有 >= %d 處 Event 字面量（事件常數），實得 %d 處——偵測器已失效",
			len(registry), len(hits))
	}
}

// TestMechanismEnumMatchesModel mechanism enum 與 model 的機制常數集合相等。
//
// 以 go/types 列舉 model 套件的 Mechanism* 常數，故新增機制而未同步 notifycat
// 會被抓到（單靠「引用 model 常數」只能擋改名，擋不住新增）。
func TestMechanismEnumMatchesModel(t *testing.T) {
	pkgs := loadBackend(t)

	var modelPkg *packages.Package
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.PkgPath == "github.com/custodexa/backend/internal/model" && p.Types != nil {
			modelPkg = p
		}
	})
	if modelPkg == nil {
		t.Fatal("找不到 internal/model 套件（比對基準缺失）")
	}

	want := map[string]bool{}
	scope := modelPkg.Types.Scope()
	for _, name := range scope.Names() {
		if !strings.HasPrefix(name, "Mechanism") {
			continue
		}
		c, ok := scope.Lookup(name).(*types.Const)
		if !ok {
			continue
		}
		v, err := strconv.Unquote(c.Val().String())
		if err != nil {
			t.Fatalf("model.%s 常數值非字串: %s", name, c.Val().String())
		}
		want[v] = true
	}
	if len(want) == 0 {
		t.Fatal("model 套件找不到任何 Mechanism* 常數——比對基準失效（防假綠）")
	}

	got := map[string]bool{}
	for _, m := range mechanismEnum {
		got[m] = true
	}
	if !sameSet(want, got) {
		t.Fatalf("mechanism enum 與 model 常數不一致:\n  model: %v\n  notifycat: %v",
			sortedKeys(want), sortedKeys(got))
	}
}
