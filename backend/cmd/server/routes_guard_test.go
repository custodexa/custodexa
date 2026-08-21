package main

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// 路由結構守衛（route-registration spec）。
//
// 禁止 cmd/server 於 registerRoutes 以外的位置變更路由。缺此守衛時，日後若有人
// 在 main() 另加 r.GET(...)，production 會多出一條路由而任何以 registerRoutes
// 為觀察點的測試都看不見——路由完備性守衛將靜默假綠。
//
// **本守衛以 go/types 解析型別，不以識別字名稱猜測。**
// 早期版本靠變數名追蹤 router，該做法有兩個致命缺陷：
//   - 名稱集合是整份檔案共用的，無視 lexical scope。`registerRoutes(r *gin.Engine)`
//     一出現，全檔所有叫 `r` 的東西都被當成 router，`r := newCache(); r.Use()` 必誤報。
//   - 只認得 ident receiver，`holder.router.GET()`、`routers[0].GET()`、
//     `newEngine().GET()` 全部漏網。
//
// 五道防線：
//  1. 直接取用：registerRoutes 以外，receiver 型別可用於註冊路由者不得取用路由變更方法
//  1b. 逸出：registerRoutes 內的路由方法只能同步直接呼叫，不得取 method value
//      存起來，也不得以 go 陳述延後到函式返回之後
//  1c. 狀態：任何位置都不得直接讀寫 gin router 的中間件鏈欄位（Handlers）
//  2. 間接繞過：registerRoutes 以外的函式、method 與**匿名函式**不得接收 gin router 型別參數
//  3. build constraint：cmd/server 的 production 原始檔不得帶任何 build constraint
//  4. 型別檢查涵蓋率：每一個 production 原始檔都必須確實進入型別檢查
//
// 方法清單以 pinned gin 版本的 IRoutes method set 為唯一事實來源
// （gin@v1.9.1 routergroup.go），另加 Group 與 handler 的 RegisterRoutes。

// routeMutators：gin IRoutes 的完整 method set ＋ Group ＋ handler 註冊入口。
// 漏列任一項即等於在守衛上開洞——StaticFileFS 曾因不常用而被遺漏。
var routeMutators = map[string]bool{
	"Use": true, "Handle": true, "Any": true, "Match": true,
	"GET": true, "POST": true, "DELETE": true, "PATCH": true,
	"PUT": true, "OPTIONS": true, "HEAD": true,
	"StaticFile": true, "StaticFileFS": true, "Static": true, "StaticFS": true,
	"Group": true, "RegisterRoutes": true,
}

const (
	registrarFunc = "registerRoutes"
	ginImportPath = "github.com/gin-gonic/gin"
	litSuffix     = "$lit" // 匿名函式的標籤後綴
)

// 違規種類。self-check 逐案例斷言種類，避免「防線 2 命中掩蓋防線 1 失效」的假綠。
const (
	kindDirect    = "direct"    // 取用路由變更方法
	kindParam     = "param"     // 接收 gin router 型別參數
	kindTagged    = "tagged"    // 帶 build constraint
	kindUnchecked = "unchecked" // 未進入型別檢查
	kindEscape    = "escape"    // 於 registrar 內取 method value 或非同步呼叫（可逸出）
	kindState     = "state"     // 直接讀寫 gin router 的中間件鏈欄位
)

// routerStateFields：gin router 上「等同於註冊操作」的可寫欄位。
// `r.Handlers = append(r.Handlers, mw)` 的效果等同（甚至可覆寫）`r.Use(mw)`，
// 但完全不經過任何方法 selector——只掃方法者對此無感。
var routerStateFields = map[string]bool{
	"Handlers": true, // gin.RouterGroup.Handlers（Engine 由內嵌取得）
}

type violation struct {
	file string
	line int
	fn   string
	kind string
	what string
}

const loadMode = packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
	packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps

// loadGoPackage 型別檢查指定目錄的 package。
//
// 載入失敗或有編譯錯誤時 Fatal 而非略過：型別資訊缺失會讓所有防線同時失能，
// 靜默通過比明確失敗危險得多。
func loadGoPackage(t *testing.T, dir string) *packages.Package {
	t.Helper()
	pkgs, err := packages.Load(&packages.Config{Mode: loadMode, Dir: dir, Tests: false}, ".")
	if err != nil {
		t.Fatalf("載入 %s 失敗: %v", dir, err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("預期 %s 只有一個 package，實得 %d 個", dir, len(pkgs))
	}
	pkg := pkgs[0]
	if len(pkg.Errors) > 0 {
		var b strings.Builder
		for _, e := range pkg.Errors {
			b.WriteString("\n  " + e.Error())
		}
		t.Fatalf("%s 型別檢查有錯，守衛無法信任其結果：%s", dir, b.String())
	}
	if len(pkg.Syntax) == 0 {
		t.Fatalf("%s 未取得任何語法樹——載入器可能失效（防假綠）", dir)
	}
	if pkg.TypesInfo == nil {
		t.Fatalf("%s 未取得型別資訊——守衛的防線全數失能（防假綠）", dir)
	}
	return pkg
}

// ginFacts：自 gin package 取得的判定基準。
type ginFacts struct {
	iroutes *types.Interface // gin.IRoutes
	routers []types.Type     // *gin.Engine、*gin.RouterGroup（真正能註冊路由的具體型別）
}

func (g ginFacts) ok() bool { return g.iroutes != nil && len(g.routers) > 0 }

// ginFactsOf 取得判定基準；package 未匯入 gin 時回傳空值。
//
// 以「型別行為」而非「型別名稱」判定 router：如此 *gin.Engine、*gin.RouterGroup、
// gin.IRouter、型別別名、import alias、自訂包裝型別一律涵蓋。
func ginFactsOf(pkg *packages.Package) ginFacts {
	gp, ok := pkg.Imports[ginImportPath]
	if !ok || gp.Types == nil {
		return ginFacts{}
	}
	scope := gp.Types.Scope()
	var g ginFacts
	if tn, ok := scope.Lookup("IRoutes").(*types.TypeName); ok {
		g.iroutes, _ = tn.Type().Underlying().(*types.Interface)
	}
	for _, name := range []string{"Engine", "RouterGroup"} {
		if tn, ok := scope.Lookup(name).(*types.TypeName); ok {
			g.routers = append(g.routers, types.NewPointer(tn.Type()))
		}
	}
	return g
}

// canHoldGinRouter 判斷介面（或型別參數的 constraint）是否**能持有實際的 gin router**。
//
// 這是「實作完整 IRoutes」之外的必要判準。窄化介面可只宣告需要的那一個方法：
//
//	type getOnly interface{ GET(string, ...gin.HandlerFunc) gin.IRoutes }
//	func hidden(r getOnly) { r.GET("/hidden") }
//
// `*gin.Engine` 滿足 getOnly，故 `hidden(r)` 是可編譯的實際繞過，但 getOnly
// 不實作完整 IRoutes——只驗 Implements 者會整個漏掉。泛型形態
// （`func hidden[T getOnly](r T)`）同理，故型別參數改看其 constraint。
//
// 判準是「**真的 gin router 可賦值進去**」而非「簽章長得像 gin」。後者會誤報：
//
//	type fake struct{}
//	func (fake) GET(string, ...gin.HandlerFunc) gin.IRoutes { return nil }
//	func consume(f fake) {}   // 完全沒碰 router，卻因方法簽章相同而被判違規
//
// 具體型別即使方法簽章與 gin 完全相同，也無法接收 `*gin.Engine`，不構成繞過管道。
//
// 另須要求該介面至少宣告一個路由方法：否則 `any`／`interface{}` 這類空介面
// 也「能持有 router」，全專案的 `interface{}` 參數都會被誤報。
func canHoldGinRouter(typ types.Type, g ginFacts) bool {
	if typ == nil || len(g.routers) == 0 {
		return false
	}
	if tp, ok := typ.(*types.TypeParam); ok {
		if typ = tp.Constraint(); typ == nil {
			return false
		}
	}
	iface, ok := typ.Underlying().(*types.Interface)
	if !ok {
		return false // 具體型別無法承接 gin router，不是繞過管道
	}
	hasRouteMethod := false
	for i := 0; i < iface.NumMethods(); i++ {
		if routeMutators[iface.Method(i).Name()] {
			hasRouteMethod = true
			break
		}
	}
	if !hasRouteMethod {
		return false // 空介面／無路由方法者不算（否則 any 全數誤報）
	}
	for _, r := range g.routers {
		if types.Implements(r, iface) {
			return true
		}
	}
	return false
}

// isGinRouter 判斷型別是否可用於註冊路由。
func isGinRouter(typ types.Type, g ginFacts) bool {
	if typ == nil || !g.ok() {
		return false
	}
	if types.Implements(typ, g.iroutes) {
		return true
	}
	// gin.RouterGroup 這類以指標接收器實作介面者，值型別本身不 Implements；
	// 但函式收到可定址的 T 之後仍能以 &T 註冊，故一併判定。
	if _, isIface := typ.Underlying().(*types.Interface); !isIface {
		if types.Implements(types.NewPointer(typ), g.iroutes) {
			return true
		}
	}
	return canHoldGinRouter(typ, g)
}

// takesGinRouter 判斷函式簽章是否收受 gin router（用於偵測 handler 的交棒形態）。
func takesGinRouter(sig *types.Signature, g ginFacts) bool {
	if sig == nil {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if isGinRouter(sig.Params().At(i).Type(), g) {
			return true
		}
	}
	return false
}

// unparen 剝除運算式外層的括號。
func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// innermostFuncAt 回傳位置所屬的**最內層**函式節點（*ast.FuncDecl 或 *ast.FuncLit）。
//
// 必須取最內層而非最外層的 FuncDecl：registerRoutes 內的匿名函式若被視為
// registrar 本身，就能寫 `escaped = func() { r.GET("/late") }` 讓 closure 逸出後
// 在別處註冊——守衛全綠而路由憑空多出一條。
func innermostFuncAt(f *ast.File, pos token.Pos) ast.Node {
	var best ast.Node
	var bestLen token.Pos
	ast.Inspect(f, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch fn := n.(type) {
		case *ast.FuncDecl:
			body = fn.Body
		case *ast.FuncLit:
			body = fn.Body
		default:
			return true
		}
		if body == nil || pos < body.Pos() || pos > body.End() {
			return true
		}
		if l := body.End() - body.Pos(); best == nil || l < bestLen {
			best, bestLen = n, l
		}
		return true
	})
	return best
}

// enclosingDeclName 回傳位置所屬的具名函式（忽略匿名層）；不在任何函式內則回 "<file scope>"。
func enclosingDeclName(f *ast.File, pos token.Pos) string {
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		if fd.Body.Pos() <= pos && pos <= fd.Body.End() {
			return fd.Name.Name
		}
	}
	return "<file scope>"
}

// labelOf 產生違規歸屬標籤；匿名函式標為「所屬具名函式$lit」。
func labelOf(f *ast.File, node ast.Node) string {
	switch n := node.(type) {
	case *ast.FuncDecl:
		return n.Name.Name
	case *ast.FuncLit:
		return enclosingDeclName(f, n.Pos()) + litSuffix
	}
	return "<file scope>"
}

// findRegistrar 找出唯一的頂層 registerRoutes 宣告。
func findRegistrar(t *testing.T, pkg *packages.Package) *ast.FuncDecl {
	t.Helper()
	var found []*ast.FuncDecl
	for _, f := range pkg.Syntax {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Recv == nil && fd.Name.Name == registrarFunc {
				found = append(found, fd)
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("預期恰有一個頂層 %s 宣告，實得 %d 個——豁免對象不唯一時守衛無從判定",
			registrarFunc, len(found))
	}
	return found[0]
}

// scanPackage 掃描已型別檢查的 package，回傳違規清單（防線 1、2）。
func scanPackage(t *testing.T, pkg *packages.Package) []violation {
	t.Helper()
	fset := pkg.Fset
	info := pkg.TypesInfo
	g := ginFactsOf(pkg)
	registrar := findRegistrar(t, pkg)

	var out []violation
	for _, f := range pkg.Syntax {
		file := filepath.Base(fset.Position(f.Pos()).Filename)

		// 防線 1：registerRoutes 以外不得**取用**路由變更方法。
		//
		// 掃所有 SelectorExpr 而非僅 CallExpr.Fun——後者只看得到直接呼叫，
		// `get := r.GET; get("/x", h)` 這種先取 method value 再呼叫的形態會整個漏掉。
		//
		// 直接作為 CallExpr.Fun 的 selector（供 registrar 內的逸出判定）。
		// 剝除括號：`(r.GET)("/x")` 仍是同步直接呼叫，不應誤判為逸出。
		calledFun := map[*ast.SelectorExpr]bool{}
		asyncFun := map[*ast.SelectorExpr]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if sel, ok := unparen(node.Fun).(*ast.SelectorExpr); ok {
					calledFun[sel] = true
				}
			case *ast.GoStmt:
				// `go r.GET(...)` 的 selector 形式上是 CallExpr.Fun，但註冊時機
				// 落在 registerRoutes 返回之後——快照與測試都已看不到它。
				if node.Call != nil {
					if sel, ok := unparen(node.Call.Fun).(*ast.SelectorExpr); ok {
						asyncFun[sel] = true
					}
				}
			}
			return true
		})

		// 中間件鏈欄位：無論位於何處（含 registrar）皆不得直接讀寫，
		// 正當途徑只有 Use。逸出後再改（`hs := r.Handlers`）同樣攔下。
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !routerStateFields[sel.Sel.Name] {
				return true
			}
			if !isGinRouter(info.TypeOf(sel.X), g) {
				return true
			}
			out = append(out, violation{
				file: file, line: fset.Position(sel.Pos()).Line,
				fn: labelOf(f, innermostFuncAt(f, sel.Pos())), kind: kindState,
				what: "直接取用 gin router 的 ." + sel.Sel.Name +
					" 中間件鏈欄位（等同繞過 Use 註冊全域中間件）",
			})
			return true
		})

		// 命中條件二擇一：
		//   a. receiver 型別可用於註冊路由（實作 IRoutes，或為能持有 router 的窄化介面）
		//   b. 該 selector 的簽章收受 gin router（handler 的 RegisterRoutes 交棒形態；
		//      receiver 是 handler 而非 router，故必須看簽章）
		// 兩者皆以型別判定，不依名稱猜測，故非 gin 的同名方法不會誤報。
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !routeMutators[sel.Sel.Name] {
				return true
			}
			hit := isGinRouter(info.TypeOf(sel.X), g)
			if !hit {
				if s := info.Selections[sel]; s != nil {
					// 取 Selection.Type() 而非 Obj().Type()：前者直接表示此 selector
					// expression 的有效簽章，語義較貼合用途。（實測兩者對泛型實例化
					// 行為相同——Selections 回傳的已是實例化後的 Func。）
					sig, _ := s.Type().(*types.Signature)
					hit = takesGinRouter(sig, g)
				}
			}
			if !hit {
				return true
			}
			site := innermostFuncAt(f, sel.Pos())
			if site == ast.Node(registrar) {
				// registrar 內的豁免僅及於**直接呼叫**。取 method value 後存起來
				// （`lateGET = r.GET`）可讓註冊逸出到其他函式執行，該函式既無
				// router 參數也無路由 selector，四道防線全數不命中。
				if calledFun[sel] && !asyncFun[sel] {
					return true
				}
				why := "取 method value 而非直接呼叫（可逸出至他處註冊）"
				if asyncFun[sel] {
					why = "以 go 陳述非同步呼叫（註冊時機落在函式返回之後，快照看不到）"
				}
				out = append(out, violation{
					file: file, line: fset.Position(sel.Pos()).Line,
					fn: labelOf(f, site), kind: kindEscape,
					what: "於 " + registrarFunc + " 內" + why,
				})
				return true
			}
			out = append(out, violation{
				file: file, line: fset.Position(sel.Pos()).Line,
				fn: labelOf(f, site), kind: kindDirect,
				what: "取用路由變更方法 ." + sel.Sel.Name + "（直接呼叫或取 method value 皆算）",
			})
			return true
		})

		// 防線 2：registerRoutes 以外的函式、method 與匿名函式不得接收 gin router 型別參數。
		// 匿名函式同樣須掃：`f := func(g *gin.RouterGroup) { g.GET(...) }` 否則整個漏掉。
		ast.Inspect(f, func(n ast.Node) bool {
			var params *ast.FieldList
			switch fn := n.(type) {
			case *ast.FuncDecl:
				if fn == registrar {
					return true // 豁免僅及於 registrar 自身的參數，不及於其內的匿名函式
				}
				params = fn.Type.Params
			case *ast.FuncLit:
				params = fn.Type.Params
			default:
				return true
			}
			if params == nil {
				return true
			}
			for _, p := range params.List {
				if !isGinRouter(info.TypeOf(p.Type), g) {
					continue
				}
				out = append(out, violation{
					file: file, line: fset.Position(p.Pos()).Line,
					fn: labelOf(f, n), kind: kindParam,
					what: "接收 gin router 型別參數（可間接繞過註冊收斂）",
				})
			}
			return true
		})
	}
	return out
}

// ── 防線 3、4：build constraint 與型別檢查涵蓋率 ─────────────────────────────

// knownGOOS／knownGOARCH：檔名後綴形式的 build constraint（`main_linux.go`）。
// 這類約束不出現在檔案內容中，只能靠檔名辨識。
var knownGOOS = map[string]bool{
	"aix": true, "android": true, "darwin": true, "dragonfly": true,
	"freebsd": true, "hurd": true, "illumos": true, "ios": true, "js": true,
	"linux": true, "nacl": true, "netbsd": true, "openbsd": true, "plan9": true,
	"solaris": true, "wasip1": true, "windows": true, "zos": true,
}

var knownGOARCH = map[string]bool{
	"386": true, "amd64": true, "amd64p32": true, "arm": true, "arm64": true,
	"arm64be": true, "armbe": true, "loong64": true, "mips": true, "mips64": true,
	"mips64le": true, "mips64p32": true, "mips64p32le": true, "mipsle": true,
	"ppc": true, "ppc64": true, "ppc64le": true, "riscv": true, "riscv64": true,
	"s390": true, "s390x": true, "sparc": true, "sparc64": true, "wasm": true,
}

// hasBuildConstraint 判斷原始檔是否帶任何 build constraint。
//
// **不可用「是否落在 pkg.GoFiles」推論**：GoFiles 只反映當前 build configuration，
// 當前為真的約束（`//go:build linux` 在 linux 上、`//go:build !nosuchtag`）依然
// 在 GoFiles 中，換個平台才消失——那正是最危險的一類，因為它在本機全綠。
//
// 檔頭以 `go/parser` 解析而非逐行字串比對：後者會被 UTF-8 BOM（Go 工具鏈會移除、
// TrimSpace 不會）與區塊註解內的 `package` 字樣騙過，兩者都能讓約束指示隱形。
//
// 檔名後綴清單為硬編（無公開 API 可取），存在版本漂移風險，但**漂移不會造成繞過**：
// 若 Go 認定某後綴為約束而本清單漏列，該檔在當前平台為真時照常編入型別檢查（防線
// 1、2 看得到），為假時則落入防線 4 的「未進入型別檢查」。漏列只影響政策完整性。
func hasBuildConstraint(t *testing.T, path string) (bool, string) {
	t.Helper()

	// 檔名後綴形式：name_GOOS.go、name_GOARCH.go、name_GOOS_GOARCH.go
	base := strings.TrimSuffix(filepath.Base(path), ".go")
	segs := strings.Split(base, "_")
	if n := len(segs); n >= 2 {
		last := segs[n-1]
		if knownGOOS[last] || knownGOARCH[last] {
			return true, "檔名後綴 _" + last + " 構成平台約束"
		}
		if n >= 3 && knownGOOS[segs[n-2]] && knownGOARCH[last] {
			return true, "檔名後綴 _" + segs[n-2] + "_" + last + " 構成平台約束"
		}
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly|parser.ParseComments)
	if err != nil {
		t.Fatalf("解析 %s 的檔頭失敗: %v", path, err)
	}
	for _, cg := range f.Comments {
		if cg.End() > f.Package {
			break // package 子句之後的同形註解只是普通註解
		}
		for _, c := range cg.List {
			// 只認行註解：`/* //go:build x */` 在 Go 規則中不構成約束
			if !strings.HasPrefix(c.Text, "//") {
				continue
			}
			if constraint.IsGoBuild(c.Text) || constraint.IsPlusBuild(c.Text) {
				return true, "檔頭含 build constraint：" + c.Text
			}
		}
	}
	return false, ""
}

// productionGoFiles 列出目錄下的 production 原始檔（排除 _test.go）。
func productionGoFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取 %s 失敗: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// scanFileLevelConstraints 防線 3、4。
//
// 帶 build constraint 的檔案對型別檢查可能完全隱形，且 tag 組合可能互斥而無法
// 一次載入；故守衛採**禁止其存在**而非嘗試掃描其內容——此規則嚴格強於掃描。
// 另斷言每個 production 檔都確實進入型別檢查，使防線 1、2 的涵蓋率不留死角。
func scanFileLevelConstraints(t *testing.T, dir string, pkg *packages.Package) []violation {
	t.Helper()
	compiled := map[string]bool{}
	for _, p := range pkg.GoFiles {
		compiled[filepath.Base(p)] = true
	}

	files := productionGoFiles(t, dir)
	if len(files) == 0 {
		t.Fatal("未找到任何 production 原始檔——掃描器可能失效（防假綠）")
	}

	var out []violation
	for _, name := range files {
		if tagged, why := hasBuildConstraint(t, filepath.Join(dir, name)); tagged {
			out = append(out, violation{
				file: name, line: 1, fn: "<file>", kind: kindTagged,
				what: why + "（不得以 build constraint 隱藏路由註冊）",
			})
		}
		if !compiled[name] {
			out = append(out, violation{
				file: name, line: 1, fn: "<file>", kind: kindUnchecked,
				what: "未進入型別檢查，防線 1、2 看不見其內容",
			})
		}
	}
	return out
}

// minAssemblyScannedFiles 組裝根的非測試 .go 檔數下限（防空集合假綠）。
// 2026-08-09 實測 6 檔（見 TestRouteRegistrationConfinedToRegisterRoutes 的 t.Logf）。
// 基數本就小，門檻取 4：足以擋下「掃描根指到空目錄／handler 整批搬離」，
// 又保留合併兩檔之類的正常重構空間。
const minAssemblyScannedFiles = 4

// guardModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const guardModulePath = "github.com/custodexa/backend"

// assemblyPkgRel 組裝根（路由註冊的唯一收口）相對 module 根的位置。
const assemblyPkgRel = "cmd/server"

// guardModuleRoot 由本測試檔位置向上找 go.mod，並核對 module 行。
// 不用「Dir(caller)/../..」的層數推算：那在守衛檔搬家時會靜默指到別處。
func guardModuleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			want := "module " + guardModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				filepath.Join(dir, "go.mod"), guardModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位",
				filepath.Dir(self), guardModulePath)
		}
		dir = parent
	}
}

// cmdServerDir 定位組裝根 cmd/server 目錄。
//
// **原以 Dir(runtime.Caller) 取本測試檔所在目錄**：那等於「守衛永遠掃自己住的
// 那個包」——守衛檔一旦隨重構搬走，它會安靜地改掃新家，而真正的組裝根從此
// 無人看守（modular-architecture W1 1.20）。改以 go.mod module 身分錨點
// ＋具名相對路徑定位，找不到即 Fatal：組裝根若搬遷，SHALL 同步改
// assemblyPkgRel，而不是讓守衛靜默跟著漂走。
func cmdServerDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(guardModuleRoot(t), filepath.FromSlash(assemblyPkgRel))
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("找不到組裝根 %s（%s）：路由收口守衛的被驗證對象不存在即等於沒有守衛。"+
			"若組裝根搬遷，SHALL 同步更新 assemblyPkgRel: %v", assemblyPkgRel, dir, err)
	}
	return dir
}

func formatViolations(vs []violation) string {
	sorted := append([]violation(nil), vs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].file != sorted[j].file {
			return sorted[i].file < sorted[j].file
		}
		return sorted[i].line < sorted[j].line
	})
	var b strings.Builder
	for _, v := range sorted {
		b.WriteString("\n  " + v.file + ":" + strconv.Itoa(v.line) +
			"  [" + v.kind + "] 函式 " + v.fn + "：" + v.what)
	}
	return b.String()
}

// TestRouteRegistrationConfinedToRegisterRoutes 斷言路由變更全數收斂於 registerRoutes。
func TestRouteRegistrationConfinedToRegisterRoutes(t *testing.T) {
	dir := cmdServerDir(t)
	pkg := loadGoPackage(t, dir)

	// 防假綠：真實 package 必須確實匯入 gin，否則 iroutes 為 nil、防線 1、2 全數空轉
	if !ginFactsOf(pkg).ok() {
		t.Fatal("未能自 cmd/server 的相依中取得 gin.IRoutes——" +
			"型別判定失去基準，所有防線將靜默放行")
	}

	// 防假綠：掃描檔數下限。handler 搬離組裝根時，「零違規」與「沒東西可掃」
	// 在斷言上不可分辨——下限使前者仍綠、後者當場紅。
	scanned := productionGoFiles(t, dir)
	if len(scanned) < minAssemblyScannedFiles {
		t.Fatalf("組裝根只有 %d 個非測試 .go（下限 %d，目錄 %s）：掃描範圍已失真，"+
			"守衛將在近乎空集合下假綠。若組裝根確實被拆小，改的是下限並同步覆核"+
			"路由註冊是否仍收斂於單一收口", len(scanned), minAssemblyScannedFiles, dir)
	}
	t.Logf("組裝根掃描檔數=%d（下限 %d）", len(scanned), minAssemblyScannedFiles)

	all := scanPackage(t, pkg)
	all = append(all, scanFileLevelConstraints(t, dir, pkg)...)

	if len(all) > 0 {
		t.Errorf("路由變更未收斂於 %s（共 %d 處違規）：%s\n\n"+
			"所有路由註冊必須位於 %s，使 production 與測試共用同一條註冊路徑；"+
			"否則路由完備性守衛會看不見這些路由而靜默假綠。",
			registrarFunc, len(all), formatViolations(all), registrarFunc)
	}
}

// ── self-check ────────────────────────────────────────────────────────────────

// sampleDir 於 testdata 下建臨時 package 目錄。
//
// 必須是 module 內的真實目錄：型別檢查需經 go list 解析 gin 相依，記憶體樣本辦不到。
// 置於 testdata 是因為 go 工具鏈會忽略該目錄名，樣本不會被正常建置捲入。
func sampleDir(t *testing.T, files map[string]string) string {
	t.Helper()
	base := filepath.Join(cmdServerDir(t), "testdata")
	dir, err := os.MkdirTemp(base, "guardselfcheck-")
	if err != nil {
		t.Fatalf("建立樣本目錄失敗: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatalf("寫入樣本 %s 失敗: %v", name, err)
		}
	}
	return dir
}

// expectation：預期的違規（函式標籤＋種類）。
type expectation struct {
	fn   string
	kind string
}

// countOf 以 multiset 計數，使同一函式同種類的多次命中不會互相折疊。
func countOf(vs []violation) map[expectation]int {
	m := map[expectation]int{}
	for _, v := range vs {
		m[expectation{fn: v.fn, kind: v.kind}]++
	}
	return m
}

// mutatorArgs：各方法的合法引數（樣本必須真的編得過，否則型別檢查失敗、守衛空轉）。
var mutatorArgs = map[string]string{
	"Use": "", "Handle": `"GET", "/x"`, "Any": `"/x"`, "Match": `nil, "/x"`,
	"GET": `"/x"`, "POST": `"/x"`, "DELETE": `"/x"`, "PATCH": `"/x"`,
	"PUT": `"/x"`, "OPTIONS": `"/x"`, "HEAD": `"/x"`,
	"StaticFile": `"/x", "f"`, "StaticFileFS": `"/x", "f", nil`,
	"Static": `"/x", "d"`, "StaticFS": `"/x", nil`, "Group": `"/x"`,
}

// TestRouteGuardScannerSelfCheck 掃描器自檢。
//
// 逐案例斷言「預期違規的確切函式與種類」，且以 multiset **完全相等**比對：
//   - 少了預期項 → 守衛失效，會靜默放行該形態
//   - 多了非預期項 → 誤報，守衛無法在真實專案存活
//
// 僅斷言「至少一項違規」是不夠的：防線 2 命中會掩蓋防線 1 失效。
func TestRouteGuardScannerSelfCheck(t *testing.T) {
	var body strings.Builder
	var want []expectation

	// 合規基準：註冊全在 registerRoutes 內（含 handler 交棒與 gin handler 匿名函式），
	// 不得產生任何違規。
	// 但 registerRoutes 內**逸出的 closure**必須被攔——豁免只及於 registrar 本身。
	body.WriteString(`
var escaped func()

var lateGET func(string, ...gin.HandlerFunc) gin.IRoutes

type fakeHandler struct{}

func (fakeHandler) RegisterRoutes(g *gin.RouterGroup) {}

func registerRoutes(r *gin.Engine) {
	r.Use()
	v1 := r.Group("/api/v1")
	v1.GET("/x", func(c *gin.Context) {})
	fakeHandler{}.RegisterRoutes(v1.Group("/y"))
	escaped = func() { r.GET("/late") }
	lateGET = r.GET
	go r.POST("/async")
	(v1.GET)("/paren")
}
`)
	want = append(want,
		// method 宣告本身收受 router，同屬防線 2 攔截對象（豁免只綁唯一頂層 registerRoutes）
		expectation{fn: "RegisterRoutes", kind: kindParam},
		// registrar 內逸出的匿名函式不得共享豁免
		expectation{fn: registrarFunc + litSuffix, kind: kindDirect},
		// registrar 內取 method value 存起來，可逸出至他處註冊
		expectation{fn: registrarFunc, kind: kindEscape},
		// go 陳述使註冊落在函式返回之後（同屬 escape，故 multiset 計 2 次）
		expectation{fn: registrarFunc, kind: kindEscape},
	)
	// 注意：registrar 內的 `(v1.GET)("/paren")` 是同步直接呼叫，
	// 括號不得使其被誤判為逸出——上方預期中刻意不含第三筆 escape

	// 逐一涵蓋 routeMutators 的**每一個**方法，而非只挑幾個代表。
	// 手選案例會隨清單增長而失去同步——StaticFileFS 當初就是這樣漏掉的。
	mutators := make([]string, 0, len(routeMutators))
	for m := range routeMutators {
		if m != "RegisterRoutes" { // 交棒形態另有專案，非 router receiver
			mutators = append(mutators, m)
		}
	}
	sort.Strings(mutators)
	for _, m := range mutators {
		args, ok := mutatorArgs[m]
		if !ok {
			t.Fatalf("routeMutators 含 %q 但 mutatorArgs 未提供引數——"+
				"新增方法時必須同步補上，否則該方法沒有自檢案例", m)
		}
		fn := "sabotageMutator" + m
		// 每個案例用**互不相同**的識別字，杜絕「靠別處同名宣告意外通過」
		fmt.Fprintf(&body, "\nfunc %s() {\n\tvar router%s *gin.Engine\n\trouter%s.%s(%s)\n}\n",
			fn, m, m, m, args)
		want = append(want, expectation{fn: fn, kind: kindDirect})
	}

	// 非 ident receiver：早期名稱追蹤版本對這些形態全數漏報
	body.WriteString(`
type routerHolder struct{ router *gin.Engine }

func sabotageField(h routerHolder)         { h.router.GET("/x") }
func sabotageSlice(rs []*gin.Engine)       { rs[0].GET("/x") }
func sabotageMap(m map[string]*gin.Engine) { m["k"].POST("/x") }
func sabotageFactory()                     { newSampleEngine().PUT("/x") }
func newSampleEngine() *gin.Engine         { return gin.New() }
func newSampleGroup() *gin.RouterGroup     { return nil }
func sabotageMethodValue()                 { var e *gin.Engine; get := e.GET; _ = get }
func sabotageTypedVar()                    { var r gin.IRoutes = gin.New(); r.GET("/x") }
`)
	for _, fn := range []string{"sabotageField", "sabotageSlice", "sabotageMap",
		"sabotageFactory", "sabotageMethodValue", "sabotageTypedVar"} {
		want = append(want, expectation{fn: fn, kind: kindDirect})
	}

	// handler 交棒的各種 selector 形態：值、method value、interface、embedded、泛型實例化。
	// （泛型案例對 Selection.Type() 與 Obj().Type() 兩種取法行為相同——實測確認
	// Selections 回傳的已是實例化後的 Func；此案例證明兩者皆能涵蓋，非用以區辨。）
	body.WriteString(`
type routeRegistrar interface{ RegisterRoutes(*gin.RouterGroup) }

type embedder struct{ fakeHandler }

type genericHandler[T any] struct{}

func (genericHandler[T]) RegisterRoutes(x T) {}

func sabotageHandoff(h fakeHandler)              { h.RegisterRoutes(newSampleGroup()) }
func sabotageHandoffValue(h fakeHandler)         { f := h.RegisterRoutes; _ = f }
func sabotageHandoffInterface(rr routeRegistrar) { rr.RegisterRoutes(newSampleGroup()) }
func sabotageHandoffEmbedded(e embedder)         { e.RegisterRoutes(newSampleGroup()) }
func sabotageHandoffGeneric() {
	genericHandler[*gin.RouterGroup]{}.RegisterRoutes(newSampleGroup())
}
`)
	for _, fn := range []string{"sabotageHandoff", "sabotageHandoffValue",
		"sabotageHandoffInterface", "sabotageHandoffEmbedded", "sabotageHandoffGeneric"} {
		want = append(want, expectation{fn: fn, kind: kindDirect})
	}

	// 窄化介面／泛型 constraint：只宣告需要的那一個方法即可持有 *gin.Engine，
	// 卻不實作完整 IRoutes。只驗 Implements 者會整個漏掉——這是可編譯的實際繞過。
	body.WriteString(`
type getOnly interface {
	GET(string, ...gin.HandlerFunc) gin.IRoutes
}

func narrowedIface(r getOnly)        { r.GET("/hidden") }
func narrowedGeneric[T getOnly](r T) { r.GET("/hidden") }

// 負向：方法簽章與 gin 完全相同的**具體**型別無法承接 *gin.Engine，不是繞過管道；
// 空介面與「gin 不滿足的同名方法介面」同理。只比簽章者會把這三種都誤報。
type ginShaped struct{}

func (ginShaped) GET(string, ...gin.HandlerFunc) gin.IRoutes { return nil }

type wrongShape interface{ GET(int) }

func consumeShaped(s ginShaped)       {}
func consumeAny(v any)                {}
func consumeEmptyIface(v interface{}) {}
func consumeWrongShape(x wrongShape)  {}

// 中間件鏈欄位：直接寫入等同繞過 Use；先逸出再改亦同。
// 負向：同名欄位但非 gin router 者不得誤報。
type notRouterState struct{ Handlers []int }

func mutateHandlers() {
	var e *gin.Engine
	e.Handlers = nil
}

func stealHandlers() {
	var e *gin.Engine
	hs := e.Handlers
	_ = hs
}

func readOtherHandlers() {
	var n notRouterState
	_ = n.Handlers
}
`)
	want = append(want,
		expectation{fn: "mutateHandlers", kind: kindState},
		expectation{fn: "stealHandlers", kind: kindState},
		expectation{fn: "narrowedIface", kind: kindParam},
		expectation{fn: "narrowedIface", kind: kindDirect},
		expectation{fn: "narrowedGeneric", kind: kindParam},
		expectation{fn: "narrowedGeneric", kind: kindDirect},
	)

	// 匿名函式：接收 router 的 closure、以及巢狀 closure 內的註冊
	body.WriteString(`
func literalTakesRouter() {
	f := func(g *gin.RouterGroup) {}
	_ = f
}

func literalRegisters() {
	var e *gin.Engine
	go func() { e.GET("/inside") }()
}
`)
	want = append(want,
		expectation{fn: "literalTakesRouter" + litSuffix, kind: kindParam},
		expectation{fn: "literalRegisters" + litSuffix, kind: kindDirect},
	)

	// 間接繞過：逐一涵蓋各種 gin router 型別入口（Engine／RouterGroup／IRouter／IRoutes），
	// 加上型別別名與 import alias——以型別判定後，這些形態應一律命中而無須逐一列名
	body.WriteString(`
type routerAlias = gin.IRouter

func indirectEngine(x *gin.Engine)           {}
func indirectRouterGroup(x *gin.RouterGroup) {}
func indirectIRouter(x gin.IRouter)          {}
func indirectIRoutes(x gin.IRoutes)          {}
func indirectAlias(x routerAlias)            {}
`)
	for _, fn := range []string{"indirectEngine", "indirectRouterGroup",
		"indirectIRouter", "indirectIRoutes", "indirectAlias"} {
		want = append(want, expectation{fn: fn, kind: kindParam})
	}

	// import alias 另置一檔：同一檔案無法重複匯入 gin
	aliasFile := `package sample

import g "github.com/gin-gonic/gin"

func indirectImportAlias(x *g.Engine) {}
`
	want = append(want, expectation{fn: "indirectImportAlias", kind: kindParam})

	// 負向：非 gin 的同名方法、跨函式同名識別字、內層 shadowing 一律不得誤報。
	// 缺此檢查時，以名稱猜測型別的守衛會把任何叫 Use/Group/Handle 的東西判違規，
	// 且其自身的正向案例會因同名宣告而意外通過——兩種假象同時存在。
	body.WriteString(`
type fakeCache struct{}

func (fakeCache) Use(string)    {}
func (fakeCache) Group(string)  {}
func (fakeCache) Handle(string) {}
func (fakeCache) Any(string)    {}
func (fakeCache) Match(string)  {}
func (fakeCache) GET(string)    {}

type workGroup struct{}

func (workGroup) Go(func() error) {}

// 與 registerRoutes 的參數同名，但型別完全無關——不得因名稱相同而被誤判
func notARouter() {
	r := fakeCache{}
	r.Use("k")
	r.Group("g")
	r.Handle("h")
	r.Any("a")
	r.Match("m")
	r.GET("/x")
	var wg workGroup
	wg.Go(nil)
}

// 內層 shadowing：同一函式內先是 router、後被非 router 遮蔽
func shadowed(e *gin.Engine) {
	{
		e := fakeCache{}
		e.Use("k")
	}
}
`)
	// shadowed 只因「接收 gin router 參數」違規（防線 2），其內層 e.Use 不得被計入
	want = append(want, expectation{fn: "shadowed", kind: kindParam})

	src := "package sample\n\nimport \"github.com/gin-gonic/gin\"\n" + body.String()
	dir := sampleDir(t, map[string]string{
		"sample.go": src,
		"alias.go":  aliasFile,
	})

	pkg := loadGoPackage(t, dir)
	if !ginFactsOf(pkg).ok() {
		t.Fatal("自檢樣本未取得 gin.IRoutes——自檢本身失效")
	}
	got := countOf(scanPackage(t, pkg))

	wantCount := map[expectation]int{}
	for _, e := range want {
		wantCount[e]++
	}
	for e, n := range wantCount {
		if got[e] != n {
			t.Errorf("掃描器對 %s 的 %s 違規命中 %d 次，預期 %d 次——"+
				"少於預期即該形態可用於繞過收斂", e.fn, e.kind, got[e], n)
		}
	}
	for e, n := range got {
		if wantCount[e] == 0 {
			t.Errorf("掃描器誤報：函式 %s 被判 %s 違規 %d 次，但該案例應合規——"+
				"誤報會讓守衛無法在真實專案存活", e.fn, e.kind, n)
		}
	}
}

// TestBuildConstraintDetection 防線 3 自檢。
//
// 關鍵在於「當前為真」的約束也必須被攔：`//go:build linux` 在 linux 上依然編入
// GoFiles，換平台才消失——以 GoFiles 差集推論約束存在性者，正是在此靜默放行。
func TestBuildConstraintDetection(t *testing.T) {
	cases := []struct {
		name     string
		filename string
		src      string
		want     bool
	}{
		{"當前為假的 tag", "hidden.go", "//go:build sometag\n\npackage sample\n", true},
		{"當前為真的 tag（GoFiles 差集看不出來）", "always.go",
			"//go:build !nosuchtag\n\npackage sample\n", true},
		{"go:build ignore", "gen.go", "//go:build ignore\n\npackage sample\n", true},
		{"舊式 +build", "old.go", "// +build legacy\n\npackage sample\n", true},
		{"檔名 GOOS 後綴", "main_linux.go", "package sample\n", true},
		{"檔名 GOOS_GOARCH 後綴", "main_darwin_amd64.go", "package sample\n", true},
		{"檔名 arm64be 後綴", "main_arm64be.go", "package sample\n", true},
		// BOM：Go 工具鏈會先移除 UTF-8 BOM，逐行 TrimSpace 則不會——
		// 字串掃描版本會看不到指示，而該約束當前為真、檔案仍在 GoFiles，防線 4 也補不到
		{"BOM 開頭仍須辨識", "bom.go",
			"\ufeff//go:build !nosuchtag\n\npackage sample\n", true},
		// 區塊註解內的 package 字樣：字串掃描會提早停止而漏掉其後的真指示
		{"區塊註解內的 package 字樣不得使掃描提早停止", "blockcomment.go",
			"/*\npackage fake\n*/\n//go:build !nosuchtag\n\npackage sample\n", true},
		{"無約束", "plain.go", "package sample\n\nfunc plain() {}\n", false},
		{"go:generate 不是 build constraint", "gogen.go",
			"//go:generate echo hi\n\npackage sample\n", false},
		{"區塊註解內的 go:build 不構成約束", "inblock.go",
			"/*\n//go:build sometag\n*/\n\npackage sample\n", false},
		{"package 之後的同形註解只是普通註解", "afterpkg.go",
			"package sample\n\n// //go:build sometag\nfunc x() {}\n", false},
		{"底線但非平台名", "routes_http.go", "package sample\n", false},
	}

	dir := t.TempDir()
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, c.filename)
			if err := os.WriteFile(path, []byte(c.src), 0o644); err != nil {
				t.Fatalf("寫入樣本失敗: %v", err)
			}
			got, why := hasBuildConstraint(t, path)
			if got != c.want {
				t.Errorf("hasBuildConstraint(%s) = %v（%s），預期 %v——"+
					"誤判會讓帶約束的檔案逃過型別檢查，或讓正常檔案被誤攔",
					c.filename, got, why, c.want)
			}
		})
	}
}

// TestRouteGuardDetectsUncheckedFiles 防線 4 自檢：未進入型別檢查的檔案必須被攔下。
func TestRouteGuardDetectsUncheckedFiles(t *testing.T) {
	dir := sampleDir(t, map[string]string{
		"sample.go": `package sample

import "github.com/gin-gonic/gin"

func registerRoutes(r *gin.Engine) { r.GET("/x") }
`,
		"hidden.go": `//go:build sometag

package sample

import "github.com/gin-gonic/gin"

func snapshotHook(r *gin.Engine) { r.Use() }
`,
	})

	pkg := loadGoPackage(t, dir)
	got := scanFileLevelConstraints(t, dir, pkg)

	kinds := map[string]bool{}
	for _, v := range got {
		if v.file != "hidden.go" {
			t.Errorf("正常編譯的檔案 %s 被誤判：%s", v.file, v.what)
		}
		kinds[v.kind] = true
	}
	if !kinds[kindTagged] {
		t.Error("帶 build constraint 的檔案未被防線 3 攔截")
	}
	if !kinds[kindUnchecked] {
		t.Error("未進入型別檢查的檔案未被防線 4 攔截——" +
			"防線 1、2 看不見其內容卻無人提醒")
	}
}

// snapshotResidue：characterization hook 的識別字。hook 屬 route-composition-root
// A-0 的一次性工具，golden 入庫後即移除，不得再度出現於 production 原始碼。
var snapshotResidue = []string{
	"routesnapshot",             // build tag 名
	"installRouteSnapshotProbe", // probe 安裝點
	"dumpRouteSnapshot",         // dump 點
	"ROUTE_SNAPSHOT_DIR",        // 輸出目錄環境變數
}

// TestNoCharacterizationHookResidue 斷言 characterization hook 未殘留於 production 原始碼。
//
// **必須是 source-level 掃描，不能只檢查 production binary 的符號**：hook 以 build tag
// 隔離，即使 tagged 檔永久留在 repo，正常編譯的 binary 本來就不含其符號——只驗 binary
// 必然假綠（實測：tagged 檔存在時 `strings` 查 production binary 仍為 0 個匹配）。
//
// hook 具備「由環境變數決定路徑的寫檔能力」，留在堡壘機的 production 原始碼中屬多餘
// 攻擊面；且其存在意味著有人可重新啟用而繞過 golden 的不可竄改性。
func TestNoCharacterizationHookResidue(t *testing.T) {
	dir := cmdServerDir(t)
	files := productionGoFiles(t, dir)
	if len(files) == 0 {
		t.Fatal("未掃描到任何 production 原始檔——掃描器可能失效（防假綠）")
	}

	var hits []string
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("讀取 %s 失敗: %v", name, err)
		}
		content := string(data)
		for _, marker := range snapshotResidue {
			if strings.Contains(content, marker) {
				hits = append(hits, name+" 含 "+marker)
			}
		}
	}
	if len(hits) > 0 {
		t.Errorf("characterization hook 殘留於 production 原始碼（%d 處）：\n  %s\n\n"+
			"hook 為 A-0 一次性工具，golden 入庫後即應移除；其寫檔能力留在堡壘機 production "+
			"原始碼中屬多餘攻擊面，且可被重新啟用而繞過 golden 的不可竄改性。",
			len(hits), strings.Join(hits, "\n  "))
	}
}
