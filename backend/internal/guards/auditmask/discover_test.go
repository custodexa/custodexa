package auditmask

import (
	"fmt"
	"go/ast"
	"go/types"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/packages"
)

// bindScanDirs 掃描範圍：**整個 internal 樹**。
//
// 刻意不縮到 `internal/api`：`/connect-tokens` 的綁定住在 `internal/sshproxy/handler.go`，
// 只掃 api 會讓它逃出射程——而「射程外的端點靜默不受守衛保護」正是本守衛要消滅的
// 失效形態。掃描成本（一次全樹型別檢查）換的是「新端點放哪都跑不掉」。
var bindScanDirs = []string{"./internal/..."}

// ginBindMethods gin.Context 上會把請求本文解進結構的方法。
//
// 只列**會讀 body 的**：`ShouldBindQuery`／`ShouldBindUri` 讀的是 query／path，
// 不進 `request_body`，列進來只會製造與遮罩無關的噪音。
var ginBindMethods = map[string]bool{
	"ShouldBindJSON":     true,
	"ShouldBindBodyWith": true,
	"BindJSON":           true,
	"ShouldBind":         true, // 內容協商，JSON 請求走 JSON binding
	"Bind":               true,
}

// bindSite 一個請求本文綁定點：某個 handler 函式綁進來的 JSON 頂層鍵集合。
//
// **頂層鍵**是刻意的：`MaskSensitiveFields` 只走一層 map，巢狀物件整包跟著頂層鍵
// 的判定走（被遮就整包變標記，被放行就整包原樣入庫）。守衛的判定粒度必須與
// 被守衛函式的粒度相同，否則會對不上。
type bindSite struct {
	Key      string // 例如 "api.(*UserHandler).AssignRoles"
	File     string // module 相對路徑
	Line     int
	Fields   []string // JSON 頂層鍵（已排序去重）
	Untagged []string // 無 json tag 的欄位名（弱點提示，見 TestBindSitesAreJSONTagged）
}

// scanResult 一次全樹掃描的產物。
//
// 快取的理由不只是省時間：四支守衛必須看到**同一份**輸入，否則「清單有死鍵」與
// 「端點無可見欄位」可能建立在兩次不同的掃描上，錯誤訊息會互相矛盾。
type scanResult struct {
	Sites []bindSite
	// RawBodyFiles 直接讀 gin `*Context.Request.Body` 的非測試檔（module 相對路徑）。
	// 判定用型別資訊而非字串比對——`ev.Request.Body`（gatewayapi 的事件結構）
	// 長得一模一樣卻與請求本文無關，字串比對會誤報
	RawBodyFiles map[string]bool
	Err          error
}

var (
	scanOnce  sync.Once
	scanCache scanResult
)

// scanTree 取（並快取）全樹掃描結果。
func scanTree(t *testing.T) scanResult {
	t.Helper()
	root := auditMaskModuleRoot(t)
	scanOnce.Do(func() { scanCache = runScan(root) })
	if scanCache.Err != nil {
		t.Fatalf("%v", scanCache.Err)
	}
	return scanCache
}

// discoverBindSites 取所有請求本文綁定點。
func discoverBindSites(t *testing.T) []bindSite {
	t.Helper()
	return scanTree(t).Sites
}

// runScan 以型別資訊掃出請求本文綁定點與原始 body 讀取點。
//
// 為什麼要型別資訊而非純 AST：綁定目標多半是具名 DTO（`identity.CreateUserRequest`），
// 純 AST 只看得到型別**名字**，得自己在別的 package 找宣告——那正是會靜默漏掉的地方。
func runScan(root string) scanResult {
	fail := func(format string, args ...any) scanResult {
		return scanResult{Err: fmt.Errorf(format, args...)}
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports,
		Dir:   root,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, bindScanDirs...)
	if err != nil {
		return fail("packages.Load 失敗，守衛無法取得輸入: %v", err)
	}
	var loadErrs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			loadErrs = append(loadErrs, fmt.Sprintf("%s: %v", p.PkgPath, e))
		}
	})
	if len(loadErrs) > 0 {
		// fail-close：型別檢查沒過就掃不到綁定點，靜默回空集合等於守衛消失
		return fail("掃描範圍內有型別錯誤，守衛拒絕在殘缺輸入上判定：\n%s", strings.Join(loadErrs, "\n"))
	}

	var sites []bindSite
	rawBody := map[string]bool{}
	for _, p := range pkgs {
		for _, file := range p.Syntax {
			path := p.Fset.Position(file.Pos()).Filename
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			rel := relTo(root, path)
			// 原始 body 讀取：`<gin.Context>.Request.Body`
			ast.Inspect(file, func(n ast.Node) bool {
				outer, ok := n.(*ast.SelectorExpr)
				if !ok || outer.Sel.Name != "Body" {
					return true
				}
				inner, ok := outer.X.(*ast.SelectorExpr)
				if !ok || inner.Sel.Name != "Request" {
					return true
				}
				if isGinContext(p.TypesInfo.TypeOf(inner.X)) {
					rawBody[rel] = true
				}
				return true
			})
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok {
					return true
				}
				display := funcDisplay(fn)
				ast.Inspect(fn.Body, func(inner ast.Node) bool {
					call, ok := inner.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || !ginBindMethods[sel.Sel.Name] || len(call.Args) == 0 {
						return true
					}
					if !isGinContext(p.TypesInfo.TypeOf(sel.X)) {
						return true
					}
					argType := p.TypesInfo.TypeOf(call.Args[0])
					fields, untagged := jsonTopLevelKeys(argType)
					// map 綁定（`var body map[string]json.RawMessage`）沒有結構欄位，
					// 鍵在程式碼裡以字串常數索引。不撈這些常數，該端點會偽裝成
					// 「無欄位」而完全逃過判定（PATCH /auth/me 即此形態）
					if isStringKeyedMap(argType) {
						fields = append(fields, mapIndexKeys(fn.Body, call.Args[0])...)
						sort.Strings(fields)
					}
					if len(fields) == 0 && len(untagged) == 0 {
						return true
					}
					pos := p.Fset.Position(call.Pos())
					sites = append(sites, bindSite{
						Key:      p.Name + "." + display,
						File:     rel,
						Line:     pos.Line,
						Fields:   fields,
						Untagged: untagged,
					})
					return true
				})
				return false
			})
		}
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].Key != sites[j].Key {
			return sites[i].Key < sites[j].Key
		}
		return sites[i].Line < sites[j].Line
	})
	return scanResult{Sites: sites, RawBodyFiles: rawBody}
}

func relTo(root, path string) string {
	if strings.HasPrefix(path, root+"/") {
		return strings.TrimPrefix(path, root+"/")
	}
	return path
}

func funcDisplay(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return "(" + exprString(fn.Recv.List[0].Type) + ")." + fn.Name.Name
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return "*" + exprString(v.X)
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.IndexExpr:
		return exprString(v.X)
	default:
		return "?"
	}
}

func isGinContext(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == "Context" && obj.Pkg() != nil &&
		strings.HasSuffix(obj.Pkg().Path(), "github.com/gin-gonic/gin")
}

// isStringKeyedMap 判斷綁定目標是否為 map[string]T（含指標一層）。
func isStringKeyedMap(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	m, ok := t.Underlying().(*types.Map)
	if !ok {
		return false
	}
	b, ok := m.Key().Underlying().(*types.Basic)
	return ok && b.Kind() == types.String
}

// mapIndexKeys 撈出函式內以字串常數索引該 map 變數的鍵名。
func mapIndexKeys(body *ast.BlockStmt, arg ast.Expr) []string {
	target := ""
	switch v := arg.(type) {
	case *ast.UnaryExpr:
		if id, ok := v.X.(*ast.Ident); ok {
			target = id.Name
		}
	case *ast.Ident:
		target = v.Name
	}
	if target == "" || body == nil {
		return nil
	}
	seen := map[string]bool{}
	var keys []string
	ast.Inspect(body, func(n ast.Node) bool {
		idx, ok := n.(*ast.IndexExpr)
		if !ok {
			return true
		}
		id, ok := idx.X.(*ast.Ident)
		if !ok || id.Name != target {
			return true
		}
		lit, ok := idx.Index.(*ast.BasicLit)
		if !ok || lit.Kind.String() != "STRING" {
			return true
		}
		key := strings.Trim(lit.Value, "`\"")
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
		return true
	})
	return keys
}

// jsonTopLevelKeys 取結構的 JSON 頂層鍵。
// 匿名嵌入的結構視為攤平（encoding/json 語義），故遞迴展開。
func jsonTopLevelKeys(t types.Type) (fields []string, untagged []string) {
	seen := map[string]bool{}
	var walk func(types.Type, int)
	walk = func(tt types.Type, depth int) {
		if tt == nil || depth > 4 {
			return
		}
		for {
			ptr, ok := tt.(*types.Pointer)
			if !ok {
				break
			}
			tt = ptr.Elem()
		}
		st, ok := tt.Underlying().(*types.Struct)
		if !ok {
			return
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			tag := reflect.StructTag(st.Tag(i)).Get("json")
			name := strings.Split(tag, ",")[0]
			if f.Anonymous() && name == "" {
				walk(f.Type(), depth+1)
				continue
			}
			if !f.Exported() {
				continue
			}
			switch {
			case name == "-":
				continue
			case name == "":
				if !seen["!"+f.Name()] {
					seen["!"+f.Name()] = true
					untagged = append(untagged, f.Name())
				}
			default:
				if !seen[name] {
					seen[name] = true
					fields = append(fields, name)
				}
			}
		}
	}
	walk(t, 0)
	sort.Strings(fields)
	sort.Strings(untagged)
	return fields, untagged
}
