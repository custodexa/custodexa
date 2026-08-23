package moduleboundary

// 資料邊界閘門（Phase B 任務 6.0a–6.0c）。
//
// **為何非有不可**：`go list -deps` 證得了 import 層零出向，證不了資料層——七個模組
// 共用 `internal/model` 並各自持有 `*gorm.DB`，任何模組都能直接讀寫他模組的表而
// 編譯器與 import 圖守衛全都看不見。
// 實證：keyvault 的 `VerifyInitialAdminCredential` 直接 `Preload("Roles")` 讀
// identity 的 users/roles 並在包內做 admin 判定。asset／identity／authz 是資料密集
// 模組，若沿用現況搬入，缺口會從「單一自有表」放大成常態跨模組通道且再也收不回。
//
// **本閘門做什麼**（限定於既有裁決範圍，不多做）：
//   - 6.0a：每張表登記所屬模組（`tableOwner`）；跨模組讀／寫以**現況為基線全數登記**
//     （`crossModuleDataAccessBaseline`）。
//   - 6.0b：ratchet——**只准縮不准增**。掃到未登記的跨模組存取即紅；登記項在現實中
//     消失（除刻意標記為掃描不可見者）亦紅，逼「移除須顯式更新登記」。
//   - 6.0c：表名解析走 `go/types`，涵蓋 `Create(&model.X{})`／`Save(&row)`／
//     `First(&row)` 這類**由變數型別決定表名**的形態，
//     並對非字面量的 `Table`／`Raw`／`Exec` **fail-close**（具名例外另列）。
//
// **誠實界定**（不得越過）：本守衛是測試守衛不是編譯器保證，射程＝模組歸屬檔內、
// 經 `*gorm.DB` 方法呼叫且表名可由字面量或型別解析者。看不見的形態逐條列在
// `dataBoundaryBlindSpots` 的註解，並以具名例外使其**可見而非隱形**。

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
	"gorm.io/gorm/schema"
)

// ---- 6.0c：掃描與型別解析 ----

const (
	// minDataBoundaryPackages `packages.Load("./...")` 載入包數下限（現況 31，取 24 為保守下界）。
	minDataBoundaryPackages = 24
	// minDataBoundaryFiles 落入模組歸屬的非測試檔數下限（現況 85+，取 80）。
	minDataBoundaryFiles = 80
	// minDataBoundaryFindings 掃到的資料存取點下限——歸零即掃描失效，「零違規」不成立。
	minDataBoundaryFindings = 200
)

// dataAccessFinding 一處資料存取。
type dataAccessFinding struct {
	Module string
	Table  string
	Kind   string // read / write
	Site   string // file:line（人可讀證據）
}

// dbBoundaryWriteMethods 會產生寫入的 gorm 方法。
var dbBoundaryWriteMethods = map[string]bool{
	"Create": true, "CreateInBatches": true, "Save": true, "Updates": true,
	"Update": true, "UpdateColumn": true, "UpdateColumns": true, "Delete": true,
	"FirstOrCreate": true,
}

// dbBoundaryTypedMethods 由「引數的型別」決定表名的方法（6.0c 的核心涵蓋面）。
var dbBoundaryTypedMethods = map[string]bool{
	"Model": true, "Create": true, "CreateInBatches": true, "Save": true,
	"Delete": true, "First": true, "Last": true, "Take": true, "Find": true,
	"FirstOrCreate": true, "FirstOrInit": true, "Updates": true,
}

var sqlTableRe = regexp.MustCompile(`(?is)\b(?:from|join|update|into)\s+"?([a-z_][a-z0-9_]*)"?`)

// dataBoundaryLiteralExemption 具名例外：非字面量的表名／SQL 來源。
//
// **列入清單不是免死金牌**：每列必須指名「由哪個守衛承擔」，且 Tables 欄逐張列出
// 該處實際會碰到的表——它們一併納入 ratchet 登記，不因掃描器看不見而消失。
type dataBoundaryLiteralExemption struct {
	File   string // 相對 module 根
	Reason string
}

var dataBoundaryLiteralExemptions = []dataBoundaryLiteralExemption{
	{File: "internal/modules/keyvault/envelope_migration_service.go",
		Reason: "信封重加密的動態表名一律取自 envelopeMigrationTargets 登記表，由 keyvault/table_ownership_guard_test.go 的 TestKeyvaultDynamicTableNamesComeFromRegistry 全面守衛（含字面量、Sprintf format、Model 型別四形態）；碰到的 7 張表已逐張列入本檔基線登記。"},
	{File: "internal/modules/keyvault/aad_residue_sentinel.go",
		Reason: "AAD 殘留哨兵同樣以 envelopeMigrationTargets 驅動掃描全部密文欄，守衛同上。"},
	{File: "internal/modules/audit/retention_service.go",
		Reason: "保留政策的分批硬刪走原生 SQL（postgres 的 DELETE 無 LIMIT，須 id IN 子查詢），表名取自 retentionTargets 登記表。該登記表現況三列（audit_logs／session_commands／command_alerts）**全為 audit 自有表**，故本例外不隱藏任何跨模組存取；若日後有人把他模組的表加進 retentionTargets，TestRetentionTargetsAreAuditOwned 會轉紅。"},
}

// TestRetentionTargetsAreAuditOwned 上方 retention_service 具名例外的**二次條件**。
//
// 列入例外清單不是免死金牌（testing.md §5 形態 8）：例外之所以安全，是因為
// `retentionTargets` 的表全屬 audit 自己；那個前提一旦不成立，例外就變成
// 「跨模組硬刪對掃描面隱形」。故把前提本身釘成一條斷言。
func TestRetentionTargetsAreAuditOwned(t *testing.T) {
	root := lifecycleModuleRoot(t)
	src := filepath.Join(root, "internal", "modules", "audit", "retention_service.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗（例外的前提無從查核，守衛不得放行）: %v", src, err)
	}
	var tables []string
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) == 0 || vs.Names[0].Name != "retentionTargets" || len(vs.Values) == 0 {
			return true
		}
		cl, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, el := range cl.Elts {
			inner, ok := el.(*ast.CompositeLit)
			if !ok || len(inner.Elts) < 2 {
				continue
			}
			bl, ok := inner.Elts[1].(*ast.BasicLit)
			if !ok || bl.Kind != token.STRING {
				continue
			}
			tables = append(tables, strings.Trim(bl.Value, `"`))
		}
		return false
	})
	if len(tables) < 3 {
		t.Fatalf("只解析出 %d 張 retentionTargets 表（現況 3）：登記表結構已變，例外的前提須重新審視", len(tables))
	}
	for _, tb := range tables {
		if owner := tableOwner[tb]; owner != "audit" {
			t.Errorf("retentionTargets 含非 audit 自有表 %q（歸 %s）：原生 SQL 硬刪他模組的表對資料邊界掃描是隱形的，"+
				"SHALL 改走該模組的對外介面，或在 crossModuleDataAccessBaseline 具名登記為 Invisible 並說明由誰守衛", tb, owner)
		}
	}
}

// dataBoundaryScan 掃描結果
type dataBoundaryScan struct {
	Findings   []dataAccessFinding
	Unresolved []string // fail-close：非字面量的表名／SQL，且不在具名例外內
	Packages   int
	Files      int
}

// modelTableNames 解析 `internal/model`：型別名 → 表名。
// 有 `TableName()` 者取其字面量，否則走 GORM 預設命名策略（與執行期同一套規則）。
func modelTableNames(t *testing.T, root string) map[string]string {
	t.Helper()
	dir := filepath.Join(root, "internal", "model")
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatalf("解析 internal/model 失敗（表名對照無來源，守衛不得在此宣稱通過）: %v", err)
	}
	structs := map[string]bool{}
	declared := map[string]string{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				switch dd := d.(type) {
				case *ast.GenDecl:
					for _, s := range dd.Specs {
						ts, ok := s.(*ast.TypeSpec)
						if !ok {
							continue
						}
						if _, ok := ts.Type.(*ast.StructType); ok {
							structs[ts.Name.Name] = true
						}
					}
				case *ast.FuncDecl:
					if dd.Name.Name != "TableName" || dd.Recv == nil || len(dd.Recv.List) == 0 || dd.Body == nil {
						continue
					}
					var recv string
					switch rt := dd.Recv.List[0].Type.(type) {
					case *ast.Ident:
						recv = rt.Name
					case *ast.StarExpr:
						if id, ok := rt.X.(*ast.Ident); ok {
							recv = id.Name
						}
					}
					ast.Inspect(dd.Body, func(n ast.Node) bool {
						bl, ok := n.(*ast.BasicLit)
						if ok && bl.Kind == token.STRING {
							declared[recv] = strings.Trim(bl.Value, `"`)
							return false
						}
						return true
					})
				}
			}
		}
	}
	if len(structs) < 30 {
		t.Fatalf("internal/model 只解析出 %d 個結構型別（現況 43）：來源失真", len(structs))
	}
	ns := schema.NamingStrategy{}
	out := map[string]string{}
	for name := range structs {
		if tn, ok := declared[name]; ok && tn != "" {
			out[name] = tn
			continue
		}
		out[name] = ns.TableName(name)
	}
	return out
}

// scanModuleDataAccess 以型別資訊掃出模組歸屬檔內的資料存取點。
func scanModuleDataAccess(t *testing.T, root string, modelTables map[string]string) dataBoundaryScan {
	t.Helper()
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps,
		Dir:   root,
		Fset:  fset,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("packages.Load 失敗（守衛無法在無視野下宣稱通過）: %v", err)
	}
	if len(pkgs) < minDataBoundaryPackages {
		t.Fatalf("只載入 %d 個包（下限 %d）：掃描範圍已失真", len(pkgs), minDataBoundaryPackages)
	}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			t.Fatalf("包 %s 有 %d 個載入／型別錯誤（首個：%v）：守衛拒絕在殘缺的 AST 上作判定",
				p.PkgPath, len(p.Errors), p.Errors[0])
		}
	}
	exempt := map[string]bool{}
	for _, e := range dataBoundaryLiteralExemptions {
		exempt[e.File] = true
	}

	scan := dataBoundaryScan{}
	scan.Packages = len(pkgs)
	rel := func(abs string) string {
		r, err := filepath.Rel(root, abs)
		if err != nil {
			return abs
		}
		return filepath.ToSlash(r)
	}
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			path := fset.Position(f.Pos()).Filename
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			rf := rel(path)
			module := moduleOfFile(rf)
			if module == "" {
				continue
			}
			scan.Files++
			collectFileDataAccess(p.TypesInfo, fset, f, rf, module, modelTables, exempt[rf], &scan)
		}
	}
	sort.Slice(scan.Findings, func(i, j int) bool {
		a, b := scan.Findings[i], scan.Findings[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Site < b.Site
	})
	sort.Strings(scan.Unresolved)
	return scan
}

// gormChainCall 鏈上的一次方法呼叫
type gormChainCall struct {
	Name string
	Args []ast.Expr
	Pos  token.Pos
}

// collectFileDataAccess 逐檔收集：找出以 `*gorm.DB` 為接收者的呼叫鏈並解析表名。
func collectFileDataAccess(info *types.Info, fset *token.FileSet, f *ast.File, rf, module string,
	modelTables map[string]string, exempt bool, scan *dataBoundaryScan) {

	isGorm := func(e ast.Expr) bool {
		tv, ok := info.Types[e]
		if !ok || tv.Type == nil {
			return false
		}
		return strings.Contains(tv.Type.String(), "gorm.io/gorm.DB")
	}
	sr := newStringResolver(info, f)
	inner := map[ast.Node]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok || inner[ce] {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok || !isGorm(sel.X) {
			return true
		}
		// 自外向內拆鏈；ast.Inspect 先訪外層，故此處必為鏈的最外呼叫
		var chain []gormChainCall
		cur := ce
		for {
			s, ok := cur.Fun.(*ast.SelectorExpr)
			if !ok {
				break
			}
			chain = append(chain, gormChainCall{Name: s.Sel.Name, Args: cur.Args, Pos: s.Sel.Pos()})
			nextCall, ok := s.X.(*ast.CallExpr)
			if !ok {
				break
			}
			if _, ok := nextCall.Fun.(*ast.SelectorExpr); !ok {
				break
			}
			inner[nextCall] = true
			cur = nextCall
		}
		resolveChain(info, sr, fset, chain, rf, module, modelTables, exempt, scan)
		return true
	})
}

// resolveChain 由一條呼叫鏈解析出它碰到的表。
func resolveChain(info *types.Info, sr *stringResolver, fset *token.FileSet, chain []gormChainCall,
	rf, module string, modelTables map[string]string, exempt bool, scan *dataBoundaryScan) {

	site := func(pos token.Pos) string {
		return fmt.Sprintf("%s:%d", rf, fset.Position(pos).Line)
	}
	write := false
	for _, c := range chain {
		if dbBoundaryWriteMethods[c.Name] {
			write = true
		}
	}
	kindOf := func(w bool) string {
		if w {
			return "write"
		}
		return "read"
	}
	var baseType *types.Named
	add := func(table, kind, s string) {
		table = strings.TrimSpace(table)
		if table == "" {
			return
		}
		scan.Findings = append(scan.Findings, dataAccessFinding{Module: module, Table: table, Kind: kind, Site: s})
	}
	for _, c := range chain {
		switch c.Name {
		case "Table":
			if len(c.Args) == 0 {
				continue
			}
			lit, ok := sr.resolve(c.Args[0])
			if !ok {
				if !exempt {
					scan.Unresolved = append(scan.Unresolved,
						fmt.Sprintf("%s：Table() 的表名不是字面量，靜態解析不到（fail-close）", site(c.Pos)))
				}
				continue
			}
			add(firstToken(lit), kindOf(write), site(c.Pos))
		case "Raw", "Exec":
			if len(c.Args) == 0 {
				continue
			}
			lit, ok := sr.resolve(c.Args[0])
			if !ok {
				if !exempt {
					scan.Unresolved = append(scan.Unresolved,
						fmt.Sprintf("%s：%s() 的 SQL 不是字面量，靜態解析不到（fail-close）", site(c.Pos), c.Name))
				}
				continue
			}
			k := "read"
			if c.Name == "Exec" || sqlIsWrite(lit) {
				k = "write"
			}
			for _, tb := range sqlTables(lit) {
				add(tb, k, site(c.Pos))
			}
		case "Joins":
			if len(c.Args) == 0 {
				continue
			}
			lit, ok := sr.resolve(c.Args[0])
			if !ok {
				continue
			}
			if strings.Contains(strings.ToUpper(lit), "JOIN") {
				for _, tb := range sqlTables(lit) {
					add(tb, "read", site(c.Pos))
				}
				continue
			}
			for _, tb := range associationTables(baseType, lit, modelTables) {
				add(tb, "read", site(c.Pos))
			}
		case "Preload":
			if len(c.Args) == 0 {
				continue
			}
			lit, ok := sr.resolve(c.Args[0])
			if !ok {
				continue
			}
			for _, tb := range associationTables(baseType, lit, modelTables) {
				add(tb, "read", site(c.Pos))
			}
		case "Where", "Not", "Or", "Select", "Having":
			// 子查詢寫在 Where／Select 字串裡的形態：`Where("id IN (SELECT ... FROM other_table)")`。
			// 不掃它，跨模組讀取可以整段藏在條件式裡而掃描面全無感。
			if len(c.Args) == 0 {
				continue
			}
			lit, ok := sr.resolve(c.Args[0])
			if !ok {
				continue
			}
			for _, tb := range sqlTables(lit) {
				add(tb, "read", site(c.Pos))
			}
		default:
			if !dbBoundaryTypedMethods[c.Name] || len(c.Args) == 0 {
				continue
			}
			named := modelNamedType(info, c.Args[0])
			if named == nil {
				continue
			}
			if baseType == nil {
				baseType = named
			}
			tb := modelTables[named.Obj().Name()]
			if tb == "" {
				scan.Unresolved = append(scan.Unresolved,
					fmt.Sprintf("%s：model.%s 沒有對應表名（表名對照失真）", site(c.Pos), named.Obj().Name()))
				continue
			}
			k := "read"
			if dbBoundaryWriteMethods[c.Name] {
				k = "write"
			}
			add(tb, k, site(c.Pos))
		}
	}
}

// stringResolver 解析「靜態可知的字串」。
//
// 三層，缺一都會讓真實的跨模組 SQL 從掃描面上消失（實測：`subtreeSQL` 這種
// 「先賦值給區域變數再交給 Raw」的形態佔了本 repo 動態 SQL 的多數）：
//  1. `go/types` 常數摺疊——字面量、具名常數、字面量拼接；
//  2. **單一賦值的變數**——同檔內只被賦值一次的 var／`:=`，回溯其 RHS；
//  3. `+` 串接——逐段解析後接起來。
//
// 解不出即 fail-close（呼叫端登記為 Unresolved），不當作「沒有存取」。
type stringResolver struct {
	info   *types.Info
	single map[types.Object]ast.Expr // 只被賦值一次的變數 → RHS
	multi  map[types.Object]bool     // 被賦值多次者一律不解析（值不確定）
}

func newStringResolver(info *types.Info, f *ast.File) *stringResolver {
	r := &stringResolver{info: info, single: map[types.Object]ast.Expr{}, multi: map[types.Object]bool{}}
	record := func(name *ast.Ident, rhs ast.Expr) {
		obj := info.Defs[name]
		if obj == nil {
			obj = info.Uses[name]
		}
		if obj == nil {
			return
		}
		if _, seen := r.single[obj]; seen {
			r.multi[obj] = true
			return
		}
		r.single[obj] = rhs
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch st := n.(type) {
		case *ast.AssignStmt:
			if len(st.Lhs) != len(st.Rhs) {
				return true
			}
			for i, lhs := range st.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					record(id, st.Rhs[i])
				}
			}
		case *ast.ValueSpec:
			if len(st.Names) != len(st.Values) {
				return true
			}
			for i, name := range st.Names {
				record(name, st.Values[i])
			}
		}
		return true
	})
	return r
}

func (r *stringResolver) resolve(e ast.Expr) (string, bool) {
	return r.resolveDepth(e, 0)
}

func (r *stringResolver) resolveDepth(e ast.Expr, depth int) (string, bool) {
	if e == nil || depth > 8 {
		return "", false
	}
	if tv, ok := r.info.Types[e]; ok && tv.Value != nil {
		// **必須用 constant.StringVal 而非 Value.String()**（修掉的遺留缺陷）：
		// `go/constant` 的 String() 是**顯示用**表示，超過約 72 字元即截斷成
		// `"…"...`。SQL 常數動輒數百字元，截斷點之後的 FROM／JOIN 表名**整段
		// 自掃描面消失**，而守衛照樣綠——`subjectCondition` 的
		// `FROM user_group_members` 正是被截成 `user_gro` 才暴露此事。
		if tv.Value.Kind() != constant.String {
			return "", false
		}
		return constant.StringVal(tv.Value), true
	}
	switch ex := e.(type) {
	case *ast.ParenExpr:
		return r.resolveDepth(ex.X, depth+1)
	case *ast.BinaryExpr:
		if ex.Op != token.ADD {
			return "", false
		}
		l, okl := r.resolveDepth(ex.X, depth+1)
		rr, okr := r.resolveDepth(ex.Y, depth+1)
		if !okl || !okr {
			return "", false
		}
		return l + rr, true
	case *ast.Ident:
		obj := r.info.Uses[ex]
		if obj == nil {
			obj = r.info.Defs[ex]
		}
		if obj == nil || r.multi[obj] {
			return "", false
		}
		rhs, ok := r.single[obj]
		if !ok {
			return "", false
		}
		return r.resolveDepth(rhs, depth+1)
	}
	return "", false
}

// modelNamedType 解析運算式的型別，回傳 `internal/model` 內的具名型別（含指標／切片剝殼）。
func modelNamedType(info *types.Info, e ast.Expr) *types.Named {
	tv, ok := info.Types[e]
	if !ok || tv.Type == nil {
		return nil
	}
	return unwrapModelNamed(tv.Type, 0)
}

func unwrapModelNamed(t types.Type, depth int) *types.Named {
	if depth > 6 || t == nil {
		return nil
	}
	switch tt := t.(type) {
	case *types.Pointer:
		return unwrapModelNamed(tt.Elem(), depth+1)
	case *types.Slice:
		return unwrapModelNamed(tt.Elem(), depth+1)
	case *types.Array:
		return unwrapModelNamed(tt.Elem(), depth+1)
	case *types.Named:
		obj := tt.Obj()
		if obj.Pkg() == nil || !strings.HasSuffix(obj.Pkg().Path(), "/internal/model") {
			return nil
		}
		if _, ok := tt.Underlying().(*types.Struct); !ok {
			return nil
		}
		return tt
	}
	return nil
}

// associationTables 由基礎型別與關聯路徑解析出被讀到的表（含 many2many join 表）。
func associationTables(base *types.Named, path string, modelTables map[string]string) []string {
	if base == nil {
		return nil
	}
	var out []string
	cur := base
	for _, seg := range strings.Split(path, ".") {
		st, ok := cur.Underlying().(*types.Struct)
		if !ok {
			return out
		}
		var next *types.Named
		for i := 0; i < st.NumFields(); i++ {
			if st.Field(i).Name() != seg {
				continue
			}
			if m2m := many2manyTable(st.Tag(i)); m2m != "" {
				out = append(out, m2m)
			}
			next = unwrapModelNamed(st.Field(i).Type(), 0)
			break
		}
		if next == nil {
			return out
		}
		if tb := modelTables[next.Obj().Name()]; tb != "" {
			out = append(out, tb)
		}
		cur = next
	}
	return out
}

var many2manyRe = regexp.MustCompile(`many2many:([a-z_][a-z0-9_]*)`)

func many2manyTable(tag string) string {
	if m := many2manyRe.FindStringSubmatch(tag); m != nil {
		return m[1]
	}
	return ""
}

func firstToken(s string) string {
	s = strings.TrimSpace(s)
	for i, r := range s {
		if r == ' ' || r == '\t' || r == '\n' {
			return s[:i]
		}
	}
	return s
}

func sqlIsWrite(sql string) bool {
	u := strings.ToUpper(sql)
	return strings.Contains(u, "INSERT") || strings.Contains(u, "UPDATE ") ||
		strings.Contains(u, "DELETE ") || strings.Contains(u, "ALTER ") ||
		strings.Contains(u, "CREATE ") || strings.Contains(u, "DROP ")
}

// sqlCTERe 抽 CTE 名：`WITH RECURSIVE name(cols) AS (` 與後續 `, name(cols) AS (`。
var sqlCTERe = regexp.MustCompile(`(?is)(?:\bwith\s+(?:recursive\s+)?|,\s*)([a-z_][a-z0-9_]*)\s*\([^()]*\)\s*as\s*\(`)

// sqlAliasRe 抽 FROM/JOIN 後的別名：`FROM assets a`、`JOIN asset_nodes AS an`。
var sqlAliasRe = regexp.MustCompile(`(?is)\b(?:from|join)\s+"?[a-z_][a-z0-9_]*"?\s+(?:as\s+)?([a-z_][a-z0-9_]*)\b`)

// sqlAliasStopWords 別名位置上的 SQL 關鍵字（不是別名，不得排除）。
var sqlAliasStopWords = map[string]bool{
	"on": true, "where": true, "union": true, "join": true, "left": true, "right": true,
	"inner": true, "outer": true, "cross": true, "group": true, "order": true, "set": true,
	"using": true, "and": true, "or": true, "select": true, "limit": true, "having": true,
	"as": true, "values": true, "when": true, "then": true, "else": true, "end": true,
}

// sqlTables 自 SQL 抽出**真正的表名**。
//
// **必須排除 CTE 名與別名**（修掉的遺留缺陷；與 constant.StringVal 那條同源——
// 截斷修好之後，遞迴 CTE 才第一次完整進入掃描面而暴露此事）：
//   - `WITH RECURSIVE node_up(id) AS (…) … FROM node_up` 的 `node_up` 不是表；
//   - `JOIN asset_node_ancestors ana ON …` 之後的 `FROM … ana` 同理。
//
// 兩者若被當成表，`tableOwner` 會被逼著登記一堆並不存在的「表」，
// 而登記不存在的東西正是讓所有權判定失去意義的第一步。
// **排除是結構性的**（名字必須在同一段 SQL 內被定義為 CTE 或別名），
// 不是白名單——真表不會因此消失（實證：同一次掃描仍抓出 authz→asset_nodes）。
//
// **表位置上的 SQL 關鍵字同樣不是表**（auditor-workbench 修）：`ON CONFLICT (…) DO UPDATE SET x = …`
// 會讓 `update\s+(\w+)` 捕到 `set`，於是掃描器要求有人為一張不存在的表「set」登記所有者——
// 而登記不存在的東西正是上一段所述那條失效路徑。判準沿用既有的 `sqlAliasStopWords`
// （同一份 SQL 關鍵字詞彙，不新增例外語彙）：**它們是保留字，不可能是表名**，
// 故排除的是解析雜訊而非真實存取面。
func sqlTables(sql string) []string {
	local := map[string]bool{}
	for _, m := range sqlCTERe.FindAllStringSubmatch(sql, -1) {
		local[strings.ToLower(m[1])] = true
	}
	for _, m := range sqlAliasRe.FindAllStringSubmatch(sql, -1) {
		a := strings.ToLower(m[1])
		if !sqlAliasStopWords[a] {
			local[a] = true
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range sqlTableRe.FindAllStringSubmatch(sql, -1) {
		tb := strings.ToLower(m[1])
		if seen[tb] || local[tb] || sqlAliasStopWords[tb] {
			continue
		}
		seen[tb] = true
		out = append(out, tb)
	}
	return out
}

// ---- 6.0b：ratchet 判定（純函式，供突變自檢）----

// accessKey 跨模組存取的登記粒度：模組 × 表 × 讀寫。
// **刻意不含 file:line**——行號隨每次改動漂移，綁上去會讓登記表變成必改的噪音，
// 且已實證 file:line allowlist 有「移位假綠」形態（testing.md §5 形態 15）。
type accessKey struct {
	Module string
	Table  string
	Kind   string
}

// dataBoundaryVerdict ratchet 判定結果。
type dataBoundaryVerdict struct {
	UnknownTables []dataAccessFinding // 表未登記所有者
	NewCrossings  []dataAccessFinding // 未登記的跨模組存取（ratchet 方向：不准增）
	StaleEntries  []accessKey         // 登記了但現實中已不存在（移除須顯式更新）
}

// evaluateDataBoundary ratchet 的判定本體。
//
// **抽成純函式的理由與 `forbiddenEdgeViolations` 相同**：`packages.Load` 需要
// 完整 module，掃描側無法以合成樣本做突變自檢；判定側可以。三個方向各自可獨立
// 失效，故三者分開回報。
func evaluateDataBoundary(findings []dataAccessFinding, owner map[string]string,
	baseline []crossModuleAccess) dataBoundaryVerdict {

	registered := map[accessKey]bool{}
	visible := map[accessKey]bool{}
	for _, b := range baseline {
		k := accessKey{Module: b.Module, Table: b.Table, Kind: b.Kind}
		registered[k] = true
		if !b.Invisible {
			visible[k] = true
		}
	}
	var v dataBoundaryVerdict
	seen := map[accessKey]bool{}
	reportedNew := map[accessKey]bool{}
	reportedUnknown := map[string]bool{}
	for _, f := range findings {
		own, ok := owner[f.Table]
		if !ok || own == "" {
			if !reportedUnknown[f.Table] {
				reportedUnknown[f.Table] = true
				v.UnknownTables = append(v.UnknownTables, f)
			}
			continue
		}
		k := accessKey{Module: f.Module, Table: f.Table, Kind: f.Kind}
		seen[k] = true
		if own == f.Module || registered[k] {
			continue
		}
		if reportedNew[k] {
			continue
		}
		reportedNew[k] = true
		v.NewCrossings = append(v.NewCrossings, f)
	}
	for k := range visible {
		if !seen[k] {
			v.StaleEntries = append(v.StaleEntries, k)
		}
	}
	sort.Slice(v.StaleEntries, func(i, j int) bool {
		a, b := v.StaleEntries[i], v.StaleEntries[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		return a.Kind < b.Kind
	})
	return v
}

// TestModuleDataBoundaryRatchet 6.0b：跨模組資料存取只准縮不准增。
func TestModuleDataBoundaryRatchet(t *testing.T) {
	root := lifecycleModuleRoot(t)
	modelTables := modelTableNames(t, root)
	scan := scanModuleDataAccess(t, root, modelTables)

	if scan.Files < minDataBoundaryFiles {
		t.Fatalf("只有 %d 個模組歸屬檔進入掃描（下限 %d）：射程已失真，「零違規」不成立",
			scan.Files, minDataBoundaryFiles)
	}
	if len(scan.Findings) < minDataBoundaryFindings {
		t.Fatalf("只掃到 %d 處資料存取（下限 %d）：解析器已失效或掃描面歸零",
			len(scan.Findings), minDataBoundaryFindings)
	}
	if len(scan.Unresolved) > 0 {
		t.Errorf("有 %d 處表名／SQL 靜態解析不到（fail-close：解不出即視為未受管，"+
			"要嘛改成可解析的形態，要嘛列入 dataBoundaryLiteralExemptions 並指名由誰守衛）：\n  %s",
			len(scan.Unresolved), strings.Join(scan.Unresolved, "\n  "))
	}

	v := evaluateDataBoundary(scan.Findings, tableOwner, crossModuleDataAccessBaseline)
	for _, f := range v.UnknownTables {
		t.Errorf("[表未登記所有者] %s 碰到表 %q（%s）：新表出現時 SHALL 在 tableOwner 標明所屬模組，"+
			"否則跨模組判定對它整個失效", f.Module, f.Table, f.Site)
	}
	for _, f := range v.NewCrossings {
		t.Errorf("[ratchet 只准縮不准增] %s 模組直接%s他模組（%s）的表 %q，且未登記：%s\n"+
			"    正解是走對方模組的對外介面；真的無可避免時，SHALL 在 crossModuleDataAccessBaseline "+
			"補一列並寫明理由——但那是在承認一筆新的資料層債，不是通過。",
			f.Module, map[string]string{"read": "讀取", "write": "寫入"}[f.Kind],
			tableOwner[f.Table], f.Table, f.Site)
	}
	for _, k := range v.StaleEntries {
		t.Errorf("[登記項已不存在] 基線登記的 %s→%s（%s）在現實中掃不到：移除跨模組存取是好事，"+
			"但 SHALL 顯式刪除該登記列（否則白名單只會越留越寬，且下一次新增會被舊列默許）",
			k.Module, k.Table, k.Kind)
	}
}

// TestTableOwnerRegistryMatchesSchema 6.0a：登記表不得放進不存在的表。
func TestTableOwnerRegistryMatchesSchema(t *testing.T) {
	root := lifecycleModuleRoot(t)
	modelTables := modelTableNames(t, root)
	known := map[string]bool{}
	for _, tb := range modelTables {
		known[tb] = true
	}
	for tb := range nonModelTables {
		known[tb] = true
	}
	for tb := range infraTables {
		known[tb] = true
	}
	if len(known) < 40 {
		t.Fatalf("已知表只有 %d 張（現況 45+）：來源失真，本比對無意義", len(known))
	}
	for tb, owner := range tableOwner {
		if !known[tb] {
			t.Errorf("[登記→現實] tableOwner 登記的 %q（歸 %s）不對應任何 model 型別、join 表或基礎設施表："+
				"幽靈登記會讓真正的新表誤以為已受管", tb, owner)
		}
		if owner == "" {
			t.Errorf("tableOwner[%q] 的模組為空字串", tb)
		}
	}
	if len(tableOwner) < 40 {
		t.Fatalf("tableOwner 只登記 %d 張表（現況 45）：登記表縮水後未登記的表會直接失去守衛",
			len(tableOwner))
	}
}

// TestDataBoundaryVerdictMutation 判定側的突變自檢：三個方向各自要抓得到。
//
// **這是本守衛「會紅得起來」的證明**——掃描側需要完整 module 故無法造樣本，
// 判定側餵合成資料即可。任一方向失效，主測試的「零違規」就沒有意義。
func TestDataBoundaryVerdictMutation(t *testing.T) {
	owner := map[string]string{"assets": "asset", "users": "identity", "audit_logs": "audit"}
	baseline := []crossModuleAccess{
		{Module: "audit", Table: "assets", Kind: "read", Reason: "合成"},
		{Module: "keyvault", Table: "users", Kind: "write", Invisible: true, Reason: "合成：掃描器看不見"},
		{Module: "policy", Table: "users", Kind: "read", Reason: "合成：現實中已消失"},
	}
	findings := []dataAccessFinding{
		{Module: "asset", Table: "assets", Kind: "write", Site: "合成:1"},  // 自有表，不計
		{Module: "audit", Table: "assets", Kind: "read", Site: "合成:2"},   // 已登記，不計
		{Module: "asset", Table: "users", Kind: "read", Site: "合成:3"},    // 未登記的新跨模組讀
		{Module: "asset", Table: "sessions", Kind: "read", Site: "合成:4"}, // 表未登記所有者
	}
	v := evaluateDataBoundary(findings, owner, baseline)

	if len(v.NewCrossings) != 1 || v.NewCrossings[0].Table != "users" {
		t.Fatalf("未登記的新跨模組存取沒被抓到（實得 %v）：ratchet 的「不准增」已失效", v.NewCrossings)
	}
	if len(v.UnknownTables) != 1 || v.UnknownTables[0].Table != "sessions" {
		t.Fatalf("未登記所有者的表沒被抓到（實得 %v）", v.UnknownTables)
	}
	if len(v.StaleEntries) != 1 || v.StaleEntries[0].Module != "policy" {
		t.Fatalf("已不存在的登記項沒被抓到（實得 %v）：移除將不需要顯式更新登記表", v.StaleEntries)
	}
	// 反向：乾淨輸入必須零命中（否則主測試會恆紅、久之被放寬）
	clean := []dataAccessFinding{
		{Module: "asset", Table: "assets", Kind: "write", Site: "合成:5"},
		{Module: "audit", Table: "assets", Kind: "read", Site: "合成:6"},
		{Module: "policy", Table: "users", Kind: "read", Site: "合成:7"},
	}
	cv := evaluateDataBoundary(clean, owner, baseline)
	if len(cv.NewCrossings)+len(cv.UnknownTables)+len(cv.StaleEntries) != 0 {
		t.Fatalf("乾淨輸入被誤判為違規：%+v", cv)
	}
	// Invisible 登記項不得因掃不到而被判為過期（它本來就掃不到）
	if len(cv.StaleEntries) != 0 {
		t.Fatalf("Invisible 登記項被誤判為過期：%v", cv.StaleEntries)
	}
}
