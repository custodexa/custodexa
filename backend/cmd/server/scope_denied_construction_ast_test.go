package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

// 範圍拒絕值只經判定器取得（型別守衛，掛在 TestScopeDenialOutlet）。
//
// 帳號目標的拒絕層次（資產層或帳號層）只能由判定器給出；生產碼若自行建構拒絕值、
// 或改寫判定器回傳的拒絕值，就能把「資產在範圍外」寫成「帳號不存在」，洩漏範圍外資產的存在。
//
// 射程：internal/、cmd/ 下全部非測試套件一律型別檢查（不以語法預篩），依建置條件分批載入，
// 並斷言磁碟上每個非測試 .go 檔至少被型別檢查一次。判定一律以解析後的型別為準
// （別名、點匯入、省略型別的元素字面值、提升欄位都看得到）。以下任一即違規：
//   - 引用 NewErrScopeDenied（呼叫或取函式值）；authz 套件內只允許判定器本身，見例外表。
//   - 型別為 ErrScopeDenied 或其指標的複合字面值（含省略型別）、轉換、new。
//   - 以 ErrScopeDenied 值型別宣告變數、型別別名或定義、結構欄位（含嵌入），或以它實體化泛型。
//   - 對 ErrScopeDenied 任一欄位賦值、遞增減、取址，不論經指標、解參照、值複本或嵌入提升。
//   - 以 = 整值覆寫 ErrScopeDenied 值（含 range 賦值）；:= 複製與傳遞指標不算。
// 不在射程內：經 reflect 寫入欄位（經 unsafe 轉成 *ErrScopeDenied 仍會被報為轉換）。

const scopeDeniedTypeName = "ErrScopeDenied"

// scopeDeniedException 例外只限 authz 內的建構路徑；每一筆須恰好命中一次（防過期、防新增呼叫點）。
type scopeDeniedException struct {
	fn, rule, reason string
}

var scopeDeniedExceptions = []scopeDeniedException{
	{fn: "NewErrScopeDenied", rule: "composite", reason: "建構函式本身"},
	{fn: "(*ScopeEvaluator).DecideWithDenial", rule: "constructor-ref", reason: "判定器以判定得出的種類、層與原因組出拒絕值"},
}

// scopeDeniedBuild 一組建置條件；後一組只載入前面仍未涵蓋到的檔案所在套件。
type scopeDeniedBuild struct {
	name  string
	env   []string
	flags []string
}

var scopeDeniedBuilds = []scopeDeniedBuild{
	{name: "linux+loopback", env: []string{"GOOS=linux", "CGO_ENABLED=0"}, flags: []string{"-tags=loopback"}},
	{name: "darwin+loopback", env: []string{"GOOS=darwin", "CGO_ENABLED=0"}, flags: []string{"-tags=loopback"}},
}

type scopeDeniedHit struct {
	line      int
	rule, msg string
	fn        string
}

func isScopeDeniedValue(t types.Type) bool {
	if t == nil {
		return false
	}
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return false
	}
	return n.Obj().Name() == scopeDeniedTypeName && n.Obj().Pkg().Path() == authzImportPath
}

// isScopeDeniedType 值或指標。
func isScopeDeniedType(t types.Type) bool {
	if t == nil {
		return false
	}
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		return isScopeDeniedValue(p.Elem())
	}
	return isScopeDeniedValue(t)
}

func derefStruct(t types.Type) (*types.Struct, bool) {
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	st, ok := t.Underlying().(*types.Struct)
	return st, ok
}

// scopeDeniedFieldOf 選取式是否落在 ErrScopeDenied 的欄位上（沿嵌入路徑找出欄位所屬的結構，不看最外層接收者）。
func scopeDeniedFieldOf(info *types.Info, e ast.Expr) (string, bool) {
	s, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	sel, ok := info.Selections[s]
	if !ok || sel.Kind() != types.FieldVal {
		return "", false
	}
	owner := sel.Recv()
	idx := sel.Index()
	for _, i := range idx[:len(idx)-1] {
		st, ok := derefStruct(owner)
		if !ok {
			return "", false
		}
		owner = st.Field(i).Type()
	}
	return s.Sel.Name, isScopeDeniedType(owner)
}

func isBlankIdent(e ast.Expr) bool {
	id, ok := ast.Unparen(e).(*ast.Ident)
	return ok && id.Name == "_"
}

func scopeDeniedFuncName(info *types.Info, fd *ast.FuncDecl) string {
	fn, ok := info.Defs[fd.Name].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return fd.Name.Name
	}
	return strings.ReplaceAll(fn.FullName(), fn.Pkg().Path()+".", "")
}

// scopeDeniedTypedScan 一個已型別檢查的檔案中的違規（依頂層宣告記下所在函式）。
func scopeDeniedTypedScan(fset *token.FileSet, info *types.Info, f *ast.File) []scopeDeniedHit {
	var out []scopeDeniedHit
	for _, decl := range f.Decls {
		fn := ""
		if fd, ok := decl.(*ast.FuncDecl); ok {
			fn = scopeDeniedFuncName(info, fd)
		}
		flag := func(n ast.Node, rule, msg string) {
			out = append(out, scopeDeniedHit{line: fset.Position(n.Pos()).Line, rule: rule, msg: msg, fn: fn})
		}
		write := func(e ast.Expr, verb string) {
			if name, ok := scopeDeniedFieldOf(info, e); ok {
				flag(e, "field-write", verb+"拒絕值的 "+name)
			}
		}
		whole := func(e ast.Expr) {
			if e != nil && !isBlankIdent(e) && isScopeDeniedValue(info.TypeOf(e)) {
				flag(e, "whole-assign", "整值覆寫拒絕值")
			}
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				if obj, ok := info.Uses[n].(*types.Func); ok && obj.Name() == "NewErrScopeDenied" &&
					obj.Pkg() != nil && obj.Pkg().Path() == authzImportPath {
					flag(n, "constructor-ref", "引用 NewErrScopeDenied（拒絕值須經判定器取得）")
				}
				if inst, ok := info.Instances[n]; ok {
					for i := 0; i < inst.TypeArgs.Len(); i++ {
						if isScopeDeniedValue(inst.TypeArgs.At(i)) {
							flag(n, "instance", "以 ErrScopeDenied 值型別實體化泛型（零值即建構）")
						}
					}
				}
			case *ast.CompositeLit:
				if isScopeDeniedType(info.TypeOf(n)) {
					flag(n, "composite", "ErrScopeDenied 複合字面值")
				}
			case *ast.CallExpr:
				if tv, ok := info.Types[n.Fun]; ok && tv.IsType() && isScopeDeniedType(tv.Type) {
					flag(n, "conversion", "轉換成 ErrScopeDenied")
				}
				if id, ok := ast.Unparen(n.Fun).(*ast.Ident); ok && len(n.Args) == 1 {
					if b, ok := info.Uses[id].(*types.Builtin); ok && b.Name() == "new" && isScopeDeniedType(info.TypeOf(n.Args[0])) {
						flag(n, "new", "new(ErrScopeDenied)")
					}
				}
			case *ast.ValueSpec:
				if n.Type != nil && isScopeDeniedValue(info.TypeOf(n.Type)) {
					flag(n, "value-var", "以 ErrScopeDenied 值型別宣告變數（零值即建構）")
				}
			case *ast.TypeSpec:
				if isScopeDeniedValue(info.TypeOf(n.Type)) {
					flag(n, "type-decl", "以 ErrScopeDenied 為底的型別別名或定義")
				}
			case *ast.StructType:
				for _, fld := range n.Fields.List {
					if isScopeDeniedValue(info.TypeOf(fld.Type)) {
						flag(fld, "value-field", "結構以值持有 ErrScopeDenied（零值即建構，欄位可經提升改寫）")
					}
				}
			case *ast.AssignStmt:
				for _, l := range n.Lhs {
					write(l, "賦值")
					if n.Tok == token.ASSIGN {
						whole(l)
					}
				}
			case *ast.RangeStmt:
				if n.Tok == token.ASSIGN {
					for _, l := range []ast.Expr{n.Key, n.Value} {
						if l != nil {
							write(l, "range 賦值")
							whole(l)
						}
					}
				}
			case *ast.IncDecStmt:
				write(n.X, "遞增減")
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					write(n.X, "取址")
				}
			}
			return true
		})
	}
	return out
}

// 合成反例以 overlay 加進生產套件（磁碟上不存在，測試先確認），與真實 authz 一起型別檢查。
// 標「// 報」的行須恰好各被報一次，其餘行不得被報。
const scopeDeniedCounterexampleSrc = `package middleware

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	az "github.com/custodexa/backend/internal/modules/authz"
)

type zzDeny = az.ErrScopeDenied // 報

type zzOther struct{ Kind, Layer string }

func zzCounterexamples(c *gin.Context, ev *az.ScopeEvaluator, tx *gorm.DB, p *az.Principal) {
	RespondScopeDenied(c, az.NewErrScopeDenied(az.ScopeTargetAssetAccount, az.ScopeLayerAccount, az.ScopeReasonOutOfScope)) // 報
	_, d, _ := ev.DecideWithDenial(tx, p, az.PermAssetUpdate, az.AssetAccountTarget(1, 2))
	if d == nil {
		return
	}
	d.Layer = az.ScopeLayerAccount // 報
	(*d).Kind = az.ScopeTargetAssetAccount // 報
	RespondScopeDenied(c, &az.ErrScopeDenied{Kind: az.ScopeTargetAsset, Layer: az.ScopeLayerAsset}) // 報
	_ = new(az.ErrScopeDenied) // 報
	_ = &zzDeny{} // 報
	mk := az.NewErrScopeDenied // 報
	_ = mk
	var zero az.ErrScopeDenied // 報
	_ = zero
	v := *d
	v.Layer = az.ScopeLayerAsset // 報
	k := &d.Kind // 報
	_ = k
	o := zzOther{}
	o.Kind, o.Layer = "x", "y" // 不報
	_ = d.Reason // 不報
	var pass *az.ErrScopeDenied = d // 不報
	RespondScopeDenied(c, pass) // 不報
}
`

// 放在只轉傳拒絕值、未寫過其欄位的生產套件：省略型別、轉換、嵌入提升、整值覆寫等形態。
const scopeDeniedCounterexampleShapesSrc = `package sshproxy

import (
	"errors"

	az "github.com/custodexa/backend/internal/modules/authz"
)

type zzFake struct {
	Kind   az.ScopeTargetKind
	Layer  az.ScopeDeniedLayer
	Reason az.ScopeReason
}

type zzWrap struct{ az.ErrScopeDenied } // 報

type zzWrapP struct{ *az.ErrScopeDenied } // 不報

type zzHolder struct{ d *az.ErrScopeDenied } // 不報

func zzZero[T any]() (z T) { return z }

func zzShapeCounterexamples(err error, other *az.ErrScopeDenied) error {
	var d *az.ErrScopeDenied // 不報
	if !errors.As(err, &d) { // 不報
		return err
	}
	_ = []*az.ErrScopeDenied{{Kind: az.ScopeTargetAssetAccount, Layer: az.ScopeLayerAccount, Reason: az.ScopeReasonOutOfScope}} // 報
	_ = map[string]az.ErrScopeDenied{"x": {Kind: az.ScopeTargetAssetAccount, Layer: az.ScopeLayerAccount}} // 報
	_ = (*az.ErrScopeDenied)(&zzFake{Kind: az.ScopeTargetAssetAccount, Layer: az.ScopeLayerAccount}) // 報
	_ = az.ErrScopeDenied(zzFake{Layer: az.ScopeLayerAccount}) // 報
	var w zzWrap // 不報
	w.Layer = az.ScopeLayerAccount // 報
	w.ErrScopeDenied = *other // 報
	wp := zzWrapP{other} // 不報
	wp.Kind = az.ScopeTargetAssetAccount // 報
	_ = &wp.ErrScopeDenied.Layer // 報
	*d = *other // 報
	d.Reason = az.ScopeReasonOutOfScope // 報
	var tmp az.ErrScopeDenied // 報
	for _, tmp = range []az.ErrScopeDenied{} { // 報
	}
	_ = zzZero[az.ErrScopeDenied]() // 報
	cp := *d // 不報
	_ = cp.Kind // 不報
	h := zzHolder{d: d} // 不報
	var e error = h.d // 不報
	_ = tmp
	return e
}
`

// 點匯入：型別判定不依賴限定名。
const scopeDeniedCounterexampleDotSrc = `package sshproxy

import . "github.com/custodexa/backend/internal/modules/authz"

func zzDotCounterexamples() error {
	_ = NewErrScopeDenied(ScopeTargetAssetAccount, ScopeLayerAccount, ScopeReasonOutOfScope) // 報
	return &ErrScopeDenied{Layer: ScopeLayerAccount} // 報
}
`

type scopeDeniedCounterexample struct {
	dir, file, src string
	marks          int
	fragments      []string // 須出現且被報的指名形態
}

var scopeDeniedCounterexamples = []scopeDeniedCounterexample{
	{dir: "internal/middleware", file: "zz_scope_denied_counterexample.go", src: scopeDeniedCounterexampleSrc, marks: 11,
		fragments: []string{"az.NewErrScopeDenied(az.ScopeTargetAssetAccount, az.ScopeLayerAccount", "d.Layer = az.ScopeLayerAccount"}},
	{dir: "internal/sshproxy", file: "zz_scope_denied_counterexample.go", src: scopeDeniedCounterexampleShapesSrc, marks: 14,
		fragments: []string{
			"_ = []*az.ErrScopeDenied{{",              // 省略型別的元素字面值
			`_ = map[string]az.ErrScopeDenied{"x": {`, // map 值省略型別
			"_ = (*az.ErrScopeDenied)(&zzFake{",       // 同欄位結構轉換
			"w.Layer = az.ScopeLayerAccount",          // 嵌入欄位提升寫入
			"*d = *other",                             // 整值覆寫
		}},
	{dir: "internal/sshproxy", file: "zz_scope_denied_counterexample_dot.go", src: scopeDeniedCounterexampleDotSrc, marks: 2},
}

type scopeDeniedFindings struct {
	production     []string
	exceptionHits  map[int]int
	counterexample map[string]map[int][]string // overlay 路徑 → 行 → 命中規則
	uncovered      []string
	files, typed   int
	loads          []string
}

// scopeDeniedDiskFiles internal/、cmd/ 下所有非測試 .go 檔（go 工具忽略的目錄與檔名除外）。
func scopeDeniedDiskFiles(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, sub := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, sub), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() {
				if name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") &&
				!strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "_") {
				out[p] = true
			}
			return nil
		})
		require.NoError(t, err)
	}
	return out
}

func scopeDeniedExceptionIndex(h scopeDeniedHit) int {
	for i, e := range scopeDeniedExceptions {
		if e.fn == h.fn && e.rule == h.rule {
			return i
		}
	}
	return -1
}

func collectScopeDeniedFindings(t *testing.T) scopeDeniedFindings {
	t.Helper()
	root := backendRoot(t)
	res := scopeDeniedFindings{exceptionHits: map[int]int{}, counterexample: map[string]map[int][]string{}}
	overlay := map[string][]byte{}
	for _, cx := range scopeDeniedCounterexamples {
		p := filepath.Join(root, filepath.FromSlash(cx.dir), cx.file)
		_, statErr := os.Stat(p)
		require.True(t, os.IsNotExist(statErr), "反例檔只能以 overlay 存在：%s", p)
		overlay[p] = []byte(cx.src)
		res.counterexample[p] = map[int][]string{}
	}

	disk := scopeDeniedDiskFiles(t, root)
	scanned := map[string]bool{}
	prod := map[string][]string{}
	patterns := []string{"./internal/...", "./cmd/..."}
	mode := packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes |
		packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps
	for _, b := range scopeDeniedBuilds {
		if len(patterns) == 0 {
			break
		}
		start := time.Now()
		pkgs, err := packages.Load(&packages.Config{Mode: mode, Dir: root, Tests: false,
			Env: append(os.Environ(), b.env...), BuildFlags: b.flags, Overlay: overlay}, patterns...)
		require.NoError(t, err)
		var loadErrs []string
		packages.Visit(pkgs, nil, func(p *packages.Package) {
			for _, e := range p.Errors {
				loadErrs = append(loadErrs, fmt.Sprintf("%s: %v", p.PkgPath, e))
			}
		})
		require.Empty(t, loadErrs, "%s 型別檢查有錯，守衛無法信任其結果", b.name)
		for _, pkg := range pkgs {
			if len(pkg.GoFiles) == 0 {
				continue // 只有測試檔的套件
			}
			require.NotNil(t, pkg.TypesInfo, "%s 未取得型別資訊（防假綠）", pkg.PkgPath)
			require.Len(t, pkg.Syntax, len(pkg.GoFiles), "%s 語法樹數與檔數不符（防假綠）", pkg.PkgPath)
			res.typed++
			for _, f := range pkg.Syntax {
				path := pkg.Fset.Position(f.Pos()).Filename
				if scanned[path] {
					continue
				}
				scanned[path] = true
				hits := scopeDeniedTypedScan(pkg.Fset, pkg.TypesInfo, f)
				if cx, ok := res.counterexample[path]; ok {
					for _, h := range hits {
						cx[h.line] = append(cx[h.line], h.rule)
					}
					continue
				}
				res.files++
				rel, _ := filepath.Rel(root, path)
				for _, h := range hits {
					if pkg.PkgPath == authzImportPath {
						if i := scopeDeniedExceptionIndex(h); i >= 0 {
							res.exceptionHits[i]++
							continue
						}
					}
					k := fmt.Sprintf("%s:%d", filepath.ToSlash(rel), h.line)
					prod[k] = append(prod[k], h.rule+" "+h.msg)
				}
			}
		}
		res.loads = append(res.loads, fmt.Sprintf("%s：%d 個套件、%v", b.name, len(pkgs), time.Since(start).Round(time.Millisecond)))
		// 下一組建置條件只補載入仍未涵蓋的檔案所在套件
		dirs := map[string]bool{}
		for p := range disk {
			if !scanned[p] {
				rel, _ := filepath.Rel(root, filepath.Dir(p))
				dirs["./"+filepath.ToSlash(rel)] = true
			}
		}
		patterns = patterns[:0]
		for d := range dirs {
			patterns = append(patterns, d)
		}
		sort.Strings(patterns)
	}
	for p := range disk {
		if !scanned[p] {
			rel, _ := filepath.Rel(root, p)
			res.uncovered = append(res.uncovered, filepath.ToSlash(rel))
		}
	}
	sort.Strings(res.uncovered)
	for k, msgs := range prod {
		res.production = append(res.production, k+" "+strings.Join(msgs, "；"))
	}
	sort.Strings(res.production)
	return res
}

func runScopeDeniedConstructionSubtests(t *testing.T) {
	start := time.Now()
	res := collectScopeDeniedFindings(t)
	t.Logf("型別檢查 %d 個套件、%d 個生產檔，總耗時 %v（%s）", res.typed, res.files,
		time.Since(start).Round(time.Millisecond), strings.Join(res.loads, "；"))

	t.Run("生產碼", func(t *testing.T) {
		assert.Empty(t, res.production, "生產碼不得建構或改寫範圍拒絕值")
		assert.Empty(t, res.uncovered, "下列非測試檔未被任何一組建置條件型別檢查（射程缺口）")
		assert.Greater(t, res.files, 700, "型別檢查的檔數過少（防假綠）")
		// 現況 47 個生產套件目錄，第二組建置條件再補 3 個（只有 !linux 檔的差異）
		assert.GreaterOrEqual(t, res.typed, 40, "型別檢查的套件數過少（防假綠）")
		for i, e := range scopeDeniedExceptions {
			assert.Equal(t, 1, res.exceptionHits[i], "例外須恰好命中一次（過期或新增呼叫點）：%s %s（%s）", e.fn, e.rule, e.reason)
		}
	})

	t.Run("合成反例", func(t *testing.T) {
		root := backendRoot(t)
		total := 0
		for _, cx := range scopeDeniedCounterexamples {
			path := filepath.Join(root, filepath.FromSlash(cx.dir), cx.file)
			got := res.counterexample[path]
			lines := strings.Split(cx.src, "\n")
			var want, gotLines []int
			for i, l := range lines {
				if strings.HasSuffix(l, "// 報") {
					want = append(want, i+1)
				}
			}
			for l, rules := range got {
				gotLines = append(gotLines, l)
				assert.Len(t, rules, 1, "%s/%s:%d 須恰好被報一次：%v", cx.dir, cx.file, l, rules)
			}
			sort.Ints(gotLines)
			require.Len(t, want, cx.marks, "%s/%s 反例標記數（防假綠）", cx.dir, cx.file)
			assert.Equal(t, want, gotLines, "%s/%s 報出行須等於標記行：%v", cx.dir, cx.file, got)
			total += len(want)
			for _, frag := range cx.fragments {
				found := false
				for i, l := range lines {
					if strings.Contains(l, frag) {
						found = true
						assert.NotEmpty(t, got[i+1], "須被報：%s", frag)
					}
				}
				assert.True(t, found, "反例原文缺：%s", frag)
			}
		}
		assert.Equal(t, 27, total, "反例總數")
	})
}
