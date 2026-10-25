package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/middleware"
)

// ---- 批次出口 ----

// batchFixtureItem 批次 fixture 的一筆；名稱與節點名用來斷言回應不外露。
type batchFixtureItem struct {
	id         uint
	name, node string
	state      string // ok／out_of_scope／missing／unauthorized
}

func batchFixture() []batchFixtureItem {
	return []batchFixtureItem{
		{731901, "fixture-host-alpha", "fixture-node-east", "ok"},
		{731902, "fixture-host-bravo", "fixture-node-east", "ok"},
		{731911, "fixture-host-charlie", "fixture-node-west", "out_of_scope"},
		{731912, "fixture-host-delta", "fixture-node-west", "out_of_scope"},
		{731921, "", "", "missing"},
		{731922, "", "", "missing"},
		{731931, "fixture-host-echo", "fixture-node-north", "unauthorized"},
		{731932, "fixture-host-foxtrot", "fixture-node-north", "unauthorized"},
	}
}

// runBatchOutletSubtests 以測試 handler 呼叫批次出口：同筆數下混入三種無法操作 ID 的回應逐位元相同。
func runBatchOutletSubtests(t *testing.T) {
	fx := batchFixture()
	byID := map[uint]batchFixtureItem{}
	for _, it := range fx {
		byID[it.id] = it
	}
	// 測試 handler：數出請求中無法操作的筆數（不分原因），只把筆數交出口
	handler := func(ids []uint) gin.HandlerFunc {
		return func(c *gin.Context) {
			n := 0
			for _, id := range ids {
				if it, ok := byID[id]; !ok || it.state != "ok" {
					n++
				}
			}
			if n > 0 {
				middleware.RespondBatchUnavailable(c, n)
				return
			}
			c.JSON(http.StatusOK, gin.H{"reached": true})
		}
	}
	mixes := map[string][]uint{
		"範圍外": {731901, 731902, 731911, 731912},
		"不存在": {731901, 731902, 731921, 731922},
		"無權":  {731901, 731902, 731931, 731932},
	}
	var first string
	for _, name := range []string{"範圍外", "不存在", "無權"} {
		pr := scopeOutletServe(t, handler(mixes[name]))
		assert.Equal(t, http.StatusNotFound, pr.code, "%s：%s", name, pr.raw)
		if first == "" {
			first = pr.raw
		}
		assert.Equal(t, first, pr.raw, "%s：三種原因的回應須逐位元相同", name)
		keys := make([]string, 0, len(pr.body))
		for k := range pr.body {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		assert.Equal(t, []string{"code", "error", "params"}, keys, name)
		assert.Equal(t, "NOTFOUND_BATCH_ITEMS_UNAVAILABLE", pr.body["code"], name)
		assert.Equal(t, map[string]any{"count": float64(2)}, pr.body["params"], "%s：params 只有 count 且等於無法操作筆數", name)
		assert.Equal(t, "2 筆項目無法操作", pr.body["error"], name)
		for _, it := range fx {
			assert.NotContains(t, pr.raw, strconv.Itoa(int(it.id)), "%s：回應不得含 fixture ID", name)
			if it.name != "" {
				assert.NotContains(t, pr.raw, it.name, name)
				assert.NotContains(t, pr.raw, it.node, name)
			}
		}
		require.True(t, pr.hasScope, "%s：須留範圍拒絕標記", name)
		assert.Equal(t, map[string]string{"denial": "scope", "scope_reason": "batch_items_unavailable", "count": "2"},
			pr.scope.AuditDetails(), name)
		assert.False(t, pr.hasCap, name)
	}
	// 筆數確實進回應：三筆無法操作時 count 為 3
	pr := scopeOutletServe(t, handler([]uint{731911, 731921, 731931}))
	assert.Equal(t, map[string]any{"count": float64(3)}, pr.body["params"])
	assert.Equal(t, "3", pr.scope.AuditDetails()["count"])
}

// ---- AST：生產碼傳給出口的種類常數皆已登記 ----

const (
	authzImportPath      = "github.com/custodexa/backend/internal/modules/authz"
	middlewareImportPath = "github.com/custodexa/backend/internal/middleware"
)

// scopeKindIndex authz 的種類與層常數值、目標建構函式對應的種類，以及對照表已登記者。
type scopeKindIndex struct {
	kinds        map[string]string // 常數名 → 值（ScopeTargetKind）
	layers       map[string]string // 常數名 → 值（ScopeDeniedLayer）
	constructors map[string]string // 函式名 → 種類值
	pairs        map[string]bool   // "kind/layer"
	regKinds     map[string]bool
}

func backendRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(root, "internal", "modules", "authz"))
	require.NoError(t, err, "backend 根定位失效")
	return root
}

func loadScopeKindIndex(t *testing.T, root string) scopeKindIndex {
	t.Helper()
	idx := scopeKindIndex{kinds: map[string]string{}, layers: map[string]string{}, constructors: map[string]string{},
		pairs: map[string]bool{}, regKinds: map[string]bool{}}
	dir := filepath.Join(root, "internal", "modules", "authz")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		require.NoError(t, err)
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				if d.Tok != token.CONST {
					continue
				}
				for _, s := range d.Specs {
					vs := s.(*ast.ValueSpec)
					typ, ok := vs.Type.(*ast.Ident)
					if !ok {
						continue
					}
					for i, n := range vs.Names {
						if i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						v, _ := strconv.Unquote(lit.Value)
						switch typ.Name {
						case "ScopeTargetKind":
							idx.kinds[n.Name] = v
						case "ScopeDeniedLayer":
							idx.layers[n.Name] = v
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil || d.Type.Results == nil || len(d.Type.Results.List) != 1 {
					continue
				}
				if rt, ok := d.Type.Results.List[0].Type.(*ast.Ident); !ok || rt.Name != "ScopeTarget" {
					continue
				}
				ast.Inspect(d.Body, func(n ast.Node) bool {
					kv, ok := n.(*ast.KeyValueExpr)
					if !ok {
						return true
					}
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Kind" {
						if v, ok := kv.Value.(*ast.Ident); ok {
							idx.constructors[d.Name.Name] = v.Name // 先記常數名，下面換成值
						}
					}
					return true
				})
			}
		}
	}
	for fn, cn := range idx.constructors {
		idx.constructors[fn] = idx.kinds[cn]
	}
	require.GreaterOrEqual(t, len(idx.kinds), 3, "種類常數解析過少（防假綠）")
	require.GreaterOrEqual(t, len(idx.layers), 4, "層常數解析過少（防假綠）")
	require.GreaterOrEqual(t, len(idx.constructors), 3, "目標建構函式解析過少（防假綠）")
	for _, r := range middleware.ScopeNotFoundRegistrations() {
		idx.pairs[string(r.Kind)+"/"+string(r.Layer)] = true
		idx.regKinds[string(r.Kind)] = true
	}
	return idx
}

// scopeKindScan 一個檔案的掃描結果：違規（行號 → 說明）與出口呼叫數。
type scopeKindScan struct {
	violations  map[int]string
	outletCalls int
}

// scanScopeKinds 掃一個檔案。pkgIsMiddleware 為真時，裸名 RespondTargetNotFound 也算出口呼叫。
//
// 規則：
//   - RespondTargetNotFound 的種類與層必須是 authz 具名常數，且（種類, 層）已登記。
//   - authz.NewErrScopeDenied 與 authz.ErrScopeDenied{...} 的種類與層同上（層非常數時只查種類）。
//   - 其餘出現的種類常數、目標建構函式（AssetTarget 等），其種類須至少登記一列。
//   - authz.ScopeTargetKind(...) 轉型（動態種類）一律違規。
func scanScopeKinds(fset *token.FileSet, f *ast.File, idx scopeKindIndex, pkgIsMiddleware bool) scopeKindScan {
	out := scopeKindScan{violations: map[int]string{}}
	authzName, mwName := "", ""
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch p {
		case authzImportPath:
			if name == "" {
				name = "authz"
			}
			authzName = name
		case middlewareImportPath:
			if name == "" {
				name = "middleware"
			}
			mwName = name
		}
	}
	if authzName == "" {
		return out
	}
	flag := func(n ast.Node, msg string) {
		line := fset.Position(n.Pos()).Line
		if _, ok := out.violations[line]; !ok {
			out.violations[line] = msg
		}
	}
	authzSel := func(e ast.Expr) (string, bool) {
		s, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		x, ok := s.X.(*ast.Ident)
		if !ok || x.Name != authzName {
			return "", false
		}
		return s.Sel.Name, true
	}
	kindOf := func(e ast.Expr) (string, bool) {
		if n, ok := authzSel(e); ok {
			v, ok := idx.kinds[n]
			return v, ok
		}
		return "", false
	}
	layerOf := func(e ast.Expr) (string, bool) {
		if n, ok := authzSel(e); ok {
			v, ok := idx.layers[n]
			return v, ok
		}
		return "", false
	}
	checkPair := func(n ast.Node, kindE, layerE ast.Expr, requireLayer bool) {
		k, ok := kindOf(kindE)
		if !ok {
			flag(n, "種類不是 authz 具名常數")
			return
		}
		l, ok := layerOf(layerE)
		if !ok {
			if requireLayer {
				flag(n, "層不是 authz 具名常數")
			} else if !idx.regKinds[k] {
				flag(n, "種類未登記："+k)
			}
			return
		}
		if !idx.pairs[k+"/"+l] {
			flag(n, "（種類, 層）未登記："+k+"/"+l)
		}
	}
	isOutlet := func(fun ast.Expr) bool {
		switch fn := fun.(type) {
		case *ast.SelectorExpr:
			x, ok := fn.X.(*ast.Ident)
			return ok && mwName != "" && x.Name == mwName && fn.Sel.Name == "RespondTargetNotFound"
		case *ast.Ident:
			return pkgIsMiddleware && fn.Name == "RespondTargetNotFound"
		}
		return false
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if isOutlet(n.Fun) {
				out.outletCalls++
				if len(n.Args) != 3 {
					flag(n, "出口參數數不符")
					return true
				}
				checkPair(n, n.Args[1], n.Args[2], true)
				return true
			}
			name, ok := authzSel(n.Fun)
			if !ok {
				return true
			}
			switch {
			case name == "NewErrScopeDenied" && len(n.Args) >= 2:
				checkPair(n, n.Args[0], n.Args[1], false)
			case name == "ScopeTargetKind":
				flag(n, "動態種類轉型")
			default:
				if k, ok := idx.constructors[name]; ok && !idx.regKinds[k] {
					flag(n, "目標建構函式的種類未登記："+k)
				}
			}
		case *ast.CompositeLit:
			if name, ok := authzSel(n.Type); ok && name == "ErrScopeDenied" {
				var kindE, layerE ast.Expr
				for _, el := range n.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok {
							switch k.Name {
							case "Kind":
								kindE = kv.Value
							case "Layer":
								layerE = kv.Value
							}
						}
					}
				}
				checkPair(n, kindE, layerE, false)
			}
		case *ast.SelectorExpr:
			if name, ok := authzSel(n); ok {
				if k, ok := idx.kinds[name]; ok && !idx.regKinds[k] {
					flag(n, "種類未登記："+k)
				}
			}
		}
		return true
	})
	return out
}

func runScopeKindASTSubtests(t *testing.T) {
	root := backendRoot(t)
	idx := loadScopeKindIndex(t, root)
	authzDir := filepath.Join(root, "internal", "modules", "authz")
	mwDir := filepath.Join(root, "internal", "middleware")

	t.Run("生產碼", func(t *testing.T) {
		fset := token.NewFileSet()
		var violations []string
		outletCalls, files := 0, 0
		for _, sub := range []string{"internal", "cmd"} {
			err := filepath.WalkDir(filepath.Join(root, sub), func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					if p == authzDir || strings.HasPrefix(p, authzDir+string(filepath.Separator)) || d.Name() == "testdata" {
						return filepath.SkipDir
					}
					return nil
				}
				if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
					return nil
				}
				f, err := parser.ParseFile(fset, p, nil, 0)
				if err != nil {
					return err
				}
				files++
				res := scanScopeKinds(fset, f, idx, filepath.Dir(p) == mwDir)
				outletCalls += res.outletCalls
				rel, _ := filepath.Rel(root, p)
				for line, msg := range res.violations {
					violations = append(violations, fmt.Sprintf("%s:%d %s", rel, line, msg))
				}
				return nil
			})
			require.NoError(t, err)
		}
		sort.Strings(violations)
		assert.Empty(t, violations, "生產碼傳給出口的種類須已登記")
		assert.Greater(t, files, 500, "掃描檔數過少（防假綠）")
		// 資產與帳號 handler 的真不存在分支（8 處）皆經出口
		assert.GreaterOrEqual(t, outletCalls, 8, "出口呼叫數過少（防假綠）")
		t.Logf("掃描 %d 檔、出口呼叫 %d 處", files, outletCalls)
	})

	t.Run("合成反例", func(t *testing.T) {
		src := `package fake

import (
	"github.com/custodexa/backend/internal/middleware"
	az "github.com/custodexa/backend/internal/modules/authz"
)

func f(c any, k az.ScopeTargetKind, l az.ScopeDeniedLayer) {
	middleware.RespondTargetNotFound(c, az.ScopeTargetNode, az.ScopeLayerAsset)
	middleware.RespondTargetNotFound(c, k, az.ScopeLayerAsset)
	middleware.RespondTargetNotFound(c, az.ScopeTargetAssetAccount, az.ScopeLayerNode)
	middleware.RespondTargetNotFound(c, az.ScopeTargetAsset, l)
	_ = az.LaterTarget(1)
	_ = az.NewErrScopeDenied(az.ScopeTargetNode, az.ScopeLayerAsset, az.ScopeReasonOutOfScope)
	_ = &az.ErrScopeDenied{Kind: az.ScopeTargetKind("later"), Layer: az.ScopeLayerTarget}
	_ = az.NewErrScopeDenied(az.ScopeTargetAsset, az.ScopeLayerAccount, az.ScopeReasonOutOfScope)
	middleware.RespondTargetNotFound(c, az.ScopeTargetAsset, az.ScopeLayerAsset)
	middleware.RespondTargetNotFound(c, az.ScopeTargetAssetAccount, az.ScopeLayerAccount)
	middleware.RespondTargetNotFound(c, az.ScopeTargetNode, az.ScopeLayerNode)
	_ = az.AssetAccountTarget(1, 2)
	_ = az.NodeTarget(1)
	_ = az.NewErrScopeDenied(az.ScopeTargetAssetAccount, az.ScopeLayerAsset, az.ScopeReasonOutOfScope)
}
`
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "fake.go", src, 0)
		require.NoError(t, err)
		// 內建種類（資產、帳號、節點、憑證）皆已登記，沒有未登記種類的真實建構函式：
		// 以索引複本加一個假的未登記種類建構函式，檢驗「目標建構函式的種類未登記」這條規則仍會報
		synth := idx
		synth.constructors = make(map[string]string, len(idx.constructors)+1)
		for k, v := range idx.constructors {
			synth.constructors[k] = v
		}
		synth.constructors["LaterTarget"] = "later"
		require.False(t, synth.regKinds["later"], "假種類不得已登記")
		res := scanScopeKinds(fset, f, synth, false)
		var lines []int
		for l := range res.violations {
			lines = append(lines, l)
		}
		sort.Ints(lines)
		// 第 9–16 行為反例（8 行），第 17–22 行為已登記的正例（含節點種類）
		assert.Equal(t, []int{9, 10, 11, 12, 13, 14, 15, 16}, lines, "違規：%v", res.violations)
		assert.Equal(t, 7, res.outletCalls)
	})
}
