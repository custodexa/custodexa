package main

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

// 範圍化輸出的結構性守衛（型別守衛）。
//
// 契約：internal/api 內，受保護型別（帳號列、輪替與成員、改密紀錄與目標、候選）的輸出，
// 只能經投影函式換形，再由 respondScoped 寫出。規則碼：
//   - SR1 來源登錄：呼叫來源方法的函式必須是登錄出口、投影集合成員或豁免。
//   - SR2 唯讀允許清單：受檢函式內，gin.Context 上只能用允許清單的選擇子；gin.Context 值只能交給登錄的函式。
//   - SR3 密封建構：scopedOutput 與投影專屬輸出型別的字面值、轉換、密封欄位存取只能出現在投影集合內。
//   - SR4 不得逃逸成介面：受保護型別的運算式不得流入介面型別的位置（投影集合與豁免除外）。
//   - SR5 不得轉手：投影集合以外，受保護型別的運算式作為呼叫引數時，被呼叫者必須是投影集合、
//     len／cap／append／copy 或豁免。
//   - R 反向與下限：登錄表每列都對得到函式、出口必呼叫 respondScoped、允許清單名稱真實存在、掃描範圍有下限。
//
// 不防清單：
//   - 在登錄出口內把受保護型別的欄位逐一抄成新值，再塞進既有錯誤出口的細節參數
//     （含以 2xx 狀態碼呼叫錯誤出口）；由各出口的序列化原文測試與程式審查承擔。
//   - 以 reflect 或 unsafe 建構或讀取。
//   - internal/api 以外直接寫 HTTP 回應（本專案的 HTTP 出口只在 internal/api）。

type sgViolation struct {
	Rule string
	File string // 相對 backend 根
	Line int
	Msg  string
}

func (v sgViolation) String() string {
	if v.File == "" {
		return fmt.Sprintf("%s %s", v.Rule, v.Msg)
	}
	return fmt.Sprintf("%s %s:%d %s", v.Rule, v.File, v.Line, v.Msg)
}

type sgRegistry struct {
	exits       []api.ScopedOutputExit
	projections []api.ScopedOutputProjection
	consumers   []api.ContextConsumer
	allow       []api.ScopedOutputContextAllowEntry
	exceptions  []api.ScopedOutputContextException
	exemptions  []api.ScopedOutputExemption
	ownTypes    []string
	protected   []string
	sources     []string
}

func sgLoadRegistry() sgRegistry {
	return sgRegistry{
		exits:       api.ScopedOutputExits(),
		projections: api.ScopedOutputProjections(),
		consumers:   api.ContextConsumers(),
		allow:       api.ScopedOutputContextAllow(),
		exceptions:  api.ScopedOutputContextExceptions(),
		exemptions:  api.ScopedOutputExemptions(),
		ownTypes:    api.ScopedOutputOwnTypes(),
		protected:   api.ScopedOutputProtectedTypes(),
		sources:     api.ScopedOutputSources(),
	}
}

type sgStats struct {
	pkgs               int
	outsideSelectors   int
	exits              int
	projections        int
	projEntries        int
	consumersWrite     int
	consumersRead      int
	allow              int
	exceptions         int
	exemptions         int
	checkedFns         int
	allowChecked       int
	sourceCalls        int
	protectedArgChecks int
}

const (
	sgGinPath = "github.com/gin-gonic/gin"
	sgAPISuf  = "/internal/api"
)

type sgChecker struct {
	root string
	pkg  *packages.Package
	info *types.Info
	reg  sgRegistry

	exitKeys    map[string]bool
	projKeys    map[string]string // key -> kind
	consWrite   map[string]bool
	consRead    map[string]bool
	exemptKeys  map[string]bool
	sourceKeys  map[string]bool
	allowNames  map[string]bool
	ownNames    map[string]bool
	protNames   map[string]bool
	memo        map[types.Type]bool
	ginContext  *types.Named
	violations  []sgViolation
	seen        map[string]bool
	stats       sgStats
	declKeys    map[string]*ast.FuncDecl
	fnExceptKey map[string][]api.ScopedOutputContextException
}

func sgFuncKey(fn *types.Func) string {
	prefix := ""
	if p := fn.Pkg(); p != nil && !strings.HasSuffix(p.Path(), sgAPISuf) {
		prefix = p.Name() + "."
	}
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		t := sig.Recv().Type()
		if p, ok := types.Unalias(t).(*types.Pointer); ok {
			t = p.Elem()
		}
		if n, ok := types.Unalias(t).(*types.Named); ok {
			return prefix + n.Obj().Name() + "." + fn.Name()
		}
	}
	return prefix + fn.Name()
}

func (g *sgChecker) add(rule string, pos token.Pos, msg string) {
	p := g.pkg.Fset.Position(pos)
	rel, err := filepath.Rel(g.root, p.Filename)
	if err != nil {
		rel = p.Filename
	}
	v := sgViolation{Rule: rule, File: filepath.ToSlash(rel), Line: p.Line, Msg: msg}
	k := v.String()
	if g.seen[k] {
		return
	}
	g.seen[k] = true
	g.violations = append(g.violations, v)
}

func (g *sgChecker) addGlobal(rule, msg string) {
	v := sgViolation{Rule: rule, Msg: msg}
	if g.seen[v.String()] {
		return
	}
	g.seen[v.String()] = true
	g.violations = append(g.violations, v)
}

func sgIsIface(t types.Type) bool {
	if t == nil {
		return false
	}
	if _, tp := types.Unalias(t).(*types.TypeParam); tp {
		return false
	}
	return types.IsInterface(t)
}

func (g *sgChecker) isProtected(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if v, ok := g.memo[t]; ok {
		return v
	}
	g.memo[t] = false // 循環型別先視為否
	r := false
	switch x := t.(type) {
	case *types.Named:
		o := x.Obj()
		if o.Pkg() != nil && g.protNames[o.Pkg().Name()+"."+o.Name()] {
			r = true
		} else {
			r = g.isProtected(x.Underlying())
		}
	case *types.Pointer:
		r = g.isProtected(x.Elem())
	case *types.Slice:
		r = g.isProtected(x.Elem())
	case *types.Array:
		r = g.isProtected(x.Elem())
	case *types.Map:
		r = g.isProtected(x.Elem())
	case *types.Struct:
		for i := 0; i < x.NumFields(); i++ {
			if g.isProtected(x.Field(i).Type()) {
				r = true
				break
			}
		}
	}
	g.memo[t] = r
	return r
}

func (g *sgChecker) isGinContext(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	n, ok := t.(*types.Named)
	return ok && n.Obj().Name() == "Context" && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == sgGinPath
}

func (g *sgChecker) isOwnType(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil || !strings.HasSuffix(n.Obj().Pkg().Path(), sgAPISuf) {
		return false
	}
	return g.ownNames[n.Obj().Name()]
}

func (g *sgChecker) callee(call *ast.CallExpr) *types.Func {
	fun := ast.Unparen(call.Fun)
	switch f := fun.(type) {
	case *ast.IndexExpr:
		fun = ast.Unparen(f.X)
	case *ast.IndexListExpr:
		fun = ast.Unparen(f.X)
	}
	switch f := fun.(type) {
	case *ast.Ident:
		fn, _ := g.info.Uses[f].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		if sel := g.info.Selections[f]; sel != nil {
			fn, _ := sel.Obj().(*types.Func)
			return fn
		}
		fn, _ := g.info.Uses[f.Sel].(*types.Func)
		return fn
	}
	return nil
}

func (g *sgChecker) isConversion(call *ast.CallExpr) bool {
	tv, ok := g.info.Types[call.Fun]
	return ok && tv.IsType()
}

func (g *sgChecker) builtinName(call *ast.CallExpr) string {
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if b, ok := g.info.Uses[id].(*types.Builtin); ok {
			return b.Name()
		}
	}
	return ""
}

func sgParamType(sig *types.Signature, i int, ellipsis bool) types.Type {
	n := sig.Params().Len()
	if n == 0 {
		return nil
	}
	if sig.Variadic() && i >= n-1 {
		last := sig.Params().At(n - 1).Type()
		if ellipsis {
			return last
		}
		if s, ok := last.(*types.Slice); ok {
			return s.Elem()
		}
		return nil
	}
	if i < n {
		return sig.Params().At(i).Type()
	}
	return nil
}

func newSGChecker(root string, pkg *packages.Package, reg sgRegistry) *sgChecker {
	g := &sgChecker{root: root, pkg: pkg, info: pkg.TypesInfo, reg: reg,
		exitKeys: map[string]bool{}, projKeys: map[string]string{}, consWrite: map[string]bool{},
		consRead: map[string]bool{}, exemptKeys: map[string]bool{}, sourceKeys: map[string]bool{},
		allowNames: map[string]bool{}, ownNames: map[string]bool{}, protNames: map[string]bool{},
		memo: map[types.Type]bool{}, seen: map[string]bool{}, declKeys: map[string]*ast.FuncDecl{},
		fnExceptKey: map[string][]api.ScopedOutputContextException{}}
	for _, e := range reg.exits {
		g.exitKeys[e.Fn] = true
	}
	for _, p := range reg.projections {
		g.projKeys[p.Fn] = p.Kind
	}
	for _, c := range reg.consumers {
		if c.Mode == api.ConsumerWrite {
			g.consWrite[c.Fn] = true
		} else {
			g.consRead[c.Fn] = true
		}
	}
	for _, e := range reg.exemptions {
		g.exemptKeys[e.Fn] = true
	}
	for _, s := range reg.sources {
		g.sourceKeys[s] = true
	}
	for _, a := range reg.allow {
		g.allowNames[a.Name] = true
	}
	for _, n := range reg.ownTypes {
		g.ownNames[n] = true
	}
	for _, n := range reg.protected {
		g.protNames[n] = true
	}
	for _, x := range reg.exceptions {
		g.fnExceptKey[x.Fn] = append(g.fnExceptKey[x.Fn], x)
	}
	for _, imp := range pkg.Types.Imports() {
		if imp.Path() == sgGinPath {
			if o, ok := imp.Scope().Lookup("Context").(*types.TypeName); ok {
				g.ginContext, _ = o.Type().(*types.Named)
			}
		}
	}
	return g
}

// run 掃描整個套件並回傳全部違規。
func (g *sgChecker) run() {
	g.stats.pkgs = 1
	g.stats.exits = len(g.reg.exits)
	g.stats.projections = len(g.reg.projections)
	for _, p := range g.reg.projections {
		if p.Kind == api.ProjectionEntry {
			g.stats.projEntries++
		}
	}
	g.stats.consumersWrite = len(g.consWrite)
	g.stats.consumersRead = len(g.consRead)
	g.stats.allow = len(g.reg.allow)
	g.stats.exceptions = len(g.reg.exceptions)
	g.stats.exemptions = len(g.reg.exemptions)

	var decls []*ast.FuncDecl
	for _, f := range g.pkg.Syntax {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			obj, _ := g.info.Defs[fd.Name].(*types.Func)
			if obj == nil {
				continue
			}
			g.declKeys[sgFuncKey(obj)] = fd
			decls = append(decls, fd)
		}
	}
	g.checkReverse()
	for _, fd := range decls {
		obj, _ := g.info.Defs[fd.Name].(*types.Func)
		g.checkFunc(sgFuncKey(obj), fd)
	}
	g.checkFloors()
}

func (g *sgChecker) isChecked(key string) bool {
	if g.exitKeys[key] {
		return true
	}
	if _, ok := g.projKeys[key]; ok {
		return key != "respondScoped"
	}
	return g.consRead[key] && g.declKeys[key] != nil
}

func (g *sgChecker) checkFunc(key string, fd *ast.FuncDecl) {
	if fd.Body == nil {
		return
	}
	checked := g.isChecked(key)
	_, inProj := g.projKeys[key]
	skipFlow := inProj || g.exemptKeys[key]
	if checked {
		g.stats.checkedFns++
	}
	var stack []ast.Node
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		g.visit(key, n, stack, checked, inProj, skipFlow)
		return true
	})
}

func (g *sgChecker) parent(stack []ast.Node, up int) ast.Node {
	i := len(stack) - 1 - up
	if i < 0 {
		return nil
	}
	return stack[i]
}

func (g *sgChecker) visit(key string, n ast.Node, stack []ast.Node, checked, inProj, skipFlow bool) {
	// 全包掃描：清單外的 gin.Context 選擇子數（下限用）
	if sel, ok := n.(*ast.SelectorExpr); ok && g.isGinContext(g.info.TypeOf(sel.X)) && !g.allowNames[sel.Sel.Name] {
		g.stats.outsideSelectors++
	}

	switch x := n.(type) {
	case *ast.CallExpr:
		g.visitCall(key, x, checked, inProj, skipFlow)
	case *ast.SelectorExpr:
		g.visitSelector(key, x, stack, checked, inProj)
	case *ast.Ident:
		if checked {
			g.visitGinIdent(key, x, stack)
		}
	case *ast.CompositeLit:
		g.visitCompositeLit(x, inProj, skipFlow)
	case *ast.AssignStmt:
		if !skipFlow && x.Tok == token.ASSIGN && len(x.Lhs) == len(x.Rhs) {
			for i, r := range x.Rhs {
				if g.isProtected(g.info.TypeOf(r)) && sgIsIface(g.info.TypeOf(x.Lhs[i])) {
					g.add("SR4", r.Pos(), "受保護型別指派到介面型別的位置")
				}
			}
		}
	case *ast.ValueSpec:
		if !skipFlow && x.Type != nil && sgIsIface(g.info.TypeOf(x.Type)) {
			for _, v := range x.Values {
				if g.isProtected(g.info.TypeOf(v)) {
					g.add("SR4", v.Pos(), "受保護型別宣告到介面型別的變數")
				}
			}
		}
	case *ast.ReturnStmt:
		if !skipFlow {
			g.visitReturn(x, stack)
		}
	case *ast.SendStmt:
		if !skipFlow {
			if ch, ok := types.Unalias(g.info.TypeOf(x.Chan)).Underlying().(*types.Chan); ok &&
				sgIsIface(ch.Elem()) && g.isProtected(g.info.TypeOf(x.Value)) {
				g.add("SR4", x.Value.Pos(), "受保護型別送入介面型別的 channel")
			}
		}
	}
}

func (g *sgChecker) visitReturn(r *ast.ReturnStmt, stack []ast.Node) {
	var sig *types.Signature
	for i := len(stack) - 1; i >= 0; i-- {
		switch f := stack[i].(type) {
		case *ast.FuncLit:
			sig, _ = g.info.TypeOf(f).(*types.Signature)
		}
		if sig != nil {
			break
		}
	}
	if sig == nil {
		// 外層為 FuncDecl：以 Defs 取簽章
		for _, f := range g.pkg.Syntax {
			if r.Pos() < f.Pos() || r.Pos() > f.End() {
				continue
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if ok && fd.Body != nil && r.Pos() >= fd.Body.Pos() && r.Pos() <= fd.Body.End() {
					if o, ok := g.info.Defs[fd.Name].(*types.Func); ok {
						sig, _ = o.Type().(*types.Signature)
					}
				}
			}
		}
	}
	if sig == nil || sig.Results().Len() != len(r.Results) {
		return
	}
	for i, e := range r.Results {
		if sgIsIface(sig.Results().At(i).Type()) && g.isProtected(g.info.TypeOf(e)) {
			g.add("SR4", e.Pos(), "受保護型別回傳到介面型別的結果")
		}
	}
}

func (g *sgChecker) visitCompositeLit(cl *ast.CompositeLit, inProj, skipFlow bool) {
	t := g.info.TypeOf(cl)
	if t == nil {
		return
	}
	if !inProj && g.isOwnType(t) {
		g.add("SR3", cl.Pos(), "投影專屬輸出型別的複合字面值出現在投影集合外")
	}
	if skipFlow {
		return
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Struct:
		for i, e := range cl.Elts {
			var ft types.Type
			val := e
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				val = kv.Value
				if id, ok := kv.Key.(*ast.Ident); ok {
					for j := 0; j < u.NumFields(); j++ {
						if u.Field(j).Name() == id.Name {
							ft = u.Field(j).Type()
						}
					}
				}
			} else if i < u.NumFields() {
				ft = u.Field(i).Type()
			}
			if sgIsIface(ft) && g.isProtected(g.info.TypeOf(val)) {
				g.add("SR4", val.Pos(), "受保護型別放入介面型別的欄位")
			}
		}
	case *types.Slice:
		g.checkElems(cl, u.Elem(), nil)
	case *types.Array:
		g.checkElems(cl, u.Elem(), nil)
	case *types.Map:
		g.checkElems(cl, u.Elem(), u.Key())
	}
}

func (g *sgChecker) checkElems(cl *ast.CompositeLit, elem, key types.Type) {
	for _, e := range cl.Elts {
		val := e
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			val = kv.Value
			if key != nil && sgIsIface(key) && g.isProtected(g.info.TypeOf(kv.Key)) {
				g.add("SR4", kv.Key.Pos(), "受保護型別作為介面型別的 map 鍵")
			}
		}
		if sgIsIface(elem) && g.isProtected(g.info.TypeOf(val)) {
			g.add("SR4", val.Pos(), "受保護型別放入介面型別的元素")
		}
	}
}

func (g *sgChecker) visitCall(key string, call *ast.CallExpr, checked, inProj, skipFlow bool) {
	if g.isConversion(call) {
		if !inProj && g.isOwnType(g.info.TypeOf(call.Fun)) {
			g.add("SR3", call.Pos(), "投影專屬輸出型別的轉換出現在投影集合外")
		}
		if !skipFlow && len(call.Args) == 1 && sgIsIface(g.info.TypeOf(call.Fun)) && g.isProtected(g.info.TypeOf(call.Args[0])) {
			g.add("SR4", call.Args[0].Pos(), "受保護型別轉成介面型別")
		}
		return
	}
	fn := g.callee(call)
	var ckey string
	if fn != nil {
		ckey = sgFuncKey(fn)
	}
	// SR1
	if ckey != "" && g.sourceKeys[ckey] {
		g.stats.sourceCalls++
		_, isProj := g.projKeys[key]
		if !g.exitKeys[key] && !isProj && !g.exemptKeys[key] {
			g.add("SR1", call.Pos(), fmt.Sprintf("%s 呼叫來源方法 %s，但不是登錄出口、投影集合成員或豁免", key, ckey))
		}
	}
	if skipFlow {
		return
	}
	bname := g.builtinName(call)
	sig, _ := types.Unalias(g.info.TypeOf(call.Fun)).Underlying().(*types.Signature)
	for i, a := range call.Args {
		if tv, ok := g.info.Types[a]; ok && tv.IsType() {
			continue // make／new 的型別引數
		}
		at := g.info.TypeOf(a)
		if !g.isProtected(at) {
			continue
		}
		g.stats.protectedArgChecks++
		// SR4：引數對應的參數是介面
		if bname == "append" {
			if i >= 1 {
				if s, ok := types.Unalias(g.info.TypeOf(call.Args[0])).Underlying().(*types.Slice); ok &&
					!call.Ellipsis.IsValid() && sgIsIface(s.Elem()) {
					g.add("SR4", a.Pos(), "受保護型別附加到介面型別的 slice")
				}
			}
		} else if sig != nil {
			if pt := sgParamType(sig, i, call.Ellipsis.IsValid()); sgIsIface(pt) {
				g.add("SR4", a.Pos(), "受保護型別流入介面型別的參數")
			}
		}
		// SR5：被呼叫者必須是投影集合、內建、豁免
		switch bname {
		case "len", "cap", "append", "copy":
			continue
		}
		_, isProj := g.projKeys[ckey]
		if ckey == "" || (!isProj && !g.exemptKeys[ckey]) {
			name := ckey
			if name == "" {
				name = "（無法解析的被呼叫者）"
			}
			g.add("SR5", a.Pos(), fmt.Sprintf("受保護型別交給投影集合外的 %s", name))
		}
	}
}

func (g *sgChecker) visitSelector(key string, sel *ast.SelectorExpr, stack []ast.Node, checked, inProj bool) {
	// SR3：scopedOutput 的 body 欄位
	if !inProj {
		if s := g.info.Selections[sel]; s != nil && s.Kind() == types.FieldVal && sel.Sel.Name == "body" && g.isOwnType(s.Recv()) {
			g.add("SR3", sel.Pos(), "密封欄位 body 的存取出現在投影集合外")
		}
	}
	if !checked || !g.isGinContext(g.info.TypeOf(sel.X)) {
		return
	}
	g.stats.allowChecked++
	name := sel.Sel.Name
	for _, ex := range g.fnExceptKey[key] {
		if ex.Name != name {
			continue
		}
		if ex.OnlyArgOf == "" {
			return
		}
		if call, ok := g.parent(stack, 1).(*ast.CallExpr); ok && len(call.Args) > 0 && call.Args[0] == ast.Expr(sel) {
			if fn := g.callee(call); fn != nil && sgFuncKey(fn) == ex.OnlyArgOf {
				return
			}
		}
		g.add("SR2", sel.Pos(), fmt.Sprintf("c.%s 只能作為 %s 的第一個引數", name, ex.OnlyArgOf))
		return
	}
	if !g.allowNames[name] {
		g.add("SR2", sel.Pos(), fmt.Sprintf("c.%s 不在唯讀允許清單內，視為寫出", name))
		return
	}
	if name == "Request" {
		// 只讀：出現在指派左側、自增減或取址即違規
		switch p := g.parent(stack, 1).(type) {
		case *ast.AssignStmt:
			for _, l := range p.Lhs {
				if l == ast.Expr(sel) {
					g.add("SR2", sel.Pos(), "c.Request 不得被指派")
				}
			}
		case *ast.IncDecStmt:
			g.add("SR2", sel.Pos(), "c.Request 不得被修改")
		case *ast.UnaryExpr:
			if p.Op == token.AND {
				g.add("SR2", sel.Pos(), "c.Request 不得取址")
			}
		}
	}
}

// visitGinIdent gin.Context 值的去向：只能是允許清單選擇子的接收者，或登錄函式的呼叫引數。
func (g *sgChecker) visitGinIdent(key string, id *ast.Ident, stack []ast.Node) {
	v, ok := g.info.Uses[id].(*types.Var)
	if !ok || !g.isGinContext(v.Type()) {
		return
	}
	switch p := g.parent(stack, 1).(type) {
	case *ast.SelectorExpr:
		if p.X == ast.Expr(id) {
			return
		}
	case *ast.CallExpr:
		for _, a := range p.Args {
			if a == ast.Expr(id) {
				fn := g.callee(p)
				if fn != nil {
					ck := sgFuncKey(fn)
					_, isProj := g.projKeys[ck]
					if isProj || g.consWrite[ck] || g.consRead[ck] {
						return
					}
					g.add("SR2", id.Pos(), fmt.Sprintf("gin.Context 交給名單外的 %s", ck))
					return
				}
				g.add("SR2", id.Pos(), "gin.Context 交給無法解析的被呼叫者")
				return
			}
		}
	case *ast.BinaryExpr:
		if p.Op == token.EQL || p.Op == token.NEQ {
			return
		}
	}
	g.add("SR2", id.Pos(), "gin.Context 值被存放、回傳或轉手（只能作為登錄函式的引數）")
}

func (g *sgChecker) checkReverse() {
	respond := g.declKeys["respondScoped"]
	for _, e := range g.reg.exits {
		fd := g.declKeys[e.Fn]
		if fd == nil {
			g.addGlobal("R", fmt.Sprintf("登錄出口 %s 找不到對應函式", e.Fn))
			continue
		}
		target := "respondScoped"
		if e.Via != "" {
			target = e.Via
			if g.declKeys[e.Via] == nil {
				g.addGlobal("R", fmt.Sprintf("出口 %s 的 Via %s 找不到對應函式", e.Fn, e.Via))
				continue
			}
			if !g.callsKey(g.declKeys[e.Via], "respondScoped") {
				g.addGlobal("R", fmt.Sprintf("Via 函式 %s 未呼叫 respondScoped", e.Via))
			}
		}
		if !g.callsKey(fd, target) {
			g.addGlobal("R", fmt.Sprintf("登錄出口 %s 未呼叫 %s", e.Fn, target))
		}
	}
	if respond == nil {
		g.addGlobal("R", "找不到 respondScoped")
	}
	for _, p := range g.reg.projections {
		fd := g.declKeys[p.Fn]
		if fd == nil {
			g.addGlobal("R", fmt.Sprintf("投影集合成員 %s 找不到對應函式", p.Fn))
			continue
		}
		if p.Kind == api.ProjectionEntry && p.Fn != "respondScoped" && !g.returnsScoped(fd) {
			g.addGlobal("R", fmt.Sprintf("投影進入點 %s 未回傳 scopedOutput", p.Fn))
		}
	}
	for _, c := range g.reg.consumers {
		if strings.Contains(c.Fn, ".") && !strings.HasPrefix(c.Fn, "middleware.") && !strings.HasPrefix(c.Fn, "apierror.") &&
			g.declKeys[c.Fn] == nil {
			g.addGlobal("R", fmt.Sprintf("ContextConsumers 列 %s 找不到對應函式", c.Fn))
		}
		if !strings.Contains(c.Fn, ".") && g.declKeys[c.Fn] == nil {
			g.addGlobal("R", fmt.Sprintf("ContextConsumers 列 %s 找不到對應函式", c.Fn))
		}
	}
	for _, e := range g.reg.exemptions {
		if g.declKeys[e.Fn] == nil {
			g.addGlobal("R", fmt.Sprintf("豁免 %s 找不到對應函式", e.Fn))
		}
	}
	for _, x := range g.reg.exceptions {
		if g.declKeys[x.Fn] == nil {
			g.addGlobal("R", fmt.Sprintf("逐函式例外 %s 找不到對應函式", x.Fn))
		}
	}
	if g.ginContext == nil {
		g.addGlobal("R", "找不到 gin.Context 型別")
		return
	}
	ptr := types.NewPointer(g.ginContext)
	for _, a := range g.reg.allow {
		obj, _, _ := types.LookupFieldOrMethod(ptr, true, g.ginContext.Obj().Pkg(), a.Name)
		if obj == nil {
			g.addGlobal("R", fmt.Sprintf("允許清單名稱 %s 不是 gin.Context 的方法或欄位", a.Name))
			continue
		}
		_, isVar := obj.(*types.Var)
		if isVar != a.Field {
			g.addGlobal("R", fmt.Sprintf("允許清單名稱 %s 的欄位／方法種類與登錄不符", a.Name))
		}
	}
	for _, x := range g.reg.exceptions {
		if obj, _, _ := types.LookupFieldOrMethod(ptr, true, g.ginContext.Obj().Pkg(), x.Name); obj == nil {
			g.addGlobal("R", fmt.Sprintf("逐函式例外名稱 %s 不是 gin.Context 的方法或欄位", x.Name))
		}
	}
}

func (g *sgChecker) callsKey(fd *ast.FuncDecl, target string) bool {
	found := false
	ast.Inspect(fd, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if fn := g.callee(call); fn != nil && sgFuncKey(fn) == target {
				found = true
			}
		}
		return !found
	})
	return found
}

func (g *sgChecker) returnsScoped(fd *ast.FuncDecl) bool {
	obj, _ := g.info.Defs[fd.Name].(*types.Func)
	if obj == nil {
		return false
	}
	sig := obj.Type().(*types.Signature)
	if sig.Results().Len() == 0 {
		return false
	}
	return g.isOwnType(sig.Results().At(0).Type()) && sig.Results().At(0).Type().String() != "" &&
		strings.HasSuffix(sig.Results().At(0).Type().String(), "scopedOutput")
}

func (g *sgChecker) checkFloors() {
	if g.stats.outsideSelectors < 100 {
		g.addGlobal("R", fmt.Sprintf("全包清單外 gin.Context 選擇子只掃到 %d 處（下限 100），掃描範圍可能縮小", g.stats.outsideSelectors))
	}
	if len(g.reg.exits) != 18 {
		g.addGlobal("R", fmt.Sprintf("登錄出口 %d 列，應為 18（帳號列 6、輪替 5、改密 7）", len(g.reg.exits)))
	}
	if len(g.reg.exemptions) > 5 {
		g.addGlobal("R", fmt.Sprintf("豁免 %d 列，超過上限 5", len(g.reg.exemptions)))
	}
}

func sgSort(vs []sgViolation) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].File != vs[j].File {
			return vs[i].File < vs[j].File
		}
		if vs[i].Line != vs[j].Line {
			return vs[i].Line < vs[j].Line
		}
		return vs[i].Rule < vs[j].Rule
	})
}

// checkScopedOutputs 判定的純函式：收集全部違規後一次回傳。
func checkScopedOutputs(root string, pkg *packages.Package, reg sgRegistry) ([]sgViolation, sgStats) {
	g := newSGChecker(root, pkg, reg)
	g.run()
	sgSort(g.violations)
	return g.violations, g.stats
}

func sgLoadAPI(t *testing.T, root string, overlay map[string][]byte) *packages.Package {
	t.Helper()
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
		packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo
	pkgs, err := packages.Load(&packages.Config{Mode: mode, Dir: root, Tests: false, Overlay: overlay}, "./internal/api")
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	return pkgs[0]
}

func sgPkgErrors(pkg *packages.Package) []string {
	var errs []string
	for _, e := range pkg.Errors {
		errs = append(errs, e.Error())
	}
	return errs
}

func sgHashFiles(t *testing.T, root string, rels []string) string {
	t.Helper()
	sort.Strings(rels)
	var sb strings.Builder
	for _, rel := range rels {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		require.NoError(t, err)
		fmt.Fprintf(&sb, "%x  %s\n", sha256.Sum256(b), rel)
	}
	return sb.String()
}

func TestScopedOutputProjectionGuard(t *testing.T) {
	root := backendRoot(t)
	reg := sgLoadRegistry()
	pkg := sgLoadAPI(t, root, nil)
	require.Empty(t, sgPkgErrors(pkg), "internal/api 型別檢查有錯，守衛無法信任其結果")
	require.NotNil(t, pkg.TypesInfo)

	vs, st := checkScopedOutputs(root, pkg, reg)
	t.Logf("載入套件 %d 個", st.pkgs)
	t.Logf("全包清單外 gin.Context 選擇子 %d 處", st.outsideSelectors)
	t.Logf("登錄出口 %d 列、投影集合 %d 列（進入點 %d）", st.exits, st.projections, st.projEntries)
	t.Logf("ContextConsumers 寫出 %d 列、唯讀 %d 列", st.consumersWrite, st.consumersRead)
	t.Logf("允許清單 %d 列（逐一經 types.LookupFieldOrMethod 確認存在）、逐函式例外 %d 列、豁免 %d 列", st.allow, st.exceptions, st.exemptions)
	t.Logf("受檢函式 %d 個、受檢 gin.Context 選擇子 %d 處、來源方法呼叫 %d 處、受保護型別引數 %d 處",
		st.checkedFns, st.allowChecked, st.sourceCalls, st.protectedArgChecks)
	if len(vs) > 0 {
		var sb strings.Builder
		for _, v := range vs {
			sb.WriteString("\n  " + v.String())
		}
		assert.Fail(t, "守衛違規", "共 %d 筆：%s", len(vs), sb.String())
	}
	assert.Len(t, reg.exits, 18)
	assert.Len(t, reg.allow, 7)
	assert.Len(t, reg.exceptions, 2)
	assert.GreaterOrEqual(t, st.outsideSelectors, 100)
}

// ---- 突變證據 ----

type sgEdit struct{ file, anchor, repl string }

type sgExpect struct {
	rule   string
	file   string // 空字串＝只要求規則碼出現（全域違規）
	marker string // 注入行（或既有行）內的唯一子字串
	exact  bool   // 該行的違規規則集合必須恰為 rule
}

type sgMutation struct {
	name     string
	edits    []sgEdit
	newFiles map[string]string // 檔名（internal/api 下）-> 內容
	registry func(sgRegistry) sgRegistry
	expect   []sgExpect
}

const sgAPIDir = "internal/api/"

func sgReplaceOnce(t *testing.T, src, anchor, repl string) (string, int) {
	t.Helper()
	if n := strings.Count(src, anchor); n != 1 {
		require.Failf(t, "MUTATION-ANCHOR", "錨點取代次數為 %d（應為 1）：%.60q", n, anchor)
	}
	i := strings.Index(src, anchor)
	return src[:i] + repl + src[i+len(anchor):], i
}

func sgLineOf(src string, offset int) int { return strings.Count(src[:offset], "\n") + 1 }

const sgEmitAnySrc = `package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func emitAny(c *gin.Context, v any) { c.JSON(http.StatusOK, v) }
`

const sgLaunderSrc = `package api

import "github.com/custodexa/backend/internal/modules/asset"

func launder(a *asset.AssetAccountDTO) map[string]string {
	return map[string]string{"n": a.CredentialName}
}
`

const sgGetBatchCopySrc = `package api

import (
	"net/http"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/gin-gonic/gin"
)

func (h *ChangeSecretHandler) GetBatchCopy(c *gin.Context) {
	ctx, viewer := batchViewer(c)
	batch, records, err := h.batches.DetailFor(ctx, viewer, 1)
	if err != nil {
		respondBatchError(c, apierror.CodeInternalChangeSecretBatchQuery, err)
		return
	}
	batchDTO := newBatchDTO(batch)
	out, err := h.projectRecords(accountContext(c), records, func(rows []changeSecretRecordDTO) any {
		return gin.H{"data": gin.H{"batch": batchDTO, "records": rows}}
	})
	if err != nil {
		respondBatchError(c, apierror.CodeInternalChangeSecretBatchQuery, err)
		return
	}
	respondScoped(c, http.StatusOK, out)
}
`

const sgForgeSrc = `package api

import "github.com/custodexa/backend/internal/model"

func forge(r []model.ChangeSecretRecord) scopedOutput { return scopedOutput{body: r} }
`

func sgAccountChunk(code, status string) string {
	return "\tout, perr := h.accountProjector().one(c, account)\n" +
		"\tif perr != nil {\n" +
		"\t\trespondAccountError(c, apierror.CodeInternalAssetAccount" + code + ", perr)\n" +
		"\t\treturn\n" +
		"\t}\n" +
		"\trespondScoped(c, http.Status" + status + ", out)"
}

func sgMutations() []sgMutation {
	const acct = sgAPIDir + "asset_account_handler.go"
	const cs = sgAPIDir + "change_secret_handler.go"
	const batch = sgAPIDir + "change_secret_batch_handler.go"
	return []sgMutation{
		{name: "m1_discard_result", edits: []sgEdit{{batch,
			"\tout, err := h.projectRecords(accountContext(c), records, func(rows []changeSecretRecordDTO) any {\n" +
				"\t\treturn gin.H{\"data\": gin.H{\"batch\": batchDTO, \"records\": rows}}\n" +
				"\t})\n" +
				"\tif err != nil {\n" +
				"\t\tapierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChangeSecretRecordQuery, err)\n" +
				"\t\treturn\n" +
				"\t}\n" +
				"\trespondScoped(c, http.StatusOK, out)",
			"\t_, err = h.projectRecords(accountContext(c), records, func(rows []changeSecretRecordDTO) any {\n" +
				"\t\treturn gin.H{\"data\": gin.H{\"batch\": batchDTO, \"records\": rows}}\n" +
				"\t})\n" +
				"\tif err != nil {\n" +
				"\t\tapierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChangeSecretRecordQuery, err)\n" +
				"\t\treturn\n" +
				"\t}\n" +
				"\tpayload := gin.H{\"mutation_records\": records}\n" +
				"\tc.JSON(http.StatusOK, payload)"}},
			expect: []sgExpect{{rule: "SR4", file: batch, marker: "payload := gin.H{"}, {rule: "SR2", file: batch, marker: "c.JSON(http.StatusOK, payload)"}}},
		{name: "m2_literal_any", edits: []sgEdit{{acct, sgAccountChunk("Create", "Created"),
			"\tc.JSON(http.StatusCreated, gin.H{\"data\": []any{account}})"}},
			expect: []sgExpect{{rule: "SR2", file: acct, marker: "[]any{account}"}, {rule: "SR4", file: acct, marker: "[]any{account}"}}},
		{name: "m3_helper_any", edits: []sgEdit{{acct, sgAccountChunk("Update", "OK"), "\temitAny(c, account)"}},
			newFiles: map[string]string{"zz_mutation_emit_any.go": sgEmitAnySrc},
			expect:   []sgExpect{{rule: "SR2", file: acct, marker: "emitAny(c, account)"}, {rule: "SR4", file: acct, marker: "emitAny(c, account)"}}},
		{name: "m4_launder", edits: []sgEdit{{acct, sgAccountChunk("SetDefault", "OK"),
			"\tc.JSON(http.StatusOK, launder(account))"}},
			newFiles: map[string]string{"zz_mutation_launder.go": sgLaunderSrc},
			expect:   []sgExpect{{rule: "SR2", file: acct, marker: "launder(account)"}, {rule: "SR5", file: acct, marker: "launder(account)"}}},
		{name: "m5_unregistered_source", newFiles: map[string]string{"zz_mutation_batch_copy.go": sgGetBatchCopySrc},
			expect: []sgExpect{{rule: "SR1", file: sgAPIDir + "zz_mutation_batch_copy.go", marker: "h.batches.DetailFor"}}},
		{name: "m6_raw_branch", edits: []sgEdit{{cs,
			"\tout, err := h.projectRecords(accountContext(c), records, func(rows []changeSecretRecordDTO) any {\n" +
				"\t\treturn gin.H{\"data\": rows, \"total\": len(rows)}",
			"\tif c.Query(\"raw\") == \"1\" {\n" +
				"\t\tc.JSON(http.StatusOK, gin.H{\"data\": records})\n" +
				"\t\treturn\n" +
				"\t}\n" +
				"\tout, err := h.projectRecords(accountContext(c), records, func(rows []changeSecretRecordDTO) any {\n" +
				"\t\treturn gin.H{\"data\": rows, \"total\": len(rows)}"}},
			expect: []sgExpect{{rule: "SR2", file: cs, marker: "gin.H{\"data\": records}"}, {rule: "SR4", file: cs, marker: "gin.H{\"data\": records}"}}},
		{name: "m7_forge", newFiles: map[string]string{"zz_mutation_forge.go": sgForgeSrc},
			expect: []sgExpect{{rule: "SR3", file: sgAPIDir + "zz_mutation_forge.go", marker: "scopedOutput{body: r}"}}},
		{name: "m8_registry_row", registry: func(r sgRegistry) sgRegistry {
			var kept []api.ScopedOutputExit
			for _, e := range r.exits {
				if e.Fn != "ChangeSecretHandler.ListCandidates" {
					kept = append(kept, e)
				}
			}
			r.exits = kept
			return r
		}, expect: []sgExpect{{rule: "SR1", file: cs, marker: "h.candidates.ListFor"}, {rule: "R"}}},
		{name: "m9_abort_with_status_json", edits: []sgEdit{{acct,
			"\t\trespondAccountError(c, apierror.CodeInternalAssetAccountUpdate, err)\n\t\treturn\n\t}\n",
			"\t\trespondAccountError(c, apierror.CodeInternalAssetAccountUpdate, err)\n\t\treturn\n\t}\n" +
				"\tif c.Query(\"raw\") == \"1\" {\n" +
				"\t\tc.AbortWithStatusJSON(http.StatusOK, gin.H{\"credential_name\": account.CredentialName})\n" +
				"\t\treturn\n" +
				"\t}\n"}},
			expect: []sgExpect{{rule: "SR2", file: acct, marker: "c.AbortWithStatusJSON(", exact: true}}},
		{name: "m10_header", edits: []sgEdit{{acct,
			"\t\trespondAccountError(c, apierror.CodeInternalAssetAccountSetDefault, err)\n\t\treturn\n\t}\n",
			"\t\trespondAccountError(c, apierror.CodeInternalAssetAccountSetDefault, err)\n\t\treturn\n\t}\n" +
				"\tc.Header(\"X-Credential-Name\", account.CredentialName)\n"}},
			expect: []sgExpect{{rule: "SR2", file: acct, marker: "c.Header(", exact: true}}},
	}
}

// resolveLine 在 overlay 後的原始碼裡找出標記所在的行號；標記必須恰出現一次於注入處（或既有檔）。
func sgResolveLine(t *testing.T, root string, ov map[string][]byte, file, marker string) int {
	t.Helper()
	var src string
	if b, ok := ov[filepath.Join(root, filepath.FromSlash(file))]; ok {
		src = string(b)
	} else {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
		require.NoError(t, err)
		src = string(raw)
	}
	require.Equal(t, 1, strings.Count(src, marker), "標記 %q 在 %s 內應恰出現一次", marker, file)
	return sgLineOf(src, strings.Index(src, marker))
}

func TestScopedOutputProjectionGuardMutations(t *testing.T) {
	root := backendRoot(t)
	reg := sgLoadRegistry()
	// 被突變改寫的生產檔與登錄表：前後雜湊必須相同（其餘檔案可能有並行的正常編輯，不納入斷言）
	hashed := map[string]bool{sgAPIDir + "scoped_output_registry.go": true, sgAPIDir + "scoped_output_projection.go": true}
	for _, m := range sgMutations() {
		for _, e := range m.edits {
			hashed[e.file] = true
		}
	}
	var hashFiles []string
	for f := range hashed {
		hashFiles = append(hashFiles, f)
	}
	before := sgHashFiles(t, root, hashFiles)

	runCase := func(t *testing.T, m sgMutation) {
		ov := map[string][]byte{}
		for _, e := range m.edits {
			p := filepath.Join(root, filepath.FromSlash(e.file))
			raw, err := os.ReadFile(p)
			require.NoError(t, err)
			out, _ := sgReplaceOnce(t, string(raw), e.anchor, e.repl)
			ov[p] = []byte(out)
		}
		for name, src := range m.newFiles {
			p := filepath.Join(root, "internal", "api", name)
			_, statErr := os.Stat(p)
			require.True(t, os.IsNotExist(statErr), "反例檔只能以 overlay 存在：%s", p)
			ov[p] = []byte(src)
		}
		pkg := sgLoadAPI(t, root, ov)
		if errs := sgPkgErrors(pkg); len(errs) > 0 {
			require.Failf(t, "MUTATION-COMPILE", "overlay 型別檢查有錯：%v", errs)
		}
		r := reg
		if m.registry != nil {
			r = m.registry(reg)
		}
		vs, _ := checkScopedOutputs(root, pkg, r)

		expectedLines := map[string]bool{}
		for _, e := range m.expect {
			if e.file == "" {
				found := false
				for _, v := range vs {
					if v.Rule == e.rule && v.File == "" {
						found = true
					}
				}
				assert.True(t, found, "期望全域規則 %s 命中", e.rule)
				t.Logf("%s：規則 %s 命中（全域）", m.name, e.rule)
				continue
			}
			line := sgResolveLine(t, root, ov, e.file, e.marker)
			expectedLines[fmt.Sprintf("%s:%d", e.file, line)] = true
			var onLine []string
			hit := false
			for _, v := range vs {
				if v.File == e.file && v.Line == line {
					onLine = append(onLine, v.Rule)
					if v.Rule == e.rule {
						hit = true
					}
				}
			}
			assert.True(t, hit, "期望規則 %s 命中 %s:%d，實得 %v", e.rule, e.file, line, onLine)
			if e.exact {
				assert.Equal(t, []string{e.rule}, onLine, "注入行的違規只能有 %s", e.rule)
			}
			if hit {
				t.Logf("%s：規則 %s 命中 %s:%d（該行全部規則 %v）", m.name, e.rule, e.file, line, onLine)
			}
		}
		for _, v := range vs {
			if v.File == "" || expectedLines[fmt.Sprintf("%s:%d", v.File, v.Line)] {
				continue
			}
			assert.Fail(t, "注入行以外出現違規", "%s", v.String())
		}
	}

	t.Run("clean", func(t *testing.T) {
		pkg := sgLoadAPI(t, root, nil)
		require.Empty(t, sgPkgErrors(pkg))
		vs, _ := checkScopedOutputs(root, pkg, reg)
		t.Logf("clean 違規數 %d", len(vs))
		assert.Empty(t, vs)
	})
	for _, m := range sgMutations() {
		t.Run(m.name, func(t *testing.T) { runCase(t, m) })
	}
	after := sgHashFiles(t, root, hashFiles)
	assert.Equal(t, before, after, "被突變的生產檔在突變前後必須逐位元相同")
	t.Logf("被突變的生產檔 sha256（前後一致）：\n%s", after)
}
