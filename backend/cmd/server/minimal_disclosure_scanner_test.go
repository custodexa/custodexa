package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 最小揭露例外守衛的 AST 掃描器；判準 (a)–(d) 的定義見 minimal_disclosure_registry_guard_test.go 檔頭。

// ── 掃描器 ───────────────────────────────────────────────────────────────

type discViolation struct {
	file string
	line int
	msg  string
}

type discScanResult struct {
	violations     []discViolation
	literalMapKeys int
	jsonTags       int
	prefixedConsts []string // 登錄外以 out_of_scope 為值的套件層字串常數或變數（file:name）
}

func (r discScanResult) reported(rel string) bool {
	for _, v := range r.violations {
		if v.file == rel {
			return true
		}
	}
	return false
}

type discScanner struct {
	regConsts  map[string]string          // 登錄常數名 → 字串值
	fieldKinds map[string]map[string]bool // 輸出欄名 → 允許的例外常數名
	codeKinds  map[string]map[string]bool // 規則碼 → 允許的例外常數名
	flagKinds  map[string]bool            // 列級旗標 count 允許的例外常數名
}

func newDiscScanner(t *testing.T, regFiles []*parsedFile) *discScanner {
	t.Helper()
	sc := &discScanner{
		regConsts:  map[string]string{},
		fieldKinds: map[string]map[string]bool{},
		codeKinds:  map[string]map[string]bool{},
		flagKinds:  map[string]bool{disclosure.OutOfScopeNodeCount.String(): true},
	}
	for _, pf := range regFiles {
		for _, d := range pf.File.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if lit, ok := discStringLit(vs.Values[i]); ok {
							sc.regConsts[n.Name] = lit
						}
					}
				}
			}
		}
	}
	for _, e := range disclosure.Entries() {
		for _, f := range e.Fields {
			if sc.fieldKinds[f] == nil {
				sc.fieldKinds[f] = map[string]bool{}
			}
			sc.fieldKinds[f][e.Name] = true
		}
		for _, c := range e.RuleCodes {
			if sc.codeKinds[c] == nil {
				sc.codeKinds[c] = map[string]bool{}
			}
			sc.codeKinds[c][e.Name] = true
		}
	}
	if sc.regConsts["FlagReasonOutOfScopeNodes"] != disclosure.FlagReasonOutOfScopeNodes ||
		sc.regConsts["AuditDetailOutOfScopeCount"] != disclosure.AuditDetailOutOfScopeCount ||
		len(sc.codeKinds) == 0 {
		t.Fatalf("登錄常數解析失真：%v／%v", sc.regConsts, sc.codeKinds)
	}
	return sc
}

// discFileCtx 一個檔的解析脈絡。
type discFileCtx struct {
	pf        *parsedFile
	discName  string              // 登錄套件在本檔的引用名
	errName   string              // 錯誤碼套件在本檔的引用名；本身即錯誤碼套件時為 ""
	inErrPkg  bool                // 本檔屬錯誤碼套件
	importDir map[string]string   // 引用名 → 相對 module 根的目錄
	local     map[string]ast.Expr // 目前函式內宣告的識別字 → 初始值（const、var、:=）
}

// discDecl 套件層 const／var 的初始值。
type discDecl struct {
	expr ast.Expr
	file string
}

// discDecls 目錄 → 套件層識別字 → 初始值。
type discDecls map[string]map[string]discDecl

// discMaxChain 常數鏈的解析深度上限（防自我引用的病態輸入）。
const discMaxChain = 8

func (sc *discScanner) scan(files []*parsedFile) discScanResult {
	var res discScanResult
	// 前置：各目錄套件層 const／var 的初始值、錯誤碼識別字 → 碼。
	decls := discDecls{}
	codeIdents := map[string]string{}
	for _, pf := range files {
		dir := filepath.ToSlash(filepath.Dir(pf.Rel))
		for _, d := range pf.File.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if !discInRegistry(pf.Rel) {
						if decls[dir] == nil {
							decls[dir] = map[string]discDecl{}
						}
						decls[dir][n.Name] = discDecl{expr: vs.Values[i], file: pf.Rel}
					}
					if dir == discAPIErrorDir {
						if call, ok := vs.Values[i].(*ast.CallExpr); ok && len(call.Args) > 0 {
							if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "register" {
								if lit, ok := discStringLit(call.Args[0]); ok {
									codeIdents[n.Name] = lit
								}
							}
						}
					}
				}
			}
		}
	}
	for dir, m := range decls {
		for name, d := range m {
			if v, ok, _ := sc.resolve(nil, dir, d.expr, decls, 0); ok && discHasPrefix(v) {
				res.prefixedConsts = append(res.prefixedConsts, d.file+":"+name)
			}
		}
	}
	sort.Strings(res.prefixedConsts)

	for _, pf := range files {
		if discInRegistry(pf.Rel) {
			continue
		}
		fc := &discFileCtx{pf: pf, importDir: map[string]string{},
			inErrPkg: filepath.ToSlash(filepath.Dir(pf.Rel)) == discAPIErrorDir}
		for _, imp := range pf.File.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			name := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if p == discRegistryPath && name == "." {
				res.add(pf, imp.Pos(), "以 . import 揭露登錄：常數失去套件前綴，守衛無從辨認欄名與 Count 呼叫")
			}
			if p == discRegistryPath {
				fc.discName = name
			}
			if p == discAPIErrorPath {
				fc.errName = name
			}
			if strings.HasPrefix(p, auditPointModulePath+"/") {
				fc.importDir[name] = strings.TrimPrefix(p, auditPointModulePath+"/")
			}
		}
		fc.importDir[""] = filepath.ToSlash(filepath.Dir(pf.Rel)) // 同包常數
		for _, d := range pf.File.Decls {
			guarded := map[string]bool{}
			fc.local = nil
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				guarded = sc.guardedKinds(fc, fd.Body, codeIdents)
				fc.local = discLocalDecls(fd.Body)
			}
			sc.inspect(fc, d, guarded, decls, &res)
		}
	}
	return res
}

// guardedKinds 函式內引用到的計數類規則碼所屬例外。
func (sc *discScanner) guardedKinds(fc *discFileCtx, body *ast.BlockStmt, codeIdents map[string]string) map[string]bool {
	out := map[string]bool{}
	addCode := func(code string) {
		for k := range sc.codeKinds[code] {
			out[k] = true
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && fc.errName != "" && id.Name == fc.errName {
				addCode(codeIdents[x.Sel.Name])
			}
		case *ast.Ident:
			if fc.inErrPkg {
				addCode(codeIdents[x.Name])
			}
		case *ast.BasicLit:
			if lit, ok := discStringLit(x); ok {
				addCode(lit)
			}
		}
		return true
	})
	return out
}

// discKey 鍵的分類結果。
type discKey struct {
	value    string
	resolved bool // 解析出字串值
	registry bool // 引用登錄常數
	ident    string
}

func (sc *discScanner) classifyKey(fc *discFileCtx, e ast.Expr, decls discDecls) discKey {
	v, ok, registry := sc.resolve(fc, fc.importDir[""], e, decls, 0)
	if ok {
		return discKey{value: v, resolved: true, registry: registry}
	}
	if id, isID := discUnparen(e).(*ast.Ident); isID {
		return discKey{ident: id.Name}
	}
	return discKey{}
}

// resolve 解析鍵運算式的字串值：字面值（含括號）、函式內宣告、同包或他包的套件層
// const／var，沿常數鏈遞迴。鏈的終點是登錄常數時 registry 為真。fc 為 nil 時只解析
// 同目錄的套件層宣告（前置收集用）。
func (sc *discScanner) resolve(fc *discFileCtx, dir string, e ast.Expr, decls discDecls, depth int) (string, bool, bool) {
	if depth > discMaxChain {
		return "", false, false
	}
	e = discUnparen(e)
	if lit, ok := discStringLit(e); ok {
		return lit, true, false
	}
	switch k := e.(type) {
	case *ast.Ident:
		if fc != nil {
			if init, ok := fc.local[k.Name]; ok {
				return sc.resolve(fc, dir, init, decls, depth+1)
			}
		}
		if d, ok := decls[dir][k.Name]; ok {
			return sc.resolve(nil, dir, d.expr, decls, depth+1)
		}
	case *ast.SelectorExpr:
		x, ok := k.X.(*ast.Ident)
		if !ok || fc == nil {
			return "", false, false
		}
		if fc.discName != "" && x.Name == fc.discName {
			v, ok := sc.regConsts[k.Sel.Name]
			return v, ok, ok
		}
		if other, ok := fc.importDir[x.Name]; ok {
			if d, ok := decls[other][k.Sel.Name]; ok {
				return sc.resolve(nil, other, d.expr, decls, depth+1)
			}
		}
	}
	return "", false, false
}

// discLocalDecls 函式內以 const、var 或 := 宣告、初始值可解析的識別字。
func discLocalDecls(body *ast.BlockStmt) map[string]ast.Expr {
	out := map[string]ast.Expr{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GenDecl:
			if x.Tok != token.CONST && x.Tok != token.VAR {
				return true
			}
			for _, s := range x.Specs {
				vs := s.(*ast.ValueSpec)
				for i, id := range vs.Names {
					if i < len(vs.Values) {
						out[id.Name] = vs.Values[i]
					}
				}
			}
		case *ast.AssignStmt:
			if x.Tok != token.DEFINE || len(x.Lhs) != len(x.Rhs) {
				return true
			}
			for i, l := range x.Lhs {
				if id, ok := l.(*ast.Ident); ok {
					out[id.Name] = x.Rhs[i]
				}
			}
		}
		return true
	})
	return out
}

func (sc *discScanner) inspect(fc *discFileCtx, root ast.Node, guarded map[string]bool,
	decls discDecls, res *discScanResult) {
	// checkPair 對（鍵, 值）套 (a)(b)(c)；value 為 nil 時只套 (a)（讀取式）。
	checkPair := func(pos token.Pos, key ast.Expr, value ast.Expr) {
		dk := sc.classifyKey(fc, key, decls)
		if !dk.resolved {
			return
		}
		if !dk.registry && discHasPrefix(dk.value) {
			res.add(fc.pf, pos, fmt.Sprintf("在揭露登錄外以 %q 作為 map 鍵", dk.value))
			return
		}
		if value == nil {
			return
		}
		if dk.registry {
			if allowed, ok := sc.fieldKinds[dk.value]; ok && dk.value != discCountKey {
				sc.requireCount(fc, value, allowed, fmt.Sprintf("欄位 %q", dk.value), res)
				return
			}
		}
		if dk.value == discCountKey {
			if dk.registry && len(guarded) == 0 {
				sc.requireCount(fc, value, sc.fieldKinds[discCountKey], "以登錄常數為鍵的 count", res)
				return
			}
			if len(guarded) > 0 {
				sc.requireCount(fc, value, guarded, "計數類規則碼的 params count", res)
			}
		}
	}

	ast.Inspect(root, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.StructType:
			for _, f := range x.Fields.List {
				name := ""
				pos := f.Pos()
				if f.Tag != nil {
					res.jsonTags++
					tag, err := strconv.Unquote(f.Tag.Value)
					if err != nil {
						continue
					}
					name = strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
					pos = f.Tag.Pos()
				}
				if name == "-" {
					continue
				}
				if name != "" {
					if discHasPrefix(name) {
						res.add(fc.pf, pos, fmt.Sprintf("在揭露登錄外以 %q 作為 JSON 欄名", name))
					}
					continue
				}
				// 無 tag（或 tag 未給名稱）時 JSON 欄名即 Go 欄位名
				for _, id := range f.Names {
					if discHasPrefix(id.Name) {
						res.add(fc.pf, id.Pos(), fmt.Sprintf("在揭露登錄外以欄位名 %q 作為 JSON 欄名", id.Name))
					}
				}
			}
		case *ast.CompositeLit:
			flag := false
			for _, el := range x.Elts {
				val := el
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					val = kv.Value
				}
				if sc.isFlagReason(fc, val) {
					flag = true
				}
			}
			for _, el := range x.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if _, ok := discStringLit(kv.Key); ok {
					res.literalMapKeys++
				}
				if flag {
					// 旗標字面值的 count 屬節點計數例外，由 (d) 判定，不再套 (c)：
					// 同一函式即使也引用了別條例外的規則碼，這個 count 的單位仍是範圍外節點數
					dk := sc.classifyKey(fc, kv.Key, decls)
					if (dk.resolved && dk.value == discCountKey) || dk.ident == "Count" {
						sc.requireCount(fc, kv.Value, sc.flagKinds, "列級旗標（原因 out_of_scope_nodes）的 count", res)
						continue
					}
				}
				checkPair(kv.Pos(), kv.Key, kv.Value)
			}
		case *ast.AssignStmt:
			for i, l := range x.Lhs {
				ix, ok := l.(*ast.IndexExpr)
				if !ok || len(x.Lhs) != len(x.Rhs) {
					continue
				}
				dk := sc.classifyKey(fc, ix.Index, decls)
				if dk.resolved && !dk.registry && discHasPrefix(dk.value) {
					continue // (a) 由 IndexExpr 分支回報，避免重複
				}
				checkPair(ix.Pos(), ix.Index, x.Rhs[i])
			}
		case *ast.IndexExpr:
			checkPair(x.Pos(), x.Index, nil)
		}
		return true
	})
}

func (sc *discScanner) isFlagReason(fc *discFileCtx, e ast.Expr) bool {
	if lit, ok := discStringLit(e); ok {
		return lit == disclosure.FlagReasonOutOfScopeNodes
	}
	if s, ok := e.(*ast.SelectorExpr); ok {
		if x, ok := s.X.(*ast.Ident); ok && fc.discName != "" && x.Name == fc.discName {
			return s.Sel.Name == "FlagReasonOutOfScopeNodes"
		}
	}
	return false
}

// requireCount 值必須直接是 disclosure.Count(<允許的例外常數>, n)。
func (sc *discScanner) requireCount(fc *discFileCtx, value ast.Expr, allowed map[string]bool,
	what string, res *discScanResult) {
	call, ok := value.(*ast.CallExpr)
	if ok {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && fc.discName != "" && x.Name == fc.discName &&
				sel.Sel.Name == discCountFuncName && len(call.Args) == 2 {
				if ks, ok := call.Args[0].(*ast.SelectorExpr); ok {
					if kx, ok := ks.X.(*ast.Ident); ok && kx.Name == fc.discName && allowed[ks.Sel.Name] {
						return
					}
				}
				res.add(fc.pf, value.Pos(), fmt.Sprintf("%s 的 disclosure.Count 第一個引數不是該欄位所屬例外（允許 %s）",
					what, discSortedKeys(allowed)))
				return
			}
		}
	}
	res.add(fc.pf, value.Pos(), fmt.Sprintf("%s 的值不是 disclosure.Count 呼叫", what))
}

func (r *discScanResult) add(pf *parsedFile, pos token.Pos, msg string) {
	r.violations = append(r.violations, discViolation{file: pf.Rel, line: pf.Fset.Position(pos).Line, msg: msg})
}

// ── 小工具 ───────────────────────────────────────────────────────────────

func discInRegistry(rel string) bool {
	return strings.HasPrefix(rel, discRegistryDir+"/")
}

// discHasPrefix 不分大小寫判定 out_of_scope 前綴：大小寫異名的鍵在 JSON 裡同樣可讀。
func discHasPrefix(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), discFieldPrefix)
}

// discUnparen 去掉外層括號。
func discUnparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

func discStringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

func discSortedKeys(m map[string]bool) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, "、")
}

func discParseRegistry(t *testing.T, root string) []*parsedFile {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(discRegistryDir))
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取登錄套件 %s 失敗: %v", discRegistryDir, err)
	}
	fset := token.NewFileSet()
	var out []*parsedFile
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("解析 %s 失敗: %v", e.Name(), err)
		}
		out = append(out, newParsedFile(discRegistryDir+"/"+e.Name(), f, fset))
	}
	if len(out) == 0 {
		t.Fatalf("登錄套件 %s 沒有非測試檔", discRegistryDir)
	}
	return out
}

func discSynthetic(t *testing.T, rel, src string) *parsedFile {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, 0)
	if err != nil {
		t.Fatalf("合成原始碼 %s 解析失敗: %v", rel, err)
	}
	return newParsedFile(rel, f, fset)
}
