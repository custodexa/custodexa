package main

// 審計產生點「呼叫方交易內」欄的**資料流（def-use）判定**。
//
// 本檔只做判定，守衛本體（雙向比對、允許清單、不變式）在
// `audit_points_tx_attribution_guard_test.go`；產生點掃描在
// `audit_points_manifest_guard_test.go`。三檔同包、共用同一份 AST 走訪。
//
// ── 為什麼是 def-use 而不是作用域可見性（2026-08-09 codex 外審 C1 修補） ──
//
// 修補前的判定是「產生點的任一層包覆函式帶 `*gorm.DB` 參數 ⇒ TxBound」。這只證明
// 交易句柄在該作用域**可見**，不證明審計寫入**用了它**；反方向更危險——tx 若存於
// struct 欄位、方法接收者、context、`Begin()` 後被閉包捕獲等**非形式參數**形態，
// 一律會被判成 `NotTxBound`，而 manifest 只要同步翻成「否＋AsyncSink」就能全綠。
//
// **誤判不對稱**：誤判 TxBound ⇒ 多餘的同步寫入（可用性下降）；誤判 NotTxBound ⇒
// fail-close 靜默退化為 fail-open，且失敗路徑變成功路徑、測試反而更綠。後者嚴重得多。
//
// 故本檔改為**保守格序**：
//
//	NotTxBound 只在**正面可證**時才給（來源是跨包全域句柄、struct 欄位且全域 tx 逃逸
//	           不變式成立、或 `AuditLogEntry` 的型別層結論）。
//	Indeterminate 是所有「證不到」的預設值——**任何無法追溯的形態一律落在這裡，
//	           絕不預設 NotTxBound**。守衛對 Indeterminate 另有硬不變式（不得 AsyncSink）。
//
// ── 判定流程（單一寫入 call 為中心） ────────────────────────────────────
//
//  1. 找出這一列的**落地寫入**：產生點若是 `model.AuditLog` 字面量，追它的 carrier
//     （字面量本身或它初始化的區域變數）在最內層作用域內的使用點；恰好一個 GORM 寫入
//     呼叫才算找到，多個候選／被 return／被送進 channel／被包進其他字面量一律 Indeterminate。
//     `RecordCall` 形態直接取呼叫的第一引數（那就是被使用的句柄）。
//     `AuditLogEntry` 形態不含 DB 句柄，走型別層規則。
//  2. 一跳（hop ≤ 1）：carrier 若恰好被交給同包的一個函式／方法，追進去對應參數再判一次。
//     跨包、介面派發、可變參數一律 Indeterminate（`unresolved-callee`）。
//  3. 把該寫入 call 的 **receiver 鏈**往下走到根運算式，逐步判定：
//     `.Session(&gorm.Session{NewDB: true})` ⇒ Detached（C2：以寫入 call 自身的鏈為準，
//     不再看「作用域內某處出現過 NewDB 字面量」）；`.Begin()` ⇒ Indeterminate；
//     根是 `*gorm.DB` 參數 ⇒ TxBound；根是跨包／同包的包級變數 ⇒ NotTxBound；
//     根是 `x.field` ⇒ NotTxBound（**但受全域 tx 逃逸不變式節制**，見下）；其餘 ⇒ Indeterminate。
//
// ── 全域 tx 逃逸不變式（把盲區 B1 從「靜默」變成「機器可見」） ────────────
//
// `x.field` 這個來源之所以能算「證得出非交易內」，前提是**沒有人把交易句柄塞進
// struct 欄位／包級變數／context**。這個前提本身被機器檢查：`buildTxIndex` 掃全模組，
// 找 `Transaction` 閉包參數與 `Begin()` 產物流入上述三種載體的形態（含「傳給一個會
// 把 `*gorm.DB` 參數存進欄位的函式」這條轉手路徑）。一旦命中，所有 struct 欄位來源
// 與 `AuditLogEntry` 型別層結論**同時降為 Indeterminate**——不是靜默失效，是整批轉紅。
//
// ── 誠實的殘餘邊界（不假裝涵蓋） ────────────────────────────────────────
//
//   - 介面派發的落地（carrier 交給介面方法）→ `unresolved-callee`，Indeterminate。
//   - 反射、生成碼、原生 SQL 寫入 `audit_logs` → 本檔（與整個產生點掃描）都看不見；
//     其正解是 W4 的 runtime fault-injection backstop（tasks.md 4.12c），不是更多 AST。
//   - 一跳以上的間接（A→B→C 才落地）→ Indeterminate，不做跨函式定點迭代。
//   - 逃逸偵測以**識別字名**近似（不做型別解析），會過度標記而非漏標——方向與格序一致。

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── 判定格 ────────────────────────────────────────────────────────────────

type txVerdict string

const (
	txBound         txVerdict = "TxBound"
	txDetached      txVerdict = "Detached"
	txNotBound      txVerdict = "NotTxBound"
	txIndeterminate txVerdict = "Indeterminate"
)

// txReason 判定的理由類別（受管閉集合）。Indeterminate 的理由類別**同時是允許清單的
// 綁定鍵**：豁免必須宣告與機器一致的理由，改不出「隨便寫個日期就進豁免」的路。
type txReason string

const (
	// 正面可證的來源
	reasonTxParam         txReason = "tx-param"
	reasonDetachedSession txReason = "detached-session"
	reasonRootHandle      txReason = "root-handle"
	reasonStructField     txReason = "struct-field"
	reasonEntryTypeLevel  txReason = "entry-type-level"
	// reasonSinkTxArg W4 收口形態：事件字面量交給 TxSink 落地面，交易句柄是該次呼叫的
	// 顯式引數（`port.WriteInTx(sink, tx, ev)` 或 `sink.WriteInTx(tx, ev)`）。
	// 判定沿用同一套 receiver 根追溯——只是這次要追的不是 receiver 而是那個引數。
	reasonSinkTxArg txReason = "sink-tx-arg"
	// reasonSinkAsyncCall W4 收口形態：事件字面量交給 AsyncSink（`sink.Submit(ctx, ev)`）。
	// **AsyncSink 的簽名不帶 *gorm.DB**，呼叫方的 tx 沒有語法途徑進入該次寫入——
	// 與 entry-type-level 同一條論證，只是載體從 AuditLogEntry 換成 AuditEvent。
	reasonSinkAsyncCall txReason = "sink-async-call"

	// 證不到（一律 Indeterminate）
	reasonEscapesScope       txReason = "escapes-scope"
	reasonMultiConsumer      txReason = "multi-consumer"
	reasonNoWrite            txReason = "no-write"
	reasonUnresolvedCallee   txReason = "unresolved-callee"
	reasonUnresolvedRoot     txReason = "unresolved-root"
	reasonSelfBegin          txReason = "self-begin"
	reasonTxEscape           txReason = "tx-escape"
	reasonEntryLandingUnsafe txReason = "entry-landing-unsafe"
)

// txIndeterminateReasons Indeterminate 的受管理由集合。允許清單只能宣告其中之一。
var txIndeterminateReasons = map[txReason]bool{
	reasonEscapesScope: true, reasonMultiConsumer: true, reasonNoWrite: true,
	reasonUnresolvedCallee: true, reasonUnresolvedRoot: true, reasonSelfBegin: true,
	reasonTxEscape: true, reasonEntryLandingUnsafe: true,
}

// gormWriteMethods GORM 的落地寫入方法名
var gormWriteMethods = map[string]bool{"Create": true, "CreateInBatches": true, "Save": true}

// ── 解析與作用域 ──────────────────────────────────────────────────────────

// parsedFile 一個已解析的非測試 .go 檔
type parsedFile struct {
	Rel     string
	Pkg     string
	File    *ast.File
	Fset    *token.FileSet
	imports map[string]bool // 本檔可見的 import 套件名（辨識 `database.DB` 這類跨包全域）
	scopes  []fnScope
}

// fnScope 一層函式作用域（FuncDecl 或 FuncLit）
type fnScope struct {
	label      string
	start, end token.Pos
	body       *ast.BlockStmt
	dbParams   map[string]bool // 該層的 *gorm.DB 參數名
	recvName   string          // 方法接收者變數名
	recvType   string          // 方法接收者型別名（去指標）
	txClosure  bool            // 是 X.Transaction(func(tx *gorm.DB) error {…}) 的引數
}

func parseModuleFiles(t *testing.T, root string) ([]*parsedFile, int) {
	t.Helper()
	fset := token.NewFileSet()
	var files []*parsedFile
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && auditPointSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("解析 %s 失敗（掃描不得在解析錯誤下靜默略過）: %v", rel, parseErr)
		}
		files = append(files, newParsedFile(rel, f, fset))
		return nil
	})
	if err != nil {
		t.Fatalf("走訪 %s 失敗: %v", root, err)
	}
	return files, len(files)
}

func newParsedFile(rel string, f *ast.File, fset *token.FileSet) *parsedFile {
	pf := &parsedFile{Rel: rel, Pkg: f.Name.Name, File: f, Fset: fset, imports: map[string]bool{}}
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		name := p
		if i := strings.LastIndex(p, "/"); i >= 0 {
			name = p[i+1:]
		}
		if imp.Name != nil {
			name = imp.Name.Name
		}
		pf.imports[name] = true
	}
	pf.scopes = collectFnScopes(f)
	return pf
}

func collectFnScopes(file *ast.File) []fnScope {
	txLits := map[*ast.FuncLit]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Transaction" {
			for _, a := range call.Args {
				if lit, ok := a.(*ast.FuncLit); ok {
					txLits[lit] = true
				}
			}
		}
		return true
	})
	var scopes []fnScope
	ast.Inspect(file, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body == nil {
				return true
			}
			s := fnScope{label: fn.Name.Name, start: fn.Pos(), end: fn.End(),
				body: fn.Body, dbParams: gormDBParams(fn.Type.Params)}
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				if len(fn.Recv.List[0].Names) > 0 {
					s.recvName = fn.Recv.List[0].Names[0].Name
				}
				s.recvType = baseTypeName(fn.Recv.List[0].Type)
				s.label = "(" + s.recvType + ")." + fn.Name.Name
			}
			scopes = append(scopes, s)
		case *ast.FuncLit:
			if fn.Body == nil {
				return true
			}
			scopes = append(scopes, fnScope{label: "func(…) 閉包", start: fn.Pos(), end: fn.End(),
				body: fn.Body, dbParams: gormDBParams(fn.Type.Params), txClosure: txLits[fn]})
		}
		return true
	})
	return scopes
}

// gormDBParams 該層全部 *gorm.DB 參數名
func gormDBParams(params *ast.FieldList) map[string]bool {
	out := map[string]bool{}
	if params == nil {
		return out
	}
	for _, f := range params.List {
		if !isGormDBPtr(f.Type) {
			continue
		}
		for _, nm := range f.Names {
			out[nm.Name] = true
		}
	}
	return out
}

func isGormDBPtr(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "DB" {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == "gorm"
}

func baseTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return baseTypeName(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.IndexExpr:
		return baseTypeName(e.X)
	}
	return ""
}

// ── 模組級索引 ────────────────────────────────────────────────────────────

type funcEntry struct {
	pf   *parsedFile
	decl *ast.FuncDecl
}

// txEscape 一筆交易句柄逃逸（tx 流入 struct 欄位／包級變數／context）
type txEscape struct {
	Where string
	How   string
}

type txIndex struct {
	files   []*parsedFile
	funcs   map[string]*funcEntry // pkg|recvType|name
	pkgVars map[string]bool       // pkg.varName（包級變數）

	txEscapes    []txEscape
	txStashFuncs map[string]bool // 會把 *gorm.DB 參數存進欄位／包級變數／context 的函式名

	entryTypeFound  bool
	entryTypeClean  bool     // AuditLogEntry 不含任何 gorm.DB 欄位
	entryLandingBad []string // 同時吃 AuditLogEntry 與 *gorm.DB 的函式（落地面可能拿到 tx）
}

func funcKey(pkg, recvType, name string) string { return pkg + "|" + recvType + "|" + name }

func buildTxIndex(files []*parsedFile) *txIndex {
	idx := &txIndex{files: files, funcs: map[string]*funcEntry{}, pkgVars: map[string]bool{},
		txStashFuncs: map[string]bool{}}

	for _, pf := range files {
		for _, d := range pf.File.Decls {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				recv := ""
				if decl.Recv != nil && len(decl.Recv.List) > 0 {
					recv = baseTypeName(decl.Recv.List[0].Type)
				}
				idx.funcs[funcKey(pf.Pkg, recv, decl.Name.Name)] = &funcEntry{pf: pf, decl: decl}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						if decl.Tok == token.VAR {
							for _, nm := range s.Names {
								idx.pkgVars[pf.Pkg+"."+nm.Name] = true
							}
						}
					case *ast.TypeSpec:
						if s.Name.Name == "AuditLogEntry" && pf.Pkg == "audit" {
							idx.entryTypeFound = true
							idx.entryTypeClean = !structHasGormDB(s.Type)
						}
					}
				}
			}
		}
	}

	idx.collectStashFuncs()
	idx.collectTxEscapes()
	idx.collectEntryLandingRisks()
	return idx
}

func structHasGormDB(expr ast.Expr) bool {
	st, ok := expr.(*ast.StructType)
	if !ok || st.Fields == nil {
		return false
	}
	for _, f := range st.Fields.List {
		if isGormDBPtr(f.Type) {
			return true
		}
		if sel, ok := f.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "DB" {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "gorm" {
				return true
			}
		}
	}
	return false
}

// collectStashFuncs 找出「把自己的 *gorm.DB 參數存進 struct 欄位／包級變數／context」的
// 函式（各服務建構子即屬此類）。它們本身合法，但**把交易句柄交給它們**就是逃逸。
func (idx *txIndex) collectStashFuncs() {
	for _, pf := range idx.files {
		for i := range pf.scopes {
			s := &pf.scopes[i]
			if len(s.dbParams) == 0 {
				continue
			}
			if names := idx.stashedNames(pf, s.body, s.dbParams); len(names) > 0 {
				idx.txStashFuncs[simpleFuncName(s.label)] = true
			}
		}
	}
}

// simpleFuncName 自 fnScope.label 取函式簡名（`(T).Foo` → `Foo`）
func simpleFuncName(label string) string {
	if i := strings.LastIndex(label, "."); i >= 0 {
		return label[i+1:]
	}
	return label
}

// stashedNames 回傳 body 內被存進「非參數載體」的識別字（自 names 取）
func (idx *txIndex) stashedNames(pf *parsedFile, body *ast.BlockStmt, names map[string]bool) []string {
	var out []string
	hit := func(e ast.Expr, how string) {
		if id, ok := unparen(e).(*ast.Ident); ok && names[id.Name] {
			out = append(out, id.Name+"／"+how)
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.KeyValueExpr: // T{field: tx}
			hit(node.Value, "struct 欄位字面量")
		case *ast.AssignStmt:
			for i, l := range node.Lhs {
				if i >= len(node.Rhs) {
					break
				}
				switch lhs := l.(type) {
				case *ast.SelectorExpr:
					hit(node.Rhs[i], "欄位賦值 "+exprText(lhs))
				case *ast.Ident:
					if idx.pkgVars[pf.Pkg+"."+lhs.Name] {
						hit(node.Rhs[i], "包級變數賦值 "+lhs.Name)
					}
				}
			}
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WithValue" {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "context" {
					for _, a := range node.Args {
						hit(a, "context.WithValue")
					}
				}
			}
		}
		return true
	})
	return out
}

// collectTxEscapes 找出交易句柄（Transaction 閉包參數／Begin() 產物）流入非參數載體的形態。
func (idx *txIndex) collectTxEscapes() {
	for _, pf := range idx.files {
		txNames := txOriginNames(pf)
		if len(txNames) == 0 {
			continue
		}
		for _, name := range idx.stashedNames(pf, &ast.BlockStmt{List: fileStmts(pf)}, txNames) {
			idx.txEscapes = append(idx.txEscapes, txEscape{Where: pf.Rel, How: name})
		}
		// 轉手路徑：tx 被交給一個會把 *gorm.DB 參數存起來的函式
		ast.Inspect(pf.File, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := calleeSimpleName(call)
			if name == "" || !idx.txStashFuncs[name] {
				return true
			}
			for _, a := range call.Args {
				if id, ok := unparen(a).(*ast.Ident); ok && txNames[id.Name] {
					idx.txEscapes = append(idx.txEscapes, txEscape{
						Where: fmt.Sprintf("%s:%d", pf.Rel, pf.Fset.Position(call.Pos()).Line),
						How:   id.Name + " 交給會存起句柄的 " + name})
				}
			}
			return true
		})
	}
}

// fileStmts 把整檔的函式體包成一個假 block，供 stashedNames 一次走訪
func fileStmts(pf *parsedFile) []ast.Stmt {
	var out []ast.Stmt
	for _, d := range pf.File.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
			out = append(out, fn.Body)
		}
	}
	return out
}

// txOriginNames 本檔中**可證為交易句柄**的識別字名：Transaction 閉包參數、`X.Begin()` 產物。
// 以名字近似（不做型別解析）——過度標記而非漏標，與保守格序同向。
func txOriginNames(pf *parsedFile) map[string]bool {
	out := map[string]bool{}
	for i := range pf.scopes {
		s := &pf.scopes[i]
		if !s.txClosure {
			continue
		}
		for n := range s.dbParams {
			out[n] = true
		}
	}
	ast.Inspect(pf.File, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, r := range as.Rhs {
			call, ok := unparen(r).(*ast.CallExpr)
			if !ok {
				continue
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Begin" || i >= len(as.Lhs) {
				continue
			}
			if id, ok := as.Lhs[i].(*ast.Ident); ok {
				out[id.Name] = true
			}
		}
		return true
	})
	return out
}

func calleeSimpleName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// collectEntryLandingRisks 落地面自檢：任何同時吃 `AuditLogEntry` 與 `*gorm.DB` 的
// 函式（含介面方法宣告）都會使「entry 進不了呼叫方交易」的型別層結論失效。
func (idx *txIndex) collectEntryLandingRisks() {
	check := func(where string, params *ast.FieldList) {
		if params == nil {
			return
		}
		hasEntry, hasDB := false, false
		for _, f := range params.List {
			if baseTypeName(f.Type) == "AuditLogEntry" {
				hasEntry = true
			}
			if isGormDBPtr(f.Type) {
				hasDB = true
			}
		}
		if hasEntry && hasDB {
			idx.entryLandingBad = append(idx.entryLandingBad, where)
		}
	}
	for _, pf := range idx.files {
		ast.Inspect(pf.File, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncDecl:
				check(fmt.Sprintf("%s:%s", pf.Rel, node.Name.Name), node.Type.Params)
			case *ast.InterfaceType:
				if node.Methods == nil {
					return true
				}
				for _, m := range node.Methods.List {
					if ft, ok := m.Type.(*ast.FuncType); ok {
						name := "介面方法"
						if len(m.Names) > 0 {
							name = m.Names[0].Name
						}
						check(fmt.Sprintf("%s:%s", pf.Rel, name), ft.Params)
					}
				}
			}
			return true
		})
	}
}
