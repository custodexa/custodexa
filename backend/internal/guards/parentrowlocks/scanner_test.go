// Package parentrowlocks 承載「被外鍵參照的父表（users、user_groups）明示列鎖」機械守衛。
//
// # 規則
//
// 對 users 與 user_groups 的明示列鎖一律用 FOR NO KEY UPDATE：它與同型鎖、與 UPDATE
// 的隱含鎖仍互斥，但不擋外鍵檢查取的 KEY SHARE，因此「持父列鎖的交易」與「寫入指向
// 父列的外鍵的交易」不會互等成環。任何 FOR UPDATE、FOR SHARE 或無法解析模式的父表列鎖，
// 都會被本守衛抓到。另外三類會重新引入同一個環的寫法也在此擋下：
// 對 users 新增非部分唯一索引的 DDL（唯一性檢查取隱含 FOR UPDATE）、
// 對父表的 Unscoped().Delete 與 DELETE FROM（硬刪取 FOR UPDATE）。
//
// # 解析方式
//
// 純語法解析（go/parser，不做型別檢查），所以不受編譯失敗連坐，也不載入整棵 module：
//
//   - GORM：找 clause.Locking 複合字面值，Strength 取字串字面值、clause.LockingStrength*
//     常數或同檔常數；再依「該字面值所在的呼叫鏈」解析目標表——鏈上的 Model／Table／
//     First／Take／Last／Find／Delete 的引數型別，必要時追同一函式內的區域變數
//     （q := tx.Model(...)；q = q.Clauses(...)；q.First(&x)）。
//   - 原生 SQL：掃所有字串字面值（含全為字面值的 + 串接與套件層級變數）中的
//     FOR UPDATE／FOR NO KEY UPDATE／FOR SHARE／FOR KEY SHARE，目標表取其 FROM 子句。
//
// 解析不出目標表（或模式）的命中標為「?」，視同可能是父表：必須登記在例外表，表外一律失敗。
// 既知屬於其他表的列鎖同樣要登記（檔名＋函式名＋解析結果＋理由），所以日後新增任何列鎖
// 都會被要求分類。已知限制：Strength 或 SQL 若是跨檔常數、格式化串（%s 表名）或
// 非全字面值的串接，會落入「?」而被要求登記，不會被靜默放過。
package parentrowlocks

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/custodexa/backend"

type hitKind string

const (
	kindGormLock   hitKind = "gorm-lock"
	kindSQLLock    hitKind = "sql-lock"
	kindDDL        hitKind = "ddl-unique-index"
	kindHardDelete hitKind = "hard-delete"
)

const (
	modeNoKeyUpdate = "NO KEY UPDATE"
	modeKeyShare    = "KEY SHARE"
	modeUnknown     = "?"
	tableUnknown    = "?"
)

var parentTables = map[string]bool{"users": true, "user_groups": true}

// hit 是一次掃描命中。Table 在可解析時是表名（users、user_groups）或 "model:<型別名>"
// （其他模型），不可解析為 "?"；多目標以 "+" 連接（排序後）。
type hit struct {
	File   string // 相對掃描根，斜線分隔
	Line   int
	Func   string // "Recv.Name"、"Name"，套件層級為 "var <名>"
	Kind   hitKind
	Mode   string // 僅鎖類命中有值
	Table  string
	Detail string
}

func (h hit) key() string { return h.File + "|" + h.Func + "|" + h.Table }

func (h hit) String() string {
	s := h.File + ":" + strconv.Itoa(h.Line) + " " + h.Func + " kind=" + string(h.Kind)
	if h.Mode != "" {
		s += " mode=" + h.Mode
	}
	return s + " table=" + h.Table
}

func tableIsParent(label string) bool {
	for _, p := range strings.Split(label, "+") {
		if parentTables[p] {
			return true
		}
	}
	return false
}

// violatesParentRule 回報這個命中是否違反父表規則（不看例外表）。
func violatesParentRule(h hit) bool {
	switch h.Kind {
	case kindGormLock, kindSQLLock:
		return tableIsParent(h.Table) && h.Mode != modeNoKeyUpdate && h.Mode != modeKeyShare
	case kindDDL, kindHardDelete:
		return true
	}
	return false
}

// needsClassification 回報這個命中是否必須登記在例外表：
// 非 NKU／KEY SHARE 的鎖，目標不是已知父表違規時，都要登記（含無法解析者）。
func needsClassification(h hit) bool {
	if h.Kind != kindGormLock && h.Kind != kindSQLLock {
		return false
	}
	if h.Mode == modeNoKeyUpdate || h.Mode == modeKeyShare {
		return false
	}
	return !tableIsParent(h.Table)
}

// ---- 檔案掃描 ----

var (
	reLock      = regexp.MustCompile(`(?is)\bFOR\s+(NO\s+KEY\s+UPDATE|KEY\s+SHARE|UPDATE|SHARE)\b`)
	reFragment  = regexp.MustCompile(`(?is)^\s*FOR\s+(NO\s+KEY\s+UPDATE|KEY\s+SHARE|UPDATE|SHARE)(\s+(NOWAIT|SKIP\s+LOCKED))?\s*;?\s*$`)
	reSelect    = regexp.MustCompile(`(?is)\bSELECT\b`)
	reFrom      = regexp.MustCompile(`(?is)\bFROM\s+"?([A-Za-z_][A-Za-z0-9_.]*)"?`)
	reDeleteSQL = regexp.MustCompile(`(?is)\bDELETE\s+FROM\s+(?:ONLY\s+)?"?(users|user_groups)"?\b`)
	reUniqueIdx = regexp.MustCompile(`(?is)\bCREATE\s+UNIQUE\s+INDEX\b[^;]*?\bON\s+(?:ONLY\s+)?"?users"?\b([^;]*)`)
	reAddUnique = regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+(?:ONLY\s+)?"?users"?\b[^;]*?\bADD\b[^;]*?\bUNIQUE\b`)
	reWhere     = regexp.MustCompile(`(?is)\bWHERE\b`)
)

func normMode(s string) string {
	return strings.ToUpper(strings.Join(strings.Fields(s), " "))
}

var gormStrengthConsts = map[string]string{
	"LockingStrengthUpdate":      "UPDATE",
	"LockingStrengthShare":       "SHARE",
	"LockingStrengthNoKeyUpdate": modeNoKeyUpdate,
	"LockingStrengthKeyShare":    modeKeyShare,
}

type fileScan struct {
	rel     string
	fset    *token.FileSet
	file    *ast.File
	parents map[ast.Node]ast.Node
	consts  map[string]string // 同檔套件層級字串常數
	hits    []hit
}

// scanSource 解析單一檔案內容並回傳全部命中。rel 是記入命中的相對路徑。
func scanSource(rel string, src []byte) ([]hit, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, 0) // 需要 Ident.Obj 區分同名變數的作用域
	if err != nil {
		return nil, err
	}
	fs := &fileScan{rel: rel, fset: fset, file: f, parents: map[ast.Node]ast.Node{}, consts: map[string]string{}}
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if len(stack) > 0 {
			fs.parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if i < len(vs.Values) {
					if s, ok := stringLit(vs.Values[i]); ok {
						fs.consts[name.Name] = s
					}
				}
			}
		}
	}
	fs.walk()
	sort.SliceStable(fs.hits, func(i, j int) bool { return fs.hits[i].Line < fs.hits[j].Line })
	return fs.hits, nil
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// concatLit 把「全為字串字面值的 + 串接」合成一個字串。
func concatLit(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		return stringLit(x)
	case *ast.ParenExpr:
		return concatLit(x.X)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, ok1 := concatLit(x.X)
		r, ok2 := concatLit(x.Y)
		if ok1 && ok2 {
			return l + r, true
		}
	}
	return "", false
}

func (fs *fileScan) walk() {
	ast.Inspect(fs.file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BinaryExpr:
			if s, ok := concatLit(x); ok {
				fs.sqlText(x, s)
				return false // 子節點已併入
			}
		case *ast.BasicLit:
			if s, ok := stringLit(x); ok {
				fs.sqlText(x, s)
			}
		case *ast.CompositeLit:
			if sel, ok := x.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Locking" {
				fs.gormLock(x)
			}
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Delete" {
				fs.gormDelete(x)
			}
		}
		return true
	})
}

func (fs *fileScan) add(pos token.Pos, n ast.Node, kind hitKind, mode, table, detail string) {
	fs.hits = append(fs.hits, hit{
		File: fs.rel, Line: fs.fset.Position(pos).Line, Func: fs.funcName(n),
		Kind: kind, Mode: mode, Table: table, Detail: detail,
	})
}

// funcName 回報節點所在的最外層函式宣告名稱；套件層級回 "var <名>" 或 "decl"。
func (fs *fileScan) funcName(n ast.Node) string {
	for cur := n; cur != nil; cur = fs.parents[cur] {
		switch d := cur.(type) {
		case *ast.FuncDecl:
			if d.Recv != nil && len(d.Recv.List) > 0 {
				return recvName(d.Recv.List[0].Type) + "." + d.Name.Name
			}
			return d.Name.Name
		case *ast.ValueSpec:
			if len(d.Names) > 0 {
				return "var " + d.Names[0].Name
			}
		}
	}
	return "decl"
}

func recvName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return recvName(x.X)
	}
	return "?"
}

func (fs *fileScan) enclosingFunc(n ast.Node) *ast.FuncDecl {
	for cur := n; cur != nil; cur = fs.parents[cur] {
		if d, ok := cur.(*ast.FuncDecl); ok {
			return d
		}
	}
	return nil
}

// sqlText 處理一段字串字面值：原生列鎖、DDL、硬刪 SQL。
func (fs *fileScan) sqlText(n ast.Node, s string) {
	if m := reLock.FindStringSubmatch(s); m != nil {
		mode := normMode(m[1])
		switch {
		case reSelect.MatchString(s):
			table := tableUnknown
			if idx := reLock.FindStringIndex(s); idx != nil {
				if fm := reFrom.FindStringSubmatch(s[:idx[0]]); fm != nil {
					table = strings.Trim(strings.ToLower(fm[1]), `"`)
					if i := strings.LastIndex(table, "."); i >= 0 {
						table = table[i+1:]
					}
				}
			}
			fs.add(n.Pos(), n, kindSQLLock, mode, table, "raw sql")
		case reFragment.MatchString(s):
			fs.add(n.Pos(), n, kindSQLLock, normMode(reFragment.FindStringSubmatch(s)[1]), tableUnknown, "sql fragment")
		}
	}
	if m := reUniqueIdx.FindStringSubmatch(s); m != nil && !reWhere.MatchString(m[1]) {
		fs.add(n.Pos(), n, kindDDL, "", "users", "CREATE UNIQUE INDEX 無 WHERE")
	} else if reAddUnique.MatchString(s) {
		fs.add(n.Pos(), n, kindDDL, "", "users", "ALTER TABLE ADD UNIQUE")
	}
	if m := reDeleteSQL.FindStringSubmatch(s); m != nil {
		fs.add(n.Pos(), n, kindHardDelete, "", strings.ToLower(m[1]), "DELETE FROM")
	}
}

func (fs *fileScan) strengthMode(lit *ast.CompositeLit) string {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Strength" {
			continue
		}
		if s, ok := stringLit(kv.Value); ok {
			return normMode(s)
		}
		switch v := kv.Value.(type) {
		case *ast.SelectorExpr:
			if m, ok := gormStrengthConsts[v.Sel.Name]; ok {
				return m
			}
		case *ast.Ident:
			if s, ok := fs.consts[v.Name]; ok {
				return normMode(s)
			}
		}
	}
	return modeUnknown
}

// ---- GORM 呼叫鏈解析 ----

// chainCalls 回傳 e 沿 .Fun／.X 往下走經過的呼叫，以及鏈根。
func chainCalls(e ast.Expr) (calls []*ast.CallExpr, root ast.Expr) {
	for {
		switch x := e.(type) {
		case *ast.CallExpr:
			calls = append(calls, x)
			e = x.Fun
		case *ast.SelectorExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		default:
			return calls, e
		}
	}
}

// rootObj 回傳鏈根識別字解析到的變數物件（同名變數在不同區塊是不同物件）。
func rootObj(e ast.Expr) *ast.Object {
	_, r := chainCalls(e)
	if id, ok := r.(*ast.Ident); ok {
		return id.Obj
	}
	return nil
}

func methodName(c *ast.CallExpr) string {
	if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return ""
}

type chainFacts struct {
	models  map[string]bool // Model／Table 指定的目標
	dests   map[string]bool // First／Take／Last／Find／Delete 的目的變數型別
	methods map[string]bool
}

func newFacts() *chainFacts {
	return &chainFacts{models: map[string]bool{}, dests: map[string]bool{}, methods: map[string]bool{}}
}

func (cf *chainFacts) table() string {
	set := cf.models
	if len(set) == 0 {
		set = cf.dests
	}
	if len(set) == 0 {
		return tableUnknown
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, "+")
}

// facts 由 top 這條呼叫鏈出發，收集目標表線索：鏈上的呼叫、鏈根與被指派變數在同一
// 函式內的其他用法與定義（向前向後閉包，只追有本地定義的變數，不追 tx 這類參數）。
func (fs *fileScan) facts(fn *ast.FuncDecl, top ast.Expr) *chainFacts {
	cf := newFacts()
	if fn == nil {
		return cf
	}
	defs := map[*ast.Object][]ast.Expr{} // 變數 -> 指派的右值
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, l := range x.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Obj != nil {
						defs[id.Obj] = append(defs[id.Obj], x.Rhs[i])
					}
				}
			}
		case *ast.ValueSpec:
			if len(x.Names) == len(x.Values) {
				for i, id := range x.Names {
					if id.Obj != nil {
						defs[id.Obj] = append(defs[id.Obj], x.Values[i])
					}
				}
			}
		}
		return true
	})
	// 函式與閉包的參數（tx、db 這類連線）不追：它們可能被重新指派或同名，
	// 追進去會把無關的鏈吸進來。
	isParam := func(o *ast.Object) bool {
		_, ok := o.Decl.(*ast.Field)
		return ok
	}
	names := map[*ast.Object]bool{}
	var queue []*ast.Object
	addName := func(o *ast.Object) {
		if o != nil && !names[o] && !isParam(o) {
			if _, has := defs[o]; has {
				names[o] = true
				queue = append(queue, o)
			}
		}
	}
	absorb := func(e ast.Expr) {
		calls, _ := chainCalls(e)
		for _, c := range calls {
			fs.absorbCall(fn, c, cf)
		}
	}
	absorb(top)
	addName(rootObj(top))
	// top 若是某個指派的右值，被指派的變數也納入。
	if as, ok := fs.parents[top].(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
		for i, r := range as.Rhs {
			if r == top {
				if id, ok := as.Lhs[i].(*ast.Ident); ok {
					addName(id.Obj)
				}
			}
		}
	}
	if vs, ok := fs.parents[top].(*ast.ValueSpec); ok {
		for i, v := range vs.Values {
			if v == top && i < len(vs.Names) {
				addName(vs.Names[i].Obj)
			}
		}
	}
	for len(queue) > 0 {
		obj := queue[0]
		queue = queue[1:]
		for _, d := range defs[obj] {
			absorb(d)
			addName(rootObj(d))
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if rootObj(x) == obj {
					fs.absorbCall(fn, x, cf)
				}
			case *ast.AssignStmt: // 向前：q2 := q.Clauses(...)
				if len(x.Lhs) == len(x.Rhs) {
					for i, r := range x.Rhs {
						if rootObj(r) == obj {
							if id, ok := x.Lhs[i].(*ast.Ident); ok {
								addName(id.Obj)
							}
						}
					}
				}
			}
			return true
		})
	}
	return cf
}

func (fs *fileScan) absorbCall(fn *ast.FuncDecl, c *ast.CallExpr, cf *chainFacts) {
	m := methodName(c)
	if m == "" {
		return
	}
	cf.methods[m] = true
	switch m {
	case "Model":
		if len(c.Args) > 0 {
			if l := fs.typeLabel(fn, c.Args[0]); l != "" {
				cf.models[l] = true
			}
		}
	case "Table":
		if len(c.Args) > 0 {
			if s, ok := stringLit(c.Args[0]); ok {
				cf.models[strings.ToLower(s)] = true
			} else {
				cf.models[tableUnknown] = true
			}
		}
	case "First", "Take", "Last", "Find", "Delete":
		if len(c.Args) > 0 {
			if l := fs.typeLabel(fn, c.Args[0]); l != "" {
				cf.dests[l] = true
			}
		}
	}
}

var scalarTypes = map[string]bool{
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"string": true, "bool": true, "float32": true, "float64": true, "byte": true,
	"any": true, "interface": true,
}

// typeLabel 把 GORM 目的／Model 引數解析為表標籤。回 "" 表示純量（不當作目標）。
func (fs *fileScan) typeLabel(fn *ast.FuncDecl, arg ast.Expr) string {
	switch x := arg.(type) {
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return fs.typeLabel(fn, x.X)
		}
	case *ast.ParenExpr:
		return fs.typeLabel(fn, x.X)
	case *ast.CompositeLit:
		if x.Type != nil {
			return typeExprLabel(x.Type)
		}
	case *ast.Ident:
		return fs.identLabel(fn, x)
	}
	return tableUnknown
}

func typeExprLabel(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return typeExprLabel(x.X)
	case *ast.ArrayType:
		return typeExprLabel(x.Elt)
	case *ast.ParenExpr:
		return typeExprLabel(x.X)
	case *ast.SelectorExpr:
		switch x.Sel.Name {
		case "User":
			return "users"
		case "UserGroup":
			return "user_groups"
		}
		return "model:" + x.Sel.Name
	case *ast.Ident:
		if scalarTypes[x.Name] {
			return ""
		}
	}
	return tableUnknown
}

// identLabel 在函式內找最近一個（位置在引數之前）的變數宣告，解析其型別。
func (fs *fileScan) identLabel(fn *ast.FuncDecl, id *ast.Ident) string {
	if fn == nil {
		return tableUnknown
	}
	best := tableUnknown
	var bestPos token.Pos
	consider := func(pos token.Pos, label string) {
		if pos < id.Pos() && pos >= bestPos {
			bestPos, best = pos, label
		}
	}
	visitFields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				if n.Name == id.Name {
					consider(n.Pos(), typeExprLabel(f.Type))
				}
			}
		}
	}
	visitFields(fn.Type.Params)
	if fn.Body == nil {
		return best
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			visitFields(x.Type.Params)
		case *ast.ValueSpec:
			for i, nm := range x.Names {
				if nm.Name != id.Name {
					continue
				}
				switch {
				case x.Type != nil:
					consider(nm.Pos(), typeExprLabel(x.Type))
				case i < len(x.Values):
					consider(nm.Pos(), fs.valueLabel(fn, x.Values[i]))
				}
			}
		case *ast.AssignStmt:
			if x.Tok == token.DEFINE && len(x.Lhs) == len(x.Rhs) {
				for i, l := range x.Lhs {
					if lid, ok := l.(*ast.Ident); ok && lid.Name == id.Name {
						consider(lid.Pos(), fs.valueLabel(fn, x.Rhs[i]))
					}
				}
			}
		}
		return true
	})
	return best
}

// valueLabel 由初始化右值推型別：複合字面值、&複合字面值、new(T)、make([]T, ...)。
func (fs *fileScan) valueLabel(fn *ast.FuncDecl, e ast.Expr) string {
	switch x := e.(type) {
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return fs.valueLabel(fn, x.X)
		}
	case *ast.CompositeLit:
		if x.Type != nil {
			return typeExprLabel(x.Type)
		}
	case *ast.CallExpr:
		if f, ok := x.Fun.(*ast.Ident); ok && (f.Name == "new" || f.Name == "make") && len(x.Args) > 0 {
			return typeExprLabel(x.Args[0])
		}
	}
	return tableUnknown
}

// chainTop 由鏈中的某個節點往上爬到包含它的最外層呼叫鏈。
func (fs *fileScan) chainTop(n ast.Node) ast.Expr {
	cur, _ := n.(ast.Expr)
	first := true
	for {
		p := fs.parents[cur]
		switch x := p.(type) {
		case *ast.CallExpr:
			// 只有起點本身（字面值）作為引數時才爬進呼叫（Clauses(lit)）；
			// 之後遇到「鏈作為別的呼叫的引數」就停，避免吸進無關的鏈。
			if !first {
				return cur
			}
			first = false
			cur = x
		case *ast.SelectorExpr:
			if x.X != cur {
				return cur
			}
			up, ok := fs.parents[x].(*ast.CallExpr)
			if !ok || up.Fun != x {
				return cur
			}
			cur = up
		case *ast.ParenExpr:
			cur = x
		default:
			return cur
		}
	}
}

func (fs *fileScan) gormLock(lit *ast.CompositeLit) {
	mode := fs.strengthMode(lit)
	fn := fs.enclosingFunc(lit)
	if fn == nil {
		fs.add(lit.Pos(), lit, kindGormLock, mode, tableUnknown, "package level")
		return
	}
	top := fs.chainTop(lit)
	// literal 不在呼叫鏈內（例如 lk := clause.Locking{...}）時 top 即 literal 本身。
	table := fs.facts(fn, top).table()
	fs.add(lit.Pos(), lit, kindGormLock, mode, table, "gorm clause.Locking")
}

func (fs *fileScan) gormDelete(call *ast.CallExpr) {
	fn := fs.enclosingFunc(call)
	cf := fs.facts(fn, fs.chainTop(call))
	if !cf.methods["Unscoped"] {
		return
	}
	label := cf.table()
	if tableIsParent(label) {
		fs.add(call.Pos(), call, kindHardDelete, "", label, "Unscoped().Delete")
	}
}

// ---- 樹掃描 ----

// moduleRoot 由本檔位置向上找 go.mod 並核對 module 行，不用固定層數推算。
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == "module "+modulePath {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根錨點失效", dir, modulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）", filepath.Dir(self), modulePath)
		}
		dir = parent
	}
}

// scanTree 掃 root 下全部非測試 Go 檔（只略過 vendor、node_modules 與隱藏目錄）。
// 解析失敗即回錯：不得靜默略過任何檔案。
func scanTree(root string) ([]hit, int, error) {
	var all []hit
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "vendor" || name == "node_modules" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		hs, err := scanSource(filepath.ToSlash(rel), src)
		if err != nil {
			return err
		}
		files++
		all = append(all, hs...)
		return nil
	})
	return all, files, err
}
