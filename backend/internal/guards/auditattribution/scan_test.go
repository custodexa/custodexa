package auditattribution

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/custodexa/backend"

// site 一個稽核列的產生點：組出稽核條目或稽核事件的複合字面值，以所在檔案與函式為鍵。
type site struct {
	key     string // 相對路徑#函式（方法帶接收者型別）
	kind    string // entry（稽核服務條目）／event（寫入面事件）／row（直接組資料列）
	request string // event 的 Request 欄位原始碼；未帶時為空
	wrapped bool   // 字面值是否直接作為 AttributeAuditEntry 的引數
	body    string // 所在函式本體原始碼
	line    int
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("無法取得本檔路徑")
	}
	dir := filepath.Dir(self)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == "module "+modulePath {
					return dir
				}
			}
			t.Fatalf("%s 的 go.mod 不是 %s", dir, modulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("找不到 go.mod")
		}
		dir = parent
	}
}

// literalKind 判斷複合字面值的型別是否為稽核條目、稽核事件或稽核資料列。
func literalKind(pkgName string, typ ast.Expr) string {
	switch x := typ.(type) {
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		if !ok {
			return ""
		}
		switch {
		case x.Sel.Name == "AuditLogEntry" && id.Name == "audit":
			return "entry"
		case x.Sel.Name == "AuditEvent" && (id.Name == "port" || id.Name == "gatewayapi"):
			return "event"
		case x.Sel.Name == "AuditLog" && id.Name == "model":
			return "row"
		}
	case *ast.Ident:
		switch {
		case x.Name == "AuditLogEntry" && pkgName == "audit":
			return "entry"
		case x.Name == "AuditEvent" && (pkgName == "port" || pkgName == "gatewayapi"):
			return "event"
		case x.Name == "AuditLog" && pkgName == "model":
			return "row"
		}
	}
	return ""
}

func funcKey(rel string, fd *ast.FuncDecl) string {
	name := fd.Name.Name
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		t := fd.Recv.List[0].Type
		if st, ok := t.(*ast.StarExpr); ok {
			t = st.X
		}
		if ix, ok := t.(*ast.IndexExpr); ok {
			t = ix.X
		}
		if id, ok := t.(*ast.Ident); ok {
			name = id.Name + "." + name
		}
	}
	return rel + "#" + name
}

func src(fset *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, n)
	return b.String()
}

// scanSites 掃描正式程式碼（不含測試檔）中所有帶欄位的稽核複合字面值。
// 空字面值（例如查詢時的 &model.AuditLog{}）不是產生點，不列入。
func scanSites(t *testing.T) []site {
	t.Helper()
	root := moduleRoot(t)
	var out []site
	for _, top := range []string{"internal", "cmd", "pkg"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				key := funcKey(rel, fd)
				body := ""
				wrappedArgs := map[ast.Node]bool{}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "AttributeAuditEntry" && len(call.Args) == 2 {
						arg := call.Args[1]
						if u, ok := arg.(*ast.UnaryExpr); ok {
							arg = u.X
						}
						wrappedArgs[arg] = true
					}
					return true
				})
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					cl, ok := n.(*ast.CompositeLit)
					if !ok || len(cl.Elts) == 0 {
						return true
					}
					kind := literalKind(f.Name.Name, cl.Type)
					if kind == "" {
						return true
					}
					if body == "" {
						body = src(fset, fd.Body)
					}
					s := site{key: key, kind: kind, wrapped: wrappedArgs[cl], body: body, line: fset.Position(cl.Pos()).Line}
					for _, e := range cl.Elts {
						kv, ok := e.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Request" {
							s.request = src(fset, kv.Value)
						}
					}
					out = append(out, s)
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("掃描 %s 失敗：%v", top, err)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].key != out[j].key {
			return out[i].key < out[j].key
		}
		return out[i].line < out[j].line
	})
	return out
}
