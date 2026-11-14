package auditattribution

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 操作者結構轉手的欄位完整性：帶 API token 標示的操作者結構（欄位 APIToken 型別為 APITokenRef，
// 或同時帶 UserID 與型別為 uint 的 APITokenID 的請求脈絡），每一個帶欄位的複合字面值都必須明確給出該欄位。
//
// 稽核歸因靠操作者結構從 handler 一路搬到寫入面；結構之間的轉手若逐欄複製而漏了標示，寫入面拿到的
// 是空值，產生點的字樣檢查（TestAuditAttributionSitesRegistered）看不出來。本守衛在每一個組出這類
// 結構的地方要求明寫標示欄位；確實沒有請求可歸因的組法（背景工作、系統操作者、預覽）逐筆登錄理由。
//
// 保證範圍：字面值層級的欄位存在性。它不追蹤欄位值的來源是否正確（例如明寫了標示欄位但填了別的值），
// 也不涵蓋先組出空結構再逐欄賦值的寫法；行為面的保證由各模組以 API token 請求觸發、逐列斷言的測試負責。

// carrierExempt 不帶 API token 標示的組法：鍵為「相對路徑#函式#型別」。
var carrierExempt = map[string]string{
	"internal/modules/asset/host_inventory_service.go#HostAccountInventoryService.writeDoneAudit#InventoryActor": "盤點結束留痕以發起者身分寫入：盤點在背景工作執行，發起路由也不開放 API token",
	"internal/modules/identity/mapping_rule_preview.go#mappingWriteFromChange#Operator":                          "映射規則變更的影響預覽，只計算不寫入，不產生稽核列",
	"internal/modules/identity/assignment_guard.go#systemOperator#Operator":                                      "系統操作者（閒置自動停用等背景工作），沒有請求",
}

// carrierLowerBound 掃到的操作者結構型別數下界：掃描退化時空集合會假綠。
const carrierLowerBound = 9

type carrierLiteral struct {
	key   string // 相對路徑#函式#型別
	field string // 該型別的標示欄位
	has   bool
	pos   string
}

// carrierField 結構是否帶 API token 標示欄位；回傳欄位名。
func carrierField(pkgName string, st *ast.StructType) string {
	hasUserID := false
	for _, f := range st.Fields.List {
		for _, n := range f.Names {
			if n.Name == "UserID" {
				hasUserID = true
			}
		}
	}
	for _, f := range st.Fields.List {
		for _, n := range f.Names {
			switch n.Name {
			case "APIToken":
				switch t := f.Type.(type) {
				case *ast.SelectorExpr:
					if id, ok := t.X.(*ast.Ident); ok && id.Name == "model" && t.Sel.Name == "APITokenRef" {
						return n.Name
					}
				case *ast.Ident:
					if pkgName == "model" && t.Name == "APITokenRef" {
						return n.Name
					}
				}
			case "APITokenID":
				if id, ok := f.Type.(*ast.Ident); ok && id.Name == "uint" && hasUserID {
					return n.Name
				}
			}
		}
	}
	return ""
}

type parsedFile struct {
	rel  string
	dir  string
	file *ast.File
	fset *token.FileSet
}

func parseProductionFiles(t *testing.T) []parsedFile {
	t.Helper()
	root := moduleRoot(t)
	var out []parsedFile
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
			out = append(out, parsedFile{rel: rel, dir: filepath.ToSlash(filepath.Dir(rel)), file: f, fset: fset})
			return nil
		})
		if err != nil {
			t.Fatalf("掃描 %s 失敗：%v", top, err)
		}
	}
	return out
}

// importDirs 檔案的匯入別名 → 模組內相對目錄（模組外的匯入不列）。
func importDirs(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, im := range f.Imports {
		p, err := strconv.Unquote(im.Path.Value)
		if err != nil || !strings.HasPrefix(p, modulePath+"/") {
			continue
		}
		dir := strings.TrimPrefix(p, modulePath+"/")
		alias := dir[strings.LastIndex(dir, "/")+1:]
		if im.Name != nil {
			alias = im.Name.Name
		}
		out[alias] = dir
	}
	return out
}

func scanCarrierLiterals(t *testing.T) (map[string]string, []carrierLiteral) {
	t.Helper()
	files := parseProductionFiles(t)
	carriers := map[string]string{} // 目錄.型別 → 標示欄位
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, sp := range gd.Specs {
				ts := sp.(*ast.TypeSpec)
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				if f := carrierField(pf.file.Name.Name, st); f != "" {
					carriers[pf.dir+"."+ts.Name.Name] = f
				}
			}
		}
	}
	var lits []carrierLiteral
	for _, pf := range files {
		imports := importDirs(pf.file)
		visit := func(fn string, root ast.Node) {
			ast.Inspect(root, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok || len(cl.Elts) == 0 || cl.Type == nil {
					return true
				}
				var typeKey, typeName string
				switch x := cl.Type.(type) {
				case *ast.Ident:
					typeKey, typeName = pf.dir+"."+x.Name, x.Name
				case *ast.SelectorExpr:
					id, ok := x.X.(*ast.Ident)
					if !ok {
						return true
					}
					dir, ok := imports[id.Name]
					if !ok {
						return true
					}
					typeKey, typeName = dir+"."+x.Sel.Name, x.Sel.Name
				default:
					return true
				}
				field, ok := carriers[typeKey]
				if !ok {
					return true
				}
				l := carrierLiteral{key: pf.rel + "#" + fn + "#" + typeName, field: field,
					pos: pf.fset.Position(cl.Pos()).String()}
				for _, e := range cl.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok && id.Name == field {
							l.has = true
						}
					}
				}
				lits = append(lits, l)
				return true
			})
		}
		for _, decl := range pf.file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body != nil {
					fk := funcKey(pf.rel, d)
					visit(fk[strings.Index(fk, "#")+1:], d.Body)
				}
			case *ast.GenDecl:
				visit("<package>", d)
			}
		}
	}
	return carriers, lits
}

// TestActorCarrierLiteralsSetAPIToken 每一個組出操作者結構的字面值都明寫 API token 標示欄位，
// 或登錄不帶標示的理由；登錄了已不存在的組法同樣失敗。
func TestActorCarrierLiteralsSetAPIToken(t *testing.T) {
	carriers, lits := scanCarrierLiterals(t)
	if len(carriers) < carrierLowerBound {
		t.Fatalf("掃到的操作者結構型別只有 %d 個（下界 %d），掃描可能退化", len(carriers), carrierLowerBound)
	}
	names := make([]string, 0, len(carriers))
	for k := range carriers {
		names = append(names, k)
	}
	sort.Strings(names)
	t.Logf("操作者結構型別 %d 個：%s", len(names), strings.Join(names, "、"))
	seen := map[string]bool{}
	var problems []string
	for _, l := range lits {
		if l.has {
			continue
		}
		seen[l.key] = true
		if strings.TrimSpace(carrierExempt[l.key]) != "" {
			continue
		}
		problems = append(problems, l.pos+"："+l.key+" 未帶 "+l.field+
			"（操作者結構之間的轉手要把 API token 標示一起搬；確實沒有請求可歸因時登錄理由）")
	}
	for k := range carrierExempt {
		if !seen[k] {
			problems = append(problems, "登錄了已不存在或已帶標示的組法："+k)
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}
