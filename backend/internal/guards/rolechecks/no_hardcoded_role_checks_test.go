package rolechecks

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestNoHardcodedRoleChecks 擋：日後新增的角色名稱放行判斷繞過登錄，使自訂角色上線後出現旁路。
//
// 產品程式碼（非測試檔）只允許在「登記檔案」內：
//  1. 引用角色名稱常數 model.RoleAdmin／RoleAuditor／RoleUser／RoleApprover，或以字串字面值
//     "admin"／"auditor"／"approver" 做相等比較或 switch case；
//  2. 在 authz 套件之外讀取主體的舊主角色（LegacyRole／IsAuditor）。
//
// 讀取請求脈絡的 role 鍵（Get／GetString／Value("role")）**不允許任何登記**：授權不再讀它。
// 登記項必須附理由，且必須仍有命中（過期登記即失敗）。登記只分兩類：
//   - data：資料定義（種子、遷移、範本定義、值域、回應形狀的值）；
//   - exception：保留例外（依舊主角色選擇呈現或行為，非授權判斷），由後續的角色定義階段接手。

type regEntry struct {
	kind   string // "data" | "exception"
	reason string
}

// roleNameRefs 規則 1 的登記檔案（相對 backend/ 的路徑）。
var roleNameRefs = map[string]regEntry{
	"internal/model/role.go":                              {"data", "角色名稱常數定義與保留名稱對內建範本識別的對照（寫入時套用，與遷移標記規則相同）"},
	"internal/database/seed.go":                           {"data", "內建角色與初始管理員的種子"},
	"internal/database/authz_model_report.go":             {"data", "權限模型遷移：四個內建名稱對內建範本識別的標記與遷移報告"},
	"internal/modules/authz/builtin_templates.go":         {"data", "舊相容設定檔：舊主角色字串值域與內建範本的對應"},
	"internal/modules/authz/effective_access_resolver.go": {"data", "有效權限試算回應欄位的值域（admin／auditor 字串），判定依 builtin_key"},
	"internal/modules/identity/auth_service.go":           {"exception", "primaryRoleOf 折疊 JWT role claim（claim 形狀不變）；登入時是否對帳與 MFA 僅管理者政策依舊主角色"},
	"internal/modules/identity/oidc_login_service.go":     {"data", "新帳號預設角色（一般使用者）的種子查詢"},
}

// legacyRoleReads 規則 2 的登記檔案。
var legacyRoleReads = map[string]regEntry{
	"internal/api/asset_handler.go":                {"exception", "全量列表僅對稽核員回入口判定欄、超管回應形狀凍結（呈現選擇，非授權）"},
	"internal/sshproxy/handler.go":                 {"exception", "簽發主體的 ClaimedRole 溯源欄位（僅供溯源，不作判定依據）"},
	"internal/sshproxy/observer_ticket_handler.go": {"exception", "監看票簽發主體的 ClaimedRole 溯源欄位（僅供溯源，不作判定依據）"},
}

var roleConstNames = map[string]bool{"RoleAdmin": true, "RoleAuditor": true, "RoleUser": true, "RoleApprover": true}
var roleLiterals = map[string]bool{"admin": true, "auditor": true, "approver": true}

type hit struct {
	file string
	line int
	rule string // "name" | "legacy" | "ctxrole"
	text string
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("取得工作目錄失敗: %v", err)
	}
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			if strings.Contains(string(body), "module github.com/custodexa/backend") {
				return dir
			}
			t.Fatalf("在 %s 找到 go.mod 但 module 行不符：掃描根錨點失效", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("向上找不到 go.mod：掃描根無從定位")
		}
		dir = parent
	}
}

func isRoleLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(bl.Value)
	if err != nil || !roleLiterals[v] {
		return "", false
	}
	return v, true
}

// scan 掃描一個檔案的命中。
func scan(t *testing.T, fset *token.FileSet, f *ast.File, rel string, inPkgAuthz, inPkgModel bool) []hit {
	var hits []hit
	add := func(pos token.Pos, rule, text string) {
		hits = append(hits, hit{file: rel, line: fset.Position(pos).Line, rule: rule, text: text})
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "model" && roleConstNames[x.Sel.Name] {
				add(x.Pos(), "name", "model."+x.Sel.Name)
			}
		case *ast.Ident:
			// model 套件內部的裸識別字（常數定義處本身除外：其 Obj 為宣告）
			if inPkgModel && roleConstNames[x.Name] && x.Obj != nil && x.Obj.Kind == ast.Con {
				if vs, ok := x.Obj.Decl.(*ast.ValueSpec); ok {
					declared := false
					for _, nm := range vs.Names {
						if nm == x {
							declared = true
						}
					}
					if !declared {
						add(x.Pos(), "name", x.Name)
					}
				}
			}
		case *ast.BinaryExpr:
			if x.Op == token.EQL || x.Op == token.NEQ {
				if v, ok := isRoleLit(x.X); ok {
					add(x.Pos(), "name", `== "`+v+`"`)
				} else if v, ok := isRoleLit(x.Y); ok {
					add(x.Pos(), "name", `== "`+v+`"`)
				}
			}
		case *ast.CaseClause:
			for _, e := range x.List {
				if v, ok := isRoleLit(e); ok {
					add(e.Pos(), "name", `case "`+v+`"`)
				}
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Get", "GetString", "Value":
				if len(x.Args) == 1 {
					if bl, ok := x.Args[0].(*ast.BasicLit); ok && bl.Kind == token.STRING {
						if v, _ := strconv.Unquote(bl.Value); v == "role" {
							add(x.Pos(), "ctxrole", sel.Sel.Name+`("role")`)
						}
					}
				}
			case "LegacyRole", "IsAuditor":
				if !inPkgAuthz {
					add(x.Pos(), "legacy", sel.Sel.Name+"()")
				}
			}
		}
		return true
	})
	return hits
}

func collect(t *testing.T) []hit {
	root := moduleRoot(t)
	var all []hit
	files := 0
	for _, sub := range []string{"internal", "cmd", "pkg"} {
		base := filepath.Join(root, sub)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "guards" {
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
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution&0)
			if perr != nil {
				return fmt.Errorf("解析 %s 失敗：%w", rel, perr) // 掃不到不得當成沒有違規
			}
			files++
			all = append(all, scan(t, fset, f, rel,
				strings.HasPrefix(rel, "internal/modules/authz/"), strings.HasPrefix(rel, "internal/model/"))...)
			return nil
		})
		if err != nil {
			t.Fatalf("掃描 %s 失敗: %v", sub, err)
		}
	}
	if files < 200 {
		t.Fatalf("只掃到 %d 個非測試檔，掃描根或排除規則異常", files)
	}
	return all
}

func TestNoHardcodedRoleChecks(t *testing.T) {
	hits := collect(t)

	t.Run("脈絡 role 鍵不得被讀取（不允許登記）", func(t *testing.T) {
		for _, h := range hits {
			if h.rule == "ctxrole" {
				t.Errorf("%s:%d 讀取脈絡 role 鍵（%s）：授權不再讀它，請改讀主體", h.file, h.line, h.text)
			}
		}
	})

	check := func(t *testing.T, rule string, reg map[string]regEntry, what string) {
		byFile := map[string][]hit{}
		for _, h := range hits {
			if h.rule == rule {
				byFile[h.file] = append(byFile[h.file], h)
			}
		}
		var files []string
		for f := range byFile {
			files = append(files, f)
		}
		sort.Strings(files)
		for _, f := range files {
			if _, ok := reg[f]; !ok {
				h := byFile[f][0]
				t.Errorf("%s:%d 未登記的%s（%s）：請改走能力判定或內建身分判定；確屬資料定義或保留例外才登記並附理由", f, h.line, what, h.text)
			}
		}
		var regFiles []string
		for f := range reg {
			regFiles = append(regFiles, f)
		}
		sort.Strings(regFiles)
		for _, f := range regFiles {
			e := reg[f]
			if strings.TrimSpace(e.reason) == "" || (e.kind != "data" && e.kind != "exception") {
				t.Errorf("登記項 %s 缺理由或種類不合法", f)
			}
			if len(byFile[f]) == 0 {
				t.Errorf("登記項 %s 已無對應命中（%s），請移除登記", f, what)
			}
		}
	}

	t.Run("角色名稱引用與比較只允許登記檔案", func(t *testing.T) {
		check(t, "name", roleNameRefs, "角色名稱引用或比較")
	})
	t.Run("舊主角色讀取只允許登記檔案", func(t *testing.T) {
		check(t, "legacy", legacyRoleReads, "舊主角色讀取")
	})
}
