package identity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// `user_roles` 寫入面的 AST 守衛（role-assignment-integrity task 3.1）。
//
// # 它盯的不變式
//
// 對帳把「差集非空」讀成「有人繞過應用程式改了資料庫」。這句話只有在
// **每一條寫入路徑都留痕**時才成立——少一條，對帳就會把一個合法變更報成竄改，
// 而假警報會讓真警報失去意義。故：全樹寫 `user_roles` 的位置只能是
// `internal/model/user_role_write.go` 的 `AssignUserRole`／`RevokeUserRole`。
//
// # 雙向
//
//	正向：別處出現 `user_roles` 的寫入 SQL、或 `Association("Roles")` 的寫入呼叫 → 紅。
//	反向：登記的呼叫點消失、或它帶的 origin 變了 → 紅。
//
// 少了反向，把某條路徑整個刪掉（例如 OIDC 首登不再配角色）不會有任何測試轉紅，
// 而那正是留痕靜默消失的形狀。
//
// # 為什麼掃字串字面量而不是只看函式呼叫
//
// 威脅模型明載對手可直寫資料庫；程式碼裡的原生 SQL 是同一件事的「內部版本」，
// 而它不經任何型別檢查。以 AST 取出字面量再比對，避開註解與測試檔的誤報
//（`go/parser` 天然分得出來，`grep` 分不出）。

// roleWriteFaceFile 唯一合法的寫入面（相對 module 根）
const roleWriteFaceFile = "internal/model/user_role_write.go"

// roleWriteSQLRe 寫 user_roles 的 SQL 形態
var roleWriteSQLRe = regexp.MustCompile(`(?is)(insert\s+into\s+user_roles|delete\s+from\s+user_roles|update\s+user_roles\s)`)

// roleAssociationWriteMethods `Association("Roles")` 上的寫入方法
var roleAssociationWriteMethods = map[string]bool{
	"Append": true, "Replace": true, "Delete": true, "Clear": true,
}

// roleWriteSite 一個登記的寫入呼叫點。
//
// File／Func 指出它在哪，Origins 是它應當帶的來源常數（同一個函式可能同時
// 授予與撤銷）。三段皆須吻合，任一不符即紅——程式碼一搬家或 origin 一改，
// 登記立刻失效而非靜默沿用
type roleWriteSite struct {
	File    string
	Func    string
	Origins []string
	Note    string
}

// roleWriteSites 五條**留痕**的角色寫入路徑，逐點登記。
//
// 播種不在此表：它走不留痕的 `AssignUserRoleAtSeed`，由 roleSeedWriteSite 單獨列管
var roleWriteSites = []roleWriteSite{
	{File: "internal/modules/identity/user_service.go", Func: "Create",
		Origins: []string{"RoleOriginRegister"}, Note: "本地建帳號時配的角色"},
	{File: "internal/modules/identity/user_service.go", Func: "AddRole",
		Origins: []string{"RoleOriginAPI"}, Note: "管理者一站式代配單一角色"},
	{File: "internal/modules/identity/user_service.go", Func: "AssignRoles",
		Origins: []string{"RoleOriginAPI"}, Note: "管理者替換角色集（授予與撤銷各一）"},
	{File: "internal/modules/identity/auth_service.go", Func: "provisionShadowUser",
		Origins: []string{"RoleOriginLDAP"}, Note: "LDAP 影子帳號供應"},
	{File: "internal/modules/identity/oidc_login_service.go", Func: "provisionFromClaims",
		Origins: []string{"RoleOriginOIDC"}, Note: "OIDC 首次登入建帳號"},
}

// roleSeedWriteSite 不留痕變體 `AssignUserRoleAtSeed` 的**唯一**合法呼叫點。
//
// # 為什麼開這一條例外
//
// 播種發生在段 1（`cmd/server/stage1.go:226`），解封之前——審計蓋章鑰要到段 2
// 的 `InitAuditIntegrityVersioned` 才存在。在那裡寫審計列，寫出來的必然是一列
// 永遠不帶章的列，驗章端只能把它當成上線前的歷史列；那不是留痕，是一個假的
// 「未蓋章」訊號（`TestLifecycleFullStartupThenReverseShutdown` 即以此判紅）。
//
// **對帳不因此變弱**：對帳的基準是第一個含快照的檢查點，播種的指派早在那之前，
// 本來就在快照內，不屬於「檢查點之後的變動」。
//
// # 為什麼例外必須是一條而不是一種
//
// 例外若寫成「database 包內都可以」，下一個在解封後才執行的 database 路徑就會
// 免費繼承這條豁免，而它本來是能留痕的。故登記的是**檔＋函式**，
// 且反向斷言要求它存在——被刪掉或搬家一樣轉紅。
var roleSeedWriteSite = roleWriteSite{
	File: "internal/database/seed.go", Func: "seedAdmin",
	Note: "初始管理員播種（解封前，無蓋章鑰）",
}

// TestRoleAuditWriteSitesGuard 見檔頭
func TestRoleAuditWriteSitesGuard(t *testing.T) {
	root := moduleRootForRoleGuard(t)
	found := map[string]map[string]bool{} // "file|func" → origin 集合
	seedFound := map[string]bool{}        // AssignUserRoleAtSeed 的呼叫點 "file|func"

	files := goSourceFilesForRoleGuard(t, root)
	if len(files) < 100 {
		t.Fatalf("掃到的原始檔只有 %d 個：掃描範圍本身壞了，本守衛的綠燈沒有意義", len(files))
	}
	for _, path := range files {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatalf("相對路徑: %v", err)
		}
		rel = filepath.ToSlash(rel)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("解析 %s: %v", rel, err)
		}
		inspectRoleWrites(t, fset, file, rel, found, seedFound)
	}

	for _, site := range roleWriteSites {
		key := site.File + "|" + site.Func
		got, ok := found[key]
		if !ok {
			t.Errorf("登記的寫入點消失：%s 的 %s（%s）已不再呼叫 model.AssignUserRole／RevokeUserRole。"+
				"該路徑若真的不再配角色，請一併移除登記；否則它是一條沒有留痕的路徑",
				site.File, site.Func, site.Note)
			continue
		}
		for _, origin := range site.Origins {
			if !got[origin] {
				t.Errorf("%s 的 %s 未以 model.%s 呼叫寫入面（實際帶的來源：%v）",
					site.File, site.Func, origin, sortedKeys(got))
			}
		}
	}

	// 不留痕變體：唯一呼叫點必須在、且不得有第二個
	seedKey := roleSeedWriteSite.File + "|" + roleSeedWriteSite.Func
	if !seedFound[seedKey] {
		t.Errorf("登記的播種寫入點消失：%s 的 %s（%s）已不再呼叫 model.AssignUserRoleAtSeed。"+
			"播種若改走留痕路徑，請把本例外刪掉並改登記於 roleWriteSites；"+
			"若整條路徑消失，請一併移除登記",
			roleSeedWriteSite.File, roleSeedWriteSite.Func, roleSeedWriteSite.Note)
	}
	for key := range seedFound {
		if key == seedKey {
			continue
		}
		parts := strings.SplitN(key, "|", 2)
		t.Errorf("未登記的不留痕角色寫入呼叫點：%s 的 %s。AssignUserRoleAtSeed 的射程"+
			"只有解封前的播種一處——解封之後的路徑都拿得到蓋章鑰，一律走 AssignUserRole 留痕",
			parts[0], parts[1])
	}

	// 反向：出現未登記的呼叫點
	registered := map[string]bool{}
	for _, site := range roleWriteSites {
		registered[site.File+"|"+site.Func] = true
	}
	for key := range found {
		if !registered[key] {
			parts := strings.SplitN(key, "|", 2)
			t.Errorf("未登記的角色寫入呼叫點：%s 的 %s。新增一條角色寫入路徑就要登記它，"+
				"否則沒有人知道對帳的假警報射程變寬了", parts[0], parts[1])
		}
	}
}

// inspectRoleWrites 單檔掃描：正向找違規、順帶收集登記點的實際 origin
func inspectRoleWrites(t *testing.T, fset *token.FileSet, file *ast.File, rel string,
	found map[string]map[string]bool, seedFound map[string]bool) {
	t.Helper()
	var funcStack []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			funcStack = append(funcStack, node.Name.Name)
		case *ast.BasicLit:
			if node.Kind != token.STRING || rel == roleWriteFaceFile {
				return true
			}
			if roleWriteSQLRe.MatchString(node.Value) {
				t.Errorf("%s:%d 出現 user_roles 的寫入 SQL：唯一合法的寫入面是 %s 的 "+
					"AssignUserRole／RevokeUserRole。繞過它就是一條不留痕的角色變更路徑",
					rel, fset.Position(node.Pos()).Line, roleWriteFaceFile)
			}
		case *ast.CallExpr:
			checkAssociationWrite(t, fset, node, rel)
			collectRoleWriteCall(node, rel, funcStack, found)
			collectSeedRoleWriteCall(node, rel, funcStack, seedFound)
		}
		return true
	})
	// funcStack 只在頂層 FuncDecl 進出，巢狀閉包沿用外層名——
	// 呼叫點落在閉包內（AssignRoles 的 applyRoles）時仍歸屬其外層函式，正是所欲
	_ = funcStack
}

// checkAssociationWrite `Association("Roles").Append/Replace/Delete/Clear`
func checkAssociationWrite(t *testing.T, fset *token.FileSet, call *ast.CallExpr, rel string) {
	t.Helper()
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !roleAssociationWriteMethods[sel.Sel.Name] {
		return
	}
	inner, ok := sel.X.(*ast.CallExpr)
	if !ok {
		return
	}
	innerSel, ok := inner.Fun.(*ast.SelectorExpr)
	if !ok || innerSel.Sel.Name != "Association" || len(inner.Args) != 1 {
		return
	}
	lit, ok := inner.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING || strings.Trim(lit.Value, `"`) != "Roles" {
		return
	}
	t.Errorf("%s:%d 以 Association(\"Roles\").%s 寫角色關聯：ORM 的替換是個黑箱，"+
		"它刪了什麼、加了什麼呼叫端看不到，也就寫不出對帳重放得回來的事件流",
		rel, fset.Position(call.Pos()).Line, sel.Sel.Name)
}

// collectRoleWriteCall 收集 model.AssignUserRole／RevokeUserRole 的呼叫與其 origin 引數
func collectRoleWriteCall(call *ast.CallExpr, rel string, funcStack []string,
	found map[string]map[string]bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	if sel.Sel.Name != "AssignUserRole" && sel.Sel.Name != "RevokeUserRole" {
		return
	}
	if len(funcStack) == 0 || len(call.Args) != 4 {
		return
	}
	origin, ok := call.Args[3].(*ast.SelectorExpr)
	if !ok {
		return
	}
	key := rel + "|" + funcStack[len(funcStack)-1]
	if found[key] == nil {
		found[key] = map[string]bool{}
	}
	found[key][origin.Sel.Name] = true
}

// collectSeedRoleWriteCall 收集不留痕變體 model.AssignUserRoleAtSeed 的呼叫點
func collectSeedRoleWriteCall(call *ast.CallExpr, rel string, funcStack []string,
	seedFound map[string]bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "AssignUserRoleAtSeed" || len(funcStack) == 0 {
		return
	}
	seedFound[rel+"|"+funcStack[len(funcStack)-1]] = true
}

// goSourceFilesForRoleGuard module 內全部非測試 .go 檔
func goSourceFilesForRoleGuard(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "vendor", "testdata", ".git", "tmp":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走訪原始碼樹: %v", err)
	}
	return out
}

// moduleRootForRoleGuard 由測試工作目錄上溯到 go.mod
func moduleRootForRoleGuard(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("找不到 module 根（go.mod）")
	return ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
