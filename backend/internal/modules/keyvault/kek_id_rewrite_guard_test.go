package keyvault_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 「**不存在任何改寫既有 kek_id 的程式碼路徑**」的 AST 守衛。
//
// **為何需要一道結構守衛而不是靠 code review**：早期曾裁決要做存量正規化
// migration，後續兩方獨立同判整項取消。取消的理由不是「暫時不做」而是
// 「做了就是錯的」——天真述詞（`kek_id != canonical` 即改寫）在 alias 被重指向時，
// 會把 ARN-A 包裹的列改標成 ARN-B：材料未動而標籤已錯，把原本正確的
// keyvault.ErrKEKMismatch fail-close 換成**不可逆的標籤污染**。
//
// 一個「已被明確否決的設計」如果只寫在文件裡，日後很容易被重新提出並實作
// （尤其是當有人看到 fail-close 訊息覺得「自動修一下就好了」時）。故以守衛釘住：
// 任何改寫既有列 kek_id 的寫法都會讓本測試轉紅，逼人回來讀這段理由。
//
// **允許什麼**：以 `KEKID:` 作為**複合字面鍵**建立新列（重包 clone、bootstrap、
// 輪替）——那是新增一列，不是改寫既有列的標籤。
//
// **禁止什麼**（四種等價寫法都攔，攔能力而非攔名字）：
//  1. 對既有結構的欄位賦值 `row.KEKID = x`；
//  2. `Update("kek_id", …)` / `UpdateColumn(s)("kek_id", …)`；
//  3. `Updates(map[string]any{"kek_id": …})` 或 `Updates(model.DataKey{KEKID: …})`；
//  4. 原生 SQL 字面中的 `UPDATE … SET … kek_id`。

// kekIDColumnName 資料庫欄名（單一事實源）
const kekIDColumnName = "kek_id"

// kekIDFieldName 結構欄位名
const kekIDFieldName = "KEKID"

// updateCallNames 會寫回 DB 的 gorm 方法名
var updateCallNames = map[string]bool{
	"Update": true, "UpdateColumn": true, "UpdateColumns": true, "Updates": true,
}

// kekIDRewriteAllowlist 允許改寫 kek_id 的（檔名 → 外層函式名）。
//
// **目前刻意為空**。新增任何一項都等於重新引入已被否決的設計，
// 必須先在 design 上翻案並說明如何避免 alias 重指向造成的標籤污染。
var kekIDRewriteAllowlist = map[string][]string{}

// minKEKIDScannedFiles 全 backend 掃描的檔數下限（防空集合假綠）。
// 2026-08-09 實測 299 檔（見測試的 t.Logf），門檻取 270。
const minKEKIDScannedFiles = 270

func TestNoKEKIDRewritePath(t *testing.T) {
	root := serviceGuardBackendRoot(t)
	var violations []string
	scanned := 0

	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// **scripts 刻意不排除（CV-L3）**：原本把它一併 SkipDir，
			// 於是把 `tx.Exec("UPDATE data_keys SET kek_id = ?")` 放進
			// backend/scripts/ 完全不會被偵測——而 runbook 明文禁止提供
			// 裸 UPDATE，盲區與被禁行為的型態完全重疊。
			// 該目錄的檔案帶 //go:build ignore，但 AST 掃描不看 build tag，
			// 故納入掃描零成本（env 漂移守衛排除 scripts 是另一回事：
			// 那裡判定的是「部署 env 契約」，維運工具的 env 讀取確實不屬於它）。
			switch info.Name() {
			case "vendor", "testdata", ".git", "tmp":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// 原先 `return nil` 靜默略過：解析失敗的檔等於沒被掃過，而本守衛的
			// 失敗形態正是「掃不到＝零違規＝綠」。go/parser **不套用 build tag**，
			// 故 //go:build ignore 的維運工具照樣能解析；解析失敗即代表原始碼真的
			// 壞了，fail-close 才是正確反應。
			t.Fatalf("解析 %s 失敗，守衛拒絕在殘缺 AST 上宣稱零違規: %v", path, perr)
		}
		scanned++
		rel, _ := filepath.Rel(root, path)
		violations = append(violations, scanKEKIDRewrites(fset, f, rel, filepath.Base(path))...)
		return nil
	})
	if walkErr != nil {
		t.Fatalf("掃描 backend 失敗: %v", walkErr)
	}
	if scanned < minKEKIDScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下限 %d，掃描根 %s）：掃描範圍已失真，"+
			"守衛將在近乎空集合下假綠。若目錄結構改變，改的是掃描根而不是下限",
			scanned, minKEKIDScannedFiles, root)
	}
	t.Logf("kek_id 守衛掃描檔數=%d（下限 %d）", scanned, minKEKIDScannedFiles)

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("偵測到改寫既有 kek_id 的程式碼路徑（該需求已整項取消）：\n%s\n"+
			"若確要翻案，須先於 design 說明如何避免 alias 重指向造成的不可逆標籤污染，"+
			"並把該函式列入 kekIDRewriteAllowlist", strings.Join(violations, "\n"))
	}
}

// scanKEKIDRewrites 掃單一 AST，回傳違規描述清單（空＝無違規）。
//
// 抽成獨立函式的理由：守衛本身必須被驗證（本專案的「守衛假綠」教訓——
// 一個永遠回空清單的掃描器會讓 TestNoKEKIDRewritePath 永遠綠）。
// TestKEKIDRewriteGuardDetectsViolations 以合成源碼作**正向控制**。
func scanKEKIDRewrites(fset *token.FileSet, f *ast.File, rel, base string) []string {
	allowed := kekIDRewriteAllowlist[base]
	var out []string
	report := func(pos token.Pos, form string) {
		fn := enclosingFuncName(f, pos)
		for _, a := range allowed {
			if a == fn {
				return
			}
		}
		out = append(out, fmt.Sprintf("%s:%d %s（外層函式 %s）", rel, fset.Position(pos).Line, form, fn))
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			// 形式 1：對既有結構的欄位賦值
			for _, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == kekIDFieldName {
					report(sel.Pos(), "對既有列的 "+kekIDFieldName+" 欄位賦值")
				}
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || !updateCallNames[sel.Sel.Name] {
				return true
			}
			// 形式 2／3：Update("kek_id", …) 與 Updates({"kek_id": …})
			for _, arg := range node.Args {
				if litHasKEKID(arg) {
					report(node.Pos(), sel.Sel.Name+" 寫入 "+kekIDColumnName)
				}
			}
		case *ast.BasicLit:
			// 形式 4：原生 SQL
			if node.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(node.Value)
			if err != nil {
				return true
			}
			low := strings.ToLower(s)
			if strings.Contains(low, "update ") && strings.Contains(low, "set") && strings.Contains(low, kekIDColumnName) {
				report(node.Pos(), "原生 SQL 改寫 "+kekIDColumnName)
			}
		}
		return true
	})
	return out
}

// TestKEKIDRewriteGuardDetectsViolations 守衛的**正向控制**：四種等價寫法都必須
// 被攔下，而合法的「複合字面建新列」不得被誤報。
//
// 沒有這一格，TestNoKEKIDRewritePath 綠只證明「掃描器沒回報東西」，
// 不證明「掃描器看得見東西」——那正是守衛假綠最常見的形態。
func TestKEKIDRewriteGuardDetectsViolations(t *testing.T) {
	violating := []struct {
		name string
		src  string
	}{
		{"欄位賦值", `package p
func f(row *DataKey) { row.KEKID = "x" }`},
		{"Update 欄名", `package p
func f(tx *DB) { tx.Model(nil).Update("kek_id", "x") }`},
		{"Updates map", `package p
func f(tx *DB) { tx.Model(nil).Updates(map[string]interface{}{"kek_id": "x"}) }`},
		{"Updates struct", `package p
func f(tx *DB) { tx.Model(nil).Updates(DataKey{KEKID: "x"}) }`},
		{"原生 SQL", `package p
func f(tx *DB) { tx.Exec("UPDATE data_keys SET kek_id = ? WHERE id = ?", 1, 2) }`},
	}
	for _, c := range violating {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", c.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := scanKEKIDRewrites(fset, f, "x.go", "x.go"); len(got) == 0 {
				t.Fatalf("守衛未攔下違規寫法：\n%s", c.src)
			}
		})
	}

	// 負向控制：建立新列的複合字面不得被誤報（重包 clone／bootstrap 都靠它）
	legit := `package p
func f(tx *DB) { tx.Create(&DataKey{Purpose: "data", Version: 1, KEKID: "arn:..."}) }`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "y.go", legit, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := scanKEKIDRewrites(fset, f, "y.go", "y.go"); len(got) != 0 {
		t.Fatalf("以複合字面建立新列不得被誤報：%v", got)
	}
}

// litHasKEKID 判定運算式是否以字面形式攜帶 kek_id 欄／KEKID 欄位
func litHasKEKID(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				if s, err := strconv.Unquote(node.Value); err == nil && s == kekIDColumnName {
					found = true
				}
			}
		case *ast.KeyValueExpr:
			if ident, ok := node.Key.(*ast.Ident); ok && ident.Name == kekIDFieldName {
				found = true
			}
		}
		return !found
	})
	return found
}

// enclosingFuncName 回傳位置所在的最外層函式名（找不到回 "(top-level)"）
func enclosingFuncName(f *ast.File, pos token.Pos) string {
	name := "(top-level)"
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Pos() <= pos && pos <= fn.End() {
			name = fn.Name.Name
		}
	}
	return name
}

// serviceGuardBackendRoot 定位 backend module 根。
//
// 原以 runtime.Caller + 固定 3 層 Dir 推算，那與「本檔住在樹的第幾層」綁死：
// package 下移一層即指向 internal/（而非 backend/），Walk 照樣成功、只是掃到
// 錯的子樹。改為委派 repoRoot（go.mod module 身分錨點，見 aad_write_guard_test.go）。
func serviceGuardBackendRoot(t *testing.T) string {
	t.Helper()
	return repoRoot(t)
}
