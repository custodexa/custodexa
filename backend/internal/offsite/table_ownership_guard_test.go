package offsite

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 本包的**自守衛**：`internal/offsite` 只碰自己的兩張表。
//
// # 為什麼需要它（守衛看不見的那一半）
//
// `tableOwner["offsite_objects"]="offsite"` 讓**別的模組**碰帳冊會被資料邊界閘門
// 判紅——那是要的方向。但反過來不成立：`internal/offsite` 不是模組，**不在資料
// 邊界掃描面內**，它對這兩張表以外任何表的存取都不會被任何守衛看到。
//
// 補償即本檔（沿 keyvault 的包內自守衛先例）：AST 掃本包非測試檔，斷言
// gorm 的 `Model(&model.X{})`／`Table("...")` 與 SQL 字面量只碰允許清單內的表，
// 且 **`audit_logs` 不直寫**——保管鏈事件一律走注入的 `CustodyJournal`
// （`audit_logs` 在檢查點鏈的覆蓋內，本包不得繞過 audit 的落地面）。

// offsiteOwnedTables 本包擁有的表。
var offsiteOwnedTables = map[string]string{
	"offsite_objects":  "保管帳冊：物件身分、狀態機、租約、世代歸屬皆由本包定義",
	"offsite_profiles": "設定世代表：世代生命週期、憑證模式與信封密文皆由本包定義",
}

// offsiteAllowedForeignTables 本包**得以**碰的他人表，逐張具名並附理由。
//
// **燒盡制**：新增一列等於宣告「本包也會讀寫這張表」，而那正是本守衛要讓人看見的事。
var offsiteAllowedForeignTables = map[string]string{
	"schema_migrations": "env→DB 初次 seed 的冪等執行標記（借用版本表當 marker，" +
		"沿 LDAP seed 的既有形態；已登記於 database.runtimeMarkerVersions 與 " +
		"schemaMigrationsRawWriters）",
	"information_schema": "postgres 系統目錄：判定 offsite_profiles 是否已建表" +
		"（seed 的第 (1) 步；不用 Migrator().HasTable 是因為它把「查詢失敗」與" +
		"「表不存在」混為一談）",
	"sqlite_master": "sqlite 系統目錄：同上，單元測試庫的等價查詢",
}

// offsiteForbiddenModelLiterals 本包非測試碼**不得**出現的 model 型別字面量。
var offsiteForbiddenModelLiterals = map[string]string{
	"AuditLog": "保管鏈事件一律走注入的 CustodyJournal。" +
		"直寫 audit_logs 會繞過 audit 模組的落地面與其非同步／交易內兩種語義，" +
		"且 audit_logs 在檢查點鏈的覆蓋內——本包不是它的擁有者",
	"AuditLogEntry": "同上（gatewayapi 的事件形狀亦不得由本包直接落地）",
}

// minOffsiteScannedFiles 掃描檔數下限：掃描根失真時「零違規」不成立。
const minOffsiteScannedFiles = 8

// sqlTableRe 自 SQL 字面量抽表名：FROM／JOIN／INSERT INTO／UPDATE／DELETE FROM 之後的識別字。
var sqlTableKeywords = []string{
	"from ", "join ", "insert into ", "update ", "delete from ",
}

func offsitePackageDir(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("取不到本檔路徑：掃描根無從定位")
	}
	return filepath.Dir(self)
}

// TestOffsitePackageTouchesOnlyItsOwnTables 本包的表所有權自守衛。
func TestOffsitePackageTouchesOnlyItsOwnTables(t *testing.T) {
	dir := offsitePackageDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取本包目錄失敗: %v", err)
	}

	allowed := map[string]bool{}
	for tb := range offsiteOwnedTables {
		allowed[tb] = true
	}
	for tb := range offsiteAllowedForeignTables {
		allowed[tb] = true
	}

	fset := token.NewFileSet()
	scanned := 0
	var problems []string
	seenTables := map[string]bool{}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("解析 %s 失敗（掃描不得在解析錯誤下靜默略過）: %v", e.Name(), perr)
		}
		scanned++

		ast.Inspect(f, func(n ast.Node) bool {
			// (a) model 型別字面量：禁用清單 ＋ 表歸屬
			if lit, ok := n.(*ast.CompositeLit); ok {
				if name, ok := modelTypeNameOf(lit.Type); ok {
					if reason, bad := offsiteForbiddenModelLiterals[name]; bad {
						problems = append(problems, sitef(fset, lit.Pos(), e.Name())+
							"：出現 model."+name+" 字面量——"+reason)
					}
				}
			}
			// (b) SQL 與 Table() 字面量
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				v, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					return true
				}
				for _, tb := range tablesInSQL(v) {
					seenTables[tb] = true
					if !allowed[tb] {
						problems = append(problems, sitef(fset, lit.Pos(), e.Name())+
							"：SQL 字面量碰到未登記的表 "+tb)
					}
				}
			}
			return true
		})
	}

	if scanned < minOffsiteScannedFiles {
		t.Fatalf("只掃到 %d 個非測試檔（下限 %d）：掃描根已失真，斷言會在空集合上恆真",
			scanned, minOffsiteScannedFiles)
	}
	// 防假綠：偵測器至少要看得到本包確實碰過的表
	if !seenTables["offsite_profiles"] && !seenTables["schema_migrations"] {
		t.Fatal("SQL 字面量掃描一張表都沒抽出來：抽取器已失效，" +
			"「零違規」不構成證據")
	}

	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("internal/offsite 碰了登記外的表或直寫審計（共 %d 條）：\n  %s\n\n"+
			"本包不在資料邊界掃描面內，故這條界線只有本守衛在盯。"+
			"若確實需要碰新的表，先回答「那張表的不變式歸誰」——"+
			"多半的答案是「應該經該擁有者的方法」，而不是在此加一列例外。",
			len(problems), strings.Join(problems, "\n  "))
	}
	t.Logf("已掃 %d 個非測試檔；抽出表名 %d 個（自有 %d／具名他人表 %d）",
		scanned, len(seenTables), len(offsiteOwnedTables), len(offsiteAllowedForeignTables))
}

// TestOffsiteGormModelUsageStaysInOwnedTables gorm `Model(&model.X{})` 的型別歸屬。
//
// 與 SQL 字面量面互補：`db.Model(&model.Session{}).Update(...)` 不含任何表名字串，
// SQL 面完全看不見它。
func TestOffsiteGormModelUsageStaysInOwnedTables(t *testing.T) {
	dir := offsitePackageDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取本包目錄失敗: %v", err)
	}
	// 本包允許引用的 model 型別（→ 其對應的表皆為自有表）
	allowedModels := map[string]bool{
		"OffsiteObject":  true,
		"OffsiteProfile": true,
	}

	fset := token.NewFileSet()
	var problems []string
	hits := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if perr != nil {
			t.Fatalf("解析 %s 失敗: %v", e.Name(), perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Model" && sel.Sel.Name != "Find" &&
				sel.Sel.Name != "First" && sel.Sel.Name != "Create") {
				return true
			}
			for _, arg := range call.Args {
				name, ok := modelTypeNameOfExpr(arg)
				if !ok {
					continue
				}
				hits++
				if !allowedModels[name] {
					problems = append(problems, sitef(fset, arg.Pos(), e.Name())+
						"：gorm 呼叫以 model."+name+" 為對象——本包只得操作自有表的 model")
				}
			}
			return true
		})
	}
	if hits == 0 {
		t.Fatal("掃不到任何以 model 型別為對象的 gorm 呼叫：偵測器已失效，" +
			"「零違規」不構成證據")
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("internal/offsite 以他人的 model 直接操作資料庫（共 %d 條）：\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	t.Logf("已檢查 %d 處以 model 型別為對象的 gorm 呼叫", hits)
}

// modelTypeNameOf 自複合字面量的型別取 `model.X` 的 X。
func modelTypeNameOf(expr ast.Expr) (string, bool) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != "model" {
		return "", false
	}
	return sel.Sel.Name, true
}

// modelTypeNameOfExpr 自 `&model.X{}` 或 `model.X{}` 取 X。
func modelTypeNameOfExpr(expr ast.Expr) (string, bool) {
	if unary, ok := expr.(*ast.UnaryExpr); ok {
		expr = unary.X
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	return modelTypeNameOf(lit.Type)
}

// tablesInSQL 自 SQL 字面量抽出表名（小寫比對關鍵字後取下一個識別字）。
func tablesInSQL(s string) []string {
	lower := strings.ToLower(s)
	var out []string
	for _, kw := range sqlTableKeywords {
		idx := 0
		for {
			i := strings.Index(lower[idx:], kw)
			if i < 0 {
				break
			}
			pos := idx + i + len(kw)
			idx = pos
			name := leadingIdent(lower[pos:])
			if name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}

// leadingIdent 取字串開頭的 SQL 識別字（英數與底線；忽略引號）。
func leadingIdent(s string) string {
	s = strings.TrimLeft(s, `"'`)
	end := 0
	for end < len(s) {
		c := s[end]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			end++
			continue
		}
		break
	}
	return s[:end]
}

func sitef(fset *token.FileSet, pos token.Pos, name string) string {
	return name + ":" + strconv.Itoa(fset.Position(pos).Line)
}
