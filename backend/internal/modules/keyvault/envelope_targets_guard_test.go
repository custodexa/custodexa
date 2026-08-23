package keyvault

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// envelopeMigrationTargets 完備性守衛（後補）。
//
// 這份清單原本只是「遷移覆蓋面」——漏一欄的後果是該值停在 legacy 格式。
// 本 change 讓它同時成為**銷毀前置閘**：清理退役 DEK 版本前的引用掃描就是照
// 這份清單掃，漏一欄代表「該欄的密文不被計入引用」→ 系統誤判該版本零引用而
// 銷毀其材料 → 那一欄的資料永久不可解。清單從「漏了頂多遷移不全」升級為
// 「漏了會毀資料」，卻沒有機制擋住疏忽，故補本守衛。
//
// 判定方式：AST 掃 internal/model 的結構欄位，凡欄位名以 Enc 結尾（專案慣例：
// 信封加密欄位一律 *Enc → 資料表 *_enc 欄）即視為加密欄位，逐一比對是否列於
// envelopeMigrationTargets。表名取該結構的 TableName() 回傳值；解析不出表名
// 一律讓測試失敗（fail-close，不得因解析不到而靜默放行）。
//
// 不循 *Enc 慣例的欄位（notification_channels 的 secret/url 為歷史明文欄名）
// 無法由慣例偵測，於 knownNonEncColumns 顯式列管——新增此類欄位者須同時更新
// 該清單與 envelopeMigrationTargets。

// knownNonEncColumns 不循 *Enc 慣例但確實已納入 envelopeMigrationTargets 的欄位。
// 存在的意義是「顯式承認例外」，使守衛不因無法偵測而失去意義
var knownNonEncColumns = map[string][]string{
	"notification_channels": {"secret", "url"},
}

// minModelParsedFiles model 套件的解析檔數下限（防空集合假綠）。
// 2026-08-09 實測 35 檔（見測試的 t.Logf），門檻取 30。
const minModelParsedFiles = 30

func TestEnvelopeTargetsCoverAllEncryptedColumns(t *testing.T) {
	// 掃描根以 go.mod module 身分為錨（repoRoot，見 aad_write_guard_test.go）：
	// 原先的 filepath.Join("..","model") 綁死「本 package 與 model 是兄弟」，
	// package 一下移即指向不存在的目錄，而 ParseDir 對不存在目錄只回空 map——
	// 「掃不到任何 *Enc 欄位」會被下面的斷言當成「沒有漏掉的加密欄」。
	modelDir := filepath.Join(repoRoot(t), "internal", "model")
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, modelDir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("解析 model 套件失敗（%s）: %v", modelDir, err)
	}
	parsed := 0
	for _, pkg := range pkgs {
		parsed += len(pkg.Files)
	}
	if parsed < minModelParsedFiles {
		t.Fatalf("只解析到 %d 個 model 非測試檔（下限 %d，掃描根 %s）：掃描範圍已失真，"+
			"守衛將在空集合下宣稱「所有加密欄都已納管」。若 model 搬遷，改的是掃描根而不是下限",
			parsed, minModelParsedFiles, modelDir)
	}
	t.Logf("envelope targets 守衛解析 model 檔數=%d（下限 %d）", parsed, minModelParsedFiles)

	tableNames := map[string]string{}  // 結構名 → 表名
	encFields := map[string][]string{} // 結構名 → 加密欄位名（已轉 snake_case）
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.TypeSpec:
					st, ok := node.Type.(*ast.StructType)
					if !ok {
						return true
					}
					for _, f := range st.Fields.List {
						for _, name := range f.Names {
							if !strings.HasSuffix(name.Name, "Enc") {
								continue
							}
							if f.Tag != nil && strings.Contains(f.Tag.Value, `gorm:"-"`) {
								continue // 非落庫欄位
							}
							encFields[node.Name.Name] = append(encFields[node.Name.Name], toSnakeColumn(name.Name))
						}
					}
				case *ast.FuncDecl:
					if node.Name.Name != "TableName" || node.Recv == nil || len(node.Recv.List) == 0 {
						return true
					}
					ident, ok := node.Recv.List[0].Type.(*ast.Ident)
					if !ok {
						return true
					}
					if lit := singleReturnString(node); lit != "" {
						tableNames[ident.Name] = lit
					}
				}
				return true
			})
		}
	}

	if len(encFields) == 0 {
		t.Fatal("未從 model 套件掃到任何 *Enc 欄位——AST 解析失效，守衛已失去意義")
	}

	covered := map[string]bool{}
	for _, tgt := range envelopeMigrationTargets {
		covered[tgt.table+"."+tgt.column] = true
	}

	for structName, cols := range encFields {
		table, ok := tableNames[structName]
		if !ok {
			t.Fatalf("結構 %s 有加密欄位 %v 但解析不出 TableName()——無法確認其是否納入引用掃描，"+
				"請為該結構加 TableName() 或於本測試處理其表名", structName, cols)
		}
		for _, col := range cols {
			if !covered[table+"."+col] {
				t.Fatalf("加密欄位 %s.%s（結構 %s）未列於 envelopeMigrationTargets：\n"+
					"該欄的密文不會被計入引用掃描，清理退役金鑰版本時可能誤判零引用而銷毀材料，"+
					"導致此欄資料永久不可解。請將其加入 envelope_migration_service.go 的 envelopeMigrationTargets。",
					table, col, structName)
			}
		}
	}

	// 例外清單本身也要對得上（防止例外項被自 targets 移除卻無人察覺）
	for table, cols := range knownNonEncColumns {
		for _, col := range cols {
			if !covered[table+"."+col] {
				t.Fatalf("顯式列管的加密欄位 %s.%s 已不在 envelopeMigrationTargets——"+
					"若確已移除請同步更新 knownNonEncColumns", table, col)
			}
		}
	}
}

// singleReturnString 取 func 內單一 `return "字面值"` 的值（取不到回空字串）
func singleReturnString(fn *ast.FuncDecl) string {
	if fn.Body == nil || len(fn.Body.List) != 1 {
		return ""
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return ""
	}
	lit, ok := ret.Results[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	return strings.Trim(lit.Value, `"`)
}

// toSnakeColumn Go 欄位名 → GORM 預設欄名（連續大寫視為單一縮寫，如 TOTPSecretEnc → totp_secret_enc）
func toSnakeColumn(name string) string {
	var b strings.Builder
	runes := []rune(name)
	for i, r := range runes {
		if unicode.IsUpper(r) {
			prevLower := i > 0 && unicode.IsLower(runes[i-1])
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if i > 0 && (prevLower || nextLower) {
				b.WriteRune('_')
			}
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
