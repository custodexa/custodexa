package database

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

// `schema_migrations` 執行期 marker 的登記完整性守衛
// （migration-baseline-compression D5／tasks 5.9）。
//
// # 本檔守的是什麼
//
// `RunMigrations` 的 fail-close 判定是
// `unknown := applied \ (codeDeclaredVersions ∪ runtimeMarkerVersions)`。
// 執行期 marker（模組自己借用 schema_migrations 當冪等標記表寫入的列）**永遠不會**
// 出現在 `migrations` 陣列裡，故必須逐一登記於 `runtimeMarkerVersions`。
//
// **漏登記一個 marker 的後果**：每一個實際跑過該模組初始化的全新安裝，
// 都會在**第二次啟動**時被自己的 fail-close 擋住並拒絕服務。第一次啟動完全正常
// （marker 尚未寫入），所以這個缺陷在開發機上最可能的顯現時機是「昨天還好好的，
// 今天起不來」，而錯誤訊息會指控資料庫是壓縮前的舊庫——完全誤導。
//
// 判定分兩面，缺一都留下缺口：
//
//	面 1：產品程式碼中所有 `*MarkerVersion` 常數的值，都必須在 runtimeMarkerVersions 內。
//	面 2：對 schema_migrations 下原生 INSERT 的檔，必須在具名清單內——
//	      新的寫入者若不循 `*MarkerVersion` 命名，面 1 抓不到，面 2 抓得到。

// schemaMigrationsRawWriters 允許對 schema_migrations 下原生 INSERT 的檔（相對 module 根）。
//
// **燒盡制**：新增一列等於宣告「這裡也會往版本表塞列」，而那一列必然要嘛是
// migration、要嘛是執行期 marker；前者進 migrations 陣列，後者進 runtimeMarkerVersions。
var schemaMigrationsRawWriters = map[string]string{
	"internal/modules/identity/ldap_seed_migration.go": "LDAP env→DB seed 的冪等標記" +
		"（LDAPSeedMarkerVersion，已登記於 runtimeMarkerVersions）",
}

// minScannedProductionFiles 掃描檔數下限：掃描根失真時「零違規」不成立。
const minScannedProductionFiles = 250

// moduleRootForMarkerScan 以本檔位置為錨點往上找 module 根（非 cwd、非層數推算）。
func moduleRootForMarkerScan(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("取不到本檔路徑：掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for i := 0; i < 10; i++ {
		body, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil {
			if strings.Contains(string(body), "module github.com/custodexa/backend") {
				return dir
			}
			t.Fatalf("%s/go.mod 的 module 名不是預期值：掃描根身分錨點失效", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("往上找不到 go.mod：掃描根定位失效，本守衛拒絕在未知範圍上宣告通過")
	return ""
}

func TestRuntimeMarkerVersionsCoverAllWriters(t *testing.T) {
	root := moduleRootForMarkerScan(t)
	registered := map[string]bool{}
	for _, v := range runtimeMarkerVersions {
		registered[v] = true
	}
	if len(registered) == 0 {
		t.Fatal("runtimeMarkerVersions 是空的：fail-close 會擋住每一個跑過執行期 marker 的正常安裝")
	}

	fset := token.NewFileSet()
	scanned := 0
	markerConsts := map[string]string{} // 常數名 → 值
	rawWriterFiles := map[string]int{}  // 相對路徑 → 行號

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "tmp", "testdata":
				if path != root {
					return filepath.SkipDir
				}
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
		scanned++

		ast.Inspect(f, func(n ast.Node) bool {
			// 面 1：`*MarkerVersion` 常數
			if vs, ok := n.(*ast.ValueSpec); ok {
				for i, name := range vs.Names {
					if !strings.HasSuffix(name.Name, "MarkerVersion") || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					v, uerr := strconv.Unquote(lit.Value)
					if uerr != nil {
						continue
					}
					markerConsts[name.Name] = v
				}
			}
			// 面 2：對 schema_migrations 的原生 INSERT
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				v := strings.ToLower(lit.Value)
				if strings.Contains(v, "insert into schema_migrations") {
					if _, dup := rawWriterFiles[rel]; !dup {
						rawWriterFiles[rel] = fset.Position(lit.Pos()).Line
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("走訪 %s 失敗: %v", root, err)
	}

	// 防假綠下界
	if scanned < minScannedProductionFiles {
		t.Fatalf("只掃到 %d 個非測試 .go 檔（下限 %d）：掃描根已失真，兩面斷言都會在空集合上恆真",
			scanned, minScannedProductionFiles)
	}
	if len(markerConsts) == 0 {
		t.Fatal("全庫掃不到任何 *MarkerVersion 常數：面 1 的比對對象已消失（命名慣例改了？），" +
			"本守衛拒絕在空集合上宣告通過")
	}
	if len(rawWriterFiles) == 0 {
		t.Fatal("全庫掃不到任何對 schema_migrations 的原生 INSERT：面 2 的比對對象已消失，" +
			"本守衛拒絕在空集合上宣告通過")
	}

	var problems []string
	for name, value := range markerConsts {
		if !registered[value] {
			problems = append(problems, name+" = "+strconv.Quote(value)+
				" 未登記於 runtimeMarkerVersions")
		}
	}
	for rel, line := range rawWriterFiles {
		if _, ok := schemaMigrationsRawWriters[rel]; !ok {
			problems = append(problems, rel+":"+strconv.Itoa(line)+
				" 對 schema_migrations 下原生 INSERT，但不在 schemaMigrationsRawWriters 內")
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("執行期 marker 的登記已不完整（共 %d 條）：\n  %s\n\n"+
			"RunMigrations 的 fail-close 會把未登記的 marker 判成「壓縮前的舊資料庫版本」，"+
			"於是每一個跑過該模組初始化的全新安裝，都會在第二次啟動時被自己的 fail-close 擋住"+
			"（第一次啟動正常，因為 marker 那時還沒寫入）。\n"+
			"修法：把該版本值加入 internal/database/migrations.go 的 runtimeMarkerVersions，"+
			"並在 schemaMigrationsRawWriters 登記寫入者與理由。",
			len(problems), strings.Join(problems, "\n  "))
	}
	t.Logf("已掃 %d 個產品檔；marker 常數 %d 個、原生 INSERT 檔 %d 個",
		scanned, len(markerConsts), len(rawWriterFiles))
}
