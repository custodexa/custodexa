package dbconsole

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// 本套件的兩道靜態守衛。
//
// 兩者守的都是**無症狀**的缺陷：破了以後功能照常運作、測試照常全綠，
// 只有在有人去追「憑證有沒有離開後端行程」時才會發現說法不成立。
//
//	負向 import：本套件不得 import os/exec、internal/localpty、internal/dbproxy。
//	           一旦 import 進來，「零子程序」就從結構保證退化成人的紀律。
//	無 DSN 字串：不得呼叫 ParseDSN／FormatDSN／msdsn.Parse，不得以格式化組出
//	           含 password= 之類片段的字串。DSN 一旦成形就會被複製、被記錄、
//	           被印進錯誤訊息，而它整條都是憑證。

// forbiddenImports 禁止的 import 路徑片段
var forbiddenImports = map[string]string{
	"os/exec": "起子程序是命令列路徑的形態；本路徑是 driver 直連，" +
		"兩者混在一起會讓「憑證有沒有離開後端行程」變成一個要逐條追的問題",
	"internal/localpty": "同上（PTY 是子程序的載體）",
	"internal/dbproxy":  "命令列路徑的組指令邏輯，其產物正是含憑證的命令列參數",
	"internal/model":    "方言層依賴資料庫層會讓「換一個持久化形態」變成要動 driver 適配器",
	"internal/modules":  "本套件不寫審計、不碰業務模組；留痕與狀態機在呼叫端",
}

// forbiddenCalls 禁止呼叫的函式名（以選擇器的末段比對）
var forbiddenCalls = map[string]string{
	"ParseDSN":    "會把一條 DSN 字串解回設定物件——有解析函式就代表有人組了字串",
	"FormatDSN":   "會把設定物件組成一條 DSN 字串，那條字串整條都是憑證",
	"msdsn.Parse": "同上（MSSQL 側）",
}

// dsnFragments 連線字串的特徵片段：出現在字串字面裡即視為有人在組 DSN
var dsnFragments = []string{"password=", "Password=", ":%s@", "user=%s", "Pwd="}

// parseConfigAllowlist `ParseConfig` 的唯一合法呼叫點。
//
// **不是把守衛關掉，而是收窄**：pgx 的 pgconn.Config 帶一個未匯出的
// createdByParseConfig 旗標，ConnectConfig 在它為假時直接 panic
// （pgconn/pgconn.go:144）——「自己造一個設定物件再連」在 pgx v5 上做不到。
// 折衷是以**空字串**取得一個帶旗標的預設設定，其後每一個連線欄位由我方覆寫。
// 空字串裡沒有任何憑證，故「程序內不存在 DSN 字串」的不變式仍然成立。
//
// 守衛因此改為：ParseConfig 只准出現在這個檔、只准一次、且引數必須是空字串字面。
// 引數換成任何別的東西（變數、非空字面），本守衛立刻紅。
const parseConfigAllowedFile = "postgres.go"

func dbconsoleSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("讀取套件目錄失敗: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, e.Name())
	}
	// 防假綠：掃不到檔案時所有斷言都在空集合上恆真
	if len(out) < 8 {
		t.Fatalf("只掃到 %d 個產品原始檔（下界 8）：掃描範圍已失真，此時的零違規不成立", len(out))
	}
	return out
}

func TestDBConsoleForbiddenImports(t *testing.T) {
	fset := token.NewFileSet()
	scanned := 0
	for _, name := range dbconsoleSourceFiles(t) {
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("剖析 %s 失敗，其 import 未被檢查：%v", name, err)
		}
		scanned++
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s 的 import 路徑 %s 無法解析: %v", name, spec.Path.Value, err)
			}
			for forbidden, reason := range forbiddenImports {
				if strings.Contains(path, forbidden) {
					t.Errorf("%s import 了 %s（禁止片段 %s）\n  理由：%s",
						name, path, forbidden, reason)
				}
			}
		}
	}
	t.Logf("已檢查 %d 個原始檔的 import", scanned)
}

func TestDBConsoleHasNoDSNConstruction(t *testing.T) {
	fset := token.NewFileSet()
	parseConfigSites := 0

	for _, name := range dbconsoleSourceFiles(t) {
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("剖析 %s 失敗，其呼叫未被檢查：%v", name, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				fn := calleeName(node.Fun)
				if fn == "" {
					return true
				}
				if reason, bad := forbiddenCalls[fn]; bad {
					t.Errorf("%s:%d 呼叫了 %s\n  理由：%s",
						name, fset.Position(node.Pos()).Line, fn, reason)
				}
				if fn == "ParseConfig" {
					parseConfigSites++
					if name != parseConfigAllowedFile {
						t.Errorf("%s:%d 呼叫 ParseConfig：唯一許可的位置是 %s",
							name, fset.Position(node.Pos()).Line, parseConfigAllowedFile)
					}
					if !isEmptyStringLiteral(node.Args) {
						t.Errorf("%s:%d 的 ParseConfig 引數不是空字串字面——"+
							"許可的前提正是「傳進去的東西不含任何憑證」，"+
							"引數一旦是變數或非空字面，這個前提就沒有人在保證了",
							name, fset.Position(node.Pos()).Line)
					}
				}
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				lit := node.Value
				for _, frag := range dsnFragments {
					if strings.Contains(lit, frag) {
						t.Errorf("%s:%d 的字串字面含連線字串特徵 %q：%s\n"+
							"  設定物件一律逐欄位組裝，不得以格式化組出 DSN",
							name, fset.Position(node.Pos()).Line, frag, lit)
					}
				}
			}
			return true
		})
	}

	// 正向對照：許可的那一處必須真的存在。它若消失（有人改寫了 pgx 的建構方式），
	// 上面那條「引數必須是空字串」的斷言會在空集合上恆真，而守衛的射程靜默歸零
	if parseConfigSites != 1 {
		t.Errorf("ParseConfig 呼叫點 = %d 處, want 1（%s 內的那一處）\n"+
			"  多於一處＝例外在擴散；零處＝上方的引數斷言已無對象，守衛射程歸零",
			parseConfigSites, parseConfigAllowedFile)
	}
}

// calleeName 取呼叫的名字：`Foo()` 回 Foo、`pkg.Foo()` 回 Foo 與 pkg.Foo 兩種形態
// 都要能比對，故回傳末段，另對 `msdsn.Parse` 這種需要限定套件的名稱回全名
func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if pkg, ok := f.X.(*ast.Ident); ok {
			full := pkg.Name + "." + f.Sel.Name
			if _, known := forbiddenCalls[full]; known {
				return full
			}
		}
		return f.Sel.Name
	}
	return ""
}

func isEmptyStringLiteral(args []ast.Expr) bool {
	if len(args) != 1 {
		return false
	}
	lit, ok := args[0].(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && (lit.Value == `""` || lit.Value == "``")
}

// TestGuardDetectsPlantedViolation 守衛自身的正向對照。
//
// 沒有這一條，「掃過了、沒有違規」與「掃描器根本沒在看」是同一個結果。
// 這裡不動真實原始碼，改以同一組判定函式對一段人工植入的程式碼取樣。
func TestGuardDetectsPlantedViolation(t *testing.T) {
	src := `package x

import "os/exec"

func bad() string {
	_ = exec.Command
	return fmt.Sprintf("user:%s@tcp(host)/db?password=%s", u, p)
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "planted.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("剖析植入樣本失敗: %v", err)
	}

	importHit := false
	for _, spec := range file.Imports {
		path, _ := strconv.Unquote(spec.Path.Value)
		for forbidden := range forbiddenImports {
			if strings.Contains(path, forbidden) {
				importHit = true
			}
		}
	}
	if !importHit {
		t.Error("植入的 os/exec import 未被偵測到：import 掃描已失效")
	}

	fragmentHit := false
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		for _, frag := range dsnFragments {
			if strings.Contains(lit.Value, frag) {
				fragmentHit = true
			}
		}
		return true
	})
	if !fragmentHit {
		t.Error("植入的 DSN 字串特徵未被偵測到：字面掃描已失效")
	}
}
