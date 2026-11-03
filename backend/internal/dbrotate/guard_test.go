package dbrotate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// 本套件的邊界：不起子程序、不碰命令列代理；不記 log（錯誤只回呼叫端，且只帶類別）。

var dbrotateForbiddenImports = map[string]string{
	"os/exec":           "改密走 driver 直連，不起子程序",
	"internal/localpty": "改密走 driver 直連，不起子程序",
	"internal/dbproxy":  "命令列代理是另一條路徑，混用會讓憑證流向變成要逐條追的問題",
	"log":               "本套件不記 log：log 在呼叫端，且只拿得到錯誤碼",
	"log/slog":          "本套件不記 log：log 在呼叫端，且只拿得到錯誤碼",
}

func dbrotateSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("讀取套件目錄失敗: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, e.Name())
	}
	// 防假綠：掃不到檔案時零違規不成立
	if len(out) < 5 {
		t.Fatalf("只掃到 %d 個原始檔（下界 5）：掃描範圍已失真", len(out))
	}
	return out
}

func TestDBRotateForbiddenImports(t *testing.T) {
	fset := token.NewFileSet()
	for _, name := range dbrotateSourceFiles(t) {
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("剖析 %s 失敗: %v", name, err)
		}
		for _, spec := range f.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			for forbidden, reason := range dbrotateForbiddenImports {
				if path == forbidden || strings.HasSuffix(path, "/"+forbidden) {
					t.Errorf("%s import 了 %s：%s", name, path, reason)
				}
			}
		}
	}
}

func TestDBRotateNoLogging(t *testing.T) {
	fset := token.NewFileSet()
	scanned := 0
	for _, name := range dbrotateSourceFiles(t) {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("剖析 %s 失敗: %v", name, err)
		}
		scanned++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if pkg.Name == "log" || pkg.Name == "slog" ||
				(pkg.Name == "fmt" && strings.HasPrefix(sel.Sel.Name, "Print")) ||
				(pkg.Name == "fmt" && strings.HasPrefix(sel.Sel.Name, "Fprint")) {
				t.Errorf("%s:%d 呼叫了 %s.%s：本套件不記 log、不印輸出",
					name, fset.Position(call.Pos()).Line, pkg.Name, sel.Sel.Name)
			}
			return true
		})
	}
	t.Logf("已掃描 %d 個原始檔", scanned)
}
