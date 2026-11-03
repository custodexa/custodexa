package asset

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 「有沒有主機金鑰可比」只能由 model.HostKeyTransportHasHostKey 判定。以「是不是 WinRM」二分的寫法，
// 會把任何新的無金鑰通道當成 SSH 工作，撥號前查不到主機金鑰記錄而整批停止。本守衛掃本套件全部
// 非測試原始檔（含 build tag 檔：parser 不看 tag），兩個 WinRM 常數以 ==、!=、switch case 出現時，
// 只准落在下表登錄的函式內。

// dichotomyConstants 被監看的常數（以 model.<名> 選取）。
var dichotomyConstants = map[string]bool{
	"HostKeyTransportWinRM":       true,
	"RotationChannelWindowsWinRM": true,
}

// dichotomyAllowlist 檔名 → 函式名 → 保留理由。以函式為單位登錄：同檔其他函式出現一樣算違規。
var dichotomyAllowlist = map[string]map[string]string{
	"asset_rotation_channel.go": {
		"validateRotationChannel": "判的是通道是不是 WinRM 以決定附屬欄位要不要驗，與主機金鑰無關",
	},
	"rotation_executor.go": {
		"rotationExecutorFor": "執行器工廠依通道選執行器，本來就要逐值列舉",
	},
	"rotation_loopback.go": {
		"loopbackRunScript": "回環驗證工具組 WinRM 附屬欄位，與主機金鑰無關",
	},
	"hostkey_identity_takeover_create.go": {
		"keylessConfirmTransportAllowed": "無歷史身分的工作只可能來自升級前的 SSH 或 WinRM 派送，只能以 winrm 確認",
	},
}

// dichotomySite 一處比較或 case 出現點。
type dichotomySite struct {
	File, Func string
	Line       int
	Constant   string
}

func (s dichotomySite) String() string {
	return fmt.Sprintf("%s:%d（%s）model.%s", s.File, s.Line, s.Func, s.Constant)
}

// dichotomyConstOf 表達式若為 model.<被監看常數>，回常數名。
func dichotomyConstOf(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "model" || !dichotomyConstants[sel.Sel.Name] {
		return ""
	}
	return sel.Sel.Name
}

// findDichotomySites 列出單一檔案內全部出現點（純函式，突變自檢與正式掃描共用）。
func findDichotomySites(fset *token.FileSet, name string, file *ast.File) []dichotomySite {
	var out []dichotomySite
	add := func(fn string, e ast.Expr) {
		if c := dichotomyConstOf(e); c != "" {
			out = append(out, dichotomySite{File: name, Func: fn, Line: fset.Position(e.Pos()).Line, Constant: c})
		}
	}
	for _, decl := range file.Decls {
		fn := "(套件層宣告)"
		if fd, ok := decl.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BinaryExpr:
				if x.Op == token.EQL || x.Op == token.NEQ {
					add(fn, x.X)
					add(fn, x.Y)
				}
			case *ast.CaseClause:
				for _, e := range x.List {
					add(fn, e)
				}
			}
			return true
		})
	}
	return out
}

// dichotomyViolations 不在允許清單內的出現點。
func dichotomyViolations(sites []dichotomySite, allow map[string]map[string]string) []dichotomySite {
	var out []dichotomySite
	for _, s := range sites {
		if _, ok := allow[s.File][s.Func]; ok {
			continue
		}
		out = append(out, s)
	}
	return out
}

func TestTransportDichotomyGuard(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("讀取套件目錄失敗: %v", err)
	}
	fset := token.NewFileSet()
	var sites []dichotomySite
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("解析 %s 失敗: %v", name, perr)
		}
		scanned++
		sites = append(sites, findDichotomySites(fset, name, f)...)
	}
	// 防假綠：掃描範圍失真時零違規不成立
	if scanned < 80 {
		t.Fatalf("只掃到 %d 個原始檔（下界 80）：掃描範圍已失真", scanned)
	}
	for file, funcs := range dichotomyAllowlist {
		for fn, reason := range funcs {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("允許清單 %s（%s）缺保留理由", file, fn)
			}
		}
	}
	violations := dichotomyViolations(sites, dichotomyAllowlist)
	sort.Slice(violations, func(i, j int) bool { return violations[i].String() < violations[j].String() })
	for _, v := range violations {
		t.Errorf("%s：以 WinRM 二分判定傳輸，改用 model.HostKeyTransportForChannel／HostKeyTransportHasHostKey，"+
			"或在允許清單登錄函式與理由", v)
	}
	t.Logf("掃描 %d 檔，出現點 %d 處，違規 %d 處", scanned, len(sites), len(violations))
}
