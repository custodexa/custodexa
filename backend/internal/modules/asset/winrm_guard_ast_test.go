package asset

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// WinRM 傳輸不變式的 AST 守衛：asset 模組的非測試檔對 WinRM 函式庫的使用不得出現
// 任何明文或 Basic 認證的路徑，不得觸碰函式庫的全域參數，且每個 HTTP 客戶端都必須
// 經過 winrmEncryptionGuard。
//
// 掃描根以本檔所在目錄為準（同一 package），檔數與命中數皆有下限——掃到空集合時
// 守衛必須轉紅，而不是靜默全綠。

const winrmImportPath = "github.com/masterzen/winrm"

// winrmForbiddenSymbols 函式庫內任何會建出「不經我方傳輸」的客戶端、或走明文／Basic
// 的符號（以 `winrm.X` 選擇子比對）。DefaultParameters 是全域指標，改了會污染同行程所有客戶端。
var winrmForbiddenSymbols = map[string]bool{
	"DefaultParameters":            true,
	"NewParameters":                true,
	"NewClient":                    true,
	"NewClientWithParameters":      true,
	"NewClientWithDial":            true,
	"NewClientWithProxyFunc":       true,
	"ClientNTLM":                   true,
	"NewClientNTLMWithDial":        true,
	"NewClientNTLMWithProxyFunc":   true,
	"ClientAuthRequest":            true,
	"NewClientAuthRequestWithDial": true,
	"Encryption":                   true,
	"NewEncryption":                true,
	"Powershell":                   true,
}

// winrmForbiddenAnywhere 不論來自哪個套件都不得出現的識別字：函式庫全域參數、
// 目標端關閉加密的設定名、HTTP Basic 認證。
var winrmForbiddenAnywhere = map[string]bool{
	"DefaultParameters": true,
	"AllowUnencrypted":  true,
	"SetBasicAuth":      true,
}

// winrmRequestBuilders 訊息建構子：最後一個引數（params）不得為 nil，nil 會落回函式庫全域參數。
var winrmRequestBuilders = map[string]bool{
	"NewOpenShellRequest": true, "NewDeleteShellRequest": true, "NewExecuteCommandRequest": true,
	"NewGetOutputRequest": true, "NewSendInputRequest": true, "NewSignalRequest": true,
}

func assetPackageDir(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗")
	}
	return filepath.Dir(self)
}

// TestWinRMNoPlaintextOrBasicSymbols 見檔頭。
func TestWinRMNoPlaintextOrBasicSymbols(t *testing.T) {
	dir := assetPackageDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	scanned, winrmFiles, httpClients := 0, 0, 0
	var violations []string

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		alias := ""
		for _, imp := range file.Imports {
			if strings.Trim(imp.Path.Value, `"`) == winrmImportPath {
				alias = "winrm"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
			}
		}
		if alias != "" {
			winrmFiles++
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if winrmForbiddenAnywhere[x.Name] {
					violations = append(violations, fset.Position(x.Pos()).String()+": 禁用識別字 "+x.Name)
				}
			case *ast.SelectorExpr:
				if pkg, ok := x.X.(*ast.Ident); ok && alias != "" && pkg.Name == alias && winrmForbiddenSymbols[x.Sel.Name] {
					violations = append(violations, fset.Position(x.Pos()).String()+": 禁用符號 "+alias+"."+x.Sel.Name)
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING && strings.Contains(x.Value, "AllowUnencrypted") {
					violations = append(violations, fset.Position(x.Pos()).String()+": 字串含 AllowUnencrypted")
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != alias || alias == "" {
					return true
				}
				if winrmRequestBuilders[sel.Sel.Name] {
					if len(x.Args) == 0 {
						violations = append(violations, fset.Position(x.Pos()).String()+": "+sel.Sel.Name+" 無引數")
						return true
					}
					if id, ok := x.Args[len(x.Args)-1].(*ast.Ident); ok && id.Name == "nil" {
						violations = append(violations, fset.Position(x.Pos()).String()+": "+sel.Sel.Name+" 的 params 為 nil（會落回函式庫全域參數）")
					}
				}
			case *ast.CompositeLit:
				sel, ok := x.Type.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "http" || sel.Sel.Name != "Client" {
					return true
				}
				httpClients++
				if !httpClientGuarded(x) {
					violations = append(violations, fset.Position(x.Pos()).String()+": http.Client 未經 winrmEncryptionGuard")
				}
			}
			return true
		})
	}

	// 現況 33 個非測試檔，取 25 為保守下界
	if scanned < 25 {
		t.Fatalf("只掃到 %d 個非測試檔，掃描根失真", scanned)
	}
	if winrmFiles == 0 {
		t.Fatal("沒有任何檔案匯入 WinRM 函式庫：守衛掃不到受管程式碼")
	}
	if httpClients == 0 {
		t.Fatal("沒有掃到任何 http.Client 字面量：守衛掃不到受管程式碼")
	}
	for _, v := range violations {
		t.Error(v)
	}
}

// httpClientGuarded http.Client 字面量的 Transport 欄是否為 winrmEncryptionGuard 字面量。
//
// asset 模組內的 http.Client 只有 WinRM 這一處；日後若有第二處，必須同樣走守衛
// 或把它搬出本模組——本判準刻意不留白名單。
func httpClientGuarded(lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Transport" {
			continue
		}
		inner, ok := kv.Value.(*ast.CompositeLit)
		if !ok {
			return false
		}
		id, ok := inner.Type.(*ast.Ident)
		return ok && id.Name == "winrmEncryptionGuard"
	}
	return false
}

// TestWinRMGuardSelfCheck 守衛的判準對已知違規樣本會命中（防守衛本身空轉）。
func TestWinRMGuardSelfCheck(t *testing.T) {
	src := `package x
import "net/http"
import "github.com/masterzen/winrm"
var _ = &http.Client{}
var _ = winrm.NewOpenShellRequest("u", nil)
var _ = winrm.DefaultParameters
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	hits := 0
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "winrm" && winrmForbiddenSymbols[x.Sel.Name] {
				hits++
			}
		case *ast.CompositeLit:
			if sel, ok := x.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Client" && !httpClientGuarded(x) {
				hits++
			}
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && winrmRequestBuilders[sel.Sel.Name] {
				if id, ok := x.Args[len(x.Args)-1].(*ast.Ident); ok && id.Name == "nil" {
					hits++
				}
			}
		}
		return true
	})
	if hits != 3 {
		t.Fatalf("樣本應命中 3 項違規（未守衛的 http.Client、nil params、DefaultParameters），實得 %d", hits)
	}
}
