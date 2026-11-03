package asset

import (
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

// 憑證用途一致的結構守衛：本套件內「建立掛載列」或「改寫掛載的 credential_id」的函式，
// 必須直接呼叫 assertCredentialPurpose，或列在下方附理由的白名單。新增一條選用既有憑證的
// 路徑卻忘了判定用途時，這支守衛以函式名指出它。

// credentialPurposeExempt 不需判定用途的寫入點與理由。新增帳號（Create）與建立資產（createPreparedTx）
// 的直填分支與共用分支同在一個函式，共用分支直接呼叫判定，故不列白名單；migration 不在本套件。
var credentialPurposeExempt = map[string]string{
	// 資產主表同步預設帳號：只改既有預設（登入）掛載自己的專用憑證內容，不選用其他憑證
	"syncDefaultAccountFromAsset": "只改既有預設登入掛載自己的專用憑證，不選用其他憑證",
	// 帳號修改回應的記憶體副本：不寫入資料庫，credential_id 照原列帶過
	"applyAccountUpdates": "記憶體副本，不寫入，credential_id 照原列",
	// 拆分改綁：改綁到同交易新建的專用憑證，沿用原掛載用途
	"commitSplitApplied": "改綁到同交易新建的專用憑證，沿用原掛載用途",
	// 執行身分掛載的固定欄位建構：平台產生金鑰與直填分支掛新建的專用憑證；
	// 共用分支的呼叫端（setShared）已直接判定
	"newExecutorBinding": "平台產生金鑰與直填掛新建專用憑證；共用分支呼叫端已判定",
	// 測試登入撥號用的掛載記憶體副本：由釘住值組出，不寫入資料庫；用途在設定專用帳號時已判定
	"mountFromPin": "記憶體副本供撥號，不寫入；用途在設定專用帳號時已判定",
}

// purposeWriteSites 掃描套件非測試檔，回寫入點函式名 → 是否直接呼叫 assertCredentialPurpose。
func purposeWriteSites(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			writes, checks := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					if isAssetAccountType(x.Type) && len(x.Elts) > 0 {
						writes = true
					}
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "assertCredentialPurpose" {
						checks = true
					}
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Update" || sel.Sel.Name == "Updates") {
						if updatesCredentialID(x) {
							writes = true
						}
					}
				}
				return true
			})
			if writes {
				out[fn.Name.Name] = out[fn.Name.Name] || checks
			}
		}
	}
	return out
}

func isAssetAccountType(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "model" && sel.Sel.Name == "AssetAccount"
}

// updatesCredentialID Update("credential_id", …) 或 Updates(map{"credential_id": …})。
func updatesCredentialID(call *ast.CallExpr) bool {
	found := false
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if v, err := strconv.Unquote(lit.Value); err == nil && v == "credential_id" {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

func TestCredentialPurposeGuard(t *testing.T) {
	sites := purposeWriteSites(t)
	if len(sites) == 0 {
		t.Fatal("掃描不到任何寫入點：守衛失效")
	}
	var missing []string
	for name, checked := range sites {
		if checked {
			continue
		}
		if _, ok := credentialPurposeExempt[name]; ok {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("%s 建立掛載或改寫 credential_id，卻未呼叫 assertCredentialPurpose，也不在附理由的白名單內", name)
	}
	for name := range credentialPurposeExempt {
		if _, ok := sites[name]; !ok {
			t.Errorf("白名單 %s 已不是寫入點：請移除該列", name)
		}
	}
}
