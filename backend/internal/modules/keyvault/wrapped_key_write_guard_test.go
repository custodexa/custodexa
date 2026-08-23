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

// 「`EncodeWrappedKey` 是 `wrapped_key` 值的唯一產出點」的結構守衛。
//
// **本守衛守的是什麼**：相容窗依賴「無前綴 ⇒ 本地格式」恆真。該不變式的
// 根據是 EncodeWrappedKey 對委託格式在**建構上**拒絕無 AAD 包裹、帶 AAD 者恆編
// `wk:2:<tag>:`（wrapped_key.go:89-107）。但那個保證只在「所有 wrapped_key 值都
// 經過該函式」時才成立——只要有一條旁路（自己拼字串、直接寫 base64），
// 委託格式就可能落庫成無前綴值而被讀端誤判為本地格式。
//
// 故本守衛從兩面釘住：
//
//	G1：crypto.EncodeWrappedKey 只能被 wrapMaterial 呼叫（唯一編碼入口）；
//	G2：任何寫入 data_keys.wrapped_key 的地方，其值只能是
//	    wrapMaterial 的產物或空字串（材料清理／佔位列）。
//
// **為何 G2 不能只看「有沒有呼叫 EncodeWrappedKey」**：一個把 base64 直接塞進
// WrappedKey 的寫法根本不會提到 EncodeWrappedKey，G1 看不見它。

// encodeWrappedKeyCallers 允許呼叫 crypto.EncodeWrappedKey 的函式（唯一編碼入口）
var encodeWrappedKeyCallers = map[string]bool{"wrapMaterial": true}

// wrappedKeyFieldName／wrappedKeyColumnName 欄位與欄名（單一事實源）
const (
	wrappedKeyFieldName  = "WrappedKey"
	wrappedKeyColumnName = "wrapped_key"
)

// wrappedKeyProducer 唯一被承認的產出函式
const wrappedKeyProducer = "wrapMaterial"

// wrappedKeyWriteAllowlist 允許寫入 wrapped_key 的（檔名 → 外層函式名）。
// **新增任一項都必須確認其值來源仍是 wrapMaterial 或空字串**——
// 本守衛的 G2 會逐一檢查，故此清單只放寬「哪裡可以寫」，不放寬「可以寫什麼」。
var wrappedKeyWriteAllowlist = map[string][]string{
	// 材料顯式清理（軟刪除後的銷毀）：寫入空字串，不是編碼旁路
	"key_manager_cleanup.go": {"CleanupRetiredMaterial"},
	// 金鑰鑄造與重包 clone：值恆為 wrapMaterial 的產物（或佔位列的空字串）
	"key_manager_service.go":  {"insertKey"},
	"key_manager_rotation.go": {"RewrapKEK"},
}

func TestEncodeWrappedKeyIsSoleProducer(t *testing.T) {
	root := serviceGuardBackendRoot(t)
	var violations []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "vendor", "testdata", "scripts", ".git", "tmp":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// pkg/crypto 自身是編碼原語的實作處，不是「使用者」
		rel, _ := filepath.Rel(root, path)
		if strings.HasPrefix(rel, "pkg/crypto/") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		violations = append(violations, scanWrappedKeyWrites(fset, f, rel, filepath.Base(path))...)
		return nil
	})
	if err != nil {
		t.Fatalf("掃描失敗: %v", err)
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("偵測到繞過 canonical encoder 的 wrapped_key 寫路徑：\n%s\n"+
			"「無前綴 ⇒ 本地格式」的相容窗不變式依賴 EncodeWrappedKey 為唯一產出點；"+
			"任何旁路都可能讓委託格式落庫成無前綴值而被讀端誤判為本地格式",
			strings.Join(violations, "\n"))
	}
}

// scanWrappedKeyWrites 掃單一 AST（抽出以便正向控制驗證掃描器真的看得見東西）
func scanWrappedKeyWrites(fset *token.FileSet, f *ast.File, rel, base string) []string {
	var out []string
	allowed := wrappedKeyWriteAllowlist[base]
	isAllowedFunc := func(fn string) bool {
		for _, a := range allowed {
			if a == fn {
				return true
			}
		}
		return false
	}
	report := func(pos token.Pos, form string) {
		out = append(out, fmt.Sprintf("%s:%d %s（外層函式 %s）",
			rel, fset.Position(pos).Line, form, enclosingFuncName(f, pos)))
	}

	// G1：EncodeWrappedKey 的呼叫點
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "EncodeWrappedKey" {
			return true
		}
		if !encodeWrappedKeyCallers[enclosingFuncName(f, call.Pos())] {
			report(call.Pos(), "EncodeWrappedKey 於非唯一編碼入口被呼叫")
		}
		return true
	})

	// G2：wrapped_key 的寫入點與其值來源
	producedIdents := collectProducerIdents(f)
	valueOK := func(e ast.Expr) bool {
		switch v := e.(type) {
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				s, err := strconv.Unquote(v.Value)
				return err == nil && s == ""
			}
		case *ast.Ident:
			return producedIdents[v.Name]
		case *ast.CallExpr:
			if id, ok := v.Fun.(*ast.Ident); ok && id.Name == wrappedKeyProducer {
				return true
			}
		}
		return false
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.KeyValueExpr:
			id, ok := node.Key.(*ast.Ident)
			if !ok || id.Name != wrappedKeyFieldName {
				return true
			}
			fn := enclosingFuncName(f, node.Pos())
			if !isAllowedFunc(fn) {
				report(node.Pos(), "於允許清單外寫入 "+wrappedKeyFieldName)
			} else if !valueOK(node.Value) {
				report(node.Pos(), "WrappedKey 的值非 "+wrappedKeyProducer+" 產物亦非空字串")
			}
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != wrappedKeyFieldName {
					continue
				}
				fn := enclosingFuncName(f, sel.Pos())
				if !isAllowedFunc(fn) {
					report(sel.Pos(), "於允許清單外賦值 "+wrappedKeyFieldName)
				} else if i < len(node.Rhs) && !valueOK(node.Rhs[i]) {
					report(sel.Pos(), "WrappedKey 的值非 "+wrappedKeyProducer+" 產物亦非空字串")
				}
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || !updateCallNames[sel.Sel.Name] {
				return true
			}
			for i, arg := range node.Args {
				lit, ok := arg.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil || s != wrappedKeyColumnName {
					continue
				}
				fn := enclosingFuncName(f, node.Pos())
				if !isAllowedFunc(fn) {
					report(node.Pos(), sel.Sel.Name+" 於允許清單外寫入 "+wrappedKeyColumnName)
				} else if i+1 < len(node.Args) && !valueOK(node.Args[i+1]) {
					report(node.Pos(), wrappedKeyColumnName+" 的值非 "+wrappedKeyProducer+" 產物亦非空字串")
				}
			}
		}
		return true
	})
	return out
}

// collectProducerIdents 收集「由 wrapMaterial 賦值而來」的識別字名。
//
// 以檔為單位而非以函式為單位：Go 的短變數宣告作用域雖是區塊，但本守衛要的是
// 「這個名字的值來自哪裡」的保守近似——放寬到整檔會讓守衛更寬鬆，而寬鬆的方向
// 是「可能漏報」；收緊到函式則會在跨閉包時誤報。漏報由 G1 與允許清單的雙重限制
// 補足（能寫的地方本來就只有四處）。
func collectProducerIdents(f *ast.File) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != wrappedKeyProducer {
			return true
		}
		if len(assign.Lhs) > 0 {
			if lhs, ok := assign.Lhs[0].(*ast.Ident); ok {
				out[lhs.Name] = true
			}
		}
		return true
	})
	return out
}

// TestWrappedKeyWriteGuardDetectsBypasses 守衛的**正向控制**：三種旁路寫法
// 都必須被攔下（沒有這一格，上面的綠只證明掃描器沒回報東西）
func TestWrappedKeyWriteGuardDetectsBypasses(t *testing.T) {
	cases := []struct {
		name, file, src string
	}{
		{"自拼字串塞進 WrappedKey", "key_manager_rotation.go", `package p
func RewrapKEK() { _ = DataKey{WrappedKey: "wk:2:kms:" + b64} }`},
		{"允許清單外寫入", "some_new_file.go", `package p
func sneak() { _ = DataKey{WrappedKey: "AAAA"} }`},
		{"Update 直寫欄位", "key_manager_rotation.go", `package p
func RewrapKEK(tx *DB) { tx.Model(nil).Update("wrapped_key", raw) }`},
		{"非唯一入口呼叫 EncodeWrappedKey", "key_manager_rotation.go", `package p
func RewrapKEK() { _, _ = crypto.EncodeWrappedKey(tag, raw, bound, stage) }`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, c.file, c.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := scanWrappedKeyWrites(fset, f, c.file, c.file); len(got) == 0 {
				t.Fatalf("守衛未攔下旁路：\n%s", c.src)
			}
		})
	}

	// 負向控制：合法寫法（wrapMaterial 產物與空字串佔位）不得誤報
	legit := `package p
func RewrapKEK(tx *DB) {
	column, err := wrapMaterial(kek, stage, purpose, version, raw)
	_ = err
	_ = DataKey{WrappedKey: column}
	_ = DataKey{WrappedKey: ""}
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "key_manager_rotation.go", legit, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := scanWrappedKeyWrites(fset, f, "key_manager_rotation.go", "key_manager_rotation.go"); len(got) != 0 {
		t.Fatalf("合法寫法不得被誤報：%v", got)
	}
}
