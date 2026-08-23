package kms

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

// Settings.Endpoint 的**結構性 test gate**（安全審查 high #2 的配套）。
//
// 端點覆寫的修補讓生產路徑拒絕環境變數面的改導，但 Settings.Endpoint 這個
// **程式面**的旋鈕仍在（localstack 實測需要它）。「它只有測試碼設得到」若只是
// 一句註解，第一個為了除錯而在 cmd/server 接上一個 env 鍵的人就會把它變成假話。
//
// 故以 AST 釘住：全 backend 的非測試 .go 中，不得有任何一處對 kms.Settings 的
// Endpoint 欄位賦值——無論是複合字面 `Settings{Endpoint: x}` 還是
// `s.Endpoint = x`。兩種寫法都攔，攔的是能力而非某個名字。
//
// **本檔自身不是豁免區**：client.go 讀 s.Endpoint（`s.Endpoint != ""`）不是賦值，
// 不在攔截範圍內；provider.go 把它存進結構欄位（`endpoint: s.Endpoint`）
// 同理是讀取。掃描器只認「寫入 Endpoint」。

// endpointFieldName 受管欄位名（單一事實源）
const endpointFieldName = "Endpoint"

// endpointWriteAllowlist 允許寫入 Endpoint 欄位的（相對 backend 根的檔路徑 → 函式名）。
//
// 新增任一項等於在生產二進位裡開一條「把敏感請求導向他處」的路徑，必須先在
// design 上說明為何那不是端點覆寫缺陷的原樣重現。
//
// 本掃描刻意涵蓋所有名為 Endpoint 的欄位寫入（寧可誤報不漏報），故非 KMS 的
// 合法用途須在此具名放行。
// **鍵不再硬編碼檔路徑**：原本寫死
// `internal/service/oidc_discovery.go`，該檔搬入 `internal/modules/identity`
// 後豁免落空 ⇒ 合法用途被判違規（誤報方向，不是恆綠，但下一次搬檔照壞）。
// 改以「**誰宣告了 OAuth2Config**」這個跟著程式碼走的結構性錨點定位，
// 由 `resolveOAuth2ConfigFile` 於掃描時解析；找不到或找到多個即 t.Fatal
// ——豁免對象消失時守衛必須說話，不得默默放行或默默誤報。
var endpointWriteAllowlist = map[string][]string{}

// oauth2ConfigFuncName 豁免對象的錨點符號。
//
// oauth2.Config.Endpoint 取自 go-oidc 的 discovery
// 結果，而 go-oidc 強制 discovery 文件的 issuer 與輸入完整字串一致；issuer
// 本身建後不可變且經形狀/scheme 驗證，**無任何 env 可覆寫**。所有出站另受
// OIDCEgressPolicy 約束（https、拒絕內部網段、每次連線重新解析檢查）。
//
// 與端點覆寫缺陷的本質差異：該缺陷是「外部可控的 env 直接決定含明文 DEK 之請求的目的地
// 且無任何驗證」；此處是「經 issuer 驗證的 discovery 結果 + 出站位址政策」。
const oauth2ConfigFuncName = "OAuth2Config"

// resolveOAuth2ConfigFile 全樹找出宣告 oauth2ConfigFuncName 的唯一非測試檔
// （相對 root 的 slash 路徑）。
func resolveOAuth2ConfigFile(t *testing.T, root string) string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
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
			t.Fatalf("解析 %s 失敗: %v", path, perr)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Name.Name == oauth2ConfigFuncName {
				rel, _ := filepath.Rel(root, path)
				hits = append(hits, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("尋找 %s 宣告失敗: %v", oauth2ConfigFuncName, err)
	}
	if len(hits) != 1 {
		t.Fatalf("全庫宣告 %s 的非測試檔應恰為 1 個，實得 %d 個（%v）："+
			"豁免對象的結構性錨點失效，守衛拒絕在無法定位豁免對象時作判定",
			oauth2ConfigFuncName, len(hits), hits)
	}
	return hits[0]
}

// TestNoProductionEndpointOverride 生產碼不得設定 kms.Settings.Endpoint
func TestNoProductionEndpointOverride(t *testing.T) {
	root := kmsGuardBackendRoot(t)
	violations := scanEndpointWrites(t, root)
	if len(violations) > 0 {
		t.Fatalf("偵測到生產碼寫入 kms.Settings.%s（端點覆寫僅供測試靶機，"+
			"生產路徑一律走 SDK 預設解析）：\n%s\n"+
			"若確有必要，須先寫明為何這不是同型缺陷的原樣重現（外部可控的值決定含明文 DEK 之請求的目的地），"+
			"並列入 endpointWriteAllowlist", endpointFieldName, strings.Join(violations, "\n"))
	}
}

// scanEndpointWrites 掃出所有對 Endpoint 欄位的寫入（複合字面鍵 + 賦值左值）。
//
// 抽成獨立函式是為了讓掃描器**自身可被驗證**——一個永遠回空清單的掃描器
// 會讓上面的測試永遠綠（本專案的「守衛假綠」教訓）。正向控制見
// TestEndpointWriteScannerDetectsViolations。
func scanEndpointWrites(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	scanned := 0
	allowlist := map[string][]string{resolveOAuth2ConfigFile(t, root): {oauth2ConfigFuncName}}
	for k, v := range endpointWriteAllowlist {
		allowlist[k] = v
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
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
			// 原先 `return nil` 靜默略過：解析失敗的檔等於沒被掃過，而本守衛
			// 的失敗形態正是「掃不到＝零違規＝綠」。go/parser 不套用 build tag，
			// 解析失敗即代表原始碼真的壞了，fail-close 才是正確反應。
			t.Fatalf("解析 %s 失敗，守衛拒絕在殘缺 AST 上宣稱零違規: %v", path, perr)
		}
		scanned++
		rel, _ := filepath.Rel(root, path)
		for _, v := range findEndpointWrites(fset, f, filepath.ToSlash(rel), allowlist) {
			out = append(out, v)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("掃描 backend 失敗: %v", err)
	}
	if scanned < minKMSScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下限 %d，掃描根 %s）：掃描範圍已失真，"+
			"守衛將在近乎空集合下假綠。若目錄結構改變，改的是掃描根而不是下限",
			scanned, minKMSScannedFiles, root)
	}
	t.Logf("kms endpoint 守衛掃描檔數=%d（下限 %d）", scanned, minKMSScannedFiles)
	return out
}

// findEndpointWrites 單一 AST 的掃描本體
func findEndpointWrites(fset *token.FileSet, f *ast.File, rel string, allowlist map[string][]string) []string {
	var out []string
	allowed := allowlist[rel]
	report := func(pos token.Pos, form string) {
		fn := kmsEnclosingFunc(f, pos)
		for _, a := range allowed {
			if a == fn {
				return
			}
		}
		out = append(out, "  "+rel+":"+itoaKMS(fset.Position(pos).Line)+" "+form+"（外層函式 "+fn+"）")
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.KeyValueExpr:
			// 形式 1：複合字面 `kms.Settings{Endpoint: x}`
			if id, ok := node.Key.(*ast.Ident); ok && id.Name == endpointFieldName {
				report(node.Pos(), "複合字面設定 "+endpointFieldName)
			}
		case *ast.AssignStmt:
			// 形式 2：`settings.Endpoint = x`
			for _, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == endpointFieldName {
					report(sel.Pos(), "欄位賦值 "+endpointFieldName)
				}
			}
		}
		return true
	})
	return out
}

// TestEndpointWriteScannerDetectsViolations 掃描器的**正向控制**：兩種寫法都要看得見，
// 且不相干的程式碼不得誤報
func TestEndpointWriteScannerDetectsViolations(t *testing.T) {
	violating := []struct {
		name string
		src  string
	}{
		{"複合字面", `package p
func f() { _ = Settings{Provider: "aws", Endpoint: "http://x"} }`},
		{"欄位賦值", `package p
func f(s *Settings) { s.Endpoint = "http://x" }`},
	}
	for _, c := range violating {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", c.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := findEndpointWrites(fset, f, "x.go", nil); len(got) == 0 {
				t.Fatalf("掃描器未看見違規寫法：\n%s", c.src)
			}
		})
	}

	// 負向控制：**讀取**不是寫入（client.go／provider.go 正是這樣用的）
	legit := `package p
func f(s Settings) bool { if s.Endpoint != "" { return true }; return false }`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "y.go", legit, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := findEndpointWrites(fset, f, "y.go", nil); len(got) != 0 {
		t.Fatalf("讀取 Endpoint 不得被誤報：%v", got)
	}
}

// kmsEnclosingFunc 位置所在的最外層函式名
func kmsEnclosingFunc(f *ast.File, pos token.Pos) string {
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

// kmsGuardModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const kmsGuardModulePath = "github.com/custodexa/backend"

// minKMSScannedFiles 全 backend 掃描的檔數下限（防空集合假綠）。
// 2026-08-09 實測 299 檔（見 TestNoProductionEndpointOverride 的 t.Logf），門檻取 270。
const minKMSScannedFiles = 270

// kmsGuardBackendRoot 定位 backend module 根。
//
// **原以 runtime.Caller + 固定 4 層 Dir 推算**（僅事後驗 go.mod 是否存在）：
// 層數與「本 package 住在樹的第幾層」綁死，package 位置一變，上溯 4 層可能
// 落在某個仍有 go.mod 的祖先或直接 Fatal，兩者都不是掃描根。改為「向上找
// go.mod 並核對 module 行」——找到的必定是本 module 的根。
func kmsGuardBackendRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			want := "module " + kmsGuardModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				filepath.Join(dir, "go.mod"), kmsGuardModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位",
				filepath.Dir(self), kmsGuardModulePath)
		}
		dir = parent
	}
}

// itoaKMS 避免為單一格式化引入 strconv（保持守衛檔相依最小）
func itoaKMS(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
