package moduleboundary

// 憑證密文版本表的**不可變**守衛。
//
// **為什麼版本列不得就地更新**：掛載列的就位指標之所以能表達「甲台已換到新版、
// 乙台仍是舊版」，前提正是舊版列的密文原封不動。任何一次 UPDATE 都會讓尚未就位的
// 主機在無人察覺的情況下失去可用的秘密——它的就位指標仍指著那一列，而列裡的內容
// 已經換人了。症狀出現在下一次連線，離成因很遠。
//
// **編譯器對此零保護**：GORM 的 Save／Updates 與 Create 在型別上毫無差別，
// 一行 `tx.Save(&version)` 看起來就像在存檔。這正是「正常開發會意外發生」的形態。
//
// **射程**：全 module 的非測試 `.go` 檔。判定三條——
//   1. 對 CredentialSecretVersion 值呼叫 Save／Update／Updates／UpdateColumn(s)；
//   2. 以 Model(&model.CredentialSecretVersion{}) 起頭的鏈上出現同一組更新動詞；
//   3. 任何字串字面量含 `UPDATE credential_secret_versions`（原生 SQL 路徑）。
//
// Create 與 Delete 不在判定內：新增版本是唯一合法的變更方式，刪除供保留期治理與
// 存量轉換回滾使用。
//
// **偵測器健康由正向控制保證**（TestCredentialVersionImmutableDetector）：
// 掃描面歸零時「零違規」會與「偵測器壞了」不可區分，故另備一份必被抓到的樣本。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// credentialVersionType 版本表的 model 型別名。
const credentialVersionType = "CredentialSecretVersion"

// credentialVersionTable 版本表的表名（原生 SQL 判定用）。
const credentialVersionTable = "credential_secret_versions"

// credentialVersionCtors 回傳版本值的建構／取得函式：其回傳值一併納入追蹤。
//
// 少了這一條，`version, _ := appendCredentialVersion(...)` 之後的 `Save(version)`
// 會因為左值沒有型別標記而對本守衛隱形。
var credentialVersionCtors = map[string]bool{
	"appendCredentialVersion": true,
	"loadCredentialVersion":   true,
}

// credentialVersionMutators GORM 的就地更新動詞。
var credentialVersionMutators = map[string]bool{
	"Save": true, "Update": true, "Updates": true,
	"UpdateColumn": true, "UpdateColumns": true,
}

// minVersionScanFiles 掃描檔數下限（現況 500+，取 250）。掃空即零違規＝最危險的通過。
const minVersionScanFiles = 250

// credentialVersionMutationExceptions 具名例外：允許就地更新版本列的函式全集。
//
// key＝`相對路徑#函式`，value＝理由。**新增一列＝新增一個可覆寫既有密文的位置，
// SHALL 經安全審查**。
var credentialVersionMutationExceptions = map[string]string{
	"internal/database/credential_secret_conversion.go#rebindMigratedVersionCiphertext": "存量轉換的一次性密文身分改綁。" +
		"信封 AAD 綁 表|欄，存量搬移是以原生 SQL 原樣搬過來的（那個階段沒有金鑰可用），" +
		"於是那批值仍帶著來源欄的身分，以本表的 ref 解不開。**改的是同一個秘密的封裝身分，" +
		"不是秘密本身**——密文內容經 RecryptForNewRef 逐筆解封後以新身分重封，明文不變、" +
		"版本序號與建立時刻不變，故就位指標指向它的主機拿到的仍是同一組秘密。" +
		"本例外隨存量轉換一次性存在，以執行期 marker 擋下第二次執行。",
}

// TestCredentialSecretVersionsAreAppendOnly 版本表只准 Create 與 Delete。
func TestCredentialSecretVersionsAreAppendOnly(t *testing.T) {
	root := lifecycleModuleRoot(t)
	fset := token.NewFileSet()
	scanned := 0
	var violations []string
	seenExceptions := map[string]int{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "tmp", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("解析 %s 失敗：守衛拒絕在殘缺的 AST 上作判定: %v", rel, perr)
		}
		scanned++
		for _, site := range credentialVersionMutationSites(fset, f, rel) {
			if _, allowed := credentialVersionMutationExceptions[site.Owner]; allowed {
				seenExceptions[site.Owner]++
				continue
			}
			violations = append(violations, site.Desc)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走訪 module 失敗（掃描根失真）: %v", err)
	}
	if scanned < minVersionScanFiles {
		t.Fatalf("只掃到 %d 個非測試 .go 檔（下限 %d）：射程已失真，「零違規」不成立",
			scanned, minVersionScanFiles)
	}
	// 偵測器健康：每一條具名例外都必須真的被掃到。掃不到＝該處已移除（SHALL 同步
	// 刪除登記列），或偵測器失效而本守衛已成恆綠
	for owner := range credentialVersionMutationExceptions {
		if seenExceptions[owner] == 0 {
			t.Errorf("[偵測器健康] 例外清單登記的 %s 未被掃到任何版本更新："+
				"要嘛該處已移除（SHALL 同步刪除登記列），要嘛偵測器失效", owner)
		}
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Fatalf("偵測到 %d 處就地更新憑證密文版本：\n  %s\n"+
			"版本列建立後 SHALL NOT 被覆寫——尚未就位的主機的就位指標仍指著那一列，"+
			"改掉它等於在無人察覺的情況下讓那台機器失去可用的秘密。"+
			"變更秘密一律新增版本（appendCredentialVersion）。",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// TestCredentialVersionImmutableDetector 偵測器的正向控制。
//
// 上一支測試的「零違規」只有在偵測器真的看得見違規時才有意義。這裡餵進四種
// 已知的違規形態各一份，逐形態斷言被抓到；再餵一份合法樣本斷言零誤報。
func TestCredentialVersionImmutableDetector(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "Save 追蹤的版本值",
			src: `package sample
func mutate(tx *gorm.DB) {
	version, _ := appendCredentialVersion(tx, 1, "password", "a", "", "manual")
	tx.Save(version)
}`,
			want: 1,
		},
		{
			name: "Model 鏈上的 Update",
			src: `package sample
func mutate(tx *gorm.DB) {
	tx.Model(&model.CredentialSecretVersion{}).Where("id = ?", 1).Update("password_enc", "x")
}`,
			want: 1,
		},
		{
			name: "宣告型別後 Updates",
			src: `package sample
func mutate(tx *gorm.DB) {
	var v model.CredentialSecretVersion
	tx.Updates(&v)
}`,
			want: 1,
		},
		{
			name: "原生 SQL",
			src: `package sample
func mutate(tx *gorm.DB) {
	tx.Exec("UPDATE credential_secret_versions SET password_enc = ? WHERE id = ?", "x", 1)
}`,
			want: 1,
		},
		{
			name: "合法：只新增與刪除",
			src: `package sample
func fine(tx *gorm.DB) {
	v := &model.CredentialSecretVersion{CredentialID: 1, VersionNo: 2}
	tx.Create(v)
	tx.Delete(&model.CredentialSecretVersion{}, 3)
	tx.Model(&model.Credential{}).Where("id = ?", 1).Update("current_version_id", 2)
}`,
			want: 0,
		},
	}

	for _, c := range cases {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "sample.go", c.src, 0)
		if err != nil {
			t.Fatalf("%s：樣本解析失敗（正向控制無從成立）: %v", c.name, err)
		}
		got := credentialVersionMutationSites(fset, f, "sample.go")
		if len(got) != c.want {
			t.Errorf("%s：偵測到 %d 處，期望 %d 處（%v）。"+
				"偵測器抓不到已知違規形態時，主守衛的「零違規」只代表沒掃到",
				c.name, len(got), c.want, got)
		}
	}
}

// versionMutationSite 一處版本更新。Owner 是例外清單的綁定鍵（`相對路徑#函式`）。
type versionMutationSite struct {
	Owner string
	Desc  string
}

// credentialVersionMutationSites 掃出單一檔案內的版本更新位置（含例外，由呼叫端過濾）。
func credentialVersionMutationSites(fset *token.FileSet, f *ast.File, rel string) []versionMutationSite {
	var out []versionMutationSite

	// 掃描以函式為單位：例外清單綁在函式上，檔案層的鍵擋不住「同檔另開一處」
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		owner := rel + "#" + funcQualifiedName(fn)
		tracked := trackedVersionIdents(fn.Body)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			// 原生 SQL：表名一旦以原生 SQL 更新，AST 的型別線索全部消失
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				text, err := strconv.Unquote(lit.Value)
				if err != nil {
					// 解不開的字面量不放行：判不出內容即不得斷定它安全
					text = lit.Value
				}
				normalized := strings.Join(strings.Fields(strings.ToLower(text)), " ")
				if strings.Contains(normalized, "update "+credentialVersionTable) {
					out = append(out, versionMutationSite{Owner: owner,
						Desc: rel + ":" + itoa(fset.Position(lit.Pos()).Line) +
							"：原生 SQL 更新 " + credentialVersionTable})
				}
				return true
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !credentialVersionMutators[sel.Sel.Name] {
				return true
			}
			site := rel + ":" + itoa(fset.Position(call.Pos()).Line)
			for _, arg := range call.Args {
				if isCredentialVersionExpr(arg, tracked) {
					out = append(out, versionMutationSite{Owner: owner,
						Desc: site + "：" + sel.Sel.Name + " 直接作用於憑證密文版本"})
					return true
				}
			}
			if modelChainIsCredentialVersion(sel.X, tracked) {
				out = append(out, versionMutationSite{Owner: owner,
					Desc: site + "：Model(…CredentialSecretVersion…) 鏈上的 " + sel.Sel.Name})
			}
			return true
		})
	}
	return out
}

// trackedVersionIdents 收集函式體內綁定到憑證密文版本的識別字。
func trackedVersionIdents(body *ast.BlockStmt) map[string]bool {
	tracked := map[string]bool{}
	// 兩輪：先收集，再讓「以既有追蹤值賦值」的情形也納入（如 v := version）
	for pass := 0; pass < 2; pass++ {
		ast.Inspect(body, func(n ast.Node) bool {
			switch stmt := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range stmt.Lhs {
					id, ok := lhs.(*ast.Ident)
					if !ok || i >= len(stmt.Rhs) && len(stmt.Rhs) != 1 {
						continue
					}
					var rhs ast.Expr
					if len(stmt.Rhs) == 1 {
						rhs = stmt.Rhs[0]
					} else {
						rhs = stmt.Rhs[i]
					}
					if isCredentialVersionExpr(rhs, tracked) || isVersionCtorCall(rhs) {
						tracked[id.Name] = true
					}
				}
			case *ast.DeclStmt:
				gd, ok := stmt.Decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					return true
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					if vs.Type != nil && typeIsCredentialVersion(vs.Type) {
						for _, name := range vs.Names {
							tracked[name.Name] = true
						}
					}
					for i, v := range vs.Values {
						if i < len(vs.Names) && (isCredentialVersionExpr(v, tracked) || isVersionCtorCall(v)) {
							tracked[vs.Names[i].Name] = true
						}
					}
				}
			}
			return true
		})
	}
	return tracked
}

// isVersionCtorCall 回傳值為憑證密文版本的建構／取得呼叫。
func isVersionCtorCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return credentialVersionCtors[fun.Name]
	case *ast.SelectorExpr:
		return credentialVersionCtors[fun.Sel.Name]
	}
	return false
}

// isCredentialVersionExpr 判斷表達式是否為憑證密文版本值（含取址與追蹤中的識別字）。
func isCredentialVersionExpr(e ast.Expr, tracked map[string]bool) bool {
	switch x := e.(type) {
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return isCredentialVersionExpr(x.X, tracked)
		}
	case *ast.CompositeLit:
		return x.Type != nil && typeIsCredentialVersion(x.Type)
	case *ast.Ident:
		return tracked[x.Name]
	}
	return false
}

// typeIsCredentialVersion 型別表達式是否指向憑證密文版本（含切片與指標）。
func typeIsCredentialVersion(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		return x.Sel.Name == credentialVersionType
	case *ast.Ident:
		return x.Name == credentialVersionType
	case *ast.StarExpr:
		return typeIsCredentialVersion(x.X)
	case *ast.ArrayType:
		return typeIsCredentialVersion(x.Elt)
	}
	return false
}

// modelChainIsCredentialVersion 沿呼叫鏈往回找 Model(…)，判定其參數是否為版本型別。
//
// 鏈式寫法（Model().Where().Update()）的型別線索只出現在最前面那一段，
// 停在 Update 的那個 receiver 上是看不見的。
func modelChainIsCredentialVersion(e ast.Expr, tracked map[string]bool) bool {
	for {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if sel.Sel.Name == "Model" {
			for _, arg := range call.Args {
				if isCredentialVersionExpr(arg, tracked) {
					return true
				}
			}
			return false
		}
		e = sel.X
	}
}
