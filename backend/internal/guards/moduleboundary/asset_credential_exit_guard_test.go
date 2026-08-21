package moduleboundary

// 資產憑證的**解封出口清單**（modular-architecture Phase B / W6 任務 6.3，H-4）。
//
// **安全紅線**：資產憑證的明文只在「連線收口」的那一刻出現，前端零接觸。
// 現況全庫只有兩個出口——`AssetService.GetWithCredentialsForAccount`（連線用）
// 與 `AssetService.GetSftpPassword`（SFTP 用）。R3.1 §3.1 的 H-4 原本只列了前者，
// 後者是**這一波查出來補上的**：一份不完整的出口清單比沒有清單更危險，因為它
// 會讓人以為「都在這裡了」。
//
// **本守衛擋的是**：任何人在 asset 模組**之外**、或在 asset 內的**第三個函式**
// 解封資產類密文欄。這正是「正常開發會意外發生」的形態——handler 想直接拿明文
// 塞進回應、proxy 想少繞一層、改密流程想就地解一下舊密碼。
//
// **射程**：全 module 的非測試 `.go` 檔（不限模組歸屬檔——`internal/api`、
// `internal/sshproxy` 等接入層正是最需要擋住的地方，它們不在任何模組歸屬表內）。
// 判定對象＝`DecryptFor(ctx, keyvault.RefX, …)` 中 `RefX` 為**資產類** CipherRef 者；
// 資產類的定義不是硬編碼名單，而是由 `cipher_refs.go` 的 Table 欄配上
// `tableOwner`（6.0a 登記表）機械推導——新增一個指向 assets／asset_accounts 的
// CipherRef 會自動落入本守衛射程。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// assetCredentialExits 允許出現資產類 DecryptFor 的函式全集（H-4 出口清單）。
//
// key＝`相對路徑#函式`，value＝理由。**新增一列＝新增一個明文出口，SHALL 經安全審查**。
var assetCredentialExits = map[string]string{
	"internal/modules/asset/asset_service.go#(*AssetService).GetWithCredentialsForAccount": "連線收口：SSH／RDP／VNC 撥線時把帳號憑證交給接入層，明文不出行程邊界。",
	"internal/modules/asset/asset_service.go#(*AssetService).GetSftpPassword":              "SFTP 收口：獨立的 sftp_password_enc 欄，同上（H-4 於 W6 補列的第二出口）。",
	"internal/modules/asset/change_secret_candidate_service.go#(*ChangeSecretCandidateService).Secret": "改密未驗證候選憑證的解封（change-secret-ssh-deepening D1）。" +
		"**新出口的正當性**：候選是尚未成為帳號憑證的秘密，不在 asset_accounts 的兩個既定出口涵蓋範圍內；" +
		"其明文只在同一行程內交給兩個用途——以候選登入目標機驗證、驗證成功後提交為帳號憑證，" +
		"SHALL NOT 進入任何 API 回應、日誌、審計欄位或子程序（行為式守衛 " +
		"internal/api/change_secret_candidate_leak_test.go 釘住外洩面）。",
}

// assetDecryptRefAllowlist 允許以**非字面** ref 呼叫 DecryptFor 的檔（fail-close 的具名例外）。
var assetDecryptRefAllowlist = map[string]string{
	"internal/modules/audit/notification_channel_service.go": "readChannelValue 的 ref 是函式參數；兩個呼叫端傳的都是 audit 自有的 RefChannelURL／RefChannelSecret（非資產類），由 TestChannelValueRefsAreChannelOwned 釘住。",
}

// minCredentialScanFiles 掃描檔數下限（現況 300+，取 250）。掃空即零違規＝最危險的通過。
const minCredentialScanFiles = 250

// assetClassCipherRefs 由 cipher_refs.go 機械推導「資產類」CipherRef 的識別字集合。
func assetClassCipherRefs(t *testing.T, root string) map[string]string {
	t.Helper()
	src := filepath.Join(root, "internal", "modules", "keyvault", "cipher_refs.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗（資產類 ref 無從推導，守衛不得放行）: %v", src, err)
	}
	out := map[string]string{}
	total := 0
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
			return true
		}
		cl, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		var table string
		for _, el := range cl.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			k, ok := kv.Key.(*ast.Ident)
			if !ok || k.Name != "Table" {
				continue
			}
			if bl, ok := kv.Value.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				table = strings.Trim(bl.Value, `"`)
			}
		}
		if table == "" {
			return true
		}
		total++
		if tableOwner[table] == "asset" {
			out[vs.Names[0].Name] = table
		}
		return true
	})
	if total < 8 {
		t.Fatalf("只自 cipher_refs.go 推導出 %d 個 CipherRef（現況 11）：來源失真", total)
	}
	if len(out) < 3 {
		t.Fatalf("只推導出 %d 個資產類 CipherRef（現況 5：assets 3＋asset_accounts 2）："+
			"tableOwner 或 cipher_refs.go 已變動，本守衛的射程已失真", len(out))
	}
	return out
}

// TestAssetCredentialDecryptOnlyAtDeclaredExits 資產類密文只在出口清單內解封。
func TestAssetCredentialDecryptOnlyAtDeclaredExits(t *testing.T) {
	root := lifecycleModuleRoot(t)
	assetRefs := assetClassCipherRefs(t, root)

	fset := token.NewFileSet()
	scanned := 0
	seen := map[string][]string{} // 出口鍵 → file:line
	var violations []string
	var unresolved []string

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
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			owner := rel + "#" + funcQualifiedName(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "DecryptFor" || len(ce.Args) < 2 {
					return true
				}
				site := rel + ":" + itoa(fset.Position(ce.Pos()).Line)
				refName, literal := cipherRefIdent(ce.Args[1])
				if !literal {
					if _, ok := assetDecryptRefAllowlist[rel]; !ok {
						unresolved = append(unresolved, site+"（ref 非字面 keyvault.RefX，靜態判不出是不是資產類）")
					}
					return true
				}
				if _, isAsset := assetRefs[refName]; !isAsset {
					return true
				}
				if _, allowed := assetCredentialExits[owner]; allowed {
					seen[owner] = append(seen[owner], site)
					return true
				}
				violations = append(violations, site+"："+owner+" 解封 "+refName)
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走訪 module 失敗（掃描根失真）: %v", err)
	}
	if scanned < minCredentialScanFiles {
		t.Fatalf("只掃到 %d 個非測試 .go 檔（下限 %d）：射程已失真，「零違規」不成立",
			scanned, minCredentialScanFiles)
	}
	// 偵測器健康：兩個既知出口必須被看見（掃不到＝偵測器壞了，不是「沒有出口」）
	for exit := range assetCredentialExits {
		if len(seen[exit]) == 0 {
			t.Errorf("[偵測器健康] 出口清單登記的 %s 未被掃到任何資產類 DecryptFor："+
				"要嘛該出口已移除（SHALL 同步刪除登記列），要嘛偵測器失效而本守衛已成恆綠", exit)
		}
	}
	for _, u := range unresolved {
		t.Errorf("[fail-close] %s：解不出 ref 即無法斷定它不是資產憑證。"+
			"SHALL 改為字面 keyvault.RefX，或列入 assetDecryptRefAllowlist 並指名由誰守衛", u)
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Fatalf("偵測到 %d 處在出口清單之外解封資產憑證：\n  %s\n"+
			"資產憑證明文的產生地 SHALL 收斂在 asset 模組的兩個既定出口（安全紅線：連線收口）。"+
			"需要新出口時 SHALL 在 assetCredentialExits 具名登記並經安全審查，"+
			"而不是在呼叫端就地解一次。", len(violations), strings.Join(violations, "\n  "))
	}
}

// TestChannelValueRefsAreChannelOwned 上方非字面 ref 例外的**二次條件**。
//
// 例外之所以安全，是因為 `readChannelValue` 的兩個呼叫端傳的都是 audit 自有的
// 通道 ref。把那個前提本身釘住——它一旦不成立，例外就變成「資產憑證解封對掃描面隱形」。
func TestChannelValueRefsAreChannelOwned(t *testing.T) {
	root := lifecycleModuleRoot(t)
	src := filepath.Join(root, "internal", "modules", "audit", "notification_channel_service.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗（例外的前提無從查核）: %v", src, err)
	}
	calls := 0
	ast.Inspect(f, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := ce.Fun.(*ast.Ident)
		if !ok || id.Name != "readChannelValue" || len(ce.Args) < 2 {
			return true
		}
		calls++
		name, literal := cipherRefIdent(ce.Args[1])
		if !literal || !strings.HasPrefix(name, "RefChannel") {
			t.Errorf("readChannelValue 於 %s:%d 收到非通道類 ref（%q）："+
				"assetDecryptRefAllowlist 對本檔的豁免前提已不成立，SHALL 重新審視",
				filepath.Base(src), fset.Position(ce.Pos()).Line, name)
		}
		return true
	})
	if calls < 2 {
		t.Fatalf("只找到 %d 處 readChannelValue 呼叫（現況 2）：前提查核已失真，豁免不得繼續成立", calls)
	}
}

// cipherRefIdent 取 `keyvault.RefX`／`RefX` 形式的識別字；非該形式回 literal=false。
func cipherRefIdent(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		if _, ok := x.X.(*ast.Ident); ok {
			return x.Sel.Name, true
		}
	case *ast.Ident:
		return x.Name, true
	}
	return "", false
}
