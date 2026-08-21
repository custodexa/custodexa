package keyvault_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
)

// cutover 的**結構保證**守衛（kek-provider-modularization D5／tasks 1.7）。
//
// tasks 1.7 的失敗判準之一是「cutover 後仍可能產生新的 enc:v，使『現查殘餘為 0』
// 淪為瞬時快照」。本檔原以兩道互補守衛（G1 介面反射／G2 AST 來源掃描）釘住
// 「服務層不可能寫出無 AAD 密文」。
//
// **無 AAD 寫入構件的 AST 守衛已於 release-transitional-cleanup D10 移除**：
// 其守衛對象（`keyvault.KeyManagerService.encryptNoAADForRollback` 與
// `crypto.EncodeEnvelope`）連同 `EncodeWrappedKey` 的無 AAD 分支已整組刪除，
// 「寫入端不可能產出無 AAD 密文」自此是**建構事實**而非靠 AST 名稱比對維持的
// 承諾——守衛對象不存在時，該測試只會在零命中下假綠。接手的是 grep 級機械驗收
// （`EncodeEnvelope\b|encryptNoAADForRollback` 於非測試碼零命中）與
// `pkg/crypto` 的終態負向測試（空 scheme 編碼必回錯）。
//
// **P2 M1（release-transitional-cleanup 冷驗收 E 批）再往下收一層**：
// `crypto.AESCrypto` 的四個無 AAD 入口（Encrypt／Decrypt／EncryptBytes／
// DecryptBytes）已刪除，且 EncryptBytesAAD／DecryptBytesAAD 於 len(aad)==0 時
// 回 `crypto.ErrAADRequired`。原先「守衛已刪但入口還在」的缺口就此封住——
// 在服務層非測試碼加一條無 AAD 寫出呼叫，現在會**編譯失敗**。
//
// 本檔保留的仍是**現存**能力的守衛：G1 的介面層（ColumnCodec 無明文寫入方法）
// 與委託 KMS `Encrypt` 豁免的收窄。

// guardScanRoots 掃描範圍：服務層（internal）、組裝層（cmd）**與 pkg**。
// pkg 納入是 codex med #6 的直接修正——原先排除 pkg 等於留了一整個目錄的
// 免檢區，新 package 可在其中組出無 AAD 寫入而守衛不知情。
var guardScanRoots = []string{"internal", "cmd", "pkg"}

// minAADScannedFiles 掃描檔數下限（防空集合假綠）。
// 2026-08-09 於 internal+cmd+pkg 實測 287 檔（見測試的 t.Logf），門檻取 260。
// 門檻取略低於實測值，使「掃描根失效／範圍被誤縮」當場轉紅，而非零命中假綠。
const minAADScannedFiles = 260

// serviceGuardModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const serviceGuardModulePath = "github.com/custodexa/backend"

// repoRoot 定位 backend module 根（本套件所有守衛的共用掃描根）。
//
// **不用 cwd 相對、也不用固定層數 `..`**（modular-architecture W1 1.19）：
// 兩者都與「本 package 目前住在樹的第幾層」綁死，package 一下移就指向錯誤位置，
// 而 WalkDir 對不存在／空目錄多半只回零命中——守衛於是在掃空的情況下照樣綠。
// 改以「自本測試檔位置向上找 go.mod，並核對 module 行」為身分錨點：檔案搬到
// module 內任何深度都仍指向同一個根，錨點若失效則 Fatal 而非靜默掃錯樹。
// 作法比照 cmd/server 的 lifecycle／audit-points／gatewayapi 三個 W1 守衛。
func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if body, err := os.ReadFile(gomod); err == nil {
			want := "module " + serviceGuardModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				gomod, serviceGuardModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位",
				filepath.Dir(self), serviceGuardModulePath)
		}
		dir = parent
	}
}

// repoParent 定位「backend 之上」的專案根（frontend／.env.example 等非 module 內資產）。
//
// 只有一層 `..`，但那一層是相對於 **module 根**（由 go.mod 錨定）而非相對於
// 呼叫端 package 的位置，故 package 下移不影響。取得後必須驗證 marker 存在，
// 讀不到即 Fatal——讀不到被驗證對象等於沒有守衛。
func repoParent(t *testing.T, marker string) string {
	t.Helper()
	parent := filepath.Dir(repoRoot(t))
	if _, err := os.Stat(filepath.Join(parent, filepath.FromSlash(marker))); err != nil {
		t.Fatalf("自模組根上溯一層得 %s，但其中找不到 %s：專案根定位失效，"+
			"守衛讀不到被驗證對象即等於沒有守衛（故 Fatal 而非 skip）: %v", parent, marker, err)
	}
	return parent
}

// encryptCall AST 掃到的一筆可疑呼叫
type encryptCall struct {
	File     string // 相對模組根
	Base     string // 檔名
	Func     string // 外層函式／方法名
	Line     int
	Selector string
	// Recv 被呼叫者的接收運算式原文（`p.client` 上的 Encrypt 呼叫 → "p.client"）；
	// 裸呼叫（同套件未匯出函式）為空字串。
	// 存在理由見 delegatedKMSEncryptExemption：豁免要收到「哪個物件上的 Encrypt」
	// 這一層，否則同一個函式內換個接收者就能寫出完全不同的加密。
	Recv string
	// FirstArgIsEmptyScheme 第一引數是常數空字串或 AADSchemeNone
	// （供 EncodeEnvelopeAAD 的「空 scheme＝無 AAD」別名判定）
	FirstArgIsEmptyScheme bool
}

// recvExpr 把接收運算式還原成原文（只認識別字與選擇器鏈，其餘回空字串）。
//
// 刻意不用 go/printer：本檔的守衛只需要分辨 `p.client` 與其他東西，
// 引入格式化器會為了一個字串比對拉進整個 printer 相依。
func recvExpr(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if base := recvExpr(v.X); base != "" {
			return base + "." + v.Sel.Name
		}
	}
	return ""
}

// firstArgIsEmptyScheme 呼叫的第一引數是否為字面空字串或 AADSchemeNone 識別字
func firstArgIsEmptyScheme(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	switch a := call.Args[0].(type) {
	case *ast.BasicLit:
		return a.Kind == token.STRING && (a.Value == `""` || a.Value == "``")
	case *ast.Ident:
		return a.Name == "AADSchemeNone"
	case *ast.SelectorExpr:
		return a.Sel.Name == "AADSchemeNone"
	}
	return false
}

// scanEncryptCalls 掃描非測試 Go 檔中的 `X.<name>(...)` 呼叫。
// names 為要攔截的方法名集合。
func scanEncryptCalls(t *testing.T, root string, names map[string]bool) []encryptCall {
	t.Helper()
	var found []encryptCall
	scanned := 0
	fset := token.NewFileSet()

	for _, sub := range guardScanRoots {
		dir := filepath.Join(root, sub)
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("掃描根 %s 不存在（守衛範圍失真）: %v", sub, err)
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// testdata 必須跳過：`cmd/server` 測試會在其 testdata 內建刪臨時
				// 目錄，與本 WalkDir 並行即 ENOENT（同 aad_strict_guard_test.go
				// 的冷驗收 B1 根因，此處為同族潛伏面，一併封住）。
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			scanned++
			rel, _ := filepath.Rel(root, path)
			// 以外層宣告分段，便於把呼叫歸屬到函式（允許清單以函式為粒度）
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				ast.Inspect(fn, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch fun := call.Fun.(type) {
					case *ast.SelectorExpr:
						if names[fun.Sel.Name] {
							found = append(found, encryptCall{
								File: rel, Base: filepath.Base(path), Func: fn.Name.Name,
								Line: fset.Position(call.Pos()).Line, Selector: fun.Sel.Name,
								Recv:                  recvExpr(fun.X),
								FirstArgIsEmptyScheme: firstArgIsEmptyScheme(call),
							})
						}
					case *ast.Ident:
						// 同套件內未匯出函式的裸呼叫
						if names[fun.Name] {
							found = append(found, encryptCall{
								File: rel, Base: filepath.Base(path), Func: fn.Name.Name,
								Line: fset.Position(call.Pos()).Line, Selector: fun.Name,
								FirstArgIsEmptyScheme: firstArgIsEmptyScheme(call),
							})
						}
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("掃描 %s 失敗: %v", sub, err)
		}
	}
	if scanned < minAADScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下限 %d，掃描根 %v）：掃描範圍已失真，"+
			"守衛將在近乎空集合下假綠。若目錄結構改變，改的是掃描根而不是下限",
			scanned, minAADScannedFiles, guardScanRoots)
	}
	t.Logf("scanEncryptCalls 掃描檔數=%d（下限 %d）", scanned, minAADScannedFiles)
	sort.Slice(found, func(i, j int) bool {
		if found[i].File != found[j].File {
			return found[i].File < found[j].File
		}
		return found[i].Line < found[j].Line
	})
	return found
}

// TestColumnCodecHasNoPlainEncrypt G1：服務層 codec 介面與生產 codec 型別上
// 都不存在無 AAD 的 Encrypt(plaintext)——「不寫出無 AAD 密文」是**建構保證**。
func TestColumnCodecHasNoPlainEncrypt(t *testing.T) {
	iface := reflect.TypeOf((*crypto.ColumnCodec)(nil)).Elem()

	got := make([]string, 0, iface.NumMethod())
	for i := 0; i < iface.NumMethod(); i++ {
		got = append(got, iface.Method(i).Name)
	}
	sort.Strings(got)
	want := []string{"DecryptFor", "EncryptFor"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("crypto.ColumnCodec 方法集應恰為 %v，得 %v\n"+
			"（多出的方法若能不帶欄位身分寫入，cutover 的建構保證即失效）", want, got)
	}

	// 生產 codec 不得對外暴露無 AAD 寫入
	kmType := reflect.TypeOf((*keyvault.KeyManagerService)(nil))
	for _, banned := range []string{"Encrypt", "EncryptString", "Seal"} {
		if _, ok := kmType.MethodByName(banned); ok {
			t.Fatalf("*keyvault.KeyManagerService 不得暴露無 AAD 寫入方法 %q"+
				"（tasks 1.7：無 AAD 寫入方法須自 codec 介面與型別移除）", banned)
		}
	}

	// 型別確實滿足 ColumnCodec（否則上面的檢查是空轉）
	var _ crypto.ColumnCodec = (*keyvault.KeyManagerService)(nil)
}

// delegatedKMSEncryptExemption 唯一豁免：AWS KMS 委託 provider 對 SDK 的
// `client.Encrypt(ctx, &kms.EncryptInput{...})` 呼叫
// （kek-provider-modularization D11／D11.1）。
//
// **為何是豁免而非違規**：本守衛攔的是「無 AAD 的欄位加密」，其歷史對象是
// crypto.AESCrypto 的無 AAD 寫出（產出裸 base64、不帶任何綁定；該方法本身已於
// P2 M1 刪除，故守衛現在守的是「有人把它加回來」）。KMS 的 Encrypt 是另一個
// 東西——它是**委託 KEK 的包裹原語**，而且**不可能無 AAD**：
// kmsKEKProvider.Wrap 於 len(aad)==0 時直接回 ErrAADRequired，不會走到這行
// （由 pkg/crypto/kms 的 TestWrapUnwrapRejectEmptyAAD 釘住）。
//
// **豁免收得極窄——三個條件同時成立才豁免（冷驗收 CV-L2 收窄）**：
// 精確檔案路徑（不是套件前綴）、精確外層函式名、精確接收運算式。
//
// **原本的範圍過寬**：舊版比對的是套件路徑前綴 `pkg/crypto/kms/`＋函式名 `Wrap`，
// 於是「該套件內任一檔、任一個叫 Wrap 的函式」都能寫出裸 base64、零綁定的
// 無 AAD 加密而守衛全綠。收窄後，豁免只覆蓋 provider.go 的 Wrap 內對
// `p.client`（KMS SDK 客戶端）的那一行。
//
// **殘餘面（誠實記載，不誇大保護）**：有人若在 provider.go 的 Wrap 函式體內
// 把接收者也命名成 p.client 的其他型別，仍可繞過。該函式全長不到 20 行、
// 位於加密核心且由 pkg/crypto/kms 的往返測試逐條覆蓋，本守衛不試圖取代對它的
// 直接閱讀——但除此之外，**任何檔案的任何函式寫 Encrypt 呼叫都會被攔**。
var delegatedKMSEncryptExemption = struct {
	path  string
	funcs map[string]bool
	recv  string
}{
	path:  filepath.Join("pkg", "crypto", "kms", "provider.go"),
	funcs: map[string]bool{"Wrap": true},
	recv:  "p.client",
}

// filterDelegatedKMSEncrypt 濾除委託 KMS provider 的 SDK 呼叫
func filterDelegatedKMSEncrypt(calls []encryptCall) []encryptCall {
	out := calls[:0]
	for _, c := range calls {
		if c.File == delegatedKMSEncryptExemption.path &&
			delegatedKMSEncryptExemption.funcs[c.Func] &&
			c.Recv == delegatedKMSEncryptExemption.recv {
			continue
		}
		out = append(out, c)
	}
	return out
}

// TestDelegatedKMSEncryptExemptionIsNarrow 豁免的**負向控制**。
//
// **本測試原先只擋得住「刪掉某一個條件」，擋不住「放寬某一個條件的值域」**
// （冷驗收 CV-L1，守衛假綠第 7 形態）：實測把 funcs 加進 Unwrap／EncryptColumn、
// 或把路徑放寬成 "pkg"，三個資料格全部維持綠——因為三格用的樣本都落在放寬後的
// 範圍之外，測不到範圍本身。故除了資料格，另加**字面釘子**直接斷言範圍的形狀
// （與本檔既有的 wire contract 釘死手法一致）。
func TestDelegatedKMSEncryptExemptionIsNarrow(t *testing.T) {
	// --- 字面釘子：釘住「範圍有多大」，不是「某個樣本落在範圍外」
	if n := len(delegatedKMSEncryptExemption.funcs); n != 1 || !delegatedKMSEncryptExemption.funcs["Wrap"] {
		t.Fatalf("豁免的函式集 MUST 恰為 {\"Wrap\"}，得 %v（%d 項）"+
			"——放寬值域（例如加進 Unwrap／EncryptColumn）不會被下方的資料格抓到，"+
			"故以字面釘住", delegatedKMSEncryptExemption.funcs, n)
	}
	if want := filepath.Join("pkg", "crypto", "kms", "provider.go"); delegatedKMSEncryptExemption.path != want {
		t.Fatalf("豁免路徑 MUST 恰為 %q，得 %q——放寬成套件前綴（如 \"pkg/crypto/kms\" 或 \"pkg\"）"+
			"會讓整個目錄變成免檢區", want, delegatedKMSEncryptExemption.path)
	}
	if delegatedKMSEncryptExemption.recv != "p.client" {
		t.Fatalf("豁免的接收運算式 MUST 恰為 \"p.client\"（KMS SDK 客戶端），得 %q",
			delegatedKMSEncryptExemption.recv)
	}

	// --- 資料格：逐一移除單一條件即不再豁免
	inKMS := filepath.Join("pkg", "crypto", "kms", "provider.go")
	ok := encryptCall{File: inKMS, Func: "Wrap", Recv: "p.client"}
	cases := []struct {
		name string
		call encryptCall
		want int
	}{
		{"provider.go 的 Wrap 對 p.client（豁免）", ok, 0},
		{"同檔他函式（不豁免）", encryptCall{File: inKMS, Func: "somethingElse", Recv: "p.client"}, 1},
		{"同套件他檔的 Wrap（不豁免）",
			encryptCall{File: filepath.Join("pkg", "crypto", "kms", "client.go"), Func: "Wrap", Recv: "p.client"}, 1},
		{"他處的 Wrap（不豁免）",
			encryptCall{File: filepath.Join("internal", "service", "x.go"), Func: "Wrap", Recv: "p.client"}, 1},
		{"同檔同函式但他接收者（不豁免）",
			encryptCall{File: inKMS, Func: "Wrap", Recv: "crypto.AESCrypto"}, 1},
		{"同檔同函式但裸呼叫（不豁免）", encryptCall{File: inKMS, Func: "Wrap", Recv: ""}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(filterDelegatedKMSEncrypt([]encryptCall{c.call})); got != c.want {
				t.Fatalf("豁免判定錯誤：留下 %d 筆，want %d", got, c.want)
			}
		})
	}
}

// TestDelegatedKMSEncryptExemptionIsActuallyUsed 完備性：豁免所指的呼叫點必須
// **真的存在**。少了這條，若 provider.go 的 Wrap 改名／改接收者，豁免會靜默失效，
// 而 TestNoAADLessWriteReachableFromServices 反而會因為「多出一筆未豁免的呼叫」
// 轉紅——訊息指向錯的地方。本格讓失效即刻可辨。
func TestDelegatedKMSEncryptExemptionIsActuallyUsed(t *testing.T) {
	root := repoRoot(t)
	all := scanEncryptCalls(t, root, map[string]bool{"Encrypt": true})
	for _, c := range all {
		if c.File == delegatedKMSEncryptExemption.path &&
			delegatedKMSEncryptExemption.funcs[c.Func] &&
			c.Recv == delegatedKMSEncryptExemption.recv {
			return
		}
	}
	t.Fatalf("豁免所指的呼叫點已不存在（%s 的 %v 中對 %q 的 .Encrypt 呼叫）：\n"+
		"若該路徑已移除或改名，請一併更新豁免；否則豁免在零命中下形同虛設",
		delegatedKMSEncryptExemption.path, delegatedKMSEncryptExemption.funcs,
		delegatedKMSEncryptExemption.recv)
}

// itoa 避免為單一格式化引入 strconv（保持守衛檔相依最小）
func itoa(n int) string {
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
