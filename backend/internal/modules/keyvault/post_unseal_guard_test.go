package keyvault_test

import (
	"context"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 解封後遷移佇列與審計蓋章序的**結構守衛**。
//
// 原「AAD 顯式化三道守衛」（G1 遷移無自動執行路徑／G2 佇列負向成員／G3 降級唯一
// 入口）中的 G1 與 G3 已隨其守衛對象於過渡格式收尾時整組刪除
// ——守衛對象不存在時，AST 呼叫點比對只會在零命中下假綠（先刪入口、後刪守衛）。
//
// 保留兩道：
//
//	G2（佇列成員）：解封後遷移佇列的**負向成員斷言**——不得出現任何過渡遷移項
//	   （envelope_legacy／AAD）；同時正向斷言內建 ldap_seed 確實在列
//	   （否則負向斷言可由空佇列假綠）。
//	G4（蓋章序）：凡呼叫具名遷移函式的進入點檔，SHALL 於呼叫前註冊審計蓋章 hook
//	   ——否則該路徑寫出的審計列 HMAC 為空，驗章端會誤判為上線前的歷史列。
//
// aadGuardScanRoots AST 守衛的掃描根。**scripts/ 必須在列**：它是 //go:build ignore
// 的維運工具所在，過去不在任何守衛視野內（空集合假綠的來源之一）。
var aadGuardScanRoots = []string{"internal", "cmd", "pkg", "scripts"}

// scanCallsWithin 於指定掃描根掃出 names 中任一函式／方法的呼叫點。
// 與 aad_write_guard_test.go 的 scanEncryptCalls 同型，差別僅在掃描根可指定。
func scanCallsWithin(t *testing.T, root string, roots []string, names map[string]bool) []encryptCall {
	t.Helper()
	var found []encryptCall
	scanned := 0
	fset := token.NewFileSet()
	for _, sub := range roots {
		dir := filepath.Join(root, sub)
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("掃描根 %s 不存在（守衛範圍失真）: %v", sub, err)
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// testdata 必須跳過：`cmd/server` 的測試會在
				// `cmd/server/testdata/` 內建立與刪除臨時目錄，與本守衛的
				// WalkDir 並行時會 ENOENT 而讓全量測試變成非確定性。
				// 該目錄內不含產品碼，跳過不減守衛涵蓋。沿 env_drift_test.go 前例。
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// parser 不套用 build tag，故 //go:build ignore 的工具檔一併入視野
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			scanned++
			rel, _ := filepath.Rel(root, path)
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
					var name string
					switch fun := call.Fun.(type) {
					case *ast.SelectorExpr:
						name = fun.Sel.Name
					case *ast.Ident:
						name = fun.Name
					}
					if name != "" && names[name] {
						found = append(found, encryptCall{
							File: rel, Base: filepath.Base(path), Func: fn.Name.Name,
							Line: fset.Position(call.Pos()).Line, Selector: name,
						})
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
	if scanned < minEntryPointScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下限 %d，掃描根 %v）：掃描範圍已失真，"+
			"守衛將在近乎空集合下假綠。若目錄結構改變，改的是掃描根而不是下限",
			scanned, minEntryPointScannedFiles, roots)
	}
	t.Logf("scanCallsWithin(%v) 掃描檔數=%d（下限 %d）", roots, scanned, minEntryPointScannedFiles)
	sort.Slice(found, func(i, j int) bool {
		if found[i].File != found[j].File {
			return found[i].File < found[j].File
		}
		return found[i].Line < found[j].Line
	})
	return found
}

// minEntryPointScannedFiles 進入點掃描的檔數下限（防空集合假綠）。
// 本檔的 scanCallsWithin 一律以 aadEntryPointRoots（cmd／scripts）為掃描根，
// 2026-08-09 實測 15 檔（見測試的 t.Logf），門檻取 12。
const minEntryPointScannedFiles = 12

// TestPostUnsealQueueHasNoTransitionalMigration 佇列成員的正負向斷言。
//
// 負向：佇列 SHALL NOT 含 legacy 密文信封化（`envelope_legacy`）或任何 AAD
// 遷移項——兩者的機制本體已刪除，殘留一個同名佇列項即代表拆除不完整。
// 正向：內建 `ldap_seed` 確實在列，否則負向斷言可由「空佇列」假綠。
func TestPostUnsealQueueHasNoTransitionalMigration(t *testing.T) {
	registerBuiltinsLikeAssembly()
	keyvault.ResetPostUnsealQueueForTest()
	t.Cleanup(keyvault.ResetPostUnsealQueueForTest)

	names := keyvault.PostUnsealMigrationNames()
	found := false
	for _, n := range names {
		if n == identity.PostUnsealMigrationLDAPSeed {
			found = true
		}
	}
	if !found {
		t.Fatalf("內建 ldap_seed 項不在佇列（%v）：負向斷言將由空佇列假綠", names)
	}
	for _, n := range names {
		lower := strings.ToLower(n)
		if strings.Contains(lower, "aad") || lower == "envelope_legacy" || strings.Contains(lower, "legacy") {
			t.Fatalf("解封後遷移佇列出現過渡遷移項 %q：該類機制已整組拆除", n)
		}
	}
}

// postUnsealAssemblyBuiltins 組裝根**必須**登記的內建遷移（登記器第一引數的識別字）。
//
// 具名而非只數數量：4.9 環拆解後，「生產佇列裡有哪些項」不再由 keyvault 的程式碼
// 結構保證，而由組裝根的一行呼叫保證——那一行被刪掉時，包內測試會因為自行
// registerBuiltinsLikeAssembly 而照樣綠，只有本清單會轉紅。新增內建遷移時
// SHALL 同步加入本清單。
var postUnsealAssemblyBuiltins = []string{"PostUnsealMigrationLDAPSeed"}

// TestAssemblyRegistersPostUnsealBuiltins 組裝根登記守衛（拆 4.9 環的配套）。
//
// 三條斷言：
//   - 組裝根確有 keyvault.RegisterPostUnsealBuiltin 呼叫（否則生產佇列為空＝遷移靜默不執行）；
//   - 每一筆登記都早於同檔的 keyvault.RunPostUnsealMigrations（晚於它等於佇列執行時只有一半）；
//   - postUnsealAssemblyBuiltins 逐項都真的被登記（防「登記行被刪一半」）。
func TestAssemblyRegistersPostUnsealBuiltins(t *testing.T) {
	root := repoRoot(t)
	registerCalls := scanCallsWithin(t, root, aadEntryPointRoots,
		map[string]bool{"RegisterPostUnsealBuiltin": true})
	runCalls := scanCallsWithin(t, root, aadEntryPointRoots,
		map[string]bool{"RunPostUnsealMigrations": true})

	if len(registerCalls) < 1 {
		t.Fatalf("在 %v 掃到 %d 個 keyvault.RegisterPostUnsealBuiltin 呼叫（期望 ≥1）："+
			"內建遷移的登記已自組裝根消失，生產佇列將為空", aadEntryPointRoots, len(registerCalls))
	}
	if len(runCalls) < 1 {
		t.Fatalf("在 %v 掃不到 keyvault.RunPostUnsealMigrations 呼叫：掃描或受管名單已失真", aadEntryPointRoots)
	}
	for _, run := range runCalls {
		file := filepath.ToSlash(run.File)
		first := lineOfFirst(registerCalls, file)
		if first == noCallLine {
			t.Fatalf("%s 執行了解封後遷移佇列，卻未在同檔登記任何內建遷移："+
				"佇列在執行時將為空（遷移靜默不執行，不報錯）", file)
		}
		if first > run.Line {
			t.Fatalf("%s 的內建遷移登記（L%d）晚於佇列執行（L%d）："+
				"執行時佇列只有一半", file, first, run.Line)
		}
	}

	registered := scanPostUnsealBuiltinArgs(t, root, registerCalls)
	for _, want := range postUnsealAssemblyBuiltins {
		if !registered[want] {
			t.Fatalf("組裝根未登記內建遷移 %s（實得 %v）："+
				"新增／移除內建遷移時 SHALL 同步更新 postUnsealAssemblyBuiltins",
				want, registered)
		}
	}
}

// scanPostUnsealBuiltinArgs 取出各 keyvault.RegisterPostUnsealBuiltin 呼叫第一引數的識別字名。
// 只認 `X.Ident` 與裸 `Ident` 兩形——字面量字串刻意不認，登記名必須走具名常數，
// 否則佇列項名與 service 側常數會各自漂移。
func scanPostUnsealBuiltinArgs(t *testing.T, root string, calls []encryptCall) map[string]bool {
	t.Helper()
	files := map[string]bool{}
	for _, c := range calls {
		files[filepath.ToSlash(c.File)] = true
	}
	out := map[string]bool{}
	fset := token.NewFileSet()
	for file := range files {
		f, err := parser.ParseFile(fset, filepath.Join(root, file), nil, 0)
		if err != nil {
			t.Fatalf("解析 %s 失敗（守衛不在殘缺 AST 上作判定）: %v", file, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			case *ast.Ident:
				name = fun.Name
			}
			if name != "RegisterPostUnsealBuiltin" {
				return true
			}
			switch arg := call.Args[0].(type) {
			case *ast.SelectorExpr:
				out[arg.Sel.Name] = true
			case *ast.Ident:
				out[arg.Name] = true
			}
			return true
		})
	}
	return out
}

// registerBuiltinsLikeAssembly 在測試中重現組裝根（cmd/server/stage2.go）的內建登記。
//
// **4.9 環拆解後這一步是測試自己的責任**：keyvault 的佇列不再認識任何
// 業務模組的遷移，生產側的登記在組裝根、測試側則由 setup 顯式呼叫
// （由 main 與測試 setup 顯式呼叫）。生產側真的有做這件事，
// 由 TestAssemblyRegistersPostUnsealBuiltins 以 AST 對組裝根獨立斷言——
// 本函式只負責讓包內測試看見與生產一致的佇列，不承擔那項保證。
//
// 冪等且不需清理：登記器清單同名去重，且 Reset 只清佇列不清登記器。
func registerBuiltinsLikeAssembly() {
	keyvault.RegisterPostUnsealBuiltin(identity.PostUnsealMigrationLDAPSeed, func() {
		identity.RegisterLDAPSeedMigration(audit.NewTxSink())
	})
}

// TestRegisterBuiltinPostUnsealIdempotent 重複登記防護（冪等）。
func TestRegisterBuiltinPostUnsealIdempotent(t *testing.T) {
	registerBuiltinsLikeAssembly()
	keyvault.ResetPostUnsealQueueForTest()
	t.Cleanup(keyvault.ResetPostUnsealQueueForTest)
	before := len(keyvault.PostUnsealMigrationNames())
	if before == 0 {
		t.Fatal("佇列為空，冪等斷言將在零項下假綠")
	}
	keyvault.RegisterBuiltinPostUnsealMigrations()
	keyvault.RegisterBuiltinPostUnsealMigrations()
	if after := len(keyvault.PostUnsealMigrationNames()); after != before {
		t.Fatalf("重複登記應為 no-op：%d → %d", before, after)
	}
}

// aadStampedMigrationEntries 「呼叫具名遷移函式的 main package 必須先蓋章」守衛的
// 受管函式名。
// **過渡遷移函式已全數刪除**：
// 受管集合收斂為佇列執行器一支——它仍會寫出審計列（佇列項如 ldap_seed），
// 故蓋章先後序的守衛必須保留。
var aadStampedMigrationEntries = map[string]bool{
	"RunPostUnsealMigrations": true,
}

// aadEntryPointRoots 「工具／服務進入點」的掃描根。
//
// **internal/tools 已自清單移除**：aadtool 整個
// 套件連同 scripts/ 的薄 main 已刪除，該掃描根不復存在（留著會讓 scanCallsWithin
// 在 os.Stat 失敗時整批 Fatal）。scripts/ 保留在列——它仍是 //go:build ignore 的
// 維運工具所在，日後任何新工具呼叫具名遷移函式時必須立刻落入蓋章守衛視野。
var aadEntryPointRoots = []string{"cmd", "scripts"}

// aadStampedEntryFiles 蓋章守衛**必須**驗到的進入點檔（完備性下界的具名版）。
// 具名而非只數數量：檔案改名或搬家時要當場失敗，不是靜靜地少驗一個。
// 兩段啟動重構後，服務進入點自
// cmd/server/main.go 移至 cmd/server/stage2.go——遷移佇列的執行與審計蓋章
// hook 註冊皆屬段 2，main.go 只剩組裝根。
//
// **aadtool runner 已刪除**：CLI 遷移工具整組
// 拆除後，具名遷移函式在進入點掃描根內只剩服務端一個呼叫點。
var aadStampedEntryFiles = []string{
	"cmd/server/stage2.go",
}

// TestMigrationCallersRegisterAuditHooks 蓋章守衛：凡呼叫具名遷移函式的
// **進入點檔**，SHALL 於呼叫前出現 InitAuditIntegrityVersioned＋
// SetAuditCreateHooks——否則該路徑寫出的審計列 IntegrityHMAC 為空，
// 驗章端會把它當成上線前的歷史列而不計入竄改判定。
//
// 註：本守衛只驗**結構**（同檔、先後）。原先由 internal/tools/aadtool 整合測試
// 承擔的「工具路徑實際寫出的審計列真的帶章」已隨該工具於 P1 一併拆除。
func TestMigrationCallersRegisterAuditHooks(t *testing.T) {
	root := repoRoot(t)
	migrationCalls := scanCallsWithin(t, root, aadEntryPointRoots, aadStampedMigrationEntries)
	initCalls := scanCallsWithin(t, root, aadEntryPointRoots, map[string]bool{"InitAuditIntegrityVersioned": true})
	hookCalls := scanCallsWithin(t, root, aadEntryPointRoots, map[string]bool{"SetAuditCreateHooks": true})

	// 空集合假綠的下界：aadtool 拆除後進入點只剩 stage2.go 一個呼叫點，
	// 故下界自 2 降為 1（仍能在 AST 掃描或受管名單失真時當場轉紅）；
	// 具名完備性斷言（aadStampedEntryFiles）承擔剩下的涵蓋保證。
	if len(migrationCalls) < 1 {
		t.Fatalf("在 %v 掃到 %d 個遷移函式呼叫點（期望 ≥1）："+
			"AST 掃描或受管名單已失真，本守衛將在空集合下假綠",
			aadEntryPointRoots, len(migrationCalls))
	}

	files := map[string]bool{}
	for _, c := range migrationCalls {
		files[filepath.ToSlash(c.File)] = true
	}
	for file := range files {
		if lineOfFirst(initCalls, file) == noCallLine || lineOfFirst(hookCalls, file) == noCallLine {
			t.Fatalf("%s 呼叫了具名遷移函式，卻未在同檔註冊審計蓋章 hook"+
				"（需 audit.InitAuditIntegrityVersioned 與 SetAuditCreateHooks）", file)
		}
		firstMigration := lineOfFirst(migrationCalls, file)
		if lineOfFirst(initCalls, file) > firstMigration || lineOfFirst(hookCalls, file) > firstMigration {
			t.Fatalf("%s 的審計蓋章 hook 註冊晚於遷移呼叫（遷移於 L%d）："+
				"蓋章必須先於任何會寫審計列的遷移", file, firstMigration)
		}
	}
	// 具名完備性：兩個已知進入點都必須真的在受驗集合內
	for _, want := range aadStampedEntryFiles {
		if !files[want] {
			t.Fatalf("進入點 %s 未出現在受驗集合（實得 %v）："+
				"檔案搬家或不再呼叫遷移函式時 SHALL 同步更新本清單，"+
				"否則守衛涵蓋面靜默縮水", want, files)
		}
	}
}

// noCallLine 「該檔無任何命中」的哨兵行號（大於任何真實行號，故排序比較天然成立）
const noCallLine = 1 << 30

// lineOfFirst 該檔案中最早的一筆呼叫行號；無則回 noCallLine
func lineOfFirst(calls []encryptCall, file string) int {
	best := noCallLine
	for _, c := range calls {
		if filepath.ToSlash(c.File) == file && c.Line < best {
			best = c.Line
		}
	}
	return best
}

// 以下自 `kek_provider_aad_test.go` 遷入：
// 本測試需要 registerBuiltinsLikeAssembly（登記 identity 的 ldap_seed 內建項，
// 定義於本檔）；原先留在 internal/service，該包解散後遷入本包（外部測試包）；
// 只用 keyvault 的匯出面，斷言逐字未改。

// TestPostUnsealQueueRunsWithInjectedCodec 佇列項取得的 codec 由段 2 注入；
// A／C 模式在啟動內跑完（行為與現況無異），B 模式延後至解封後——同一機制。
func TestPostUnsealQueueRunsWithInjectedCodec(t *testing.T) {
	// 內建登記器由組裝根提供；此處顯式補上，讓「內建項亦在佇列內」
	// 的下方註解與失敗計數斷言維持成立（否則本測試會依賴其他測試的登記副作用）
	registerBuiltinsLikeAssembly()
	keyvault.ResetPostUnsealQueueForTest()
	t.Cleanup(keyvault.ResetPostUnsealQueueForTest)
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)

	ran := 0
	var sawCodec crypto.ColumnCodec
	keyvault.RegisterPostUnsealMigration(keyvault.PostUnsealMigration{
		Name: "test-needs-codec",
		Run: func(_ *gorm.DB, codec crypto.ColumnCodec) error {
			ran++
			sawCodec = codec
			return nil
		},
	})
	keyvault.RegisterPostUnsealMigration(keyvault.PostUnsealMigration{
		Name: "test-fails-but-does-not-block",
		Run:  func(*gorm.DB, crypto.ColumnCodec) error { return context.Canceled },
	})

	failed := keyvault.RunPostUnsealMigrations(db, km)
	if ran != 1 {
		t.Fatalf("佇列項應被執行一次, got %d", ran)
	}
	if sawCodec == nil {
		t.Fatal("佇列 MUST 注入 codec（呼叫端不自全域取得）")
	}
	// 內建項亦在佇列內（Reset 助手清空後重註冊 builtin）：
	// - ldap_seed：**不計入失敗**——env 未啟用時
	//     寫 marker 後正常返回（schema_migrations 已於 newKeyManagerDB 建立），
	//     env 啟用時正常 seed；兩者皆非失敗。
	// legacy 信封遷移項已隨過渡機制拆除，故失敗僅來自本測試刻意註冊的一項。
	if failed != 1 {
		t.Fatalf("失敗項應被記數且不阻塞（測試項 1）, got %d", failed)
	}

	// B 模式語義：段 1（尚無 KeyManager）不得執行佇列——以「codec 為 nil 時
	// 入口即拒絕」代表該不變式
	if _, err := keyvault.RecryptForNewRef(context.Background(), nil,
		crypto.CipherRef{}, crypto.CipherRef{}, "x"); err == nil {
		t.Fatal("codec 為 nil（段 1 情境）時重加密入口 MUST 拒絕")
	}
}
