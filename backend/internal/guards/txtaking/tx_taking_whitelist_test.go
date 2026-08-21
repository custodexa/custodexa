package txtaking

import (
	"go/ast"
	"go/token"
	"go/types"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/packages"
)

// F8 tx-taking 跨模組寫入白名單（D-10 落地形態，modular-architecture W7 7.5）。
//
// **這個守衛存在的唯一理由**：把 `*gorm.DB` 交給別的模組之後，
// **編譯器與資料邊界閘門（W6 6.0b ratchet）都看不見對方寫了哪張表**——
// 寫入發生在 authz 的方法體內、對象是 authz 自有的表，掃描器判為「自己寫自己」，
// 而真正的事實是「asset／identity 的交易在寫 authz 的表」。ratchet 因此會顯示
// 「乾淨」，這正是 D-10 誠實邊界所說「DoD 第 1 條在此類路徑上名存實亡」的具體形狀。
//
// 本守衛以三個彼此獨立的軸維持可審計性：
//
//	A. **呼叫點必登記**——非 authz 的非測試檔呼叫任何 tx-taking 方法，未登記即紅。
//	B. **登記必存在＋必附理由**——登記項在現實中消失即紅（防白名單越留越寬）；
//	   理由空白即紅（防「先加一列再說」）。
//	C. **偵測器健康**——authz 對外的 tx-taking 匯出方法集合必須與登記的被呼叫方
//	   集合逐字相同。新增一個 tx-taking 匯出方法卻沒登記，A 軸抓不到
//	   （沒人呼叫就沒有呼叫點），C 軸抓得到。
//
// **本守衛擋不住的事（誠實界定，不得省略）**：有 commit 權者可以刪掉本檔；
// 也可以在 authz 的方法體內對任何一張表下手——白名單只保證「哪些呼叫點把交易交出去」
// 這件事是被登記且被審視過的，**不保證交出去之後發生了什麼**。

// txTakingEntry 一筆 tx-taking 跨模組寫入登記。
type txTakingEntry struct {
	// CallerFile 呼叫點所在檔（相對 module 根）
	CallerFile string
	// Callee authz 對外的 tx-taking 方法名
	Callee string
	// OriginalSites D-10 具名白名單所列的原始寫入點（收口前的 file:line）。
	// 收口把多個 Delete 併進一個方法，這一欄使「五處」與現況呼叫點的對應不失聯。
	OriginalSites []string
	// Reason 為何非得把交易交出去（空白即紅）
	Reason string
}

// txTakingWhitelist F8 交易級聯類的原始寫入點收口後的呼叫點。
// 原為五處寫入點／三個呼叫點；security-backlog-settlement 塊 2 新增資產刪除一處。
var txTakingWhitelist = []txTakingEntry{
	{
		CallerFile: "internal/modules/asset/asset_group_service.go",
		Callee:     "RevokeByAssetGroup",
		OriginalSites: []string{
			"internal/service/asset_group_service.go:512（Delete AssetAuthorization）",
			"internal/service/asset_group_service.go:519（Delete ApproverScope）",
		},
		Reason: "刪除資產節點必須與「撤銷掛在該節點上的授權與審核範圍」原子成立：" +
			"節點刪了而授權留著＝幽靈授權（授權列表顯示已不存在的客體），" +
			"授權撤了而節點刪除回滾＝無故失權。asset 不得 import authz（禁止邊），" +
			"authz 也不能反過來驅動 asset 的刪除交易，故只能由 asset 交出交易句柄。",
	},
	{
		CallerFile: "internal/modules/asset/asset_service.go",
		Callee:     "RevokeByAsset",
		OriginalSites: []string{
			"internal/modules/asset/asset_service.go:1092（Delete AssetAuthorization，" +
				"security-backlog-settlement 塊 2 初版直接寫 authz 的表，撞資料邊界閘門後收口）",
		},
		Reason: "刪除資產必須與「撤銷該資產的授權與審核範圍」原子成立：" +
			"權限查詢只查 asset_authorizations、不 join assets，資產刪了而授權留著" +
			"＝已刪資產的授權在權限判定中仍然命中（本 change 要修的缺陷本體）；" +
			"授權撤了而資產刪除回滾＝無故失權。ApproverScope.AssetID 同理——" +
			"資產消失後留下的是懸掛範圍（同 aaa2018 對抗驗證抓到的形態）。" +
			"asset 不得 import authz（禁止邊），authz 也不能反過來驅動 asset 的" +
			"刪除交易，故只能由 asset 交出交易句柄。與 RevokeByAssetGroup 是同一類" +
			"問題的兩個粒度（節點／單一資產）。",
	},
	{
		CallerFile: "internal/modules/identity/user_group_service.go",
		Callee:     "RevokeByUserGroup",
		OriginalSites: []string{
			"internal/modules/identity/user_group_service.go:104（Delete AssetAuthorization）",
			"internal/modules/identity/user_group_service.go:115（Delete ApproverScope）",
		},
		Reason: "刪群組即失權（spec）與「群組審核範圍一併失效」必須與群組軟刪同交易：" +
			"殘留 approver_group=null 的幽靈範圍會讓殘留成員列回復審核資格" +
			"（對抗驗證 aaa2018 #1/#2）。撤銷筆數還要進同交易的審計 Details，" +
			"分兩個交易寫會出現「審計說撤了 N 筆、實際回滾了」的不一致。",
	},
	{
		CallerFile: "internal/modules/identity/user_service.go",
		Callee:     "RevokeByUser",
		OriginalSites: []string{
			"internal/modules/identity/user_service.go:513（Delete ApproverScope）",
		},
		Reason: "帳號軟刪與其審核範圍失效必須原子成立，且整段被「本地 admin 不變式」" +
			"的系統級鎖與使用者憑證鎖包住（取鎖順序 system → user，D13）。" +
			"authz 無法另開交易——那會落在鎖外，且帳號刪除回滾時範圍已被撤。",
	},
}

// txTakingReasonViolations 比對純函式（抽出來才能對「無理由登記」做突變自檢）：
// 回傳理由空白或欄位殘缺的登記項描述。
func txTakingReasonViolations(entries []txTakingEntry) []string {
	var out []string
	for _, e := range entries {
		switch {
		case strings.TrimSpace(e.Reason) == "":
			out = append(out, e.CallerFile+" → "+e.Callee+"：理由欄空白")
		case strings.TrimSpace(e.CallerFile) == "" || strings.TrimSpace(e.Callee) == "":
			out = append(out, "登記項欄位殘缺："+e.CallerFile+" → "+e.Callee)
		case len(e.OriginalSites) == 0:
			out = append(out, e.CallerFile+" → "+e.Callee+"：未指名收口前的原始寫入點")
		}
	}
	sort.Strings(out)
	return out
}

// authzPkgPath authz 模組的 import path（tx-taking 方法的擁有者）。
const authzPkgPath = "github.com/custodexa/backend/internal/modules/authz"

// authzModuleDir authz 模組相對 module 根的目錄（判「是不是 authz 自己」用）。
const authzModuleDir = "internal/modules/authz/"

// minTxTakingScanPackages `packages.Load("./...")` 的載入下限（現況 32，取 24 為保守下界）。
const minTxTakingScanPackages = 24

// txTakingScan 一次掃描的產物
type txTakingScan struct {
	// Methods authz 對外的 tx-taking 匯出方法名集合
	Methods map[string]bool
	// Calls 非 authz 非測試檔對這些方法的呼叫點：method → []file:line
	Calls map[string][]string
	// CallerFiles 呼叫點所在檔（相對 module 根）→ 呼叫的方法集合
	CallerFiles map[string]map[string]bool
	Packages    int
	Files       int
	// Err 掃描失敗的原因（載入錯誤、包數低於下限、pkg.Errors 非空）。
	//
	// 失敗不在掃描函式內就地 t.Fatalf：結果由兩軸共用單次載入，sync.Once 內的 `t`
	// 屬於第一個進入的測試，在其中 Fatal 只會讓那一軸紅，另一軸拿到零值結構
	// （nil map、Packages 為 0）並在空集合上通過。故由每個呼叫者各自 Fatal。
	Err error
}

var (
	txTakingScanOnce  sync.Once
	txTakingScanCache txTakingScan
)

// scanTxTaking 取（並快取）掃描結果，本檔兩支守衛（A／B 軸）共用。
//
// 兩軸看的是同一棵樹的同一份事實且都不改動它，而帶完整型別資訊的全 module
// packages.Load 單次約 30 秒（guard-scan-cost-reduction 基準量測：本包 65s／2 次）。
//
// root 由呼叫點傳入而非在此取得，故 modroot 定位的失敗仍各自 Fatal，
// 不會落進 Once 內造成零值快取。失敗處理見 txTakingScan.Err。
func scanTxTaking(t *testing.T, root string) txTakingScan {
	t.Helper()
	txTakingScanOnce.Do(func() { txTakingScanCache = runTxTakingScan(root) })
	if txTakingScanCache.Err != nil {
		t.Fatalf("%v", txTakingScanCache.Err)
	}
	return txTakingScanCache
}

// runTxTakingScan 以型別資訊掃出 (a) authz 的 tx-taking 匯出方法、(b) 外部呼叫點。
//
// 不接 *testing.T：本函式在 sync.Once 內執行，任何 t 都只屬於第一個進入者。
// 載入下限與 pkg.Errors 兩道防假綠管線**判準值與時機不變**，只是改為寫入 Err。
func runTxTakingScan(root string) txTakingScan {
	fail := func(format string, args ...any) txTakingScan {
		return txTakingScan{Err: fmt.Errorf(format, args...)}
	}
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps,
		Dir:   root,
		Fset:  fset,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return fail("packages.Load 失敗（守衛無法在無視野下宣稱通過）: %v", err)
	}
	if len(pkgs) < minTxTakingScanPackages {
		return fail("只載入 %d 個包（下限 %d）：掃描範圍已失真", len(pkgs), minTxTakingScanPackages)
	}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			return fail("包 %s 有 %d 個載入／型別錯誤（首個：%v）：守衛拒絕在殘缺的 AST 上作判定",
				p.PkgPath, len(p.Errors), p.Errors[0])
		}
	}

	scan := txTakingScan{
		Methods:     map[string]bool{},
		Calls:       map[string][]string{},
		CallerFiles: map[string]map[string]bool{},
		Packages:    len(pkgs),
	}
	rel := func(abs string) string {
		r, err := filepath.Rel(root, abs)
		if err != nil {
			return abs
		}
		return filepath.ToSlash(r)
	}

	// (a) authz 的 tx-taking 匯出方法：接收者在 authz、首參數為 *gorm.DB
	for _, p := range pkgs {
		if p.PkgPath != authzPkgPath || p.Types == nil {
			continue
		}
		sc := p.Types.Scope()
		for _, name := range sc.Names() {
			obj := sc.Lookup(name)
			// 只看**匯出型別**的匯出方法：未匯出型別（如內化後的
			// assetAuthorizationRepository）的方法外部根本取不到，
			// 不構成跨模組通道，列進來只會逼人為內部細節登記白名單
			if !obj.Exported() {
				continue
			}
			named, ok := obj.Type().(*types.Named)
			if !ok {
				continue
			}
			for i := 0; i < named.NumMethods(); i++ {
				m := named.Method(i)
				if !m.Exported() {
					continue
				}
				sig, ok := m.Type().(*types.Signature)
				if !ok || sig.Params().Len() == 0 {
					continue
				}
				if signatureTakesGormDB(sig) {
					scan.Methods[m.Name()] = true
				}
			}
		}
	}
	if len(scan.Methods) == 0 {
		return fail("在 authz 找不到任何 tx-taking 匯出方法：偵測器已失明，" +
			"「零未登記呼叫」不構成證據（比對本檔的 authzPkgPath 是否仍正確）")
	}

	// (b) 外部呼叫點
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			path := fset.Position(f.Pos()).Filename
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			rf := rel(path)
			if strings.HasPrefix(rf, authzModuleDir) {
				continue // authz 自己在自己的表上寫，不是跨模組
			}
			scan.Files++
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !scan.Methods[sel.Sel.Name] {
					return true
				}
				// 以型別資訊確認被呼叫的真的是 authz 的方法：同名方法在別的型別上
				// 很常見（例：api.RecordingTokenManager.RevokeByUser），
				// 純名稱比對會誤報，而誤報會逼人把不相干的呼叫點寫進白名單
				if !isAuthzMethodCall(p.TypesInfo, sel) {
					return true
				}
				site := rf + ":" + itoa(fset.Position(call.Pos()).Line)
				scan.Calls[sel.Sel.Name] = append(scan.Calls[sel.Sel.Name], site)
				if scan.CallerFiles[rf] == nil {
					scan.CallerFiles[rf] = map[string]bool{}
				}
				scan.CallerFiles[rf][sel.Sel.Name] = true
				return true
			})
		}
	}
	return scan
}

// isAuthzMethodCall 判 selector 指向的是否為 authz 包內宣告的方法
// （消費者側窄介面的呼叫同樣成立——介面方法的宣告包是消費者，
// 故另判「介面方法名在 authz 的 tx-taking 集合內且首參數為 *gorm.DB」）。
func isAuthzMethodCall(info *types.Info, sel *ast.SelectorExpr) bool {
	obj := info.Uses[sel.Sel]
	fn, ok := obj.(*types.Func)
	if !ok {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || !signatureTakesGormDB(sig) {
		return false
	}
	if fn.Pkg() != nil && fn.Pkg().Path() == authzPkgPath {
		return true
	}
	// 消費者側窄介面：方法宣告在呼叫方的包，但簽名收 *gorm.DB 且名字落在
	// authz 的 tx-taking 集合內——那正是 D-10 所定義的窄 port 形狀
	recv := sig.Recv()
	return recv != nil && recv.Type() != nil && types.IsInterface(recv.Type())
}

// signatureTakesGormDB 判簽名是否在「任一參數位置」收 *gorm.DB。
//
// 刻意掃全部位置而非只看 At(0)：本庫自己的慣例就有 tx 不在首位的形式
// （`port.WriteInTx(sink, tx, event)`），故 `RevokeByAsset(assetID uint, tx *gorm.DB)`
// 是純風格選擇而非繞過。原本的位置式判定會讓這種寫法**靜默失明**——
// 方法集合軸與呼叫點軸同源，兩軸會一起瞎，而 D-10 的誠實邊界已明列
// F8 只剩「窄化／白名單／code review」三道防線，白名單這道不能被參數順序關掉。
// （2026-08-10 W7 對抗輪 H-1 實證：tx 放第二位時三支守衛全 PASS。）
func signatureTakesGormDB(sig *types.Signature) bool {
	for i := 0; i < sig.Params().Len(); i++ {
		if isGormDBPointer(sig.Params().At(i).Type()) {
			return true
		}
	}
	return false
}

// isGormDBPointer 判型別是否為 *gorm.DB（以型別資訊判，不看識別字拼法）。
func isGormDBPointer(t types.Type) bool {
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := ptr.Elem().(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == "DB" && obj.Pkg() != nil && obj.Pkg().Path() == "gorm.io/gorm"
}

// TestTxTakingCrossModuleWritesAreWhitelisted A 軸＋B 軸。
func TestTxTakingCrossModuleWritesAreWhitelisted(t *testing.T) {
	root := lifecycleModuleRoot(t)
	scan := scanTxTaking(t, root)

	registered := map[string]map[string]bool{}
	for _, e := range txTakingWhitelist {
		if registered[e.CallerFile] == nil {
			registered[e.CallerFile] = map[string]bool{}
		}
		registered[e.CallerFile][e.Callee] = true
	}

	// A 軸：呼叫點必登記
	var unregistered []string
	for file, methods := range scan.CallerFiles {
		for m := range methods {
			if !registered[file][m] {
				unregistered = append(unregistered, file+" → authz."+m)
			}
		}
	}
	sort.Strings(unregistered)
	if len(unregistered) > 0 {
		t.Errorf("以下呼叫點把交易句柄交給了 authz 卻未登記於 txTakingWhitelist：\n  %s\n"+
			"tx-taking 不受編譯器保護（D-10），未登記＝無人審視過它寫了什麼",
			strings.Join(unregistered, "\n  "))
	}

	// B 軸之一：登記項在現實中必須仍存在（防白名單越留越寬）
	var stale []string
	for _, e := range txTakingWhitelist {
		if !scan.CallerFiles[e.CallerFile][e.Callee] {
			stale = append(stale, e.CallerFile+" → authz."+e.Callee)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("以下登記項在現實中已不存在（移除須顯式更新白名單，否則下一次新增會被舊列默許）：\n  %s",
			strings.Join(stale, "\n  "))
	}

	// B 軸之二：理由欄
	if v := txTakingReasonViolations(txTakingWhitelist); len(v) > 0 {
		t.Errorf("白名單登記缺理由或欄位殘缺：\n  %s", strings.Join(v, "\n  "))
	}

	// 具名白名單的每一處都必須有歸屬。
	//
	// **數量是契約**：D-10 原定五處（modular-architecture F8 收口的既有寫入點）；
	// security-backlog-settlement 塊 2 新增資產刪除一處＝六處。調整此數字必須連同
	// 上方 txTakingWhitelist 的登記與其理由一起改——這正是「新增 tx-taking 呼叫點
	// 要被看見」的機制，不是可以隨手放寬的門檻。
	const expectedTxTakingSites = 6
	total := 0
	for _, e := range txTakingWhitelist {
		total += len(e.OriginalSites)
	}
	if total != expectedTxTakingSites {
		t.Errorf("F8 交易級聯白名單應為 %d 處，現登記 %d 處："+
			"新增／移除都必須同步 design.md D-H 的具名清單與本常數",
			expectedTxTakingSites, total)
	}
	if scan.Files < 250 {
		t.Errorf("只掃了 %d 個非測試檔（下限 250）：掃描面已失真", scan.Files)
	}
	t.Logf("tx-taking 掃描：%d 包／%d 非測試檔／authz tx-taking 匯出方法 %d 個／外部呼叫點 %d 個",
		scan.Packages, scan.Files, len(scan.Methods), len(scan.CallerFiles))
}

// TestTxTakingMethodSetMatchesWhitelist C 軸（偵測器健康）：
// authz 的 tx-taking 匯出方法集合必須與白名單登記的被呼叫方集合逐字相同。
// 新增一個 tx-taking 匯出方法而無人呼叫時，A 軸抓不到，本軸抓得到。
func TestTxTakingMethodSetMatchesWhitelist(t *testing.T) {
	root := lifecycleModuleRoot(t)
	scan := scanTxTaking(t, root)

	declared := map[string]bool{}
	for _, e := range txTakingWhitelist {
		declared[e.Callee] = true
	}
	var missing, extra []string
	for m := range scan.Methods {
		if !declared[m] {
			extra = append(extra, m)
		}
	}
	for m := range declared {
		if !scan.Methods[m] {
			missing = append(missing, m)
		}
	}
	sort.Strings(extra)
	sort.Strings(missing)
	if len(extra) > 0 {
		t.Errorf("authz 有未登記的 tx-taking 匯出方法：%s\n"+
			"每一個把 *gorm.DB 收進來的匯出方法都是一條編譯器看不見的跨模組寫入通道，"+
			"必須登記於 txTakingWhitelist 並附理由", strings.Join(extra, ", "))
	}
	if len(missing) > 0 {
		t.Errorf("白名單登記了 authz 並不存在的 tx-taking 方法：%s（登記已過期）",
			strings.Join(missing, ", "))
	}
}

// TestTxTakingReasonMutation 判定純函式的突變自檢：
// 餵合成的登記表，證明「無理由」「欄位殘缺」「未指名原始寫入點」三種形態都會被挑出，
// 且乾淨輸入零誤判。（`packages.Load` 需要完整 module，無法以 TempDir 造樣本樹）
func TestTxTakingReasonMutation(t *testing.T) {
	clean := []txTakingEntry{
		{CallerFile: "a.go", Callee: "M", OriginalSites: []string{"x:1"}, Reason: "有理由"},
	}
	if v := txTakingReasonViolations(clean); len(v) != 0 {
		t.Errorf("乾淨輸入不得誤判: %v", v)
	}
	cases := []struct {
		name  string
		entry txTakingEntry
	}{
		{"理由空白", txTakingEntry{CallerFile: "a.go", Callee: "M", OriginalSites: []string{"x:1"}}},
		{"理由僅空白字元", txTakingEntry{CallerFile: "a.go", Callee: "M", OriginalSites: []string{"x:1"}, Reason: "   "}},
		{"欄位殘缺", txTakingEntry{CallerFile: "", Callee: "M", OriginalSites: []string{"x:1"}, Reason: "有理由"}},
		{"未指名原始寫入點", txTakingEntry{CallerFile: "a.go", Callee: "M", Reason: "有理由"}},
	}
	for _, c := range cases {
		if v := txTakingReasonViolations([]txTakingEntry{c.entry}); len(v) != 1 {
			t.Errorf("%s：應恰好挑出 1 筆違規, got %v", c.name, v)
		}
	}
}
