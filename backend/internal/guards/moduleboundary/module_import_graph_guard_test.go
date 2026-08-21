package moduleboundary

// 模組相依圖守衛骨架（modular-architecture Phase B / W1 任務 1.13）。
//
// **本波要釘的是三條剛拆掉的環**（1.10–1.12）：keyvault→identity、keyvault→audit、
// policy→audit 零依賴。R3.1 §3.2 的完整依賴矩陣留待各模組真正搬包後逐波開啟。
//
// **為何不是「import 守衛」而是「符號參照守衛」**（W1 的誠實邊界）：W1 是零搬檔波，
// 七個模組仍同居於 `internal/service` 一個 Go package，包級 import 邊此刻並不存在
// ——只看 import 會零違規恆綠，正是 R3.1 §6.3／基線 §6.2 反覆指出的假綠形態。
// 故本守衛以「檔案→模組」歸屬表把未來的包界線提前投影到現況，判定跨模組的
// **符號參照**（`types.Info.Uses`）。搬包完成後，同一份歸屬表會自然退化為
// import 判定（跨包參照必然伴隨 import），判準連續、不需重寫。
//
// 三道防假綠（R3.1 §6.3 三條，逐條落地）：
//  1. `packages.Load` 載入包數下限（空圖＝零違規＝綠是最危險的失敗形態）；
//  2. `len(pkg.Errors) > 0` 即 `t.Fatal`——遷移中途編譯最不穩，殘缺 AST 上的
//     「零違規」不成立；
//  3. 比對邏輯抽為純函式並以合成違規表做突變自檢（`packages.Load` 需完整 module，
//     TempDir 造樣本的作法在此不適用，R3.1 §6.3 已明改）。
//
// 掃描根一律以 `go.mod` 的 module 身分為錨點（沿用 `lifecycleModuleRoot`），
// 不用 cwd 相對或固定層數 `..`——基線 §6.2 實證 17 處守衛因層數推算而在搬檔後
// 掃空仍綠。

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// minModuleGraphPackages `packages.Load("./...")` 的載入包數下限。
// 現況 28 個包（W1 新增 internal/kernel、internal/kernel/dberr）；取 24 為保守下界。
// **遷移只會增加包（internal/modules/*），不會減少**，故此下限在十波期間恆有效。
const minModuleGraphPackages = 24

// minAttributedServiceFiles 落入模組歸屬的非測試檔數下限。
// 現況 85 檔（R3 §1.2 的 84 檔完全劃分＋W2 2.1 拆出的 keyvault/release.go）；取 80 為下界——
// 掉到下限以下代表掃描範圍或歸屬判定失真，此時「零違規」不成立。
const minAttributedServiceFiles = 80

// serviceScanDir 已消滅的扁平 service 包（相對 module 根，slash 分隔）。
// **W9 起它必須不存在**——七模組全數搬包完成，`internal/service` 連同其
// 13 個殘留測試檔一併解散（keyvault 11／identity 1／夾具殘餘 1）。
const serviceScanDir = "internal/service"

// moduleDirForRootProof 用來反證掃描根的具名目錄：`serviceScanDir` 的
// 「不存在」斷言在掃描根本身失真時同樣成立（假綠），故要求同一個根底下
// 必須看得到一個已知存在的模組目錄。
const moduleDirForRootProof = "internal/modules/session"

// moduleRootPrefix 已搬包模組的路徑前綴（W2 起逐波填充）。
const moduleRootPrefix = "internal/modules/"

// W1 要釘住的禁止邊。key＝依賴方模組，value＝其不得參照的模組集合。
//
// **只列三條，不多不少**：1.10–1.12 就地拆掉的三條真環（R3.1 §3.1 的 4.9／4.10／4.11）。
// 其餘矩陣邊（policy→authz 屬 §4.8，W3；模組對 `internal/repository` 的直讀等）
// 尚未拆解，此刻列入只會得到一份必紅的清單，反而逼人放寬守衛——那正是驗收條件
// 明令禁止的方向。逐波開啟時 SHALL 在此加行，並附該波的拆解依據。
var forbiddenModuleEdges = map[string]map[string]bool{
	// 4.9：登記動作上移組裝根後，keyvault 不再認識 identity 的遷移登記
	// 4.10：KEKRetirementMonitor 改吃 keyvault 自宣告的 AuditFailureReporter
	"keyvault": {"identity": true, "audit": true},
	// 4.11：TransmissionInventoryService 改吃 policy 自宣告的 ChannelInventoryProvider
	//
	// **W3 起 policy 列改為全零出向**（3.8 驗收條件）：§4.8 環於本波拆解後
	// （`AnnotateConnectStates` 歸 authz、`ConnectSourceResolver` 窄介面反轉），
	// policy 對六個業務模組皆無出向。W1 只釘 policy→audit，是因為當時 §4.8 尚未拆；
	// 現況已可釘滿整列（R3.1 §3.2 矩陣 policy 列全 ✗）。
	"policy": {
		"audit":    true,
		"authz":    true,
		"identity": true,
		"asset":    true,
		"session":  true,
		"keyvault": true,
	},
	// **W4 起新增 audit 列**（4.13 驗收條件）：15 檔搬入 `internal/modules/audit` 後，
	// audit 對四個業務模組零出向。**刻意不列 keyvault 與 policy**——那兩條是既有的
	// 合法反向邊：蓋章需 keyvault 的 KeyManager／ExportSigning（audit_integrity、
	// audit_export），失效通知與保留天數需 policy 的 SecurityPolicyService。
	// 兩者在 R3.1 §3.2 矩陣中即為 ✔。
	//
	// 本波拆掉的三條真出向邊：`RecordingService`（session）於 4.8 反轉為
	// RecordingReader／RecordingCleaner 兩個消費者側窄介面；`AuditLogEntry` 的
	// 四個 identity/authz 消費者改為反向 import（service→audit）；`causeText`
	// 匯出為 CauseText 供 session 的 recording_failure_report.go 消費。
	"audit": {
		"identity": true,
		"asset":    true,
		"authz":    true,
		"session":  true,
	},
	// **W6 起新增 asset 列**（6.7 驗收條件）：9 檔搬入 `internal/modules/asset` 後，
	// asset 對 authz／identity／session 零出向。**刻意不列 audit／keyvault／policy**
	// ——那三條是 R3.1 §3.2 矩陣中既有的合法出向邊：交易內審計走
	// `audit/port.TxSink`、憑證欄的 CipherRef 常數來自 keyvault、資產列表的傳輸風險
	// 徽章來自 policy。
	//
	// 本波拆掉的兩條真出向邊：`FillNodeInfoForDTOs`（吃 authz 的 AuthorizedAssetDTO）
	// 整個方法改掛 `*AssetAuthorizationService`（§5.5，提前執行 W7 7.6）；
	// `AssetAccountService.authz` 的型別由 `*AssetAuthorizationService` 換成
	// 消費者側宣告的未匯出窄介面 `assetViewPermissionChecker`。
	"asset": {
		"authz":    true,
		"identity": true,
		"session":  true,
	},
	// **W7 起新增 authz 列**（7.10 驗收條件）：9＋5 檔搬入 `internal/modules/authz` 後，
	// authz 對 identity／session／keyvault 零出向。**刻意不列 asset／audit／policy**
	// ——那三條是 R3.1 §3.2 矩陣中既有的合法出向邊：`asset.ValidateAccountUsername`／
	// `asset.FillNodeInfo`、交易內審計走 `audit/port.TxSink` 與 `audit.AuditLogService`、
	// 存取政策與時長上限來自 policy。
	//
	// 本波拆掉的唯一一條真出向邊：`AccessRequestService.sessions` 的型別由
	// `*SessionService`（session）換成消費者側宣告的窄介面 `SessionTerminator`
	// （§4.6，同型前例＝`user_service.go` 的同名介面）。
	"authz": {
		"identity": true,
		"session":  true,
		"keyvault": true,
	},
	// **W8 起新增 identity 列**（9.10 驗收條件）：31 檔搬入 `internal/modules/identity`
	// 後，identity 對 asset／session 零出向。**刻意不列 audit／authz／keyvault／policy**
	// ——那四條是 R3.1 §3.2 矩陣中既有的合法出向邊：外部身分與 OIDC/LDAP 的審計走
	// `audit`（AuditLogService／TxSink）、登入回應的 `is_approver` 走
	// `authz.IsEffectiveApprover`、TOTP／client secret／bind 密碼的欄位密文走
	// `keyvault` 的 CipherRef 與 ColumnCodec、密碼合規與 LDAP 風險徽章走 `policy`。
	//
	// **本波零真出向邊要拆**（開工實測）：identity 對 asset 與 session 的跨模組符號
	// 參照本來就是 0，故搬檔阻力集中在測試夾具而不在生產碼。
	"identity": {
		"asset":   true,
		"session": true,
	},
}

// **W9 起不再有「尚未搬包」的檔**：原本此處有一份 `serviceFileModule` 歸屬表，
// 登記 `internal/service` 中尚未搬包之非測試檔的模組歸屬。七波搬完後該包已解散
// （W9 搬走 session 的 8 個非測試檔，其餘 13 個測試檔改居擁有者模組的外部測試包），
// 表因此歸零並整份刪除——留一份空表比刪掉更糟：它會讓讀者以為判定還有第二條路徑。
// 模組歸屬自此只有一條判準＝`internal/modules/<name>/` 路徑前綴（見 moduleOfFile），
// 而「扁平包不得復活」由 TestModuleGraphHasNoForbiddenEdges 的目錄存在性斷言承接。

// moduleEdge 一筆跨模組參照（比對純函式的輸入單位）
type moduleEdge struct {
	From   string // 參照方模組
	To     string // 被參照方模組
	Detail string // 人可讀的證據：file:line 參照的符號
}

// forbiddenEdgeViolations 比對純函式：自跨模組參照表挑出禁止邊。
//
// **抽成純函式是為了讓突變自檢可行**：`packages.Load` 需要完整 module，無法以
// TempDir 造樣本樹（R3.1 §6.3 第 3 條）。故把判定與掃描切開，餵合成的違規表
// 即可證明「守衛真的會紅」。輸出依 From/To/Detail 排序，錯誤訊息可重現。
func forbiddenEdgeViolations(edges []moduleEdge, forbidden map[string]map[string]bool) []moduleEdge {
	var out []moduleEdge
	for _, e := range edges {
		if e.From == e.To {
			continue
		}
		if forbidden[e.From][e.To] {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

// moduleOfFile 由「相對 module 根的檔路徑」判模組；非模組範圍回空字串。
//
// **W9 起只剩一條判準**＝`internal/modules/<name>/` 路徑前綴。W2–W8 期間另有
// 一條「查 `internal/service` 歸屬表」的分支服務尚未搬包的檔，該包已於 W9 解散。
func moduleOfFile(rel string) string {
	if !strings.HasPrefix(rel, moduleRootPrefix) {
		return ""
	}
	rest := strings.TrimPrefix(rel, moduleRootPrefix)
	if i := strings.Index(rest, "/"); i > 0 {
		return rest[:i]
	}
	return ""
}

// moduleGraphScan 掃描結果
type moduleGraphScan struct {
	Edges      []moduleEdge
	Packages   int
	Attributed int             // 落在某模組內的非測試檔數
	SeenFiles  map[string]bool // 歸屬表命中過的 service 檔名
}

// scanModuleEdges 以型別資訊收集全樹的跨模組符號參照。
func scanModuleEdges(t *testing.T, root string) moduleGraphScan {
	t.Helper()
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
		t.Fatalf("packages.Load 失敗（守衛無法在無視野下宣稱通過）: %v", err)
	}
	if len(pkgs) < minModuleGraphPackages {
		t.Fatalf("只載入 %d 個包（下限 %d）：掃描範圍已失真，守衛將在近乎空集合下假綠",
			len(pkgs), minModuleGraphPackages)
	}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			t.Fatalf("包 %s 有 %d 個載入／型別錯誤（首個：%v）：守衛拒絕在殘缺的 AST 上作判定",
				p.PkgPath, len(p.Errors), p.Errors[0])
		}
	}

	rel := func(abs string) string {
		r, err := filepath.Rel(root, abs)
		if err != nil {
			return abs
		}
		return filepath.ToSlash(r)
	}

	scan := moduleGraphScan{SeenFiles: map[string]bool{}}
	scan.Packages = len(pkgs)
	// 先建「宣告位置 → 模組」的解析器：跨模組判定要看被參照符號的**宣告檔**
	declModule := func(pos token.Pos) string {
		if !pos.IsValid() {
			return ""
		}
		return moduleOfFile(rel(fset.Position(pos).Filename))
	}

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
			from := moduleOfFile(rf)
			if from == "" {
				continue
			}
			scan.Attributed++
			scan.SeenFiles[filepath.Base(rf)] = true
			ast.Inspect(f, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				obj := p.TypesInfo.Uses[id]
				if obj == nil {
					return true
				}
				to := declModule(obj.Pos())
				if to == "" || to == from {
					return true
				}
				scan.Edges = append(scan.Edges, moduleEdge{
					From: from,
					To:   to,
					Detail: fmt.Sprintf("%s:%d 參照 %s（宣告於 %s）",
						rf, fset.Position(id.Pos()).Line, id.Name,
						rel(fset.Position(obj.Pos()).Filename)),
				})
				return true
			})
		}
	}
	return scan
}

// TestModuleGraphHasNoForbiddenEdges W1 三條拆掉的環：拆後零反向參照。
func TestModuleGraphHasNoForbiddenEdges(t *testing.T) {
	root := lifecycleModuleRoot(t)
	scan := scanModuleEdges(t, root)

	// 扁平包不得復活（W9 起）：`internal/service` 一旦重新出現，落在其中的檔
	// **不屬於任何模組**（moduleOfFile 回空字串），其跨模組參照會被整批跳過而
	// 本守衛照樣綠——這正是 W2–W8 期間靠歸屬表堵住的洞。
	//
	// 二次條件：「不存在」在掃描根本身失真時同樣成立，故先以一個已知存在的
	// 模組目錄反證根是對的，再判缺席。
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(moduleDirForRootProof))); err != nil {
		t.Fatalf("掃描根失真：%s 底下看不到 %s（%v）", root, moduleDirForRootProof, err)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(serviceScanDir))); err == nil {
		t.Errorf("%s 又出現了：七模組切分完成後不得存在扁平 service 包——"+
			"落在其中的檔不屬於任何模組，其跨模組參照會被本守衛整批跳過而照樣綠",
			serviceScanDir)
	} else if !os.IsNotExist(err) {
		t.Fatalf("判定 %s 是否存在時出錯（不得以錯誤當成缺席）: %v", serviceScanDir, err)
	}
	if scan.Attributed < minAttributedServiceFiles {
		t.Fatalf("只有 %d 個檔落入模組歸屬（下限 %d）：掃描或歸屬已失真",
			scan.Attributed, minAttributedServiceFiles)
	}
	if len(scan.Edges) == 0 {
		t.Fatal("全樹零跨模組參照：這在拆包前不可能為真，掃描必已失效（型別資訊缺失或歸屬全空）")
	}

	violations := forbiddenEdgeViolations(scan.Edges, forbiddenModuleEdges)
	if len(violations) == 0 {
		return
	}
	// 同一條邊只印前 5 筆證據，避免錯誤訊息淹沒真正的第一因
	shown := map[string]int{}
	var lines []string
	for _, v := range violations {
		key := v.From + "→" + v.To
		shown[key]++
		if shown[key] <= 5 {
			lines = append(lines, "  "+key+"：	"+v.Detail)
		}
	}
	t.Fatalf("偵測到 %d 筆禁止的跨模組參照（W1 1.10–1.12 拆掉的環不得回潮）：\n%s",
		len(violations), strings.Join(lines, "\n"))
}

// TestForbiddenEdgeComparatorMutation 比對純函式的突變自檢。
//
// **這是本守衛「會紅得起來」的證明**：掃描側需要完整 module 故無法造樣本樹，
// 判定側則可以——餵一份含三條禁止邊的合成參照表，函式必須逐條挑出；
// 餵一份只含允許邊的表，必須零命中。任一方向失效，主測試的「零違規」即無意義。
func TestForbiddenEdgeComparatorMutation(t *testing.T) {
	violating := []moduleEdge{
		{From: "keyvault", To: "identity", Detail: "合成：4.9 環回潮"},
		{From: "keyvault", To: "audit", Detail: "合成：4.10 環回潮"},
		{From: "policy", To: "audit", Detail: "合成：4.11 環回潮"},
		{From: "audit", To: "keyvault", Detail: "合成：允許的反向邊（蓋章需 km）"},
		{From: "audit", To: "policy", Detail: "合成：允許的反向邊（讀政策）"},
		{From: "keyvault", To: "keyvault", Detail: "合成：同模組不計"},
	}
	got := forbiddenEdgeViolations(violating, forbiddenModuleEdges)
	if len(got) != 3 {
		t.Fatalf("合成違規表應挑出 3 筆禁止邊，實得 %d 筆（%v）：比對函式已失效，"+
			"主測試的零違規不成立", len(got), got)
	}
	wantKeys := map[string]bool{"keyvault→audit": true, "keyvault→identity": true, "policy→audit": true}
	for _, v := range got {
		key := v.From + "→" + v.To
		if !wantKeys[key] {
			t.Fatalf("挑出非預期的邊 %s", key)
		}
		delete(wantKeys, key)
	}
	if len(wantKeys) != 0 {
		t.Fatalf("下列禁止邊未被挑出：%v", wantKeys)
	}

	clean := []moduleEdge{
		{From: "audit", To: "keyvault", Detail: "合成"},
		{From: "identity", To: "policy", Detail: "合成"},
		{From: "session", To: "audit", Detail: "合成"},
	}
	if got := forbiddenEdgeViolations(clean, forbiddenModuleEdges); len(got) != 0 {
		t.Fatalf("允許邊被誤判為違規：%v", got)
	}
}
