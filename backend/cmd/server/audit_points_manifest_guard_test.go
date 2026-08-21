package main

// 審計產生點 manifest 雙向完備性守衛（modular-architecture W1 任務 1.2）。
//
// **為什麼需要這個守衛**：模組化重構要把散落各處的審計寫入收口成兩個 sink 變體
// （TxSink 同步／參與呼叫方交易／回 error；AsyncSink 非同步／fire-and-forget）。
// 其中一部分寫入是**交易內 fail-close**（審計寫失敗 → 業務操作整筆回滾），若被
// 誤分派成 AsyncSink，fail-close 會靜默退化為 fail-open——而且測試會**更綠**
// （原本會失敗的路徑變成永遠成功）。編譯器對此零保護。
//
// 因此在動任何介面之前，先把「現實中有哪些審計產生點」凍結成一份 manifest，
// 並以本守衛雙向釘住：
//
//	方向 1（manifest → 現實）：manifest 每一列的 file:line 必須真的存在一個產生點。
//	方向 2（現實 → manifest）：現實中每一個產生點都必須在 manifest 內。
//
// **方向 2 才是關鍵**（比照 internal/service/post_unseal_guard_test.go 的
// aadStampedEntryFiles 反向完備性紀律）：只驗方向 1 的守衛，在有人新增一個未登記
// 的審計寫入點時仍然全綠。
//
// ── 掃描範圍的誠實邊界 ──────────────────────────────────────────────────
//
// 「審計產生點」定義＝**產生一筆 audit_logs 資料列**的程式碼位置。故本守衛不涵蓋：
//   - 非 INSERT 的 audit_logs 存取（保留期硬刪的原生 SQL、migration 的 DDL/回填）；
//   - 非 DB 落地的降級路徑（AuditLogService 的 JSONL fallback）；
//   - 其他審計性資料表（command_alerts／session_commands／clipboard_events 等）。
//
// 這三類在 manifest 的 §1.2 逐條列出並說明為何不進 sink，但**不在本守衛的斷言範圍
// 內**——寫在這裡是為了讓範圍缺口是明載的，而不是靠讀者自己發現。

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// ── 受管常數 ──────────────────────────────────────────────────────────────

// auditPointManifestEnv manifest 路徑的環境覆寫鍵（比照 APIERROR_LOCALE_DIR 的作法）
const auditPointManifestEnv = "AUDIT_POINT_MANIFEST"

// auditPointManifestRelPath manifest 相對「change 目錄」的路徑。
//
// **單一來源，無副本**：權威檔只有 repo 根的 openspec/ 下這一份。docker 掛載點、host 直跑與
// 歸檔後（任意日期前綴）三種佈局的解析統一由 `openspecManifestPath` 承擔，見
// `openspec_manifest_path_test.go` 的檔頭說明（含「找不到即 Fatal」「找到複本即 Fatal」
// 兩條刻意保留的 fail-close）。不存在人讀版／機器版分家。
const auditPointManifestRelPath = "research/manifest-audit-points.md"

// auditPointModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
// 以 module 身分而非「往上跳幾層」定位掃描根——後者在檔案搬家時會靜默指到別處
// （R4 已實證兩處現有守衛有此假綠孔）。
const auditPointModulePath = "github.com/custodexa/backend"

// minScannedGoFiles 掃描檔數下限：防止掃描根失真或走訪邏輯壞掉時「掃到 0 個檔＝
// 0 個產生點＝與 manifest 對不上以外全綠」。取現況 291 的保守下界。
const minScannedGoFiles = 250

// minAuditPointSites 產生點數量下限：manifest 與現實同時被清空時仍須轉紅。
const minAuditPointSites = 50

// auditRecordFuncs model 層三個 exported 審計函式：它們**不是 GORM hook**，
// 由 service 層顯式呼叫並吃呼叫方的 tx，是編譯器與型別引數守衛都看不見的寫入面。
var auditRecordFuncs = map[string]bool{
	"RecordAssetChange":        true,
	"RecordAssetNodeChange":    true,
	"RecordAssetAccountChange": true,
}

// assetAuditWriteFuncs asset 模組收口後的三個審計產生 helper（W6 6.1／6.2）。
//
// **為何判準必須延伸到這裡**（沿 W4 的同一條教訓）：6.1 把 11 個 T-2 呼叫點自
// `model.RecordAsset*Change(tx, …)` 改為呼叫本包內的 helper，helper 才建構
// `port.AuditEvent` 並交給 `port.WriteInTx`。若判準停在「`model.` 限定的呼叫」，
// **11 個交易內產生點會整批自掃描面消失**，而 manifest 這一側仍登記著它們——
// 結果是雙向完備性在「現實→manifest」那一側零違規、在「manifest→現實」那一側
// 整批誤報，最終誘使有人把 11 列刪掉了事。判準隨收口形態延伸，涵蓋面才守得住。
//
// helper 為未匯出識別字，呼叫形態是裸 `*ast.Ident`（同包呼叫），故與上表分開判。
var assetAuditWriteFuncs = map[string]bool{
	"writeAssetAccountAudit":    true,
	"writeAssetChangeAudit":     true,
	"writeAssetNodeChangeAudit": true,
}

// auditPointSkipDirs 不走訪的目錄名
var auditPointSkipDirs = map[string]bool{
	"vendor": true, ".git": true, "testdata": true,
	"node_modules": true, "tmp": true, "bin": true, "logs": true, "data": true,
}

// ── 掃描結果型別 ──────────────────────────────────────────────────────────

type auditPointKind string

const (
	kindAuditLogLit   auditPointKind = "AuditLog"      // model.AuditLog 具名欄位字面量（直寫路徑與 hook 內落地）
	kindAuditEntryLit auditPointKind = "AuditLogEntry" // audit.AuditLogEntry 字面量（走 AuditLogService.Log）
	kindRecordCall    auditPointKind = "RecordCall"    // model.RecordAsset*Change 呼叫點
	// kindAuditEventLit 收口後的產生點形態（W4）：`port.AuditEvent{...}` 或
	// `gatewayapi.AuditEvent{...}` 複合字面量。
	//
	// **為何必須納入判準**：4.4／4.6 收口把「建構審計列」與「落地」分了家——收口後的
	// 產生點不再建構 model.AuditLog，而是建構傳輸形狀交給 sink。若判準停在舊三條，
	// 那五個交易內 fail-close 點會**整批從掃描面上消失**，manifest 反向斷言不再看得見
	// 它們，而 sink 內部那唯一一個 model.AuditLog 字面量會讓「產生點總數」看起來只是
	// 少了幾個——正是本波要防的「收口即失明」。判準隨收口形態延伸，涵蓋面才守得住。
	kindAuditEventLit auditPointKind = "AuditEvent"
)

type auditPointSite struct {
	File string // 相對 module 根，slash 分隔
	Line int
	Kind auditPointKind

	// Tx 交易歸屬的**機器判定**（資料流判定見 audit_points_tx_dataflow_test.go）。
	Tx txVerdict
	// TxReason 判定的理由類別（受管閉集合；Indeterminate 時同時是允許清單的綁定鍵）。
	TxReason txReason
	// TxWhy 判定理由散文（錯誤訊息用，含追溯到的 receiver 與來源）。
	TxWhy string
	// FuncLabel 最內層包覆函式標籤（允許清單的語法指紋之一）。
	FuncLabel string
}

func (s auditPointSite) key() string { return fmt.Sprintf("%s:%d", s.File, s.Line) }

// ── 掃描根與 manifest 定位 ────────────────────────────────────────────────

// auditPointModuleRoot 由本測試檔位置向上找 go.mod，並核對 module 路徑。
// 不用「Dir(Caller)/../..」的層數推算：那在守衛檔搬家時會靜默指到別處。
func auditPointModuleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if body, err := os.ReadFile(gomod); err == nil {
			want := "module " + auditPointModulePath
			found := false
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q："+
					"掃描根定位錨點失效，守衛可能正在掃錯的樹", gomod, auditPointModulePath)
			}
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 一路向上找不到 go.mod，掃描根無從定位", filepath.Dir(self))
		}
		dir = parent
	}
}

// auditPointManifestPath 解析 manifest 的實際路徑。
//
// 依序嘗試：環境覆寫 → 容器掛載點（/app/testdata/openspec/…）→ host 的 repo 根
// （module 根的上一層 openspec/…）。三條路徑指向同一份權威檔。
//
// **找不到即 t.Fatal，絕不 skip**：本專案已實證過 gated 測試永久 skip 的假綠形態
// （CI 從未設 TEST_PG_DSN）。守衛沒跑到就是沒守到，必須當場紅。
func auditPointManifestPath(t *testing.T, moduleRoot string) string {
	t.Helper()
	// env 覆寫優先（比照 APIERROR_LOCALE_DIR）：指到不存在的檔時回退掃描，
	// 由掃描端的 Fatal 承擔「一份都找不到」的 fail-close。
	if override := os.Getenv(auditPointManifestEnv); override != "" {
		if _, err := os.Stat(override); err == nil {
			return override
		}
		t.Logf("%s=%s 指向的檔案不存在，回退為 openspec 掃描解析", auditPointManifestEnv, override)
	}
	return openspecManifestPath(t, moduleRoot, openspecChangeDirName, auditPointManifestRelPath)
}

// ── 現實側掃描 ────────────────────────────────────────────────────────────

// scanAuditPointSites 以 AST 掃出全模組（非測試碼）的審計產生點。
//
// 判準（三條，皆為型別／識別字精確比對，不是字串 grep）：
//  1. `model.AuditLog{...}`（在 model 包內為 `AuditLog{...}`）**且至少帶一個欄位**——
//     空字面量 `&model.AuditLog{}` 是 GORM 的型別標記（Model()／AutoMigrate），不產生列。
//  2. `audit.AuditLogEntry{...}`（在 audit 包內為 `AuditLogEntry{...}`）且至少帶一個欄位。
//  3. `port.AuditEvent{...}`／`gatewayapi.AuditEvent{...}`（W4 收口後的形態）且至少帶一個欄位。
//  3. 呼叫 `model.RecordAssetChange` ／ `RecordAssetNodeChange` ／ `RecordAssetAccountChange`。
func scanAuditPointSites(t *testing.T, root string) ([]auditPointSite, int) {
	sites, scanned, _ := scanAuditPointSitesIndexed(t, root)
	return sites, scanned
}

// scanAuditPointSitesIndexed 同上，另回傳模組級索引（交易歸屬守衛要用它的自檢事實）。
//
// 兩趟：先解析全模組建索引（tx 逃逸不變式、同包函式表、AuditLogEntry 落地面自檢），
// 再逐檔找產生點並以資料流判定交易歸屬。一趟做不到——判定需要跨檔的模組級事實。
func scanAuditPointSitesIndexed(t *testing.T, root string) ([]auditPointSite, int, *txIndex) {
	t.Helper()
	files, scanned := parseModuleFiles(t, root)
	if scanned < minScannedGoFiles {
		t.Fatalf("只掃到 %d 個非測試 .go 檔（下限 %d）："+
			"掃描根或走訪邏輯已失真，本守衛將在縮水的範圍上假綠", scanned, minScannedGoFiles)
	}
	idx := buildTxIndex(files)

	var sites []auditPointSite
	for _, pf := range files {
		assertGormImportUnaliased(t, pf.Rel, pf.File)
		ast.Inspect(pf.File, func(n ast.Node) bool {
			pos, kind, ok := auditSiteAt(n, pf.Pkg)
			if !ok {
				return true
			}
			verdict, reason, why := idx.verdictAt(pf, n, kind)
			sites = append(sites, auditPointSite{
				File: pf.Rel, Line: pf.Fset.Position(pos).Line, Kind: kind,
				Tx: verdict, TxReason: reason, TxWhy: why,
				FuncLabel: idx.innermostLabel(pf, pos),
			})
			return true
		})
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	return sites, scanned, idx
}

// auditSiteAt 三條判準的單一實作（掃描與交易歸屬判定共用，
// 避免兩處判準漂移後其中一處靜默失效）。
func auditSiteAt(n ast.Node, pkg string) (token.Pos, auditPointKind, bool) {
	switch node := n.(type) {
	case *ast.CompositeLit:
		if len(node.Elts) == 0 {
			return 0, "", false
		}
		switch typeNameOf(node.Type, pkg) {
		case "model.AuditLog":
			return node.Pos(), kindAuditLogLit, true
		case "audit.AuditLogEntry":
			return node.Pos(), kindAuditEntryLit, true
		case "port.AuditEvent", "gatewayapi.AuditEvent":
			// port.AuditEvent 是 gatewayapi.AuditEvent 的型別別名，兩種寫法都要認：
			// 交易內收口點寫 port.AuditEvent（同時 import 了 port），
			// AsyncSink 收口點寫 gatewayapi.AuditEvent。
			return node.Pos(), kindAuditEventLit, true
		}
	case *ast.CallExpr:
		// 收口後的形態（W6 6.1）：同包未匯出 helper，裸 Ident 呼叫
		if id, ok := node.Fun.(*ast.Ident); ok {
			if assetAuditWriteFuncs[id.Name] {
				return node.Pos(), kindRecordCall, true
			}
			return 0, "", false
		}
		// 收口前的形態：model.RecordAsset*Change（函式已於 W6 6.2 刪除，
		// 判準保留為復辟偵測——真被加回來，這裡會把呼叫點抓成未登記產生點）
		sel, ok := node.Fun.(*ast.SelectorExpr)
		if !ok {
			return 0, "", false
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || x.Name != "model" || !auditRecordFuncs[sel.Sel.Name] {
			return 0, "", false
		}
		return node.Pos(), kindRecordCall, true
	}
	return 0, "", false
}

// typeNameOf 把複合字面量的型別運算式正規化為 "pkg.Type"。
// 同包內的裸 Ident 以該檔所屬套件名補齊，故 model 包內的 `AuditLog{}` 與外部的
// `model.AuditLog{}` 收斂到同一個名字。
func typeNameOf(expr ast.Expr, pkg string) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return pkg + "." + e.Name
	case *ast.SelectorExpr:
		if x, ok := e.X.(*ast.Ident); ok {
			return x.Name + "." + e.Sel.Name
		}
	}
	return ""
}

// ── manifest 側解析 ───────────────────────────────────────────────────────

type manifestRow struct {
	ID      string
	File    string
	Line    int
	Kind    auditPointKind
	Variant string
	// Wave 落地波次欄（4.4b）：TxSink 點必須有主，否則會靜默停在舊形態。
	Wave    string
	DocLine int // manifest 檔內行號，錯誤訊息用

	// TxBase／TxNote 「呼叫方交易內」欄的兩段：括號前的判定值（是／否／自開交易）
	// 與括號內的限定註記（如「部分呼叫路徑」「機器不可判定」）。
	TxBase string
	TxNote string
	// Evidence 末欄（判定證據／備註），人工複核標記寫在此欄。
	Evidence string
}

func (r manifestRow) key() string { return fmt.Sprintf("%s:%d", r.File, r.Line) }

// parseAuditPointManifest 解析 manifest 的產生點總表。
//
// 只認「以 `| AP-` 開頭」的資料列，欄位順序＝
// ID | 產生點 file:line | 種類 | 呼叫方交易內 | fail-close? | 目標變體 | 落地波次 | 對應測試 | 證據
func parseAuditPointManifest(t *testing.T, path string) []manifestRow {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取 manifest %s 失敗（守衛不得在缺檔時跳過）: %v", path, err)
	}
	var rows []manifestRow
	for i, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "| AP-") {
			continue
		}
		cols := splitMarkdownRow(trimmed)
		if len(cols) < 6 {
			t.Fatalf("manifest 第 %d 行欄位不足（實得 %d，至少 6）: %s", i+1, len(cols), trimmed)
		}
		loc := stripBackticks(cols[1])
		idx := strings.LastIndex(loc, ":")
		if idx < 0 {
			t.Fatalf("manifest 第 %d 行的產生點欄不是 file:line 形態: %q", i+1, loc)
		}
		lineNo := 0
		if _, scanErr := fmt.Sscanf(loc[idx+1:], "%d", &lineNo); scanErr != nil || lineNo <= 0 {
			t.Fatalf("manifest 第 %d 行的行號無法解析: %q", i+1, loc)
		}
		base, note := splitTxCell(stripMarkdownEmphasis(cols[3]))
		evidence := ""
		if len(cols) >= 9 {
			evidence = cols[8]
		}
		rows = append(rows, manifestRow{
			ID:       stripBackticks(cols[0]),
			File:     loc[:idx],
			Line:     lineNo,
			Kind:     auditPointKind(stripBackticks(cols[2])),
			Variant:  stripMarkdownEmphasis(cols[5]),
			Wave:     waveCell(cols),
			DocLine:  i + 1,
			TxBase:   base,
			TxNote:   note,
			Evidence: evidence,
		})
	}
	return rows
}

func splitMarkdownRow(s string) []string {
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimSuffix(s, "|")
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func stripBackticks(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "`", ""))
}

// stripMarkdownEmphasis 去掉粗體標記與反引號（manifest 用 **…** 強調關鍵分派）
func stripMarkdownEmphasis(s string) string {
	return stripBackticks(strings.ReplaceAll(s, "*", ""))
}

// ── 受管的變體詞彙 ────────────────────────────────────────────────────────

// auditPointVariants 合法的目標變體。**閉集合**：新增第三種 sink 或改名時必須
// 同步這裡，否則錯字（如 "Asyncsink"）會讓某一列的分派靜默失去意義。
var auditPointVariants = map[string]bool{
	"TxSink":    true,
	"AsyncSink": true,
	"維持 hook":   true,
	"不進 sink":   true,
}

// ── 守衛本體 ──────────────────────────────────────────────────────────────

// TestAuditPointManifestIsBidirectionallyComplete 雙向完備性。
func TestAuditPointManifestIsBidirectionallyComplete(t *testing.T) {
	root := auditPointModuleRoot(t)
	sites, scanned := scanAuditPointSites(t, root)
	if len(sites) < minAuditPointSites {
		t.Fatalf("只掃到 %d 個審計產生點（下限 %d，掃描 %d 檔）："+
			"判準或掃描範圍已失真", len(sites), minAuditPointSites, scanned)
	}

	manifestPath := auditPointManifestPath(t, root)
	rows := parseAuditPointManifest(t, manifestPath)
	if len(rows) < minAuditPointSites {
		t.Fatalf("manifest（%s）只有 %d 列（下限 %d）：manifest 被清空時守衛仍須轉紅",
			manifestPath, len(rows), minAuditPointSites)
	}

	byKey := map[string]auditPointSite{}
	for _, s := range sites {
		byKey[s.key()] = s
	}
	inManifest := map[string]manifestRow{}
	seenID := map[string]string{}
	for _, r := range rows {
		if prev, dup := inManifest[r.key()]; dup {
			t.Errorf("manifest 重複登記 %s（%s 與 %s）：穩定 ID 與產生點須一對一",
				r.key(), prev.ID, r.ID)
		}
		if prevKey, dup := seenID[r.ID]; dup {
			t.Errorf("manifest 的穩定 ID %s 重複使用（%s 與 %s）：ID 一經指派不得重指",
				r.ID, prevKey, r.key())
		}
		inManifest[r.key()] = r
		seenID[r.ID] = r.key()
	}

	// 方向 1：manifest → 現實
	for _, r := range rows {
		site, ok := byKey[r.key()]
		if !ok {
			t.Errorf("[manifest→現實] %s 登記的 %s 在現實中不存在審計產生點"+
				"（manifest L%d）：程式碼已移動或該列已過時，須逐條更新",
				r.ID, r.key(), r.DocLine)
			continue
		}
		if r.Kind != site.Kind {
			t.Errorf("[manifest→現實] %s（%s）種類登記為 %q，實際為 %q",
				r.ID, r.key(), r.Kind, site.Kind)
		}
		if !auditPointVariants[r.Variant] {
			t.Errorf("[manifest→現實] %s（%s）的目標變體 %q 不在受管詞彙 %v 內："+
				"未分派或拼錯的產生點正是本 manifest 要防的事",
				r.ID, r.key(), r.Variant, keysOf(auditPointVariants))
		}
	}

	// 方向 2：現實 → manifest（**關鍵反向斷言**）
	//
	// 沒有這段，任何人新增一個未登記的審計寫入點，守衛都會全綠——而未登記的寫入點
	// 在 sink 收口時就是會被漏掉、或被誤分派成 AsyncSink 的那一個。
	var missing []string
	for _, s := range sites {
		if _, ok := inManifest[s.key()]; !ok {
			missing = append(missing, fmt.Sprintf("%s（%s）", s.key(), s.Kind))
		}
	}
	if len(missing) > 0 {
		t.Errorf("[現實→manifest] 下列 %d 個審計產生點未登記於 manifest：\n  %s\n"+
			"新增審計寫入點 SHALL 同步登記（含是否在呼叫方交易內、目標變體）——"+
			"交易內 fail-close 的點若被漏登或誤標 AsyncSink，回滾語義會靜默退化為 fail-open，"+
			"且失敗路徑變成功路徑，測試反而更綠。manifest：%s",
			len(missing), strings.Join(missing, "\n  "), manifestPath)
	}
}

// TestAuditPointTxSitesAreDispatchedToTxSink 交易內產生點的變體不變式。
//
// 「呼叫方交易內＝是」的產生點吃的是呼叫方的 *gorm.DB，AsyncSink 的簽名根本表達
// 不了；把它標成 AsyncSink 即是把 fail-close 改成 fail-open。這條單獨成測，是為了
// 讓「誤標」這個最嚴重的錯誤形態有自己的失敗訊息，而不是混在完備性訊息裡。
func TestAuditPointTxSitesAreDispatchedToTxSink(t *testing.T) {
	root := auditPointModuleRoot(t)
	manifestPath := auditPointManifestPath(t, root)
	body, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("讀取 manifest %s 失敗: %v", manifestPath, err)
	}
	txRows := 0
	for i, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "| AP-") {
			continue
		}
		cols := splitMarkdownRow(trimmed)
		if len(cols) < 6 {
			continue
		}
		inTx := stripMarkdownEmphasis(cols[3])
		if !strings.HasPrefix(inTx, "是") {
			continue
		}
		txRows++
		if variant := stripMarkdownEmphasis(cols[5]); variant != "TxSink" {
			t.Errorf("%s（%s，manifest L%d）標為「呼叫方交易內＝%s」卻分派 %q："+
				"交易內寫入必須走 TxSink（WriteInTx(tx, ev) error）。"+
				"分派成 AsyncSink 會讓 fail-close 靜默退化為 fail-open，且失敗路徑變成功路徑、測試更綠",
				stripBackticks(cols[0]), stripBackticks(cols[1]), i+1, inTx, variant)
		}
	}
	// 下界：交易內產生點被整批刪掉／欄位改名時，這條斷言不得因掃到 0 列而假綠。
	if txRows < 15 {
		t.Fatalf("manifest 只有 %d 列標為「呼叫方交易內＝是」（下限 15）："+
			"欄位順序或標記詞彙已變動，本斷言正在空集合上假綠", txRows)
	}
}

// waveCell 取落地波次欄（第 7 欄；欄數不足時回空字串由呼叫端判定）。
func waveCell(cols []string) string {
	if len(cols) < 7 {
		return ""
	}
	return stripMarkdownEmphasis(cols[6])
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// auditPointWaveRe 落地波次欄的合法形態（W1…W10，可帶括號的任務編號）。
var auditPointWaveRe = regexp.MustCompile(`^W(1|2|3|4|5|6|7b?|8|9|10)(（[^）]*）|／.*)?$`)

// minTxSinkWaveRows 受本守衛檢查的 TxSink 列下限（現況 19，取 15）。
const minTxSinkWaveRows = 15

// TestTxSinkPointsAllHaveLandingWave 4.4b：每個 TxSink 點都必須有指定的落地波次。
//
// # 為什麼這件事需要機器管
//
// tasks.md 4.4b 的緣由正是一次人工清點失誤：正文寫「W4 的 5 條＋W6 的 11 處＝16」，
// 而 manifest 實測 19 點——差的 3 點（AP-22／26／27，`RecordAsset*Change` 的落地本體）
// 其實已由 6.2 涵蓋，是**正文漏算**而非真的無主。但那次差異靠的是有人去數；
// 下一次新增 TxSink 點時，「忘了指定波次」不會有任何東西轉紅，而漏掉的那一點
// 會停在舊形態上——fail-close 不會退化，但也永遠不會被收口，且沒有人知道。
//
// 本守衛把「每個 TxSink 點都有主」變成機器事實。
func TestTxSinkPointsAllHaveLandingWave(t *testing.T) {
	root := auditPointModuleRoot(t)
	rows := parseAuditPointManifest(t, auditPointManifestPath(t, root))

	checked := 0
	for _, r := range rows {
		if r.Variant != "TxSink" {
			continue
		}
		checked++
		if r.Wave == "" {
			t.Errorf("%s（%s，manifest L%d）分派 TxSink 但落地波次欄為空："+
				"沒有指定波次的收口點不會被任何一波認領，會靜默停在舊形態",
				r.ID, r.key(), r.DocLine)
			continue
		}
		if !auditPointWaveRe.MatchString(r.Wave) {
			t.Errorf("%s（%s，manifest L%d）的落地波次 %q 不是合法形態（W1…W10，可帶括號任務編號）："+
				"自由字串會讓「有沒有主」變成讀者的主觀判斷", r.ID, r.key(), r.DocLine, r.Wave)
		}
	}
	if checked < minTxSinkWaveRows {
		t.Fatalf("只檢查到 %d 個 TxSink 列（下限 %d）：欄位順序或變體詞彙已變動，本斷言正在空集合上假綠",
			checked, minTxSinkWaveRows)
	}
	t.Logf("4.4b 覆蓋完整性：%d 個 TxSink 點全部有指定落地波次", checked)
}
