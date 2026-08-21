package main

// 審計產生點「呼叫方交易內」欄的機器驗證守衛（W1 對抗 F1 的修補，2026-08-09 依
// codex 外審 C1/C2/C3 重寫判定與豁免紀律）。
//
// 本檔＝守衛本體（雙向比對、允許清單、不變式）；判定邏輯在
// `audit_points_tx_dataflow_test.go`；產生點掃描在 `audit_points_manifest_guard_test.go`。
//
// **為什麼要有這一段**：manifest 的「呼叫方交易內」欄原本是純人工註記，從不與現實
// 比對。W1 fresh-context 對抗演練（發現編號 F1；演練紀錄歸檔於維護者的私有開發歷程，
// 未隨公開倉庫發佈）實證：把某一列
// **同時**翻成「否｜否｜AsyncSink」，雙向完備性與 TxSink 分派兩個守衛雙雙 PASS——
// 因為前者不看 tx 欄、後者只在 tx 欄＝是時才斷言。tx 欄＋變體協同翻轉不在原威脅模型內，
// 而它正是 fail-close 退化為 fail-open 的最短路徑。
//
// ── 三條硬不變式（缺一即為本守衛失守） ─────────────────────────────────
//
//	I1 雙向比對：機器判 TxBound 而 manifest 標「否」→ 紅；反之亦然。
//	I2 **Indeterminate 不得標 AsyncSink**（C1 核心指標）：機器證不出「不在交易內」的點
//	   若被 fire-and-forget 化，就是把未知當成安全。允許清單**不豁免這一條**——豁免只
//	   說明「人看過」，不足以支撐把未知寫入丟進 at-most-once 通道。
//	I3 豁免不得濫發（C3）：`isMU ⇒ 機器 verdict == Indeterminate`，且豁免須綁定
//	   file／最內層函式／機器給出的理由類別，並受條數上限節制。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"
)

// ── 受管的豁免登記 ────────────────────────────────────────────────────────

// auditPointTxUndeterminableMark manifest tx 欄的「機器不可判定」標記字面。
const auditPointTxUndeterminableMark = "機器不可判定"

// auditPointHumanReviewRe 人工複核標記：`[人工複核 YYYY-MM-DD]`。
// 日期只是「有人在某天看過」的錨點，**不是**豁免的依據——依據是下方 txExemption
// 的三段指紋（檔／函式／機器理由類別）必須與機器判定逐項吻合。
var auditPointHumanReviewRe = regexp.MustCompile(`\[人工複核 \d{4}-\d{2}-\d{2}\]`)

// txExemption 一筆機器不可判定豁免。三段指紋皆須與機器判定吻合，任一不符即紅：
// 程式碼一搬家（File／Func 變）或形態一改變（Reason 變），豁免立刻失效而非靜默沿用。
type txExemption struct {
	File   string   // 產生點所在檔（相對 module 根）
	Func   string   // 最內層包覆函式標籤（`(T).Method` 或自由函式名）
	Reason txReason // **機器自己給出的** Indeterminate 理由類別
	// TxBase 人工複核所認定的交易歸屬（manifest 交易欄括號**前**的值）。
	//
	// **W4 4.12b(a) 補上的第四段指紋**：在此之前，豁免列的交易欄可以在保留
	// 「機器不可判定」標記的前提下被任意翻轉（實測 `自開交易→是` 全綠），
	// 因為機器對這些列本來就說不出話、而其餘檢查只看標記在不在。
	// 把人工結論也釘進守衛，改 manifest 就必須同時改這裡——這正是 C3 對豁免的
	// 一貫要求（缺口必須在 PR diff 裡看得見），只是原本漏了這一欄。
	TxBase string
	Note   string // 人讀說明
}

// auditPointTxMachineUndeterminable 機器不可判定的列（ID → 指紋）。
//
// 這份清單住在守衛裡而不是只寫在 manifest：豁免必須同時改守衛程式碼，才在 PR diff
// 裡看得見。只改 manifest 就想把某列移出比對範圍，本守衛會紅。
//
// **豁免不是萬用鑰匙**：它只免除 I1 的雙向比對，不免除 I2（Indeterminate 不得 AsyncSink）。
var auditPointTxMachineUndeterminable = map[string]txExemption{
	"AP-43": {
		File: "internal/modules/audit/audit_log_service.go", Func: "(AuditLogService).logAt",
		Reason: reasonMultiConsumer, TxBase: "否",
		Note: "列在 logAt 內建構，落地分岔為 logChan 消費端與 writeToDatabase 批次，資料流無唯一落地點",
	},
	"AP-56": {
		File: "internal/modules/audit/seal_replay_sink.go", Func: "sealEventRow",
		Reason: reasonEscapesScope, TxBase: "自開交易",
		Note: "列由 sealEventRow 回傳給 SubmitSealReplayRows（:158 自開交易）落地",
	},
	"AP-57": {
		File: "internal/modules/audit/seal_replay_sink.go", Func: "sealAggregateRow",
		Reason: reasonEscapesScope, TxBase: "自開交易",
		Note: "列由 sealAggregateRow 回傳給同一落地入口",
	},
	// W4 4.3 新增：TxSink 落地本體。**這是本波唯一新增的豁免**，理由與 AP-56／57 同型
	//（列在 A 函式建構、回傳後才落地），且它本身就是 19 個 TxSink 點的落地實作——
	// 它的交易歸屬由呼叫端決定，不是它自己的性質。變體「不進 sink」滿足 I2。
	"AP-61": {
		File: "internal/modules/audit/tx_sink.go", Func: "auditRowOf",
		Reason: reasonEscapesScope, TxBase: "自開交易",
		Note: "列由 auditRowOf 回傳給 WriteInTx，以呼叫方傳入的 tx 落地",
	},
}

// maxTxMachineUndeterminable 豁免條數上限（W4 起 4；W1 為 3）。
//
// **本波調高 1 的理由必須被質問，故寫在這裡**：4.3 的 TxSink 落地器把 19 個交易內
// 產生點的 `model.AuditLog` 建構收攏到 `auditRowOf` 一處，該處的列回傳後才落地
// （escapes-scope）。收攏本身是本波的目的，但它確實製造了一列機器不可判定——
// 代價是這一列，回報是原本 5 個分散的 fail-close 點全部升級為機器可正面證明的
// `sink-tx-arg`（見 dump：五點皆 TxBound）。淨值為正，且新增的那一列變體是
// 「不進 sink」、由 4.12c 的 runtime backstop 從執行期覆蓋。
//
// **這個常數是 C3 的關鍵**：沒有它，允許清單可以靠「多列進豁免」把比對覆蓋率稀釋掉，
// 而每一列的失去保護都不必付出任何代價。要新增豁免就得在 PR diff 裡把這個數字調高，
// 那是一個必須被質問的動作。
const maxTxMachineUndeterminable = 4

// auditPointTxHumanQualified 機器判得出 TxBound、實際歸屬依**呼叫路徑**二分的列。
// 仍受雙向比對約束（是↔TxBound），但括號註記與人工複核標記是該列語義的權威。
var auditPointTxHumanQualified = map[string]string{
	"AP-50": "ldapDirectoryAuditLog 六條呼叫路徑二分：三條在 WithLDAPDirectoryLock 交易閉包內（fail-close）、" +
		"三條傳 s.db（fail-open）。機器只能判到 TxBound（W4 起理由類別為 sink-tx-arg），路徑二分屬人工權威",
}

// minTxBoundSites 機器判為 TxBound 的產生點數量下限（現況 19，取 15）。
// 判定邏輯壞掉時最可能的症狀是「一個都判不出」，那會讓本守衛在空集合上假綠。
const minTxBoundSites = 15

// minTxComparedRows 實際進入雙向比對的列數絕對下限。
const minTxComparedRows = 50

// ── 守衛本體 ──────────────────────────────────────────────────────────────

// TestAuditPointTxAttributionMatchesCode manifest 的「呼叫方交易內」欄 vs 資料流機器判定。
func TestAuditPointTxAttributionMatchesCode(t *testing.T) {
	root := auditPointModuleRoot(t)
	sites, _, idx := scanAuditPointSitesIndexed(t, root)
	manifestPath := auditPointManifestPath(t, root)
	rows := parseAuditPointManifest(t, manifestPath)

	assertMachineFactsIntact(t, idx)

	if n := len(auditPointTxMachineUndeterminable); n > maxTxMachineUndeterminable {
		t.Fatalf("機器不可判定豁免已達 %d 筆（上限 %d）：允許清單正在稀釋比對覆蓋。"+
			"要新增豁免必須同時調高 maxTxMachineUndeterminable，該動作在 PR diff 中必須被質問",
			n, maxTxMachineUndeterminable)
	}

	byKey := map[string]auditPointSite{}
	bound := 0
	for _, s := range sites {
		byKey[s.key()] = s
		if s.Tx == txBound {
			bound++
		}
	}
	if bound < minTxBoundSites {
		t.Fatalf("機器只判出 %d 個 TxBound 產生點（下限 %d，共掃到 %d 點）："+
			"交易歸屬判定已失真，本守衛將在近乎空集合上假綠", bound, minTxBoundSites, len(sites))
	}

	seenMU := map[string]bool{}
	seenQualified := map[string]bool{}
	compared := 0
	verdictCount := map[txVerdict]int{}

	for _, r := range rows {
		site, ok := byKey[r.key()]
		if !ok {
			continue // 該列 file:line 對不上現實，由雙向完備性守衛負責報錯
		}
		verdictCount[site.Tx]++
		exempt, isMU := auditPointTxMachineUndeterminable[r.ID]
		marked := strings.Contains(r.TxNote, auditPointTxUndeterminableMark)

		// ── I2：Indeterminate 不得 AsyncSink（允許清單不豁免這一條） ──
		if site.Tx == txIndeterminate && r.Variant == "AsyncSink" {
			t.Errorf("[交易歸屬] %s（%s，manifest L%d）機器判定為 Indeterminate（%s：%s），"+
				"manifest 卻分派 AsyncSink。\n"+
				"    資料流證不出這一列「不在呼叫方交易內」，把它 fire-and-forget 化就是把未知當成安全——"+
				"若它其實吃著呼叫方的 tx，fail-close 會靜默退化為 fail-open，且失敗路徑變成功路徑、測試反而更綠。\n"+
				"    要嘛改走 TxSink（保守側，最壞只是多一次同步寫入），"+
				"要嘛改程式碼讓落地路徑可被資料流追蹤（單一寫入點、句柄來源可證）。"+
				"**機器不可判定允許清單不豁免本條**：豁免只證明有人看過，不足以支撐把未知寫入丟進 at-most-once 通道",
				r.ID, r.key(), r.DocLine, site.TxReason, site.TxWhy)
		}

		// ── I3：豁免不得濫發 ──
		if marked && !isMU {
			t.Errorf("%s（%s，manifest L%d）在 manifest 自行標記「%s」，但守衛的允許清單無此列："+
				"豁免機器比對必須同時改守衛程式碼（PR diff 可見），不得只改 manifest 就把自己移出檢查範圍",
				r.ID, r.key(), r.DocLine, auditPointTxUndeterminableMark)
		}
		if isMU && !marked {
			t.Errorf("%s（%s，manifest L%d）列於守衛的機器不可判定清單，manifest 的交易欄卻未標「%s」："+
				"缺口必須在人讀的那一份上也看得見", r.ID, r.key(), r.DocLine, auditPointTxUndeterminableMark)
		}

		if isMU {
			seenMU[r.ID] = true
			assertExemptionFingerprint(t, r, site, exempt)
			requireHumanReview(t, r, auditPointTxUndeterminableMark)
			continue
		}

		if r.TxNote != "" {
			if _, ok := auditPointTxHumanQualified[r.ID]; !ok {
				t.Errorf("%s（%s，manifest L%d）的交易欄帶括號註記 %q，卻不在 auditPointTxHumanQualified："+
					"括號註記代表機器看不見的語義（如呼叫路徑二分），必須在守衛內登記並附人工複核",
					r.ID, r.key(), r.DocLine, r.TxNote)
			} else {
				seenQualified[r.ID] = true
				requireHumanReview(t, r, "機器只判得出 TxBound、實際歸屬依呼叫路徑")
				if site.Tx != txBound {
					t.Errorf("%s（%s，manifest L%d）登記於 auditPointTxHumanQualified（該清單的語義是"+
						"「機器判得出 TxBound、只有呼叫路徑二分屬人工權威」），機器實判為 %s（%s：%s）："+
						"人工限定不得用來覆蓋機器判不出來的列——那是機器不可判定，走另一份清單並受 I2 節制",
						r.ID, r.key(), r.DocLine, site.Tx, site.TxReason, site.TxWhy)
				}
			}
		}

		compared++
		manifestInTx := strings.HasPrefix(r.TxBase, "是")
		machineInTx := site.Tx == txBound

		if site.Tx == txIndeterminate {
			t.Errorf("%s（%s，manifest L%d）機器判定為 Indeterminate（%s：%s），卻不在機器不可判定清單："+
				"資料流對這一列說不出任何話，不得靜默當成已驗證。"+
				"登記豁免須附 file／函式／理由類別三段指紋，並調高 maxTxMachineUndeterminable",
				r.ID, r.key(), r.DocLine, site.TxReason, site.TxWhy)
			continue
		}
		if manifestInTx == machineInTx {
			continue
		}
		if machineInTx {
			t.Errorf("[交易歸屬] %s（%s，manifest L%d）manifest 標「呼叫方交易內＝%s」，"+
				"但機器判定為交易內：%s。\n"+
				"    這正是 fail-close 靜默退化為 fail-open 的入口——把交易內寫入標成非交易內，"+
				"就可以合法地把它分派成 AsyncSink（fire-and-forget、AuditLogEnabled 關閉即丟棄），"+
				"而回滾語義消失後失敗路徑會變成功路徑、測試反而更綠。\n"+
				"    要嘛改回「是」並分派 TxSink，要嘛先改程式碼讓它真的不吃呼叫方 tx。",
				r.ID, r.key(), r.DocLine, txCellText(r), site.TxWhy)
			continue
		}
		t.Errorf("[交易歸屬] %s（%s，manifest L%d）manifest 標「呼叫方交易內＝%s」，"+
			"但機器判定為非交易內（%s）：%s。\n"+
			"    虛報交易內會讓 sink 收口方去找一個不存在的 tx。",
			r.ID, r.key(), r.DocLine, txCellText(r), site.TxReason, site.TxWhy)
	}

	// 允許清單 → manifest 的反向完備：清單登記了卻在 manifest 找不到的列＝清單已過時。
	for id, ex := range auditPointTxMachineUndeterminable {
		if !seenMU[id] {
			t.Errorf("auditPointTxMachineUndeterminable 登記的 %s（%s）未在 manifest 中命中："+
				"清單已過時，請隨程式碼變動同步", id, ex.Note)
		}
	}
	for id, reason := range auditPointTxHumanQualified {
		if !seenQualified[id] {
			t.Errorf("auditPointTxHumanQualified 登記的 %s（%s）未在 manifest 中命中：清單已過時", id, reason)
		}
	}

	// 比對覆蓋下限：絕對值＋「豁免上限推導」雙軌，允許清單無法靠多列進豁免稀釋覆蓋。
	if want := len(rows) - maxTxMachineUndeterminable; compared < want || compared < minTxComparedRows {
		t.Fatalf("只有 %d 列進入交易歸屬比對（manifest 共 %d 列，扣掉至多 %d 筆豁免後應至少 %d 列，"+
			"絕對下限 %d）：豁免清單被撐大、解析失真或列對不上現實，本守衛已名存實亡",
			compared, len(rows), maxTxMachineUndeterminable, want, minTxComparedRows)
	}
	t.Logf("交易歸屬雙向比對：%d 列比對通過；機器判定分佈 TxBound=%d／Detached=%d／NotTxBound=%d／Indeterminate=%d；"+
		"機器不可判定 %d 列（上限 %d）、人工限定 %d 列（皆帶人工複核標記）；tx 逃逸 %d 筆",
		compared, verdictCount[txBound], verdictCount[txDetached], verdictCount[txNotBound],
		verdictCount[txIndeterminate], len(auditPointTxMachineUndeterminable), maxTxMachineUndeterminable,
		len(auditPointTxHumanQualified), len(idx.txEscapes))
}

// assertMachineFactsIntact 判定所依賴的模組級事實自檢：任何一項不成立時，
// 判定會整批降為 Indeterminate（不是靜默失效），但仍應當場說清楚為什麼。
func assertMachineFactsIntact(t *testing.T, idx *txIndex) {
	t.Helper()
	if !idx.entryTypeFound {
		t.Fatal("找不到 audit.AuditLogEntry 型別宣告：AuditLogEntry 形態的型別層結論無從成立，" +
			"該形態產生點會全數降為 Indeterminate。判定基礎已變，請先修判定再談比對")
	}
	if len(idx.txEscapes) > 0 {
		t.Errorf("偵測到 %d 筆交易句柄逃逸（tx 被存進 struct 欄位／包級變數／context）：\n  %v\n"+
			"struct 欄位來源不再能證明「非呼叫方交易」，相關產生點已全數降為 Indeterminate。"+
			"這正是盲區 B1 從「靜默」變成「機器可見」的地方——不是放寬判定，是把該列改走 TxSink 或拆掉逃逸",
			len(idx.txEscapes), idx.txEscapes)
	}
	if len(idx.entryLandingBad) > 0 {
		t.Errorf("下列落地面同時吃 AuditLogEntry 與 *gorm.DB：%v\n"+
			"AuditLogEntry 的型別層結論（entry 不帶句柄 ⇒ 進不了呼叫方交易）就此失效，"+
			"該形態產生點已降為 Indeterminate", idx.entryLandingBad)
	}
}

// assertExemptionFingerprint 豁免的三段指紋比對（C3 的核心）。
func assertExemptionFingerprint(t *testing.T, r manifestRow, site auditPointSite, ex txExemption) {
	t.Helper()
	if site.Tx != txIndeterminate {
		t.Errorf("[豁免濫發] %s（%s，manifest L%d）登記於機器不可判定清單，但機器實判為 %s（%s：%s）："+
			"允許清單只能用在**機器真的判不出來**的列。機器判得出來卻進豁免，等於用一份人工清單把"+
			"已經有機器保護的列移出比對——這是 fail-close 退化最省事的路徑",
			r.ID, r.key(), r.DocLine, site.Tx, site.TxReason, site.TxWhy)
		return
	}
	if !txIndeterminateReasons[ex.Reason] {
		t.Errorf("%s 的豁免理由類別 %q 不在受管集合內：理由必須是機器會產出的類別，不是自由字串",
			r.ID, ex.Reason)
	}
	if ex.File != site.File {
		t.Errorf("[豁免指紋不符] %s 登記檔 %q，實際產生點在 %q：程式碼已搬家，豁免不得靜默沿用",
			r.ID, ex.File, site.File)
	}
	if ex.Func != site.FuncLabel {
		t.Errorf("[豁免指紋不符] %s 登記函式 %q，實際最內層包覆函式為 %q：形態已變，豁免不得靜默沿用",
			r.ID, ex.Func, site.FuncLabel)
	}
	if ex.TxBase == "" {
		t.Errorf("%s 的豁免未登記 TxBase：人工複核的交易歸屬結論必須釘在守衛內，"+
			"否則 manifest 的那一欄可以被任意翻轉而無人攔（W4 4.12b(a) 實證）", r.ID)
	} else if ex.TxBase != r.TxBase {
		t.Errorf("[豁免指紋不符] %s 登記交易歸屬 %q，manifest 交易欄卻是 %q："+
			"機器對本列說不出話，人工結論就是唯一權威——它一變就必須在守衛的 diff 裡看得見",
			r.ID, ex.TxBase, r.TxBase)
	}
	if ex.Reason != site.TxReason {
		t.Errorf("[豁免指紋不符] %s 登記理由類別 %q，機器實際給出 %q（%s）："+
			"豁免綁定的是「機器為什麼判不出來」，理由一變就代表落地形態變了，須重新人工複核",
			r.ID, ex.Reason, site.TxReason, site.TxWhy)
	}
}

func requireHumanReview(t *testing.T, r manifestRow, why string) {
	t.Helper()
	if !auditPointHumanReviewRe.MatchString(r.Evidence) {
		t.Errorf("%s（%s，manifest L%d）屬「%s」，末欄缺人工複核標記 `[人工複核 YYYY-MM-DD]`："+
			"機器保護不到的列必須有帶日期的人工權威錨點，否則「無機器驗證」會被誤讀成「已驗證」",
			r.ID, r.key(), r.DocLine, why)
	}
}

func txCellText(r manifestRow) string {
	if r.TxNote == "" {
		return r.TxBase
	}
	return r.TxBase + "（" + r.TxNote + "）"
}

// splitTxCell 把「呼叫方交易內」欄拆成判定值與括號註記。
func splitTxCell(cell string) (base, note string) {
	i := strings.Index(cell, "（")
	if i < 0 {
		return strings.TrimSpace(cell), ""
	}
	note = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(cell[i+len("（"):]), "）"))
	return strings.TrimSpace(cell[:i]), note
}

// ── 判定格序的自檢（C1 的核心指標，不依賴現實碼） ─────────────────────────

// TestTxVerdictLatticeIsConservative 用合成原始碼直接考判定器：**未知形態一律不得被判成
// NotTxBound**。這條比任何 manifest 突變都關鍵——manifest 突變只證明「現況這一列被守住」，
// 本測試證明的是**格序本身**：tx 存 struct 欄位、經 context、Begin() 後被閉包捕獲、
// 跨包轉手等形態，機器都必須落在 Indeterminate（或 TxBound），絕不落在 NotTxBound。
//
// 判定器一旦被「放寬成更好用」，這裡會立刻紅——而 manifest 比對不會，因為放寬後
// 現實與 manifest 仍然一致（兩邊一起錯）。
func TestTxVerdictLatticeIsConservative(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		forbid  txVerdict
		want    txVerdict // 空＝只驗 forbid
		wantWhy string
	}{
		{
			name: "tx 存進 struct 欄位後由該欄位落地",
			src: `package service
import "gorm.io/gorm"
type holder struct{ db *gorm.DB }
func run(root *gorm.DB) error {
	return root.Transaction(func(tx *gorm.DB) error {
		h := holder{db: tx}
		return h.write()
	})
}
func (h holder) write() error {
	entry := &model.AuditLog{Action: "x"}
	return h.db.Create(entry).Error
}`,
			forbid: txNotBound, want: txIndeterminate, wantWhy: "tx-escape",
		},
		{
			name: "tx 經 context 傳遞後由 context 取出落地",
			src: `package service
import ("context"; "gorm.io/gorm")
func run(root *gorm.DB, ctx context.Context) error {
	return root.Transaction(func(tx *gorm.DB) error {
		c := context.WithValue(ctx, "tx", tx)
		return write(c)
	})
}
func write(ctx context.Context) error {
	entry := &model.AuditLog{Action: "x"}
	return ctx.Value("tx").(*gorm.DB).Create(entry).Error
}`,
			forbid: txNotBound, want: txIndeterminate,
		},
		{
			name: "Begin() 取得的交易被閉包捕獲後落地",
			src: `package service
import "gorm.io/gorm"
func run(root *gorm.DB) {
	tx := root.Begin()
	func() {
		entry := &model.AuditLog{Action: "x"}
		tx.Create(entry)
	}()
	tx.Commit()
}`,
			forbid: txNotBound, want: txIndeterminate, wantWhy: "self-begin",
		},
		{
			name: "落地交給跨包函式（無法解析的轉手）",
			src: `package service
import "example.com/other"
func run() {
	other.Land(&model.AuditLog{Action: "x"})
}`,
			forbid: txNotBound, want: txIndeterminate, wantWhy: "unresolved-callee",
		},
		{
			name: "Session 引數非字面量：脫離與否證不出",
			src: `package service
import "gorm.io/gorm"
func run(tx *gorm.DB, sess *gorm.Session) error {
	entry := &model.AuditLog{Action: "x"}
	return tx.Session(sess).Create(entry).Error
}`,
			forbid: txNotBound, want: txIndeterminate,
		},
		{
			name: "receiver 有多處賦值，來源不唯一",
			src: `package service
import "gorm.io/gorm"
func run(a *gorm.DB, flag bool) error {
	h := a
	if flag {
		h = a.Session(&gorm.Session{})
	}
	entry := &model.AuditLog{Action: "x"}
	return h.Create(entry).Error
}`,
			forbid: txNotBound, want: txIndeterminate,
		},
		{
			name: "對照組：真正的脫離（NewDB: true）仍判 Detached",
			src: `package service
import "gorm.io/gorm"
func run(tx *gorm.DB) error {
	entry := &model.AuditLog{Action: "x"}
	return tx.Session(&gorm.Session{NewDB: true}).Create(entry).Error
}`,
			forbid: txNotBound, want: txDetached,
		},
		{
			name: "對照組：吃呼叫方 tx 仍判 TxBound",
			src: `package service
import "gorm.io/gorm"
func run(tx *gorm.DB) error {
	entry := &model.AuditLog{Action: "x"}
	return tx.Create(entry).Error
}`,
			forbid: txNotBound, want: txBound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, reason, why := verdictOfSynthetic(t, tc.src)
			if v == tc.forbid {
				t.Fatalf("**格序破口**：本形態被判成 %s（%s：%s）。"+
					"機器證不到來源時一律 Indeterminate，禁止預設 NotTxBound——"+
					"誤判 NotTxBound 會讓 fail-close 靜默退化為 fail-open 且測試更綠",
					v, reason, why)
			}
			if tc.want != "" && v != tc.want {
				t.Fatalf("判定為 %s（%s：%s），預期 %s", v, reason, why, tc.want)
			}
			if tc.wantWhy != "" && string(reason) != tc.wantWhy {
				t.Fatalf("理由類別為 %q，預期 %q（why=%s）", reason, tc.wantWhy, why)
			}
		})
	}
}

// verdictOfSynthetic 對一段合成原始碼中的唯一 `model.AuditLog{…}` 產生點做判定。
func verdictOfSynthetic(t *testing.T, src string) (txVerdict, txReason, string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("合成原始碼解析失敗: %v", err)
	}
	pf := newParsedFile("synthetic.go", f, fset)
	idx := buildTxIndex([]*parsedFile{pf})

	var v txVerdict
	var r txReason
	var why string
	found := 0
	ast.Inspect(pf.File, func(n ast.Node) bool {
		if _, kind, ok := auditSiteAt(n, pf.Pkg); ok {
			found++
			v, r, why = idx.verdictAt(pf, n, kind)
		}
		return true
	})
	if found != 1 {
		t.Fatalf("合成原始碼應恰有 1 個審計產生點，實得 %d（判定器的輸入前提已變）", found)
	}
	return v, r, why
}
