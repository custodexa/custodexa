package main

// 資產樞紐主體鍵（`audit_logs.asset_id`）守衛（auditor-workbench 任務 2.4）。
//
// # 為什麼需要這個守衛
//
// 稽核工作台的資產樞紐採**納入原則**：一個資產的時間軸＝
// 「所有 `audit_logs.asset_id` 非空的列」，而不是一份列舉動作的清單。這個選擇讓
// 日後新增的資產類動作自動涵蓋、不需回頭改工作台——**代價全部壓在寫入端**：
// 產生點沒填 `asset_id`，該事件就從資產樞紐上整個消失。
//
// 而這種消失是**靜默且不可察覺**的三重不可見：
//
//  1. 編譯器零保護——`AssetID` 是 `*uint`，不填就是 nil，型別完全合法。
//  2. 既有測試零保護——審計列照樣寫入、行為照樣正確，沒有任何斷言會紅。
//  3. **稽核端零可見**——調查員在資產樞紐上看到的是「這台機器上沒發生過這件事」，
//     與「這件事真的沒發生」在資料上無從分辨。漏填的代價不是少一列，是**誤導**。
//
// 故本守衛把「每一個審計產生點對資產主體鍵的處置」變成登記制：每個產生點都必須
// 在 `assetPivotRegistry` 有一筆明示的分類，且分類與現實碼**雙向**比對。
//
// # 三個受守衛的面
//
//	面 1（產生點側，本檔主體）：manifest 每一列 × 登記分類 × AST 實況三方對齊。
//	面 2（委派鏈）：`RecordCall` 產生點本身不建列，其 `asset_id` 由被呼叫的 helper
//	  賦值——守衛追到 helper 的產生點，要求它自己登記為「填 AssetID」。斷鏈即紅。
//	面 3（中介層覆寫側）：路徑上沒有資產 id 的端點（授權建立、候選處置…）靠 handler
//	  呼叫 `setAuditAssetID*` 補主體。這些注入點以「包覆函式標籤 → 呼叫次數」雙向釘住：
//	  刪掉任一注入即紅，新增未登記的注入亦紅。
//
// # 明載的邊界（不假裝涵蓋）
//
//   - 本守衛驗的是**欄位有沒有被賦值**，不驗**賦的值對不對**（填錯機器 AST 看不出來；
//     那是 `asset_subject_audit.go` 的「只在單一資產時才填」語義與人工複核的職權）。
//   - 「新增一個作用於資產的產生點卻整個忘了填」這件事，AST 無法從語義上判定該點是否
//     作用於資產。守衛給的是**兩道機械壓力**而非完備證明：(a) 新產生點必然缺登記 → 紅，
//     作者被迫做出分類決定；(b) 登記為「非資產類」但包覆函式作用域內握有資產識別字時，
//     必須在登記中顯式承認（`AssetInScope: true`）並寫下理由——「有資產在手卻不填」
//     從此是白紙黑字的決定，不再是沒人注意到的疏漏。
//   - 已知缺口以 `pivotGap` 明載並受條數上限節制，見 `maxAssetPivotGaps`。

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// ── 分類詞彙（閉集合）────────────────────────────────────────────────────

type assetPivotClass string

const (
	// pivotFilled 該產生點的事件／列字面量**必須**賦值 AssetID。
	pivotFilled assetPivotClass = "填 AssetID"
	// pivotDelegated 該產生點是 helper 呼叫，AssetID 由 helper 內的產生點賦值。
	pivotDelegated assetPivotClass = "委由 helper"
	// pivotNotAsset 非資產類事件，**不得**賦值 AssetID（反向亦釘住：填了就是把
	// 不相干的事件掛到某台機器上，是本守衛要消滅的假事件）。
	pivotNotAsset assetPivotClass = "非資產類"
	// pivotGap 屬資產類、現況未填的**已知缺口**。守衛斷言它「仍未填」——有人補上
	// 就轉紅，逼登記改為 pivotFilled（缺口不會被默默關掉也不會被默默擴大）。
	pivotGap assetPivotClass = "已知缺口"
)

var assetPivotClasses = map[assetPivotClass]bool{
	pivotFilled: true, pivotDelegated: true, pivotNotAsset: true, pivotGap: true,
}

// assetPivotEntry 一個產生點的資產主體鍵登記。
type assetPivotEntry struct {
	Class assetPivotClass
	// AssetInScope 包覆函式（最內層 FuncDecl）的作用域內是否出現資產識別字。
	// **只對 pivotNotAsset／pivotGap 有意義且雙向比對**：登記說沒有而現實有 → 紅
	//（有資產在手卻判非資產類，必須是明示的決定）；登記說有而現實沒有 → 也紅
	//（指紋過期，該重新檢視這列還成不成立）。
	AssetInScope bool
	// Why 分類理由。空字串不合法——沒有理由的分類等於沒有分類。
	Why string
}

// ── 登記表 ────────────────────────────────────────────────────────────────
//
// 鍵＝manifest 的穩定 AP ID（**不是 file:line**）。ID 一經指派不得重指，故程式碼
// 搬家、行號漂移都不會使本表失準；反之若以 file:line 為鍵，每次無關的編輯都會製造
// 假紅，最終誘使有人把守衛關掉。
var assetPivotRegistry = map[string]assetPivotEntry{
	// ── 資產類：直接賦值 ──
	"AP-04": {pivotFilled, false, "kubectl cp 成功留痕；檔案傳輸類的資產樞紐來源（檔案傳輸列）"},
	"AP-65": {pivotFilled, false, "kubectl cp 被傳輸閘擋下的 denied 留痕，與 AP-04 對稱"},
	"AP-14": {pivotFilled, false, "SFTP 上傳／下載／刪除／建目錄成功留痕（resource=file，資產樞紐讀 asset_id）"},
	"AP-21": {pivotFilled, false, "HTTP 中介層批次：resource=asset 時由 resource_id 推導，其餘由 handler 經 audit_asset_id 覆寫（見面 3）"},
	"AP-22": {pivotFilled, false, "資產帳號 CRUD／設預設／同步的落地本體；11 個 RecordCall 呼叫點全部委由本點"},
	"AP-23": {pivotFilled, false, "資產建立 GORM hook（AfterCreate）"},
	"AP-24": {pivotFilled, false, "資產更新 GORM hook（AfterUpdate）"},
	"AP-25": {pivotFilled, false, "資產刪除 GORM hook（AfterDelete）"},
	"AP-26": {pivotFilled, false, "資產欄位變更落地本體；AssetID 與 ResourceID 同源（刪除事件取 old.ID）"},
	"AP-27": {pivotFilled, false, "節點掛載搬移落地本體：主體是被搬的資產本身，非被掛的節點"},
	"AP-28": {pivotFilled, false, "FileTap 檔案傳輸留痕（成功與被拒共用的單一投遞實作）"},
	"AP-43": {pivotFilled, false, "AsyncSink 的 entry→列轉換：**全部非同步產生點的主體鍵都經此欄流過**，漏掉這一行即整條 async 路徑失去主體"},
	"AP-58": {pivotFilled, false, "傳輸同意（strict 模式）留痕"},
	"AP-59": {pivotFilled, false, "傳輸閘拒絕留痕"},
	"AP-61": {pivotFilled, false, "TxSink 的 event→列轉換：**全部 21 個交易內產生點的主體鍵都經此欄流過**"},
	"AP-69": {pivotFilled, false, "連線票證兌換拒絕留痕：「有人試圖連這台機器但被擋下」必須出現在資產樞紐上，" +
		"否則探測行為在資產視角完全不可見（同 AP-66 的論證）。票證本身不成立時目標未知，該情形寫 NULL 而非 0"},
	"AP-70": {pivotFilled, false, "唯讀觀看（監看／分享）加入留痕：稽核問題本身就是「誰看了這台機器上的操作」，" +
		"缺資產鍵時資產樞紐與「沒有人看過」不可分辨。與 AP-68（錄影取證，主體是錄影檔本體）刻意不同"},
	"AP-74": {pivotFilled, false, "剪貼簿單筆內容調閱的逐筆 fail-close 留痕：" +
		"剪貼簿事件不帶資產欄，主體經所屬會話解析後填入——「這台資產的剪貼簿內容被誰調閱過」" +
		"必須出現在資產樞紐上，缺鍵時與「沒有人調閱過」不可分辨（同 AP-70 的論證）"},
	"AP-62": {pivotFilled, false, "AsyncSink.Submit 的 event→entry 轉換：gateway 側產生點的主體鍵入口"},

	// ── 資產類：委由 helper ──（helper 內的產生點即 AP-22／26／27）
	"AP-30": {pivotDelegated, false, "帳號建立 → writeAssetAccountAudit"},
	"AP-31": {pivotDelegated, false, "帳號更新 → writeAssetAccountAudit"},
	"AP-32": {pivotDelegated, false, "帳號刪除 → writeAssetAccountAudit"},
	"AP-33": {pivotDelegated, false, "帳號設預設 → writeAssetAccountAudit"},
	"AP-34": {pivotDelegated, false, "資產內嵌憑證同步為預設帳號（建立分支）→ writeAssetAccountAudit"},
	"AP-35": {pivotDelegated, false, "同上（更新分支）→ writeAssetAccountAudit"},
	"AP-38": {pivotDelegated, false, "資產建立時的預設帳號留痕 → writeAssetAccountAudit"},
	"AP-39": {pivotDelegated, false, "資產建立時的節點掛載留痕 → writeAssetNodeChangeAudit"},
	"AP-40": {pivotDelegated, false, "資產改密（密碼）→ writeAssetAccountAudit"},
	"AP-41": {pivotDelegated, false, "資產更新時的節點掛載變更 → writeAssetNodeChangeAudit"},
	"AP-42": {pivotDelegated, false, "資產欄位更新 → writeAssetChangeAudit"},
	"AP-63": {pivotDelegated, false, "資產改密（私鑰輪替）→ writeAssetAccountAudit"},
	"AP-64": {pivotDelegated, false, "admin 清除候選憑證 → writeAssetAccountAudit"},

	// ── 已知缺口（受 maxAssetPivotGaps 節制；歸屬另案，見各列理由）──
	"AP-66": {pivotGap, true, "SFTP 被全域政策擋下的 denied 留痕未填 asset_id，與同檔成功路徑 AP-14 不對稱：" +
		"資產樞紐的檔案傳輸類只讀 asset_id，故「有人試圖從這台機器搬走什麼但被擋下」在資產樞紐上完全不可見，" +
		"與「沒有人試過」無從分辨。修法為一行（`AssetID: &aid`），但該檔屬 data-transfer-control 期 1 職權且正在改動中，" +
		"本 change 不越權動它——登記為缺口使其機器可見且不得擴大"},
	"AP-67": {pivotGap, true, "連線建立時的傳輸能力快照（resource=session）未填 asset_id：" +
		"該列是事後回答「那次連線當時允許什麼」的唯一來源，未填則不出現在資產樞紐的「對資產做的事」。" +
		"同屬 data-transfer-control 期 1 職權，理由同 AP-66"},

	// ── 非資產類 ──
	"AP-01": {pivotNotAsset, false, "封印狀態機留痕，主體是系統"},
	"AP-71": {pivotNotAsset, false, "認證中介層拒絕的匿名列與其聚合列：主體是來源位址與被拒的請求，" +
		"與任何資產無關——拒絕發生在認證階段，此時連「他想連哪一台」都尚未成立"},
	"AP-72": {pivotNotAsset, false, "OIDC 登入流程留痕（成功交換／MFA 待驗證／JIT 建帳號／各階段失敗）：" +
		"主體是身分與 provider，與任何資產無關——登入尚未選擇資產，同 AP-07 的類別"},
	"AP-73": {pivotNotAsset, false, "本地登入來源限流的聚合列：主體是來源位址與被擋下的請求數，" +
		"與任何資產無關——被擋下的請求連密碼比對都沒走到，遑論選擇資產。同 AP-71 的類別"},
	"AP-02": {pivotNotAsset, false, "KEK 切換補記，主體是金鑰"},
	"AP-03": {pivotNotAsset, false, "週期性存取複審建立，主體是複審單"},
	"AP-05": {pivotNotAsset, false, "稽核證據匯出，主體是匯出作業"},
	"AP-75": {pivotNotAsset, false, "匯出 job 發起／下載／拒絕留痕：主體是匯出作業，" +
		"與 AP-05 同判——篩選內的資產維度是匯出範圍的一部分，記在 error_msg 的篩選快照，不冒充事件主體鍵"},
	"AP-76": {pivotNotAsset, false, "worker 失權取消留痕：主體是匯出作業與申請者（details），與任何單一資產無關"},
	"AP-77": {pivotNotAsset, false, "單實例守衛事件：主體是本實例與持鎖工作階段（details），系統列，與任何資產無關"},
	"AP-78": {pivotNotAsset, false, "帳號自新來源位址登入的標記：主體是帳號與來源位址，登入本身不涉任何資產（建線點的同族告警才有資產，那一筆走 command_alerts 不走本表）"},
	"AP-79": {pivotNotAsset, false, "離機保管鏈事件的交易內落地點：主體是儲存設定世代與帳冊物件（resource=offsite_storage／session／audit_export），" +
		"擁有者是會話或匯出作業而非資產；錄影的資產維度由該會話列自身承擔，不在保管鏈事件上冒充主體鍵"},
	"AP-80": {pivotNotAsset, false, "離機保管鏈事件的非交易落地點：與 AP-79 同判——上傳結果、租約回收、保留到期與完整性拒付的主體都是帳冊物件與其擁有者"},
	"AP-06": {pivotNotAsset, false, "登入時偵測密碼不符政策，主體是使用者"},
	"AP-07": {pivotNotAsset, false, "登入留痕"},
	"AP-08": {pivotNotAsset, false, "token 更新留痕"},
	"AP-09": {pivotNotAsset, false, "改密留痕（使用者自身密碼）"},
	"AP-10": {pivotNotAsset, false, "MFA 事件留痕"},
	"AP-11": {pivotNotAsset, false, "告警審閱處置，主體是告警（告警自身的資產樞紐由 command_alerts.asset_id 承擔）"},
	"AP-12": {pivotNotAsset, false, "退役金鑰清理，主體是金鑰"},
	"AP-13": {pivotNotAsset, false, "安全政策變更，主體是全域政策"},
	"AP-15": {pivotNotAsset, false, "syslog 設定更新"},
	"AP-16": {pivotNotAsset, false, "syslog 設定更新（同函式第二處）"},
	"AP-17": {pivotNotAsset, false, "syslog 連線測試，主體是外送設定而非受管資產"},
	"AP-18": {pivotNotAsset, false, "傳輸清冊查詢留痕"},
	"AP-19": {pivotNotAsset, false, "帳號解鎖，主體是使用者"},
	"AP-20": {pivotNotAsset, false, "閒置停用豁免設定，主體是使用者"},
	"AP-29": {pivotNotAsset, false, "連線申請單狀態轉移，主體是申請單；申請所指資產由 access_requests.asset_id 承擔"},
	"AP-36": {pivotNotAsset, false, "節點建立／改名／搬移：ResourceID 是節點 id。一次影響其下全部資產，沒有單一主體可釘；" +
		"把 nodeID 填進 asset_id 等於宣稱事件發生在編號相同的那台資產上（假事件）"},
	"AP-37": {pivotNotAsset, false, "刪節點連動撤授權：主體是節點；被撤授權的逐資產事實在 authz 側各自留痕"},
	"AP-44": {pivotNotAsset, false, "LDAP 身分解析失敗，主體是身分來源"},
	"AP-45": {pivotNotAsset, false, "LDAP 傳輸層留痕"},
	"AP-46": {pivotNotAsset, false, "每日複審簽章，主體是複審紀錄"},
	"AP-47": {pivotNotAsset, false, "外部身分綁定變更，主體是使用者"},
	"AP-48": {pivotNotAsset, false, "外部登入嘗試批次留痕"},
	"AP-49": {pivotNotAsset, false, "閒置停用，主體是使用者"},
	"AP-50": {pivotNotAsset, false, "LDAP 目錄同步留痕"},
	"AP-51": {pivotNotAsset, false, "LDAP 種子遷移留痕"},
	"AP-52": {pivotNotAsset, false, "通知管道確認，主體是通知管道"},
	"AP-53": {pivotNotAsset, false, "OIDC 流程錯誤留痕"},
	"AP-54": {pivotNotAsset, false, "錄影失敗回報：主體是 session（sessions.asset_id 已承擔資產樞紐）"},
	"AP-55": {pivotNotAsset, false, "保留期清除留痕，主體是清除作業"},
	"AP-56": {pivotNotAsset, false, "封印期 journal 回灌的個別事件列，主體是封印事件"},
	"AP-57": {pivotNotAsset, false, "封印期 journal 回灌的合成聚合列，同上"},
	"AP-60": {pivotNotAsset, false, "刪使用者群組連動撤授權：主體是群組"},
	"AP-68": {pivotNotAsset, false, "以錄影 token 取走錄影本體的留痕：主體是連線（sessions.asset_id 已承擔資產樞紐），" +
		"與同型的 AP-54（錄影失敗回報）一致。resource_id 是連線 id，填進 asset_id 等於宣稱這件事發生在編號相同的那台資產上（假事件）"},
}

// maxAssetPivotGaps 已知缺口的條數上限。**要新增一個缺口就必須在 diff 裡把這個
// 數字調高**——缺口從此是需要有人簽字的動作，而不是安靜多一列登記。
const maxAssetPivotGaps = 2

// minAssetPivotFilled／minAssetPivotDelegated 下限：整批分類被翻成「非資產類」
// 時（那正是最省事的消紅手法），守衛不得因為空集合而假綠。
const (
	minAssetPivotFilled    = 12
	minAssetPivotDelegated = 10
)

// assetPivotFieldName 主體鍵在三種產生點形態上的共同欄位名。
// `port.AuditEvent`／`gatewayapi.AuditEvent`／`audit.AuditLogEntry`／`model.AuditLog`
// 四個型別都以此名承載資產主體鍵（sink 逐層原樣傳遞），故單一欄位名即可覆蓋全形態。
const assetPivotFieldName = "AssetID"

// ── 面 1＋面 2：產生點側 ──────────────────────────────────────────────────

// assetPivotSite 一個產生點的 AST 實況。
type assetPivotSite struct {
	Key       string // file:line
	Kind      auditPointKind
	Node      ast.Node
	FuncName  string // 最內層包覆 FuncDecl 名（委派鏈解析用）
	FuncLabel string // 同上帶接收者的可讀標籤（錯誤訊息用）
	HasField  bool   // 字面量是否賦值 AssetID
	FieldExpr string // 賦值運算式（錯誤訊息用）
	Callee    string // kindRecordCall 時的被呼叫 helper 名
	InScope   bool   // 包覆 FuncDecl 作用域內是否出現資產識別字
}

// scanAssetPivotSites 掃出全模組產生點的資產主體鍵實況。
//
// 判準沿用 `auditSiteAt`（與 manifest 雙向完備性守衛**同一個實作**）——判準若在此處
// 另寫一份，兩邊漂移後本守衛會在縮水的集合上假綠。
func scanAssetPivotSites(t *testing.T, root string) map[string]assetPivotSite {
	t.Helper()
	files, scanned := parseModuleFiles(t, root)
	if scanned < minScannedGoFiles {
		t.Fatalf("只掃到 %d 個非測試 .go 檔（下限 %d）：掃描根或走訪邏輯已失真", scanned, minScannedGoFiles)
	}
	out := map[string]assetPivotSite{}
	for _, pf := range files {
		ast.Inspect(pf.File, func(n ast.Node) bool {
			pos, kind, ok := auditSiteAt(n, pf.Pkg)
			if !ok {
				return true
			}
			decl := enclosingFuncDecl(pf.File, pos)
			site := assetPivotSite{
				Key:       fmt.Sprintf("%s:%d", pf.Rel, pf.Fset.Position(pos).Line),
				Kind:      kind,
				Node:      n,
				FuncName:  funcDeclName(decl),
				FuncLabel: funcDeclLabel(decl),
				InScope:   assetIdentInScope(decl),
			}
			if lit, ok := n.(*ast.CompositeLit); ok {
				if v := compositeLitField(lit, assetPivotFieldName); v != nil {
					site.HasField = true
					site.FieldExpr = exprSnippet(v)
				}
			}
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok {
					site.Callee = id.Name
				} else if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					site.Callee = sel.Sel.Name
				}
			}
			out[site.Key] = site
			return true
		})
	}
	return out
}

// TestAssetPivotRegistryCoversEveryAuditPoint 登記完備性（雙向）。
//
// 方向 1（manifest → 登記）：每一個審計產生點都必須有分類。**新增產生點卻沒登記
// 時這裡會紅**——那是本守衛唯一能對「新增資產類產生點忘了填 asset_id」施加的
// 前置壓力：作者被迫在此做出一次明示的分類決定。
//
// 方向 2（登記 → manifest）：登記表不得有孤兒列。過期的登記會讓人誤以為某個點
// 仍受守衛涵蓋，而它其實早已不存在。
func TestAssetPivotRegistryCoversEveryAuditPoint(t *testing.T) {
	root := auditPointModuleRoot(t)
	rows := parseAuditPointManifest(t, auditPointManifestPath(t, root))
	if len(rows) < minAuditPointSites {
		t.Fatalf("manifest 只有 %d 列（下限 %d）", len(rows), minAuditPointSites)
	}

	byID := map[string]manifestRow{}
	var missing []string
	for _, r := range rows {
		byID[r.ID] = r
		if _, ok := assetPivotRegistry[r.ID]; !ok {
			missing = append(missing, fmt.Sprintf("%s（%s）", r.ID, r.key()))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("[manifest→登記] 下列 %d 個審計產生點未在 assetPivotRegistry 分類：\n  %s\n"+
			"資產樞紐採納入原則（凡 asset_id 非空即納入），故每個產生點都必須明示"+
			"「填／委由 helper／非資產類／已知缺口」四者之一。漏填 asset_id 的資產類事件"+
			"在稽核調查中永遠不可見，且與「事情沒發生」無從分辨。",
			len(missing), strings.Join(missing, "\n  "))
	}

	var orphan []string
	counts := map[assetPivotClass]int{}
	for id, e := range assetPivotRegistry {
		if _, ok := byID[id]; !ok {
			orphan = append(orphan, id)
		}
		if !assetPivotClasses[e.Class] {
			t.Errorf("%s 的分類 %q 不在受管詞彙內：拼錯的分類會讓該列的斷言靜默失去意義", id, e.Class)
		}
		if strings.TrimSpace(e.Why) == "" {
			t.Errorf("%s 的登記沒有理由：沒有理由的分類等於沒有分類，日後無人能判斷它還成不成立", id)
		}
		counts[e.Class]++
	}
	if len(orphan) > 0 {
		sort.Strings(orphan)
		t.Errorf("[登記→manifest] assetPivotRegistry 有 %d 筆孤兒登記（manifest 無對應 AP ID）：%s\n"+
			"過期登記會讓人誤以為某產生點仍受涵蓋", len(orphan), strings.Join(orphan, "、"))
	}

	if counts[pivotFilled] < minAssetPivotFilled {
		t.Errorf("登記為「%s」者只有 %d 列（下限 %d）：分類被整批翻成非資產類是最省事的消紅手法，"+
			"本下限使它不可能悄悄發生", pivotFilled, counts[pivotFilled], minAssetPivotFilled)
	}
	if counts[pivotDelegated] < minAssetPivotDelegated {
		t.Errorf("登記為「%s」者只有 %d 列（下限 %d）", pivotDelegated, counts[pivotDelegated], minAssetPivotDelegated)
	}
	if counts[pivotGap] > maxAssetPivotGaps {
		t.Errorf("已知缺口 %d 列，超過上限 %d：新增缺口必須在同一份 diff 裡把 maxAssetPivotGaps 調高，"+
			"使「又少填一個主體鍵」成為需要簽字的動作", counts[pivotGap], maxAssetPivotGaps)
	}
	t.Logf("資產樞紐登記：填 %d／委由 helper %d／非資產類 %d／已知缺口 %d（共 %d 列）",
		counts[pivotFilled], counts[pivotDelegated], counts[pivotNotAsset], counts[pivotGap], len(assetPivotRegistry))
}

// TestAssetPivotRegistryMatchesCode 登記 × 現實碼的雙向比對（本守衛的核心）。
//
// 四條斷言，每條都對應一種真實的失效形態：
//
//	pivotFilled    → 字面量必須有 AssetID 欄。**移除任一既有賦值即紅**——這正是
//	                 「資產類事件從資產樞紐上消失」的唯一入口。
//	pivotDelegated → 必須是 helper 呼叫，且 helper 內的產生點自己登記為 pivotFilled。
//	                 委派鏈斷掉（helper 改名、helper 內不再填）即紅。
//	pivotNotAsset  → 不得有 AssetID 欄。反向也要釘：把不相干事件掛上某台機器，
//	                 產出的是假事件，比漏掉更糟。
//	pivotGap       → 仍不得有 AssetID 欄。有人補上就轉紅，逼登記改為 pivotFilled。
func TestAssetPivotRegistryMatchesCode(t *testing.T) {
	root := auditPointModuleRoot(t)
	rows := parseAuditPointManifest(t, auditPointManifestPath(t, root))
	sites := scanAssetPivotSites(t, root)

	// helper 名 → 該 helper 內產生點的 AP ID（委派鏈解析用）
	keyToID := map[string]string{}
	for _, r := range rows {
		keyToID[r.key()] = r.ID
	}
	helperPoints := map[string][]string{}
	for key, s := range sites {
		if s.FuncName == "" {
			continue
		}
		if id, ok := keyToID[key]; ok {
			helperPoints[s.FuncName] = append(helperPoints[s.FuncName], id)
		}
	}

	checked := map[assetPivotClass]int{}
	for _, r := range rows {
		entry, ok := assetPivotRegistry[r.ID]
		if !ok {
			continue // 完備性由 TestAssetPivotRegistryCoversEveryAuditPoint 負責
		}
		site, ok := sites[r.key()]
		if !ok {
			continue // file:line 對不上由雙向完備性守衛負責，不在此重複報
		}
		checked[entry.Class]++

		switch entry.Class {
		case pivotFilled:
			if !site.HasField {
				t.Errorf("%s（%s，%s）登記為「%s」，但該產生點的字面量沒有賦值 %s。\n"+
					"  登記理由：%s\n"+
					"  後果：這一類事件在資產樞紐（凡 audit_logs.asset_id 非空即納入）上完全不可見，"+
					"稽核調查看到的是「這台機器上沒發生過這件事」——與事情真的沒發生無從分辨。"+
					"若這是刻意的，登記必須同步改為「%s」並補上理由。",
					r.ID, r.key(), site.FuncLabel, pivotFilled, assetPivotFieldName, entry.Why, pivotNotAsset)
			}
		case pivotDelegated:
			if site.Kind != kindRecordCall {
				t.Errorf("%s（%s）登記為「%s」，但它不是 helper 呼叫（實際種類 %s）："+
					"委派分類只適用於把建列工作交給 helper 的呼叫點", r.ID, r.key(), pivotDelegated, site.Kind)
				continue
			}
			if !assetAuditWriteFuncs[site.Callee] {
				t.Errorf("%s（%s）委派給 %q，該名不在 assetAuditWriteFuncs 內："+
					"委派鏈的另一端不受本守衛涵蓋時，主體鍵可能已在無人看管處被拿掉",
					r.ID, r.key(), site.Callee)
				continue
			}
			targets := helperPoints[site.Callee]
			if len(targets) == 0 {
				t.Errorf("%s（%s）委派給 %s，但該 helper 內找不到任何已登記的審計產生點："+
					"委派鏈已斷，主體鍵無人負責", r.ID, r.key(), site.Callee)
				continue
			}
			for _, tid := range targets {
				te, ok := assetPivotRegistry[tid]
				if !ok || te.Class != pivotFilled {
					t.Errorf("%s（%s）委派給 %s，但該 helper 的產生點 %s 未登記為「%s」（實際 %q）："+
						"呼叫點以為 helper 會填，helper 卻沒有義務填——這正是主體鍵靜默消失的路徑",
						r.ID, r.key(), site.Callee, tid, pivotFilled, te.Class)
				}
			}
		case pivotNotAsset, pivotGap:
			if site.HasField {
				verb := "登記為非資產類卻賦值了"
				if entry.Class == pivotGap {
					verb = "登記為已知缺口卻已賦值"
				}
				t.Errorf("%s（%s，%s）%s %s（＝%s）。\n"+
					"  登記理由：%s\n"+
					"  非資產類填了主體鍵＝把不相干事件掛到某台機器上，產出假事件；"+
					"缺口被補上是好事，但登記必須同步改為「%s」，否則守衛會在下一次有人拿掉它時保持沉默。",
					r.ID, r.key(), site.FuncLabel, verb, assetPivotFieldName, site.FieldExpr, entry.Why, pivotFilled)
			}
			// 「有資產在手卻不填」的指紋——雙向比對，兩個方向都要紅
			if site.InScope != entry.AssetInScope {
				t.Errorf("%s（%s，%s）的資產識別字指紋不符：登記 AssetInScope=%v，實況 %v。\n"+
					"  登記理由：%s\n"+
					"  這個指紋的用途是把「包覆函式握有資產識別字、卻仍判定非資產類」變成"+
					"白紙黑字的決定。實況變成 true 而登記仍是 false，代表這個產生點的處境已經改變"+
					"（周圍多了資產上下文），該重新判斷它是不是漏填了主體鍵；反向則代表指紋過期。",
					r.ID, r.key(), site.FuncLabel, entry.AssetInScope, site.InScope, entry.Why)
			}
		}
	}

	if checked[pivotFilled] < minAssetPivotFilled {
		t.Fatalf("只實際比對到 %d 個「%s」產生點（下限 %d）：manifest 與現實碼的對應已大面積失準，"+
			"本守衛正在縮水的集合上假綠", checked[pivotFilled], pivotFilled, minAssetPivotFilled)
	}
	if checked[pivotDelegated] < minAssetPivotDelegated {
		t.Fatalf("只實際比對到 %d 個「%s」產生點（下限 %d）", checked[pivotDelegated], pivotDelegated, minAssetPivotDelegated)
	}
	t.Logf("資產樞紐雙向比對：填 %d／委由 helper %d／非資產類 %d／已知缺口 %d",
		checked[pivotFilled], checked[pivotDelegated], checked[pivotNotAsset], checked[pivotGap])
}

// ── 面 3：中介層主體鍵覆寫（handler 注入點）──────────────────────────────

// assetSubjectInjectFuncs 允許呼叫主體鍵覆寫入口的函式名（`internal/api` 內）。
const (
	assetSubjectInjectPtr   = "setAuditAssetID"
	assetSubjectInjectValue = "setAuditAssetIDValue"
)

// assetSubjectInjectionSites 登記表：包覆函式標籤 → 該函式內的注入呼叫次數。
//
// # 為什麼這一面必須單獨守
//
// 中介層只能由路由推導主體（`resource == asset` 且路徑帶 `:id`）。一整類端點
// **作用於資產、路徑上卻沒有資產 id**——授權建立（客體在 body）、候選憑證處置
// （資產在候選列上）、資產建立（id 建完才存在）。這些端點靠 handler 顯式注入補主體；
// 注入被刪掉時：審計列照寫、測試全綠、回應不變，只有資產樞紐上少了這一類事件。
//
// 以「函式標籤 → 次數」而非 file:line 登記：行號會漂移，函式身分不會。
var assetSubjectInjectionSites = map[string]int{
	"(AssetHandler).Create":                  1, // POST /assets：路徑無 :id，資產 id 建完才存在
	"(ChangeSecretHandler).RetryCandidate":   1, // :id 是候選 id，讀出候選才知道打哪台機器
	"(ChangeSecretHandler).DiscardCandidate": 1, // 同上；主體須在刪除前取（刪後查不回）
	"(AuthorizationHandler).Create":          1, // 授權客體在 body
	"(AuthorizationHandler).UpdateAccounts":  1, // :id 是授權列 id
	"(AuthorizationHandler).Delete":          1, // 撤銷：:id 是授權列 id
	"setAuditAssetIDValue":                   1, // 值型入口轉呼叫指標型入口（本身即實作）
}

// TestAssetSubjectInjectionSitesAreRegistered 注入點雙向完備。
func TestAssetSubjectInjectionSitesAreRegistered(t *testing.T) {
	root := auditPointModuleRoot(t)
	files, _ := parseModuleFiles(t, root)

	actual := map[string]int{}
	for _, pf := range files {
		ast.Inspect(pf.File, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || (id.Name != assetSubjectInjectPtr && id.Name != assetSubjectInjectValue) {
				return true
			}
			actual[funcDeclLabel(enclosingFuncDecl(pf.File, call.Pos()))]++
			return true
		})
	}

	for label, want := range assetSubjectInjectionSites {
		got := actual[label]
		if got == want {
			continue
		}
		if got == 0 {
			t.Errorf("%s 登記為資產主體鍵注入點，實際找不到任何 %s／%s 呼叫。\n"+
				"  這類端點路徑上沒有資產 id，中介層推導不出主體；注入被拿掉時審計列照寫、"+
				"測試全綠、回應不變，只有資產樞紐上少了整整一類事件——沒有任何其他東西會發現。",
				label, assetSubjectInjectPtr, assetSubjectInjectValue)
			continue
		}
		t.Errorf("%s 的注入呼叫數為 %d，登記為 %d：分支被增刪時主體鍵的覆蓋面隨之改變，須重新確認每條回應路徑都有主體",
			label, got, want)
	}
	for label, got := range actual {
		if _, ok := assetSubjectInjectionSites[label]; !ok {
			t.Errorf("%s 有 %d 個未登記的資產主體鍵注入呼叫：注入面擴張必須經過登記，"+
				"否則「哪些端點負責補主體」這件事沒有單一可查的清單", label, got)
		}
	}
	if len(actual) < len(assetSubjectInjectionSites) {
		t.Fatalf("只掃到 %d 個注入函式（登記 %d）：掃描判準或入口函式名已變動，本守衛正在縮水的集合上假綠",
			len(actual), len(assetSubjectInjectionSites))
	}
}

// ── AST 小工具 ────────────────────────────────────────────────────────────

// enclosingFuncDecl 找包覆某位置的頂層函式宣告（找不到回 nil，如包級變數初始化）。
func enclosingFuncDecl(file *ast.File, pos token.Pos) *ast.FuncDecl {
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Pos() <= pos && pos <= fn.End() {
			return fn
		}
	}
	return nil
}

func funcDeclName(fn *ast.FuncDecl) string {
	if fn == nil {
		return ""
	}
	return fn.Name.Name
}

// funcDeclLabel 帶接收者型別的可讀函式標籤（`(AssetHandler).Create`）。
func funcDeclLabel(fn *ast.FuncDecl) string {
	if fn == nil {
		return "(包級)"
	}
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return "(" + assetPivotRecvType(fn.Recv.List[0].Type) + ")." + fn.Name.Name
}

func assetPivotRecvType(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return assetPivotRecvType(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr: // 泛型接收者
		return assetPivotRecvType(e.X)
	}
	return "?"
}

// compositeLitField 取複合字面量的具名欄位值（沒有回 nil）。
func compositeLitField(lit *ast.CompositeLit, name string) ast.Expr {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == name {
			return kv.Value
		}
	}
	return nil
}

// assetIdentInScope 包覆函式內是否出現資產識別字。
//
// 判準刻意保守且純語法：**識別字**（含選擇器的欄位／方法名）小寫後含 "assetid"。
// 只認識別字、不掃註解與字串——註解裡的「AssetID 刻意留空」不該被算成「手上有資產」。
func assetIdentInScope(fn *ast.FuncDecl) bool {
	if fn == nil {
		return false
	}
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		if found {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && strings.Contains(strings.ToLower(id.Name), "assetid") {
			found = true
			return false
		}
		return true
	})
	return found
}

// exprSnippet 取運算式的單行片段（錯誤訊息用）。
func exprSnippet(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.UnaryExpr:
		return "&" + exprSnippet(v.X)
	case *ast.SelectorExpr:
		return exprSnippet(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprSnippet(v.Fun) + "(…)"
	}
	return "<運算式>"
}
