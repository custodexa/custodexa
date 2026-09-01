package apierror

import "fmt"

// 串流／連線閘出口碼。
//
// 本檔與 codes.go 同一 registry，分檔僅為並行開發隔離：codes.go 是 HTTP handler
// 大掃除（A 段）的地盤，本檔專收兩類出口——
//
//  1. WebSocket 幀（MsgError／MsgNotice）與 guacd error instruction 的碼。
//     這些出口不是 HTTP JSON，走 sshproxy.EncodeErrorMessage /
//     EncodeNoticeMessage / proxy 的 guac instruction，Data 欄一律取本檔的
//     ZhFallback 當 fallback（前端查譯優先，譯文缺鍵時退回 Data）。
//  2. 連線決策閘（asset/recording/session/access policy）的 HTTP 出口。
//     這些回應除 error/code 外還帶 reason/policy 等**機器欄**，經
//     ErrorResponse.Meta 平鋪到封套 top-level——前端 connect.js 依
//     `resp.data.reason` 做控制流分支，欄位名與值一字不可改。
//
// 命名沿用 codes.go 的 RULE_<DOMAIN>_* 慣例（可預期的業務／連線規則攔截，
// 非 5xx 內部故障）。
var (
	// --- K8s / DB 撥號失敗（升級後以 MsgError 幀送出）---

	// CodeK8sPodUnavailable 取 pod 快照失敗。k8sproxy 內部已把 client-go 錯誤分成
	// 五類人話（unauthorized/forbidden/notfound/tls/unreachable），該分類目前仍走
	// Message.Data 的 zh fallback 傳遞，未各自碼化——碼化屬 k8sproxy 遷移範圍。
	CodeK8sPodUnavailable = register("RULE_K8S_POD_UNAVAILABLE", Descriptor{
		ZhFallback: "無法取得 Pod 資訊，請確認 pod 名稱、Token 權限與叢集可達性"})
	CodeK8sStartFailed = register("RULE_K8S_START_FAILED", Descriptor{
		ZhFallback: "K8s 連線啟動失敗"})
	CodeDBClientStartFailed = register("RULE_DB_CLIENT_START_FAILED", Descriptor{
		ZhFallback: "資料庫客戶端啟動失敗"})

	// --- 會話狀態注入（bridge / monitor / share）---

	// CodeSessionEnded 監看／分享房間已關閉（會話剛結束的競態）。
	CodeSessionEnded = register("RULE_SESSION_ENDED", Descriptor{
		ZhFallback: "會話已結束"})
	// CodeSessionIdleTimeout / CodeSessionMaxDuration 由 sshproxy.bridge 與
	// proxy.Tunnel 共用（同一組政策鍵驅動，兩協議族語義必須一致）。
	CodeSessionIdleTimeout = register("RULE_SESSION_IDLE_TIMEOUT", Descriptor{
		ZhFallback: "閒置逾時，連線已中斷"})
	CodeSessionMaxDuration = register("RULE_SESSION_MAX_DURATION", Descriptor{
		ZhFallback: "已達會話時間上限，連線已中斷"})
	// CodeSessionTerminated 管理端強制收線／啟動前複查發現會話已被收線。
	CodeSessionTerminated = register("RULE_SESSION_TERMINATED", Descriptor{
		ZhFallback: "連線已被終止"})
	// CodeAccountDisabled bridge 啟動前複查發現帳號已停用或鎖定。
	CodeAccountDisabled = register("RULE_ACCOUNT_DISABLED", Descriptor{
		ZhFallback: "帳號已停用或鎖定"})

	// --- 指令阻斷警告（MsgNotice 幀，非錯誤）---

	// CodeCommandBlocked 指令命中阻斷規則。規則名稱不進 ZhFallback：它是
	// opaque 自由字串（AlertRule.Name 僅驗 required），以 Message.Params["rule"]
	// 經 notifycat.SanitizeOpaque 後單獨傳遞，由前端組字。
	CodeCommandBlocked = register("RULE_COMMAND_BLOCKED", Descriptor{
		ZhFallback: "指令命中阻斷規則，已阻止送往目標主機"})

	// CodeCommandBlockClearFailed 阻斷後送 Ctrl+C 清遠端行緩衝失敗（fail-close）。
	// 清行失敗代表遠端行緩衝可能殘留被阻斷指令的前綴，使用者下次按 Enter 即送出
	// 殘句——阻斷等於沒發生。故清行失敗一律終止會話（end_reason=block_clear_failed），
	// 本碼即該終止的對使用者說明。
	CodeCommandBlockClearFailed = register("RULE_COMMAND_BLOCK_CLEAR_FAILED", Descriptor{
		ZhFallback: "阻斷後無法清除遠端輸入，連線已中止"})

	// --- 連線決策閘（HTTP，reason/policy 走 Meta）---

	CodeAssetDisabled = register("RULE_ASSET_DISABLED", Descriptor{
		ZhFallback: "資產已停用，無法連線"})
	CodeSessionRecordFailed = register("RULE_SESSION_RECORD_FAILED", Descriptor{
		ZhFallback: "會話記錄建立失敗，連線已中止"})
	CodeRecordingUnavailable = register("RULE_RECORDING_UNAVAILABLE", Descriptor{
		ZhFallback: "錄影儲存異常，暫停新連線，請聯繫管理員"})
	CodeAccessApprovalRequired = register("RULE_ACCESS_APPROVAL_REQUIRED", Descriptor{
		ZhFallback: "本資產的存取政策要求申請核准後連線"})
	CodeAccessReasonRequired = register("RULE_ACCESS_REASON_REQUIRED", Descriptor{
		ZhFallback: "本資產的存取政策要求填寫事由後連線"})
)

// CommandBlockedAuditMarker 產生指令阻斷的**稽核標準格式**標記文字
// （2026-08-01 使用者核可的稽核語義變更）。
//
// 這不是「使用者所見文案的伺服端副本」——使用者端看到的是 MsgNotice 幀由前端依
// 自身語系渲染的結果。本函式產出的是**伺服端固定 zh 格式＋機器碼前綴**，寫入
// 錄影／即時監看／稽核 tap 三軌，讓阻斷事件在事後回放與稽核時留有可 grep 的軌跡
// （`[RULE_COMMAND_BLOCKED]`）。格式刻意不隨語系變動：錄影檔是不可變的稽核物件，
// 內容若隨觀看者語系改變就失去可比對性。
//
// ruleName 為 opaque 自由字串（AlertRule.Name 僅驗 required），呼叫端須先過
// notifycat.SanitizeOpaque——它會被直接寫進終端輸出軌，未淨化即為注入面。
func CommandBlockedAuditMarker(ruleName string) string {
	return fmt.Sprintf("[%s] 指令命中阻斷規則「%s」，已阻止送往目標主機",
		CodeCommandBlocked, ruleName)
}
