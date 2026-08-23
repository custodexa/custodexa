package gatewayapi

import (
	"context"
	"errors"
	"time"
)

// CommandAlert 指令告警（command_alerts 表）的傳輸形狀。
// 欄位對齊 internal/model/command_alert.go，去 GORM 化。
type CommandAlert struct {
	// OccurredAt 觸發時刻，對應 model.CommandAlert.TriggeredAt。
	OccurredAt time.Time

	SessionID uint
	Actor     Actor

	// AssetID **指標型**：手動連線可能無資產，該欄在 DB 為 nullable
	//（model/command_alert.go:25 與 session_commands 一致）。值型 uint 分不出
	// 「無資產」與「資產 ID 為 0」，會把 NULL 靜默寫成 0。
	AssetID *uint

	Command string

	// RuleID **指標型**（同 AssetID 的理由）：Kind 為降級類的告警沒有規則可指，
	// 該欄在 DB 為 nullable。值型 uint 分不出「無規則」與「規則 ID 為 0」，
	// 會把 NULL 靜默寫成 0。
	RuleID *uint
	// RuleName 觸發當下的規則名快照：規則之後改名／刪除不影響既有告警可讀性，
	// 與 model.CommandAlert.RuleName 的冗餘設計同取向。缺此欄則收口後告警列會失去
	// 現況已有的資訊。**降級類填機器碼**（該類無規則名可快照）。
	RuleName string

	// Kind 告警來源類別（model.AlertKind* 之一，值域不在本套件重述以維持純度）。
	//
	// **存在的理由是規格不變式不該掛在可 CRUD 的資料列上**：指令審計降級是規格
	// 要求的安全訊號，若借一條內建規則承載，管理員停用該規則即可靜默關掉它。
	// 落地面依本欄決定 rule_id 寫不寫得進去（DB CHECK 釘死兩者的對應）。
	Kind string
	// ReasonCode 非規則類告警的機器碼；規則類為空字串。
	// **SHALL NOT 用來承載使用者可見文案**——它是機器欄，翻譯由消費端依碼對映。
	ReasonCode string

	// Level 嚴重度，對應 model.CommandAlert.Severity。
	Level string

	// Disposition 審閱處置（model.AlertDisposition* 之一）。
	//
	// **兩條寫入路徑已統一為 pending**：收口前 matcher 路徑顯式寫 pending、
	// 阻斷路徑未設（DB 收到空字串）。現況兩條路徑
	//（internal/modules/audit/alert_matcher.go、internal/sshproxy/command_blocker.go）
	// 皆顯式設 model.AlertDispositionPending。實作端 SHALL 顯式設值，
	// 不得倚賴 DB default——本欄的預設值語義屬 migration，不屬本契約。
	//
	// **統一的性質是欄位一致性補齊，不是修正已知的消費端差異**：
	// 現況無消費者以本欄判定未審閱（全庫的未審閱篩選一律走 reviewed_at IS NULL），
	// 故統一在行為上是惰性的；它防的是未來——兩種值並存之下，任何以
	// disposition = 'pending' 寫的查詢都會靜默漏掉整類阻斷告警。
	Disposition string

	// Blocked 觸發當下規則是否為阻斷型（結構化表達，不得回退成把「（已阻斷）」
	// 塞進 RuleName 的字串標示）。
	Blocked bool
}

// AlertSink 指令告警寫入面。與審計 sink 分開，因為落地表、轉發路徑與消費者都不同。
//
// **實作 SHALL 同時完成「入庫」與「離機轉發」**——這是「漏 tee」的結構性解法：
// 現況阻斷告警直寫 DB、繞過 syslog tee，離機證據缺一整類。收口後兩條路徑共用本介面，
// tee 即結構性不可漏。
//
// # 錯誤語義（取代原先的「二擇一待定」）
//
// **選同步變體，不選 async 變體**，逐條理由：
//
//   - 落地面本身 SHALL 同步寫、SHALL NOT 吞錯、SHALL NOT 入佇列後回 nil。
//     告警的價值全在「事後查得到」；fire-and-forget 會讓寫入失敗完全不可觀測，
//     而且測試會更綠（失敗路徑永遠成功）——那正是 AsyncSink 的 at-most-once
//     語義不該擴散到本介面的理由。
//   - **呼叫端**（阻斷路徑與比對路徑）維持「記 log 不阻斷」，這是**刻意保留現況**
//     而非疏漏：兩條路徑都沒有可回滾的業務交易——比對是指令入庫**之後**的異步批次，
//     阻斷則在告警寫入前就已生效（指令未送往目標）。把告警寫入失敗升級為中斷會話，
//     是範圍外的另一個行為變更，且會讓「告警系統故障」變成「使用者被踢線」。
//   - **fail-close 只掛在「未注入」這一格**：sink 未注入時 SHALL NOT 降級為 no-op
//     （比照 cmd/server/audit_sinks.go 的啟動自檢，不沿用 alert_matcher 對**下游 tee**
//     的寬鬆跳過）。組裝根 requireAlertSink 使啟動失敗；呼叫側以
//     ErrAlertSinkMissing 承接「有人另開一條建構路徑繞過組裝根」。
type AlertSink interface {
	// RecordAlert 落地單筆告警。
	RecordAlert(ctx context.Context, a CommandAlert) error

	// RecordAlerts 批次落地。
	//
	// **存在的理由是保存現況的單次批寫**：internal/modules/audit/alert_matcher.go 現況為
	// 一次 Create(&alerts)；若只提供 RecordAlert，matcher 路徑會被拆成 N 次 INSERT
	// ——那是效能與交易語義的雙重行為變更。實作 SHALL NOT 把本方法實作成迴圈呼叫
	// RecordAlert。
	//
	// 空批次 SHALL 為 no-op 並回 nil：呼叫端「本批沒有命中」是常態，
	// 不該因此產生一次空 INSERT，也不該被當成錯誤。
	RecordAlerts(ctx context.Context, as []CommandAlert) error
}

// ErrAlertSinkMissing 告警落地面未注入。
//
// **不是 panic**：生產上由組裝根的啟動自檢（cmd/server/audit_sinks.go 的
// requireAlertSink）保證走不到這裡；在測試與旁路建構路徑上以 error 表達，
// 讓呼叫端至少能把它記進 log——而 no-op 會讓阻斷告警靜默消失且一切看起來正常。
var ErrAlertSinkMissing = errors.New("告警落地面（gatewayapi.AlertSink）未注入（阻斷告警不得靜默丟棄）")

// RecordAlert 是呼叫端使用 AlertSink 單筆落地的**唯一合法形式**。
//
// 存在理由與 audit/port.WriteInTx 同型：最危險的退化不是寫錯欄位，而是**忘記注入**
// ——一個 nil sink 若被實作成 no-op，告警靜默消失、阻斷照常生效、所有測試更綠。
// 本函式讓「沒接線」與「寫失敗」落在同一格，都回 error。
//
// **SHALL NOT 包裝錯誤**：包裝詞留在呼叫端，收口前後的 log 字串才逐字可比。
func RecordAlert(ctx context.Context, sink AlertSink, a CommandAlert) error {
	if sink == nil {
		return ErrAlertSinkMissing
	}
	return sink.RecordAlert(ctx, a)
}

// RecordAlerts 是呼叫端使用 AlertSink 批次落地的**唯一合法形式**（理由同 RecordAlert）。
func RecordAlerts(ctx context.Context, sink AlertSink, as []CommandAlert) error {
	if sink == nil {
		return ErrAlertSinkMissing
	}
	return sink.RecordAlerts(ctx, as)
}
