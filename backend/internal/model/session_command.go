package model

import "time"

// 降級原因機器碼。
//
// 定位與 audit_failure.go 的 `Cause*` 常數同一慣例：**碼是權威表述**，
// 三語散文由前端按碼查譯，值即 DB 與前端契約，改值等同 migration。
//
// 兩個值域，以 `SessionCommand.Degraded` 區分，**刻意不合併**：
//   - Degraded=true  → 該輪**沒有可信的指令文字**，Command 必為空（DB CHECK 釘死）。
//     此時 DegradeReason 取下列 `Degrade*` 之一。
//   - Degraded=false 且 DegradeReason 非空 → **文字已入庫、但可能不等於實際執行的指令**。
//     此時 DegradeReason 取下列 `Qualify*` 之一。
//
// 合併兩者會讓「Degraded=false ⇒ 文字可信」變成假話——那是另一種捏造。
const (
	// DegradeAltScreen 當輪落在 alternate screen 標記區間內：回顯是全螢幕程式畫的，
	// 不是 shell 的指令回顯。此時任何錨都可能只是巧合對上，故一律不發指令文字。
	DegradeAltScreen = "altscreen_round"
	// DegradeRedrawUnanchored 當輪的重組螢幕出現全螢幕重繪或跨列，且錨全部落空：
	// 手上沒有任何證據把螢幕上那一行綁回使用者的輸入，發出去即是捏造。
	DegradeRedrawUnanchored = "redraw_unanchored"
	// DegradeFullScreenInput 重放輪未能在輸出中定位自身回顯，且當輪為全螢幕重繪：
	// 那些按鍵是餵給全螢幕程式的，以輸入位元組結算會記下從未當成指令執行的字串。
	DegradeFullScreenInput = "fullscreen_input"
	// DegradeQueueDiscarded 當輪判定為全螢幕重繪時，仍排在重放佇列中的輸入一併丟棄。
	// 列數＝佇列中的 Enter 數（計數，不是猜測）。
	DegradeQueueDiscarded = "queue_discarded"
	// DegradeQueueDiscardedAtClose 會話結束時佇列殘留且當輪為全螢幕重繪。同上計數。
	DegradeQueueDiscardedAtClose = "queue_discarded_at_close"
	// DegradeQueueUncounted 同上兩者，但本連線的重放佇列曾達上限——
	// 佇列裡的 Enter 數只是**下界**，真實輪數不可知。
	// **UI 與 spec SHALL NOT 宣稱該區段的輪數正確。**
	DegradeQueueUncounted = "queue_uncounted"
	// DegradeQueueOverflow 重放佇列達上限，其後抵達的輸入不再排隊。
	// 一筆＝一次溢出的起點，不代表其後只有一輪。
	DegradeQueueOverflow = "queue_overflow"
	// DegradeNoEcho 該輪收到過實質輸入位元組，但輸出流重組不出任何文字。
	//
	// 典型成因是**對端關閉回顯**（`stty -echo`、密碼提示）；虛擬螢幕觸及記憶體
	// 上限而丟棄內容時同樣落在此碼。兩者的共同事實是「這一輪沒有可還原的文字」，
	// **UI 文案 SHALL 描述該事實、SHALL NOT 斷言成因**。
	//
	// **關閉回顯這一類連錄影都救不回**：asciicast 只有輸出方向的 "o" 事件，
	// 回顯關掉就沒有輸出，回放看到的是一片空白。故必須留下紀錄。
	// **絕不回填輸入位元組**——記錄按鍵內容是獨立能力（獨立資料流、獨立加密、
	// 查看須留痕且填理由），有自己的使用者裁決，不在本 change 的射程內。
	DegradeNoEcho = "input_without_echo"

	// QualifyReplayFallback 重放輪未能在輸出中定位自身回顯，改以使用者送出的
	// 輸入位元組結算：文字是使用者確實送出的位元組，**但 tab 補全與歷史鍵的
	// 實際執行內容只存在於回顯中**，故可能不等於實際執行的指令。
	QualifyReplayFallback = "replay_input_bytes"
)

// SessionCommand SSH 會話指令記錄
// 由 proxy 端重組 client→guacd 的 key instruction 而來（command-audit）
// user_id/asset_id 為冗餘欄位：跨會話搜尋不需 JOIN sessions
// 注意：本表由 migration v7.8 以原生 SQL 建立，不走 AutoMigrate，
// 欄位定義需與 migration 保持一致
type SessionCommand struct {
	ID        uint  `gorm:"primarykey" json:"id"`
	SessionID uint  `gorm:"not null" json:"session_id"`
	UserID    uint  `gorm:"not null" json:"user_id"`
	AssetID   *uint `json:"asset_id,omitempty"` // 手動連線可能無資產 ID，與 sessions.asset_id 一致為 nullable

	Command    string    `gorm:"type:text;not null" json:"command"`
	Seq        int       `gorm:"not null" json:"seq"` // 會話內執行順序（從 1 開始）
	ExecutedAt time.Time `gorm:"type:timestamptz;not null" json:"executed_at"`

	// Degraded 該輪的指令文字無法可信重組。
	//
	// 為真時 Command **必為空**，且此不變式由 baseline 的
	// `CHECK (NOT degraded OR command = '')` 在 DB 層釘死而非靠約定——
	// 「降級紀錄 SHALL NOT 包含推測的指令文字」是規格條文，
	// 捏造比漏記更嚴重，不該掛在任何一段可被繞過的應用層程式碼上。
	//
	// **為假不代表文字必然可信**：偵測判準（vtscreen.Redrawn／跨列）是充分條件
	// 而非必要條件，存在不觸發判準卻仍捏造的形態。UI SHALL NOT 把「無降級標記」
	// 呈現為「內容已驗證」。
	Degraded bool `gorm:"not null;default:false" json:"degraded"`
	// DegradeReason 降級／限定的機器碼，值域見本檔 Degrade*／Qualify* 常數。
	// Degraded 為真時取 Degrade*；為假而本欄非空時取 Qualify*（文字受限定）。
	DegradeReason string `gorm:"size:64;not null;default:''" json:"degrade_reason"`

	// K8s 冗餘欄（k8s-exec）：當次選定 pod/container，跨會話搜尋免 JOIN sessions
	K8sPod       string `gorm:"size:253" json:"k8s_pod,omitempty"`
	K8sContainer string `gorm:"size:63" json:"k8s_container,omitempty"`

	// --- 查詢主控台的結果事實（db-query-console）---
	//
	// 命令列會話的列一律留在預設值：`result_status = ''` 即「這不是主控台列」，
	// 是本組欄位的唯一判別鍵（`event_id = ''` 同義，兩者恆一致）。
	//
	// **本組欄位是唯一真相**：轉錄錄影是自同一事件派生的閱讀面，以 EventID 對應。
	// 兩者不是原子寫入，衝突或缺件時一律以本組欄位為準。

	// EventID 執行單位的穩定識別（ULID，26 字元）。在 matcher 之前配發，
	// 同一個值出現於本列、即時訊息、轉錄的每一行、結果匯出 URL 與會話詳情錨點。
	// CLI 列為空字串；DB 層以 partial unique 索引約束非空值的唯一性
	EventID string `gorm:"size:26;not null;default:''" json:"event_id,omitempty"`
	// TargetDatabase 送出當下的目標資料庫名（伺服器目錄回傳的原樣名稱）
	TargetDatabase string `gorm:"size:128;not null;default:''" json:"target_database,omitempty"`

	// ResultStatus 執行單位的終態，值域見本檔 ResultStatus* 常數（DB CHECK 釘死）。
	// `running` 停在已結束的會話上＝結果未回填，**不得呈現為「執行中」**
	ResultStatus string `gorm:"size:16;not null;default:''" json:"result_status,omitempty"`
	// ResultReason 終態的原因碼，值域見本檔 ResultReason* 常數。
	// 狀態回答「結果是什麼」，原因碼回答「為什麼是這個狀態」——
	// `cancelled` 與 `effect_unknown` 的差別全在原因碼上
	ResultReason string `gorm:"size:32;not null;default:''" json:"result_reason,omitempty"`

	// ResultRows 回傳的資料列數（跨結果集合計）；NULL＝不適用或未回填
	ResultRows *int64 `json:"result_rows,omitempty"`
	// RowsAffected 目標端回報的影響列數；NULL＝不適用或未回填
	RowsAffected *int64 `json:"rows_affected,omitempty"`
	// ResultSets 本單位回傳的結果集數；NULL＝不適用或未回填
	ResultSets *int32 `json:"result_sets,omitempty"`

	// ErrorCode 目標端的錯誤碼（SQLSTATE／MySQL errno／MSSQL number 的字串形態）。
	// **只記碼不記訊息**：錯誤文本可能夾帶資料片段（唯一約束違反會回鍵值），
	// 而審計列是長期保存的
	ErrorCode string `gorm:"size:64;not null;default:''" json:"error_code,omitempty"`
	// DurationMS 送出到取得終態的耗時（毫秒）；NULL＝未回填
	DurationMS *int32 `json:"duration_ms,omitempty"`
	// ResultTruncated 回傳結果因上限而截斷（列數、位元組或單欄值）。
	// 上限是**回傳**上限：目標端仍可能已計算完整結果
	ResultTruncated bool `gorm:"not null;default:false" json:"result_truncated"`

	// TxStateAfter 本單位執行後的交易態，值域見本檔 TxState* 常數（DB CHECK 釘死）。
	// 取自逐單位本就會做的一次探詢，零額外往返；MySQL 恆為 unknown（無失敗交易態，
	// 且探詢進行中交易需要額外權限）。稽核據此能判讀「這筆 ok 落在未提交的交易內」
	TxStateAfter string `gorm:"size:8;not null;default:''" json:"tx_state_after,omitempty"`
}

// 查詢主控台執行單位的終態。**機器碼是權威表述**，三語散文由前端按碼查譯；
// 值域由 DB 的 session_commands_result_status_domain CHECK 釘死，改值等同 migration。
//
// 空字串不在此列：它是「非主控台列」的標記，不是一個狀態。
const (
	// ResultStatusRunning 列已寫、結果尚未回填。它是唯一的非終態，
	// 且是唯一可被 UPDATE 轉出的狀態（回填條件 WHERE result_status='running'）
	ResultStatusRunning = "running"
	// ResultStatusOK 目標端回報全部完成、無錯誤。
	// **不等於「已提交」**：單位落在使用者開啟的交易內時，最終命運由後續的
	// COMMIT／ROLLBACK／會話結束回滾決定——TxStateAfter 是判讀這件事的依據
	ResultStatusOK = "ok"
	// ResultStatusError 目標端回錯，且回錯前沒有任何語句完成
	ResultStatusError = "error"
	// ResultStatusPartial 同一單位內目標端已回報至少一個語句完成後才回錯。
	// 已完成部分**是否已提交**取決於方言與使用者寫的交易結構，系統不推斷；
	// 正確的解讀是「不可假設沒有生效」
	ResultStatusPartial = "partial"
	// ResultStatusBlocked 未送出目標端（規則命中，或比對器不可用而 fail-close）
	ResultStatusBlocked = "blocked"
	// ResultStatusCancelled **確認未生效**：目標端確認取消，或根本未送出
	ResultStatusCancelled = "cancelled"
	// ResultStatusTimeout 逾時且目標端確認取消
	ResultStatusTimeout = "timeout"
	// ResultStatusEffectUnknown 已送出，目標端既未回報完成也未確認取消。
	// 與停在 running 的差別是：這是伺服器**確知自己不知道**並寫了下來，
	// 那是回填失敗。兩者皆不得讀成「未生效」
	ResultStatusEffectUnknown = "effect_unknown"
)

// 終態的原因碼。與狀態成對，逐狀態的合法值見各常數說明。
const (
	// ReasonMatcherHit 阻斷規則命中（blocked）
	ReasonMatcherHit = "matcher_hit"
	// ReasonMatcherUnavailable 比對器不可用而拒絕執行（blocked）。
	// 規則集為空與比對器壞掉是兩件事：前者比對正常回未命中，後者必須 fail-close，
	// 否則刪掉規則檔就等於關掉阻斷
	ReasonMatcherUnavailable = "matcher_unavailable"
	// ReasonErrorAfterResults 回錯前已有語句完成（partial）
	ReasonErrorAfterResults = "error_after_results"
	// ReasonCancelConfirmed 目標端確認取消（cancelled）
	ReasonCancelConfirmed = "cancel_confirmed"
	// ReasonBatchStopped 前一批次失敗，本批次從未送出（cancelled）
	ReasonBatchStopped = "batch_stopped"
	// ReasonTimeoutConfirmed 逾時且目標端確認取消（timeout）
	ReasonTimeoutConfirmed = "timeout_confirmed"
	// ReasonCancelUnconfirmed 取消未獲目標端確認（effect_unknown）
	ReasonCancelUnconfirmed = "cancel_unconfirmed"
	// ReasonTimeoutUnconfirmed 逾時未獲目標端確認（effect_unknown）
	ReasonTimeoutUnconfirmed = "timeout_unconfirmed"
	// ReasonConnectionLost 送出後連線中斷（effect_unknown）
	ReasonConnectionLost = "connection_lost"
	// ReasonCellTruncated 單欄原始值逾上限而截斷（ok／partial 皆可能）
	ReasonCellTruncated = "cell_truncated"
)

// 交易態。值域由 DB 的 session_commands_tx_state_domain CHECK 釘死。
// 空字串同樣不在此列（非主控台列的標記）。
const (
	// TxStateNone 不在交易內
	TxStateNone = "none"
	// TxStateActive 交易進行中且尚未提交
	TxStateActive = "active"
	// TxStateFailed 交易處於失敗態，須先 ROLLBACK 才能繼續
	TxStateFailed = "failed"
	// TxStateUnknown 探詢不可得（MySQL 恆為此值）
	TxStateUnknown = "unknown"
)

// TableName 指定表名
func (SessionCommand) TableName() string {
	return "session_commands"
}
