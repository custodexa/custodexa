package model

import "time"

// AuditChainVerifyState 檢查點鏈自動驗證的營運狀態。
//
// **單列表**（ID 恆為 1）：成功輪次的歷史沒有證據價值，異常的歷史已由
// audit_failure_events 永久承載且帶起訖區間；每輪一列只會多一張需要保留政策的表。
//
// **它不是證據，讀取端必須明說**：本表不在檢查點鏈的覆蓋範圍內（鏈只覆蓋
// audit_logs），可由資料庫直寫改寫成「最近驗過且通過」。此風險已落在既有邊界
// R0（同時掌握金鑰與資料庫者）之內，不新增風險面；但驗證頁 SHALL 明示此區塊
// 為營運狀態顯示而非完整性證明——真正的證據是失效事件、離機錨定，以及外部
// 查核方以公鑰自行驗章。
//
// **兩層各記一組最近執行時點**（recent_* 與 full_*，不合併）：兩層的停擺成因與
// 後果不同——近期層停擺代表低延遲告警失效，全鏈層停擺代表歷史不再被重驗。
// 壓成一個欄位會讓「其中一層已死」在畫面上完全看不出來。而排程若靜默停擺，
// 不會有任何異常告警發出（沒跑就沒有異常可報），最近執行時點是唯一可讓人與
// 稽核看出「機制其實沒在運作」的訊號。
type AuditChainVerifyState struct {
	// ID 固定為 AuditChainVerifyStateID：單列語義以主鍵釘死，
	// 併發 tick 只會更新同一列而非長出第二份狀態
	ID uint `gorm:"primarykey" json:"id"`

	// ── 近期層（封存完成觸發，範圍＝封章時間落在最近 N 天的已封區間）──
	RecentLastRunAt      *time.Time `json:"recent_last_run_at,omitempty"`
	RecentLastStatus     string     `gorm:"size:16;not null;default:''" json:"recent_last_status"`
	RecentLastDurationMs int64      `gorm:"not null;default:0" json:"recent_last_duration_ms"`
	// RecentWindowDaysEffective 本次實際生效的窗口天數（政策值經審計保留天數 clamp 後）。
	// 顯示生效值而非設定值：承諾驗證保留期以外的範圍是空頭支票，畫面上得看得出真正驗了幾天
	RecentWindowDaysEffective int `gorm:"not null;default:0" json:"recent_window_days_effective"`
	// RecentLastSeq 上次近期層觀測到的鏈尾 seq；「前進」即代表期間有新封章。
	// 觀測式觸發的狀態載體（不以回呼掛入封存流程——封存排程無防重入層，
	// 把可達數十秒的驗證掛進去會與下一次封存重疊，而封存是唯一的寫入端）
	RecentLastSeq uint `gorm:"not null;default:0" json:"recent_last_seq"`

	// ── 全鏈層（排程週期觸發，結構層全鏈＋內容層滾動窗）──
	FullLastRunAt      *time.Time `json:"full_last_run_at,omitempty"`
	FullLastStatus     string     `gorm:"size:16;not null;default:''" json:"full_last_status"`
	FullLastDurationMs int64      `gorm:"not null;default:0" json:"full_last_duration_ms"`

	// StructureFailedCount 最近一次結構層全鏈驗證的失敗點數（兩層共用同一支驗證）
	StructureFailedCount int `gorm:"not null;default:0" json:"structure_failed_count"`
	// ContentVerifiedIntervals 最近一輪實際驗過的內容層區間數
	ContentVerifiedIntervals int `gorm:"not null;default:0" json:"content_verified_intervals"`
	// ContentCursorSeq 內容層滾動游標（下一輪自此 seq 起推進）
	ContentCursorSeq uint `gorm:"not null;default:0" json:"content_cursor_seq"`
	// LastFullCycleAt 最近一次滾動游標繞完全歷史一輪的時點
	LastFullCycleAt *time.Time `json:"last_full_cycle_at,omitempty"`

	// OpenFailedSeqs 未結案的失敗區間集合（JSON 陣列，兩層共用同一份）。
	//
	// **假恢復修法的核心**：滾動窗每輪驗的是不同窗口，若以「本輪驗過的
	// 區間全數通過」為結案條件，則於某輪驗出區間 X 異常後，下一輪驗別的窗口且
	// 全過即會結案並發出恢復通知，**而 X 的列早已被刪除且根本未被重驗**。
	// 故本集合每輪必被重驗（比照鏈尾必驗、不受列預算限制），
	// 且失效事件僅在本集合清空時才准結案
	OpenFailedSeqs string `gorm:"type:text;not null;default:''" json:"open_failed_seqs"`

	// LastFingerprint 由「最嚴重狀態＋結構層失敗點數＋OpenFailedSeqs」計算的指紋。
	//
	// **不得由本輪驗過的區間結果計算**：兩層與滾動窗每輪驗到的區間本就不同，
	// 以本輪結果算指紋會讓指紋逐輪抖動而每輪觸發重發通知，其實際效果即為
	// 「每輪重複發送」——收件端會靜音整個通道，把會出聲的機制變成被靜音的機制
	LastFingerprint string `gorm:"size:32;not null;default:''" json:"last_fingerprint"`

	UpdatedAt time.Time `json:"updated_at"`
}

// AuditChainVerifyStateID 單列狀態的固定主鍵
const AuditChainVerifyStateID uint = 1

// TableName 指定表名
func (AuditChainVerifyState) TableName() string {
	return "audit_chain_verify_states"
}
