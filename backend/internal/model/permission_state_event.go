package model

import "time"

// 權限狀態事件種類。
const (
	PermEventActivate = "activate" // 啟用界標：附證啟用當下的基準狀態
	PermEventChange   = "change"   // 一次權限版本推進（與資料變更同交易）
	PermEventRestore  = "restore"  // 備份還原後的恢復交易
	// PermEventUntraced 無來源變動：寫入合法變更之前，目前狀態與上一筆事件的事後狀態不一致
	// （兩次合法事件之間有人繞過應用層直接改庫）。獨立成一筆，差集不併入隨後的合法事件。
	PermEventUntraced = "untraced"
	// PermEventAccept 超管確認「無來源變動」：以目前實際狀態為新基準（差集記在事件內，
	// 確認人、原因、差集摘要另寫一筆審計列）。其前的 untraced 事件不再使對帳判不符。
	PermEventAccept = "accept"
)

// PermissionStateEvent 權限狀態的可重放變更證據。
//
// 與每次 authz.AdvanceVersion 同交易寫入：記連續序號、前一事件摘要、變更前後狀態摘要與
// 元素層級差集。重放從附證快照出發逐筆套用 Delta，核對每筆 AfterDigest 與鏈。
// AfterBody 是該事件後的完整 canonical 快照，供寫下一筆事件時計算差集（不是重放的輸入）。
// 歸稽核模組（audit）所有；僅 append，不更新、不刪除（唯一例外：段 2 之前寫入、當時取不到
// 完整性密鑰的列，由同一行程在完整性服務就緒後補上驗證碼，見 audit.StampPendingPermissionEvents）。
//
// IntegrityHMAC／KeyVersion 逐列完整性驗證碼，與 audit_logs 用同一組完整性密鑰：
// 只持資料庫帳密的人算得出 Digest 卻算不出這一欄，重放時驗不過的列一律視為不可信。
type PermissionStateEvent struct {
	ID           uint      `gorm:"primaryKey"`
	Seq          int64     `gorm:"not null;uniqueIndex:uq_permission_state_events_seq"`
	Version      int64     `gorm:"not null"`
	Kind         string    `gorm:"size:16;not null"`
	OpID         string    `gorm:"size:64;not null"`
	PrevDigest   string    `gorm:"size:64;not null"`
	BeforeDigest string    `gorm:"size:64;not null"`
	AfterDigest  string    `gorm:"size:64;not null"`
	Delta        string    `gorm:"type:text;not null"`
	AfterBody    string    `gorm:"type:text;not null"`
	Digest       string    `gorm:"size:64;not null"`
	ActivatedSeq *int64    // 僅 activate 事件：啟用時封章的檢查點序號
	CreatedAt    time.Time `gorm:"not null"`
	// IntegrityHMAC 空字串＝未蓋章（升級前的舊列或寫入當下取不到密鑰），對帳時視為不可信
	IntegrityHMAC string `gorm:"type:varchar(64);not null;default:''"`
	// KeyVersion 蓋章鑰版本（與 audit_logs.key_version 同一條版本鏈）
	KeyVersion int `gorm:"not null;default:0"`
}

// TableName 指定表名
func (PermissionStateEvent) TableName() string { return "permission_state_events" }
