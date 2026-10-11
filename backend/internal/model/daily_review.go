package model

import "time"

// DailyReviewLog 每日審閱簽核記錄（PCI 10.4.1/10.4.1.1）。
//
// 每個所屬日至多一筆（ReviewDate 唯一）。**所屬日與簽核時刻分欄**：
// ReviewDate 是「審哪一天」，SignedAt 是「哪個時刻簽的」，後者只由伺服器寫入，
// 請求無從指定——補做不得倒填到較早期間的資料面保證。切日時區、該日起訖與
// 準時期限存在列上，之後改業務時區不會回頭改變已簽的紀錄。
// SnapshotJSON 固化簽核當下所見的事件計數，供稽核者比對簽核者當時審閱的內容。
type DailyReviewLog struct {
	ID uint `gorm:"primarykey" json:"id"`
	// ReviewDate 所屬日（YYYY-MM-DD 字串——避免 date 型別在 sqlite 測試 scan 失敗）
	ReviewDate   string `gorm:"type:varchar(10);not null;uniqueIndex" json:"review_date"`
	ReviewerID   uint   `gorm:"not null" json:"reviewer_id"`
	ReviewerName string `gorm:"type:varchar(100);not null" json:"reviewer_name"`
	// SnapshotJSON 簽核當下的事件計數快照（登入失敗/未審閱告警/高危操作與告警處置分布）
	SnapshotJSON string `gorm:"type:text;not null" json:"snapshot_json"`
	Note         string `gorm:"type:text" json:"note,omitempty"`
	// CreatedAt 列的建立時刻（ORM 慣例欄）。對外的簽核時刻一律讀 SignedAt
	CreatedAt time.Time `json:"created_at"`

	// SignedAt 簽核時刻：伺服器受理簽核時取當下時間寫入
	SignedAt time.Time `gorm:"not null" json:"signed_at"`
	// Timezone 切出這一天所用的 IANA 時區
	Timezone string `gorm:"type:varchar(64);not null" json:"timezone"`
	// TimezoneInferred 時區是升級時推定的，不是當時記下的
	TimezoneInferred bool `gorm:"not null;default:false" json:"timezone_inferred"`
	// WindowStart／WindowEnd 該日起訖（半開區間）；改時區的轉換日可能不是 24 小時
	WindowStart time.Time `gorm:"not null" json:"window_start"`
	WindowEnd   time.Time `gorm:"not null" json:"window_end"`
	// DueAt 準時期限：所屬日加兩個日曆日在同一時區的 00:00
	DueAt time.Time `gorm:"not null" json:"due_at"`
	// Late 是否遲簽（SignedAt >= DueAt）
	Late bool `gorm:"not null" json:"late"`
	// DelayReason 延遲原因；只在遲簽時保存，準時簽核為 NULL
	DelayReason *string `gorm:"type:text" json:"delay_reason"`
	// Coverage 時間窗涵蓋方式（DailyReviewCoverage*）
	Coverage string `gorm:"type:varchar(16);not null" json:"coverage"`
	// SourceStatus 簽核當下三類來源中最差的完整性狀態（DailyReviewSource*）
	SourceStatus string `gorm:"type:varchar(16);not null" json:"source_status"`
	// EnabledBasis 這一天在啟用範圍內的依據（DailyReviewBasis*），簽核時固化
	EnabledBasis string `gorm:"type:varchar(16);not null;default:recorded" json:"enabled_basis"`
}

// TableName 指定表名
func (DailyReviewLog) TableName() string {
	return "daily_review_logs"
}

// 時間窗涵蓋方式（daily_review_logs.coverage）
const (
	// DailyReviewCoverageFullDay 快照涵蓋該日開始至結束的整段時間
	DailyReviewCoverageFullDay = "full_day"
	// DailyReviewCoverageUntilSigned 快照只涵蓋到簽核時刻（升級前的紀錄）
	DailyReviewCoverageUntilSigned = "until_signed"
)

// 來源資料完整性（daily_review_logs.source_status 與快照逐項狀態）。
// 依保留政策的清除水位判定；值的順序即「好→差」
const (
	DailyReviewSourceComplete = "complete"
	DailyReviewSourcePartial  = "partial"
	DailyReviewSourcePurged   = "purged"
)

// 所屬日在啟用範圍內的依據（daily_review_logs.enabled_basis）
const (
	// DailyReviewBasisRecorded 變更歷史或升級前的簽核紀錄證明當天開著
	DailyReviewBasisRecorded = "recorded"
	// DailyReviewBasisPresumedPurged 升級時審計已依保留政策清除，無法證明而推定為開
	DailyReviewBasisPresumedPurged = "presumed_purged"
	// DailyReviewBasisPresumedGap 升級時相鄰兩筆變更紀錄銜接不上，兩者之間推定為開
	DailyReviewBasisPresumedGap = "presumed_gap"
	// DailyReviewBasisPresumedTail 升級時重建結果與現值不一致，最後一筆變更之後推定為開
	DailyReviewBasisPresumedTail = "presumed_tail"
)
