package model

import "time"

// DailyReviewLog 每日審閱簽核記錄（PCI 10.4.1/10.4.1.1）。
// 每個審閱日至多一筆（ReviewDate 唯一）；SnapshotJSON 固化簽核當下所見的
// 事件計數，供 QSA 比對簽核者當時審閱的內容
type DailyReviewLog struct {
	ID uint `gorm:"primarykey" json:"id"`
	// ReviewDate 審閱日（YYYY-MM-DD 字串——避免 date 型別在 sqlite 測試 scan 失敗）
	ReviewDate   string `gorm:"type:varchar(10);not null;uniqueIndex" json:"review_date"`
	ReviewerID   uint   `gorm:"not null" json:"reviewer_id"`
	ReviewerName string `gorm:"type:varchar(100);not null" json:"reviewer_name"`
	// SnapshotJSON 簽核當下的事件計數快照（登入失敗/未審閱告警/高危操作）
	SnapshotJSON string    `gorm:"type:text;not null" json:"snapshot_json"`
	Note         string    `gorm:"type:text" json:"note,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// TableName 指定表名
func (DailyReviewLog) TableName() string {
	return "daily_review_logs"
}
