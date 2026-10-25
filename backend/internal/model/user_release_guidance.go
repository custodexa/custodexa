package model

import "time"

// UserReleaseGuidance 使用者對某個說明版本的關閉狀態。
//
// 只存個人偏好：缺列等於尚未關閉，不寫空列。（user_id, notice_version）為複合主鍵，
// 重複關閉以冪等 upsert 處理；不存說明全文，也不存任何帳號、資產或憑證資訊。
type UserReleaseGuidance struct {
	UserID        uint      `gorm:"primaryKey;autoIncrement:false" json:"user_id"`
	NoticeVersion string    `gorm:"primaryKey;type:varchar(32);autoIncrement:false" json:"notice_version"`
	DismissedAt   time.Time `gorm:"not null" json:"dismissed_at"`
}

// TableName 指定表名
func (UserReleaseGuidance) TableName() string {
	return "user_release_guidance"
}
