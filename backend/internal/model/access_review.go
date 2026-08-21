package model

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// ErrAccessReviewImmutable 複審簽核不可修改/刪除（append-only 稽核證據）
var ErrAccessReviewImmutable = errors.New("存取複審簽核為不可變證據，不得修改或刪除")

// AccessReview 週期性存取複審簽核紀錄（audit-workflows D2 v1，PCI 7.2.4）。
// v1 補償控制：一筆簽核＝複審者＋時間＋範圍＋結論＋複審當下的存取矩陣快照（不可變證據）。
// 完整逐列 campaign（保留/撤銷決策）列 v1.1，本表為 append-only 稽核紀錄
type AccessReview struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	ReviewedBy   uint      `gorm:"not null" json:"reviewed_by"`
	ReviewerName string    `gorm:"size:50" json:"reviewer_name"`
	ReviewedAt   time.Time `gorm:"not null" json:"reviewed_at"`

	// Scope 複審範圍描述（v1 為全庫；未來可帶篩選）
	Scope string `gorm:"size:200;not null" json:"scope"`
	// Note 複審結論備註（管理層確認語意，7.2.4）
	Note string `gorm:"type:text;not null" json:"note"`
	// AuthorizationCount 複審當下的授權筆數（快速摘要）
	AuthorizationCount int `gorm:"not null" json:"authorization_count"`
	// MatrixSnapshot 複審當下完整存取矩陣的 JSON 快照（不可變證據，可匯出）
	MatrixSnapshot string `gorm:"type:text;not null" json:"-"`

	CreatedAt time.Time `json:"created_at"`
}

// TableName 指定表名
func (AccessReview) TableName() string {
	return "access_reviews"
}

// BeforeUpdate 縱深防禦（對抗驗證 F4）：簽核為不可變證據，ORM 層拒更新——
// 即使未來誤加 update 路由或程式路徑，快照也不會被靜默竄改（比照 AuditLog）
func (AccessReview) BeforeUpdate(tx *gorm.DB) error {
	return ErrAccessReviewImmutable
}

// BeforeDelete 縱深防禦：簽核不得刪除（append-only 稽核紀錄）
func (AccessReview) BeforeDelete(tx *gorm.DB) error {
	return ErrAccessReviewImmutable
}
