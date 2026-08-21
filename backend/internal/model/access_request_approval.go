package model

import (
	"time"
)

// AccessRequestApproval 申請單核准記錄（approval-routing-quorum D-3）：
// 最少核准人數（quorum）的逐票資料軌。每筆核准一列；(request_id, approver_id)
// 唯一索引硬擋同人重複核准（含 admin）。核准數達政策門檻
// （access_request_min_approvals）的那一票才觸發申請單 CAS 轉 approved——
// 完整核准軌跡以本表為準，AccessRequest.ApproverID 僅記補齊門檻的最終核准人
// （門檻 1 時即唯一核准人，與歷史資料語義相容）。
// 記錄不可變（無軟刪、無更新）：拒絕/撤回/逾時終態下已存在的票留存供審計。
type AccessRequestApproval struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`

	RequestID  uint   `gorm:"not null;uniqueIndex:idx_request_approval_once;index" json:"request_id"`
	ApproverID uint   `gorm:"not null;uniqueIndex:idx_request_approval_once" json:"approver_id"`
	Note       string `gorm:"type:varchar(1000)" json:"note,omitempty"`

	// 關聯（用於 Preload）
	Approver User `gorm:"foreignKey:ApproverID" json:"approver,omitempty"`
}

// TableName 指定表名
func (AccessRequestApproval) TableName() string {
	return "access_request_approvals"
}
