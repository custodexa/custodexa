package model

import (
	"time"

	"gorm.io/gorm"
)

// ApproverScope 審核範圍（「審核方 × 客體」全交叉）：
// 審核方＝個人 XOR 使用者群組（群組即資格——
// 屬於審核方群組即具審核資格，成員異動即時反映）；客體＝資產 XOR 節點 XOR
// 申請人 XOR 申請人群組。
// 資產側與授權客體同構——範圍命中查詢與授權解析同形（共用寫法不共用語義）；
// 申請人側（subject_user/subject_group）為 OR 資格擴充：申請人本人或其所屬群組
// 命中即具核准資格，非收斂路由（乙案不做，使用者拍板）。
// 核准資格＝〔資產側命中 OR 申請人側命中〕且操作者為審核方（本人或群組成員）；
// admin 恆可核（兜底——池不足門檻時 admin 介入補票）。
// 資產/節點範圍隱含 view 可視（可視解析第三來源，個人與群組成員同語義）；
// 申請人側不隱含任何資產可視。不隱含連線權、不進複審矩陣。
// 唯一索引 partial（WHERE deleted_at IS NULL）：移除範圍＝軟刪，同 Change 1 慣例
type ApproverScope struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// 審核方（恰一）：個人 XOR 使用者群組
	ApproverID      *uint `gorm:"uniqueIndex:idx_approver_scope_asset,where:deleted_at IS NULL;uniqueIndex:idx_approver_scope_agroup,where:deleted_at IS NULL;uniqueIndex:idx_approver_scope_suser,where:deleted_at IS NULL;uniqueIndex:idx_approver_scope_sgroup,where:deleted_at IS NULL" json:"approver_id,omitempty"`
	ApproverGroupID *uint `gorm:"uniqueIndex:idx_approver_scope_g_asset,where:deleted_at IS NULL;uniqueIndex:idx_approver_scope_g_agroup,where:deleted_at IS NULL;uniqueIndex:idx_approver_scope_g_suser,where:deleted_at IS NULL;uniqueIndex:idx_approver_scope_g_sgroup,where:deleted_at IS NULL" json:"approver_group_id,omitempty"`

	// 客體（恰一）：資產 XOR 節點 XOR 申請人 XOR 申請人群組
	AssetID        *uint `gorm:"uniqueIndex:idx_approver_scope_asset;uniqueIndex:idx_approver_scope_g_asset" json:"asset_id,omitempty"`
	AssetGroupID   *uint `gorm:"uniqueIndex:idx_approver_scope_agroup;uniqueIndex:idx_approver_scope_g_agroup" json:"asset_group_id,omitempty"`
	SubjectUserID  *uint `gorm:"uniqueIndex:idx_approver_scope_suser;uniqueIndex:idx_approver_scope_g_suser" json:"subject_user_id,omitempty"`
	SubjectGroupID *uint `gorm:"uniqueIndex:idx_approver_scope_sgroup;uniqueIndex:idx_approver_scope_g_sgroup" json:"subject_group_id,omitempty"`

	// 分配元數據（admin only 管理，入審計）
	GrantedBy uint `gorm:"not null" json:"granted_by"`

	// 關聯（用於 Preload）
	Approver      *User       `gorm:"foreignKey:ApproverID" json:"approver,omitempty"`
	ApproverGroup *UserGroup  `gorm:"foreignKey:ApproverGroupID" json:"approver_group,omitempty"`
	Asset         *Asset      `gorm:"foreignKey:AssetID" json:"asset,omitempty"`
	AssetGroup    *AssetGroup `gorm:"foreignKey:AssetGroupID" json:"asset_group,omitempty"`
	SubjectUser   *User       `gorm:"foreignKey:SubjectUserID" json:"subject_user,omitempty"`
	SubjectGroup  *UserGroup  `gorm:"foreignKey:SubjectGroupID" json:"subject_group,omitempty"`
	GrantedByUser User        `gorm:"foreignKey:GrantedBy" json:"granted_by_user,omitempty"`
}

// TableName 指定表名
func (ApproverScope) TableName() string {
	return "approver_scopes"
}

// BeforeCreate GORM Hook - 審核方恰一（approver XOR approver_group）＋客體恰一
// （asset XOR asset_group XOR subject_user XOR subject_group）。
// 主要約束由資料庫 CHECK constraint 保證（chk_approver_scope_actor/
// chk_approver_scope_target）
func (s *ApproverScope) BeforeCreate(tx *gorm.DB) error {
	actors := 0
	for _, p := range []*uint{s.ApproverID, s.ApproverGroupID} {
		if p != nil {
			actors++
		}
	}
	if actors != 1 {
		return gorm.ErrInvalidValue
	}
	targets := 0
	for _, p := range []*uint{s.AssetID, s.AssetGroupID, s.SubjectUserID, s.SubjectGroupID} {
		if p != nil {
			targets++
		}
	}
	if targets != 1 {
		return gorm.ErrInvalidValue
	}
	return nil
}
