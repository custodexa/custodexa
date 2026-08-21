package model

import (
	"time"

	"gorm.io/gorm"
)

// Role 角色模型
type Role struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name        string `gorm:"uniqueIndex;not null;size:50" json:"name"`
	Description string `gorm:"size:200" json:"description"`

	// 關聯
	Users []User `gorm:"many2many:user_roles;" json:"users,omitempty"`
}

// TableName 指定表名
func (Role) TableName() string {
	return "roles"
}

// 預定義角色常數。
// approver 為可疊加職能角色（access-policy-approval D5）：不參與 primaryRoleOf
// 三階排序（admin>auditor>user）、不進 JWT；審核端點守門即時查 DB roles
const (
	RoleAdmin    = "admin"
	RoleUser     = "user"
	RoleAuditor  = "auditor"
	RoleApprover = "approver"
)
