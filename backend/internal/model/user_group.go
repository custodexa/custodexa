package model

import (
	"time"

	"gorm.io/gorm"
)

// UserGroup 使用者群組：授權主體的分組維度。
// 與 RBAC 的 Role 正交——Role 管職能（端點權限），UserGroup 管授權分組
// （資產可及範圍），不可混用。
type UserGroup struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name        string `gorm:"uniqueIndex;not null;size:100" json:"name"`
	Description string `gorm:"size:500" json:"description"`

	// 成員多對多（一人可屬多群），join 表 user_group_members
	Users []User `gorm:"many2many:user_group_members;" json:"users,omitempty"`
}

// TableName 指定表名
func (UserGroup) TableName() string {
	return "user_groups"
}
