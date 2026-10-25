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

	// BuiltinKey 內建範本識別（非空即為鎖定的內建範本）；不出現在任何 JSON 回應。
	BuiltinKey *string `gorm:"size:32;uniqueIndex:uq_roles_builtin_key,where:builtin_key IS NOT NULL" json:"-"`

	// DefinitionVersion 角色定義版本。0＝升級前存量（相容目錄成員，
	// 由舊入口沿用，內容在程式中）；>=1＝新服務管理的角色（兩個鎖定範本與自訂角色），單調遞增，
	// 供樂觀衝突檢查。舊列預設 0，所以不靠可改名稱區分存量。
	DefinitionVersion int64 `gorm:"not null;default:0" json:"-"`
	// TemplateRoleID 自訂角色的起手來源（只作說明，不繼承未來範本變更）。
	TemplateRoleID *uint `json:"-"`

	// 關聯
	Users []User `gorm:"many2many:user_roles;" json:"users,omitempty"`
}

// TableName 指定表名
func (Role) TableName() string {
	return "roles"
}

// 預定義角色常數。
// approver 為可疊加職能角色：不參與 primaryRoleOf
// 三階排序（admin>auditor>user）、不進 JWT；審核端點守門即時查 DB roles
const (
	RoleAdmin    = "admin"
	RoleUser     = "user"
	RoleAuditor  = "auditor"
	RoleApprover = "approver"
)

// builtinKeyForReservedName 四個保留角色名稱對應的內建範本識別（與權限模型遷移標記列的規則相同）。
func builtinKeyForReservedName(name string) (string, bool) {
	switch name {
	case RoleAdmin:
		return BuiltinSuperAdmin, true
	case RoleAuditor:
		return BuiltinAuditor, true
	case RoleUser:
		return BuiltinUser, true
	case RoleApprover:
		return BuiltinApprover, true
	}
	return "", false
}

// BeforeCreate 以保留名稱建立的角色列帶入對應的內建範本識別（未明確指定時）。
//
// 內建範本的身分只由 builtin_key 決定（解析器與所有授權判定都只讀這個欄位，不看名稱）；
// 這個 hook 只是在**寫入**時套用與遷移相同的「保留名稱 → 識別」規則，使以保留名稱建立
// 的列（種子、測試夾具）一開始就是被標記的內建列，而不是等遷移補標。
// 非保留名稱的角色不受影響；已明確指定 BuiltinKey（含刻意留空以外的值）者不覆寫。
func (r *Role) BeforeCreate(_ *gorm.DB) error {
	if r.BuiltinKey != nil {
		return nil
	}
	if key, ok := builtinKeyForReservedName(r.Name); ok {
		k := key
		r.BuiltinKey = &k
	}
	return nil
}
