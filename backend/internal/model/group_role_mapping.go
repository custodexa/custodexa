package model

import (
	"time"

	"gorm.io/gorm"
)

// GroupRoleMapping 一條「外部群組 → 本系統角色」的映射規則。
//
// # 來源恰一
//
// 規則掛在一個外部身分來源上：目錄 XOR 身分提供者。以兩條可空外鍵加檢查約束
// 表達，而不是「來源種類欄 ＋ 通用識別欄」的多型鍵——多型鍵掛不上真外鍵，
// 來源被刪除之後規則會指向一個不存在的識別，而沒有任何東西會發現。
// 來源種類由哪一欄非空推導，不另存。
//
// **檢查約束只在 postgres 跑得動**（單元測試的 sqlite 建表走 GORM 標籤，
// 不含 CHECK），故互斥同時要在服務層驗證。
//
// # MatchValue 存什麼
//
// 群組的比對值，**原樣存、不做正規化**。目錄側是群組的辨識名稱，比對時兩邊
// 各自解析成結構再比（屬性型別不分大小寫、屬性值分大小寫），故存進來的字串
// 不必、也不該被預先改寫；提供者側是該提供者宣告裡的字面值，逐字比對。
// 另存一份正規化值等於在兩種比對規則之外再造一套，而它必然與其中一種不一致。
type GroupRoleMapping struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// LDAPDirectoryID 目錄來源（與 OIDCProviderID 恰一非空）
	LDAPDirectoryID *uint `gorm:"uniqueIndex:idx_group_role_mappings_ldap,where:deleted_at IS NULL" json:"ldap_directory_id,omitempty"`
	// OIDCProviderID 身分提供者來源（與 LDAPDirectoryID 恰一非空）
	OIDCProviderID *uint `gorm:"column:oidc_provider_id;uniqueIndex:idx_group_role_mappings_oidc,where:deleted_at IS NULL" json:"oidc_provider_id,omitempty"`

	// MatchValue 群組的比對值（原樣存，見本結構的說明）
	MatchValue string `gorm:"size:500;not null;uniqueIndex:idx_group_role_mappings_ldap;uniqueIndex:idx_group_role_mappings_oidc" json:"match_value"`

	// RoleID 命中該群組時賦予的角色
	RoleID uint `gorm:"not null;uniqueIndex:idx_group_role_mappings_ldap;uniqueIndex:idx_group_role_mappings_oidc" json:"role_id"`

	// Enabled 停用的規則於重算時視同不存在（不刪規則即可暫停一條映射）
	Enabled bool `gorm:"not null;default:true" json:"enabled"`

	// CreatedBy 建立這條規則的管理者。映射到管理員角色是特權賦予路徑，
	// 「誰開的」必須留在資料裡，不能只靠審計列
	CreatedBy uint `gorm:"not null" json:"created_by"`

	// Role 關聯（用於 Preload；管理端列表要顯示角色名）
	Role *Role `gorm:"foreignKey:RoleID" json:"role,omitempty"`
}

// TableName 指定資料表名
func (GroupRoleMapping) TableName() string {
	return "group_role_mappings"
}
