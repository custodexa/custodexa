package model

import "time"

// APIToken 人類帳號為自己建立的管理 API 憑證。只存明文的 SHA-256 摘要，明文不入庫。
//
// ExpiresAt 為 NULL 表示永不到期。名稱占用（未撤銷、未到期、還原世代與目前相同）的唯一性
// 由建立流程在帳號層級鎖內判定，不以資料庫索引表達：是否到期隨時間改變，索引無法描述。
type APIToken struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	UserID    uint      `gorm:"not null;index:idx_api_tokens_user_revoked,priority:1" json:"user_id"`
	Name      string    `gorm:"size:100;not null" json:"name"`
	TokenHash string    `gorm:"size:64;not null;uniqueIndex:idx_api_tokens_token_hash" json:"-"`
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt 到期時刻；NULL＝永不到期
	ExpiresAt *time.Time `json:"expires_at"`
	// LastUsedAt、LastUsedIP 最近一次成功認證的時間與來源；屬遙測，不作為閘門
	LastUsedAt *time.Time `json:"last_used_at"`
	LastUsedIP string     `gorm:"size:50;not null;default:''" json:"last_used_ip"`
	RevokedAt  *time.Time `gorm:"index:idx_api_tokens_user_revoked,priority:2" json:"revoked_at"`
	RevokedBy  *uint      `json:"revoked_by"`
	RevokeNote string     `gorm:"type:text;not null;default:''" json:"revoke_note"`
	// RestoreGeneration 建立當下的還原世代；與目前世代不同即視為已因還原失效
	RestoreGeneration string `gorm:"size:64;not null;default:''" json:"-"`
}

func (APIToken) TableName() string { return "api_tokens" }

// APITokenRole 一把 API token 建立時授權的角色（以角色識別為準，不以名稱）。
// 角色被刪除後列仍保留，有效權限由解析器以帳號當下的指派與此集合取交集。
type APITokenRole struct {
	APITokenID uint `gorm:"primaryKey;autoIncrement:false" json:"api_token_id"`
	RoleID     uint `gorm:"primaryKey;autoIncrement:false" json:"role_id"`
}

func (APITokenRole) TableName() string { return "api_token_roles" }
