package model

import "time"

// AgentToken stores only the SHA-256 digest; plaintext is never persisted.
type AgentToken struct {
	ID        uint   `gorm:"primarykey" json:"id"`
	UserID    uint   `gorm:"not null;index" json:"user_id"`
	Name      string `gorm:"size:100;not null" json:"name"`
	TokenHash string `gorm:"size:64;not null;uniqueIndex" json:"-"`
	CreatedBy uint   `gorm:"not null" json:"created_by"`
	// Current username for CreatedBy; read-only projection, not a stored name snapshot.
	CreatedByUsername string     `gorm:"-" json:"created_by_username,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `gorm:"not null" json:"expires_at"`
	LastUsedAt        *time.Time `json:"last_used_at"`
	RevokedAt         *time.Time `json:"revoked_at"`
	RevokedBy         *uint      `json:"revoked_by"`
	RevokeNote        string     `gorm:"type:text" json:"revoke_note"`
	SuspendedAt       *time.Time `json:"suspended_at"`
	SuspendedReason   string     `gorm:"type:text" json:"suspended_reason"`
	// RestoreGeneration 簽發當下的恢復世代；空＝簽發於 legacy 世代。
	RestoreGeneration string `gorm:"size:64;not null;default:''" json:"-"`
	// RestoreInvalidated 列表投影（不入庫）：簽發世代與目前還原世代不同，真實入口已拒絕這把鑰匙
	// （備份帶回的舊鑰匙即使資料列仍顯示有效）。只在為真時出現在回應，且僅 List 填入。
	RestoreInvalidated bool `gorm:"-" json:"restore_invalidated,omitempty"`
}

func (AgentToken) TableName() string { return "agent_tokens" }
