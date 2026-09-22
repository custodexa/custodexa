package model

import "time"

// AgentToken stores only the SHA-256 digest; plaintext is never persisted.
type AgentToken struct {
	ID              uint       `gorm:"primarykey" json:"id"`
	UserID          uint       `gorm:"not null;index" json:"user_id"`
	Name            string     `gorm:"size:100;not null" json:"name"`
	TokenHash       string     `gorm:"size:64;not null;uniqueIndex" json:"-"`
	CreatedBy       uint       `gorm:"not null" json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `gorm:"not null" json:"expires_at"`
	LastUsedAt      *time.Time `json:"last_used_at"`
	RevokedAt       *time.Time `json:"revoked_at"`
	RevokedBy       *uint      `json:"revoked_by"`
	RevokeNote      string     `gorm:"type:text" json:"revoke_note"`
	SuspendedAt     *time.Time `json:"suspended_at"`
	SuspendedReason string     `gorm:"type:text" json:"suspended_reason"`
}

func (AgentToken) TableName() string { return "agent_tokens" }
