package model

import "time"

// AgentVisibilityExposure records disclosed identifiers, not historical authorization.
type AgentVisibilityExposure struct {
	UserID      uint      `gorm:"primaryKey;autoIncrement:false"`
	AssetID     uint      `gorm:"primaryKey;autoIncrement:false"`
	FirstSeenAt time.Time `gorm:"not null"`
	LastSeenAt  time.Time `gorm:"not null"`
}

func (AgentVisibilityExposure) TableName() string { return "agent_visibility_exposures" }
