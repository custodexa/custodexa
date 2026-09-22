package model

import "time"

const (
	ProbeNeverVisible = "never_visible"
	ProbeRevoked      = "revoked"
	ProbeRetired      = "retired"
)

type AgentProbeEvent struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	UserID       uint      `gorm:"not null;index:idx_agent_probe_events_user_class_created,priority:1" json:"user_id"`
	AgentTokenID uint      `gorm:"not null" json:"agent_token_id"`
	AssetRef     uint      `gorm:"not null" json:"asset_ref"`
	Endpoint     string    `gorm:"size:255;not null" json:"endpoint"`
	Class        string    `gorm:"size:16;not null;index:idx_agent_probe_events_user_class_created,priority:2" json:"class"`
	CreatedAt    time.Time `gorm:"not null;index:idx_agent_probe_events_user_class_created,priority:3" json:"created_at"`
}

func (AgentProbeEvent) TableName() string { return "agent_probe_events" }
