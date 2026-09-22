package model

import (
	"gorm.io/gorm"
	"time"
)

type AgentTaskReport struct {
	ID              uint      `gorm:"primarykey" json:"id"`
	AccessRequestID uint      `gorm:"not null;uniqueIndex:idx_agent_task_reports_request_version,priority:1" json:"access_request_id"`
	UserID          uint      `gorm:"not null" json:"user_id"`
	Version         uint      `gorm:"not null;uniqueIndex:idx_agent_task_reports_request_version,priority:2" json:"version"`
	Body            string    `gorm:"type:text;not null" json:"body"`
	SubmittedAt     time.Time `gorm:"not null" json:"submitted_at"`
}

func (AgentTaskReport) TableName() string { return "agent_task_reports" }

func (*AgentTaskReport) BeforeUpdate(*gorm.DB) error { return gorm.ErrInvalidValue }
func (*AgentTaskReport) BeforeDelete(*gorm.DB) error { return gorm.ErrInvalidValue }
