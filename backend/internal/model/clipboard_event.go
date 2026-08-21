package model

import "time"

// ClipboardEvent RDP/VNC 剪貼簿內容留存（clipboard-audit）
type ClipboardEvent struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	SessionID uint      `gorm:"index;not null" json:"session_id"`
	Direction string    `gorm:"size:8;not null" json:"direction"` // send=入遠端, recv=回拷
	Content   string    `gorm:"type:text" json:"content"`         // 上限 64KB（tap 截斷）
	CreatedAt time.Time `json:"created_at"`
}
