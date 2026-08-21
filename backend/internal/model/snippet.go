package model

import "time"

// Snippet 使用者命令片段（terminal-snippets）：
// user-scoped，內容僅作為文字注入終端輸入，不直接執行
type Snippet struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	UserID    uint      `gorm:"index;not null" json:"user_id"`
	Name      string    `gorm:"size:128;not null" json:"name"`
	Content   string    `gorm:"size:4096;not null" json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
