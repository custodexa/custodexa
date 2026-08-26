package model

import "time"

// UserSourceIP 帳號 × 來源位址的「已見」基準（user_source_ips）。
//
// 它是新來源位址告警的**判定依據**，不是日誌、也不是防篡改證據（告警列與審計列
// 才是證據）；故**不在任何保留政策的清除目標內**——清除會讓舊位址回來時再被判為新。
// 表大小上界＝使用者數 × 相異位址數，每列只更新時間、不追加，無無界增長來源。
//
// FirstSessionAt／FirstSessionID 與 FirstSeenAt 分開追蹤：登入只把位址納入基準
// （FirstSeenAt），首次**建線**才設 FirstSessionAt 並取得告警資格。
// FirstSessionID 同時是並發首連線的單勝者判定鍵：條件更新只讓第一個提交者寫入，
// 回傳值等於自己 session id 者才發告警（詳見 modules/audit/source_ip_baseline.go）。
//
// 刻意無 FK（與 command_alerts 同取向）：軟刪使用者的列保留（可能重新啟用），
// 硬刪使用者的殘列惰性無害。
type UserSourceIP struct {
	UserID   uint   `gorm:"primaryKey;autoIncrement:false" json:"user_id"`
	ClientIP string `gorm:"primaryKey;size:50;index:idx_user_source_ips_ip_seen,priority:1" json:"client_ip"`
	// FirstSeenAt 首次見到（登入或建線皆算）
	FirstSeenAt time.Time `gorm:"not null" json:"first_seen_at"`
	// LastSeenAt 最近見到；候選查詢依此降序，故與 ClientIP 同在覆蓋索引內
	LastSeenAt time.Time `gorm:"not null;index:idx_user_source_ips_ip_seen,priority:2" json:"last_seen_at"`
	// FirstSessionAt 首次自此位址建線的時刻；NULL＝從未建線（只登入過）
	FirstSessionAt *time.Time `json:"first_session_at,omitempty"`
	// FirstSessionID 取得首次建線資格的會話 id；NULL＝尚無勝者
	FirstSessionID *uint `json:"first_session_id,omitempty"`
}

// TableName 指定表名
func (UserSourceIP) TableName() string {
	return "user_source_ips"
}
