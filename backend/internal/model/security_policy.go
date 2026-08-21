package model

import "time"

// SecurityPolicy 安全政策（key-value 儲存，auth-hardening D1）。
// 政策值一律以字串存放，型別語義由 service 層常數表（PolicyDef）定義；
// 無對應列時以常數表出廠預設值生效，故 seed 不需預先物化政策列
type SecurityPolicy struct {
	Key       string    `gorm:"primaryKey;size:64" json:"key"`
	Value     string    `gorm:"size:128;not null" json:"value"`
	UpdatedBy string    `gorm:"size:100" json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (SecurityPolicy) TableName() string {
	return "security_policies"
}

// PasswordHistory 密碼歷史（PCI 8.3.7，auth-hardening D3/D12）。
// 每次設定密碼（建立帳號/seed/自助改密/admin 重設）都寫入一筆，
// 改密時 bcrypt 逐筆比對近 N 筆拒絕重用；初始密碼也入表，
// 否則首次強制改密可設回原密碼（D12）
type PasswordHistory struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	UserID       uint      `gorm:"not null;index" json:"user_id"`
	PasswordHash string    `gorm:"not null" json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// TableName 指定表名
func (PasswordHistory) TableName() string {
	return "password_histories"
}
