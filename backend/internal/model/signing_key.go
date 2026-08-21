package model

import "time"

// ExportSigningKey 稽核證據匯出的 Ed25519 簽章金鑰（audit-log-compliance，
// PCI 10.3.4；收叢集 D backlog F5）。單列表（ID 恆為 1）：
// 私鑰以 AES（資產憑證同一把 ENCRYPTION_KEY）加密存放；
// 公鑰以 base64 明文存放供下載端點直接回傳
type ExportSigningKey struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	PrivateKeyEnc string    `gorm:"type:text;not null" json:"-"`
	PublicKey     string    `gorm:"type:varchar(64);not null" json:"public_key"`
	CreatedAt     time.Time `json:"created_at"`
}

// TableName 指定表名
func (ExportSigningKey) TableName() string {
	return "export_signing_keys"
}
