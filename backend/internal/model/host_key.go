package model

import "time"

// AssetHostKey 資產的 SSH host key 記錄（host-key-verification）：
// TOFU——首連記錄，之後指紋不符即拒線
type AssetHostKey struct {
	ID          uint      `gorm:"primarykey" json:"id"`
	AssetID     uint      `gorm:"uniqueIndex;not null" json:"asset_id"`
	Algorithm   string    `gorm:"size:64;not null" json:"algorithm"`
	Fingerprint string    `gorm:"size:128;not null" json:"fingerprint"` // SHA256:xxx 格式
	PublicKey   string    `gorm:"type:text;not null" json:"-"`          // base64 公鑰本體不外露
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
