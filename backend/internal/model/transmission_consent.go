package model

import "time"

// TransmissionConsent 傳輸風險同意記錄（transmission-security-policy D3）：
// per user×資產一列（唯一索引冪等更新）。不存 expires_at——效期以
// consented_at＋政策 TTL 讀時動態判定，政策改動立即全域生效；
// 失效另靠 risk_fingerprint 比對（資產傳輸屬性變更即不符，同意自然作廢）
type TransmissionConsent struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	UserID  uint `gorm:"not null;uniqueIndex:idx_consent_user_asset" json:"user_id"`
	AssetID uint `gorm:"not null;uniqueIndex:idx_consent_user_asset;index" json:"asset_id"`

	// RiskFingerprint 同意當下風險項集合的確定性雜湊（sha256 hex）
	RiskFingerprint string `gorm:"size:64;not null" json:"risk_fingerprint"`
	// RiskItems 同意當下的風險項清單（JSON，含 key 與 label——稽核可讀）
	RiskItems string `gorm:"type:text;not null" json:"risk_items"`
	// ConsentedAt 最近一次同意時間（重複同意冪等刷新）
	ConsentedAt time.Time `gorm:"not null" json:"consented_at"`
}

// TableName 指定表名
func (TransmissionConsent) TableName() string {
	return "transmission_consents"
}
