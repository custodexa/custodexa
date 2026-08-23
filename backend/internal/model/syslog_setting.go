package model

import "time"

// syslog 傳輸協議
const (
	SyslogProtocolUDP    = "udp"
	SyslogProtocolTCP    = "tcp"
	SyslogProtocolTCPTLS = "tcp+tls"
)

// SyslogSetting syslog 轉發設定（PCI 10.3.3）。
// 單列表（ID 恆為 1）：目的地含 TLS CA PEM 等結構化欄位，
// 不適合塞進 security_policies 的 key-value（value 上限 128 字元），
// 故獨立存放；UI 仍呈現於安全政策頁「日誌保留與轉發」區塊
type SyslogSetting struct {
	ID      uint   `gorm:"primarykey" json:"id"`
	Enabled bool   `gorm:"not null;default:false" json:"enabled"`
	Host    string `gorm:"type:varchar(255);not null;default:''" json:"host"`
	Port    int    `gorm:"not null;default:514" json:"port"`
	// Protocol udp / tcp / tcp+tls
	Protocol string `gorm:"type:varchar(10);not null;default:'udp'" json:"protocol"`
	// TLSCA 驗證 syslog 伺服器憑證的 CA（PEM）；空 = 用系統信任庫
	TLSCA     string    `gorm:"type:text;not null;default:''" json:"tls_ca"`
	UpdatedBy string    `gorm:"type:varchar(100)" json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (SyslogSetting) TableName() string {
	return "syslog_settings"
}
