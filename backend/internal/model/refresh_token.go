package model

import "time"

// RefreshToken 撤銷原因
const (
	RefreshRevokeRotated        = "rotated"         // 正常輪替：舊憑證作廢、鏈上有新憑證
	RefreshRevokeLogout         = "logout"          // 使用者登出
	RefreshRevokePasswordChange = "password_change" // 改密撤銷全部會話（8.3.5 語義延伸）
	RefreshRevokeDisabled       = "disabled"        // 帳號停用（admin）撤銷全部
	RefreshRevokeLocked         = "locked"          // 帳號自動鎖定撤銷全部（不砍協議會話）
	RefreshRevokeReuseDetected  = "reuse_detected"  // 已輪替憑證被重放 → 家族撤銷（RFC 9700）
	RefreshRevokeIdleTimeout    = "idle_timeout"    // 閒置逾政策窗口（8.2.8）
	RefreshRevokeExpired        = "expired"         // 逾絕對壽命
	// RefreshRevokeProviderDisabled provider 停用/刪除/密鑰輪替
	RefreshRevokeProviderDisabled = "provider_disabled"
	// RefreshRevokeCredentialEpoch 使用者憑證世代推進（解綁外部身分／改為僅外部登入等）
	RefreshRevokeCredentialEpoch = "credential_epoch"
)

// RefreshToken Web 會話 refresh 憑證（PCI 8.2.8）。
// 明文僅在發放當下回傳客戶端，資料庫只存 SHA-256；
// 刷新時輪替（舊列標 rotated、發新列），已輪替列再被提交視為憑證洩漏訊號，
// 撤銷該使用者全部 refresh（家族撤銷，RFC 9700）
type RefreshToken struct {
	ID        uint   `gorm:"primarykey" json:"id"`
	UserID    uint   `gorm:"not null;index" json:"user_id"`
	TokenHash string `gorm:"size:64;uniqueIndex;not null" json:"-"`

	// SessionStartedAt 絕對壽命錨點（登入時刻）；rotation 沿用不重置，
	// 確保持續刷新也無法超過 max session 上限
	SessionStartedAt time.Time `gorm:"not null" json:"session_started_at"`
	// ExpiresAt 絕對壽命（登入時刻 + web_max_session_hours；政策 0=不限時為遠期哨兵）
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	// LastUsedAt sliding 閒置錨點：發放與每次刷新時間（8.2.8 閒置判定基準）
	LastUsedAt time.Time `gorm:"not null" json:"last_used_at"`

	// 認證脈絡：記錄「本會話由哪個 provider、以何種方式建立」。
	//
	// rotation SHALL 原樣沿用此三欄——現行 rotation 只複製五個欄位，若不顯式沿用，
	// access token 到期輪替一次（分鐘級）後撤銷目標即失聯，provider 停用時
	// 「正在使用中的會話一個都撤不到」，且測試若寫成「登入後立刻停用」會恆綠而無效。
	//
	// 零值＝本地/LDAP 登入，不受任何 provider 停用影響（升級期既有列 backfill 為此）
	AuthMethod string `gorm:"size:32" json:"-"`
	ProviderID uint   `gorm:"index" json:"-"`
	AuthEpoch  int    `gorm:"not null;default:0" json:"-"`
	CredEpoch  int    `gorm:"not null;default:0" json:"-"`

	RevokedAt *time.Time `gorm:"index" json:"revoked_at,omitempty"`
	// RevokedReason 撤銷原因（RefreshRevoke* 常數），供審計與 reuse detection 判別
	RevokedReason string `gorm:"size:32" json:"revoked_reason,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}
