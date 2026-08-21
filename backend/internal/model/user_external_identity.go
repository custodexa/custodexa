package model

import (
	"time"

	"gorm.io/gorm"
)

// UserExternalIdentity 使用者的外部身分關聯（idp-oidc-integration D2）。
//
// 身分域鍵為 (Issuer, ClientID, Subject) 而非 ProviderID——身分歸屬於「issuer＋client_id」
// 這個外部事實，不是我方 provider 列的識別碼。以代理鍵當身分域會使 admin 誤刪重建
// provider 後全體使用者被鎖出（新 provider_id 使既有身分全數未命中，繼而撞名被拒）。
// ProviderID 僅記錄當前設定來源，登入查找一律以三元組為準。
//
// Subject 驗證規則（D2）：非空、長度上限、原值大小寫敏感比對、不做任何正規化——
// 空 subject 會使第一個異常 token 吸附該 provider 後續全部異常 token。
type UserExternalIdentity struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	UserID uint  `gorm:"not null;index" json:"user_id"`
	User   *User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// ProviderID 當前設定載體（非身分域鍵）。provider 軟刪後以同 tuple 重建時，
	// 身分仍可經三元組查回，此欄於下次登入修正指向
	ProviderID uint `gorm:"index" json:"provider_id"`

	// 身分域三元組：(Issuer, ClientID, Subject) 唯一索引
	Issuer   string `gorm:"size:500;not null" json:"issuer"`
	ClientID string `gorm:"size:255;not null" json:"client_id"`
	Subject  string `gorm:"size:255;not null" json:"subject"`

	// ClaimUsername / ClaimEmail 為 IdP 端自報值的快照，回訪時更新。
	//
	// 與 users 本體刻意分離：本體是授權主體識別（授權綁定、審計歸屬皆依它），
	// 回訪不得改寫；快照則是 IdP 現況的觀測值，供管理端辨識。
	// 快照內容完全由外部控制（低權使用者可把自己的 preferred_username 設為 "admin"），
	// 故 UI 顯示時必須標示為「身分提供者自報值」並與本地使用者名稱分欄，不得混排。
	// ClaimEmail 僅保存已驗證的 email，未驗證則留空。
	ClaimUsername string `gorm:"size:255" json:"claim_username"`
	ClaimEmail    string `gorm:"size:255" json:"claim_email"`

	// LastLoginAt 最近一次經此身分登入的時間
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// TableName 指定資料表名
func (UserExternalIdentity) TableName() string {
	return "user_external_identities"
}
