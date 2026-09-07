package model

import (
	"time"

	"gorm.io/gorm"
)

// AssetAccount 資產帳號：一資產多系統帳號，
// 各自持有加密憑證。既有 Asset 內嵌憑證由 migration 複製為一筆 IsDefault 帳號
// （密文原樣複製——信封密文自帶 DEK 版本前綴、無 AAD 列綁定，跨表可解）。
//
// default 語義：「至多一個 default」由 partial unique index
// (asset_id) WHERE is_default AND deleted_at IS NULL 於 DB 層強制（見 migrations.go
// 20260802_asset_accounts）；「有帳號必有 default」屬服務層交易式維護，不在 DB 層。
// 零帳號資產合法（原本即無憑證的資產）。
//
// 本表**不再持有任何密文**：登入秘密的落點是 credential_secret_versions，
// 掛載列只以 CredentialID／EffectiveVersionID 指向它。密文欄與其
// envelopeMigrationTargets 登記已於收縮階段一併卸下。
type AssetAccount struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	AssetID uint `gorm:"not null;index" json:"asset_id"`

	// CredentialID 本掛載所引用的憑證（見 credential.go）。
	// 登入帳號名與密文一律屬憑證，掛載列只回答「這台以哪筆憑證登入」。
	// 唯一鍵 (asset_id, credential_id) WHERE deleted_at IS NULL 於 DB 層強制
	// 「同一憑證不重複掛同一資產」
	CredentialID uint `gorm:"not null" json:"credential_id"`
	// EffectiveVersionID 該台當下用以連線的密文版本，**必須屬於 CredentialID 那筆憑證**。
	// 空＝該掛載尚未取得任何密文。
	//
	// **連線一律只取本欄**：不依憑證的現行或待生效版本推測、不自動試兩個版本
	// ——自動試兩版會製造鎖帳與秘密探測面。寫入時機依密文來源分流：操作者宣告的
	// 密文（建立、直接寫入、掛載、改綁）於同一交易立即設定；系統產生的密文
	// （改密輪替）只有在該台驗證成功的那一筆交易才改寫
	EffectiveVersionID *uint `json:"effective_version_id"`

	// Username 登入帳號名的顯示副本。
	// **真相在憑證**（credentials.username）：連線與改密一律以憑證上的名字為準，
	// 本欄由帳號服務同步維護，供尚未切換的讀取面與唯一索引 (asset_id, username) 沿用
	Username string `gorm:"size:100" json:"username"`

	// IsDefault 預設帳號：系統路徑（改密 runner、k8s、SFTP 側車）與未指定帳號的
	// 連線一律走此帳號；每資產至多一個（DB partial unique index）
	IsDefault bool `gorm:"default:false;index" json:"is_default"`
	// Privileged 特權帳號標記：純標示欄，供 UI 與審計辨識（如 root/sa），不改變授權判定
	Privileged bool `gorm:"default:false" json:"privileged"`

	// AuthMethod 認證類型：sql｜domain。
	// **真相在憑證**（credentials.auth_method）；本欄為同步維護的顯示副本。
	// **放帳號而非資產**——憑證屬帳號，且同一台 MSSQL 可同時掛 SQL login 與域帳號。
	// 1.0 只接受 sql；domain 為 schema 與連線層的預留，由驗證層明確拒絕
	// （回 VALIDATION_ACCOUNT_AUTH_METHOD_UNSUPPORTED，不靜默降級為 sql——
	// 靜默接受一個做不到的設定會讓管理員以為域認證已生效）。
	AuthMethod string `gorm:"size:20;default:sql" json:"auth_method"`

	Note string `gorm:"size:255" json:"note"`
}

// TableName 指定表名
func (AssetAccount) TableName() string {
	return "asset_accounts"
}
