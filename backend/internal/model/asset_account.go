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
// 安全紅線：PasswordEnc/PrivateKeyEnc 必須登記於 keyvault 的
// envelopeMigrationTargets（internal/modules/keyvault/envelope_migration_service.go）
// ——該清單同時驅動 DEK 輪替重加密與退役金鑰
// 銷毀前的引用掃描，漏登會使銷毀前掃描看不見本表密文而誤判零引用。
// AST 守衛 envelope_targets_guard_test.go 會強制此約束。
type AssetAccount struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	AssetID  uint   `gorm:"not null;index" json:"asset_id"`
	Username string `gorm:"size:100" json:"username"`

	// 認證資訊（信封加密儲存，絕不出現於 JSON 與審計 Details）
	PasswordEnc   string `gorm:"type:text" json:"-"`
	PrivateKeyEnc string `gorm:"type:text" json:"-"`

	// IsDefault 預設帳號：系統路徑（改密 runner、k8s、SFTP 側車）與未指定帳號的
	// 連線一律走此帳號；每資產至多一個（DB partial unique index）
	IsDefault bool `gorm:"default:false;index" json:"is_default"`
	// Privileged 特權帳號標記：純標示欄，供 UI 與審計辨識（如 root/sa），不改變授權判定
	Privileged bool `gorm:"default:false" json:"privileged"`

	// AuthMethod 認證類型：sql｜domain。
	// **放帳號而非資產**——憑證屬帳號，且同一台 MSSQL 可同時掛 SQL login 與域帳號。
	// 1.0 只接受 sql；domain 為 schema 與連線層的預留，由驗證層明確拒絕
	// （回 VALIDATION_ACCOUNT_AUTH_METHOD_UNSUPPORTED，不靜默降級為 sql——
	// 靜默接受一個做不到的設定會讓管理員以為域認證已生效）。
	AuthMethod string `gorm:"size:20;default:sql" json:"auth_method"`

	Note string `gorm:"size:255" json:"note"`

	// CredentialGroup 憑證群組識別（UUID）：同值＝系統已知這些帳號共用同一組
	// 憑證。空＝不屬於任何群組。
	//
	// **只由兩條路徑寫入**：以「從其他帳號複製」建號時，來源與新帳號同交易歸入
	// 同一群組；帳號經系統改密成功並提交新憑證時脫離群組（脫離後群組只剩一員時
	// 該員一併脫離）。管理者手動編輯憑證**不動**此欄——手動輸入的憑證是否仍與
	// 他人共用，系統無從判定，改動它等於宣稱一件不知道的事。
	//
	// **不出站**：對外只投影成「共用憑證」布林（見 asset 模組的帳號 DTO）。
	// 群組識別本身是一組帳號之間的連結關係，揭露它等於免費提供「哪些帳號共用
	// 憑證」的完整拓撲，而那正是橫向移動最想要的那張圖。
	CredentialGroup string `gorm:"size:36;index" json:"-"`
}

// TableName 指定表名
func (AssetAccount) TableName() string {
	return "asset_accounts"
}
