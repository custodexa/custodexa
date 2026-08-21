package model

import (
	"time"

	"gorm.io/gorm"
)

// LDAPDirectory LDAP 目錄設定（ldap-settings-migration D1）。
//
// **設定面自 env 遷入 DB**：本表取代 `config.LDAPConfig` 成為執行期唯一事實源，
// 由 admin 於身分管理 UI 以 singleton 資源維護（GET／PUT upsert／DELETE）。
//
// **帶 id 的資料列而非單列固定表**：把「主目錄＋HA 備援」攤成同一列裡的兩套重複
// 欄位，是不做資料模型的代價；帶 id 的列使未來多目錄只需解除單列限制＋補身分歸屬，不需 schema
// 重做。單列限制由 DB 層守衛：`singleton` 欄 ＋ `CHECK (singleton = 1)` ＋
// partial unique index `(singleton) WHERE deleted_at IS NULL`——**CHECK 不可省**，
// 單靠 unique index 只禁止相同值重複，`singleton=1` 與 `singleton=2` 仍可並存。
// 軟刪列不佔 singleton，刪除後可重建。
//
// **建表走 baseline，CHECK 就在建表語句裡**（migration-baseline-compression D3）：
// 表由 `database.baselineIdentityTables` 的 `CREATE TABLE ldap_directories` 建立，
// `CONSTRAINT ldap_directories_singleton_check CHECK ((singleton = 1))` 是該語句的
// 一部分，partial unique index 則在同域的 `baselineIdentityIndexes`
// （皆見 internal/database/baseline_schema_identity.go）。
// 壓縮前本 model 刻意排除於開機 AutoMigrate 清單之外（GORM 不產出 inline CHECK，
// 先被建出的表會讓 migration 的 `CREATE TABLE IF NOT EXISTS` 靜默略過而 CHECK 在
// 生產缺席）；AutoMigrate 自產品程式碼移除後該排除失去對象，本 model 現正常列於
// `database.schemaParityModels`——來龍去脈記在 internal/database/database.go 該項旁。
//
// **單列語義的現行保護者有三條**（改 baseline 前先確認它們會紅）：
//
//	TestBaselineStructuralInvariantsPostgres        逐條比對 CHECK 定義文字，不只驗存在
//	TestLDAPDirectoriesSingletonConstraintsPostgres 行為層實證：singleton=2 須被 DB 拒
//	TestNoAutoMigrateInProductionCode               產品程式碼零 AutoMigrate（原排除理由的根因）
//
// 前兩條需要 PG（未設 `TEST_PG_DSN` 即 skip，`REQUIRE_INTEGRATION=1` 時 skip 轉 fail），
// 第三條是純 AST 掃描、無前置條件。
//
// 安全紅線：BindPasswordEnc 必須登記於 keyvault 的 envelopeMigrationTargets
// （envelope_migration_service.go）與 cipher_refs.go——該清單同時驅動 DEK 輪替重加密
// 與退役金鑰銷毀前的引用掃描，漏登會使銷毀前掃描看不見本表密文而誤判零引用。
// AST 守衛 envelope_targets_guard_test.go 強制此約束。
type LDAPDirectory struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Singleton 單列守衛欄；恆為 1，由 DB 的 CHECK 與 partial unique index 保證。
	// 不對外暴露（json:"-"）——它是 schema 層的不變式載體，非業務欄位
	Singleton int `gorm:"not null;default:1" json:"-"`

	// Name 管理端顯示名
	Name string `gorm:"size:100;not null;default:''" json:"name"`

	// URL 目錄伺服器位址；僅接受 origin 形狀 `ldap[s]://host[:port]`
	// （拒 userinfo/path/query/fragment，見 D3；服務層驗證於後續批次）
	URL string `gorm:"size:500;not null;default:''" json:"url"`
	// BindDN service bind 帳號 DN
	BindDN string `gorm:"size:500;not null;default:''" json:"bind_dn"`
	// BindPasswordEnc service bind 密碼（信封加密）。write-only：任何讀取回應
	// 皆不含此欄，改回 `has_bind_password` 布林旗標
	BindPasswordEnc string `gorm:"type:text;not null;default:''" json:"-"`

	// BaseDN 使用者搜尋起點
	BaseDN string `gorm:"size:500;not null;default:''" json:"base_dn"`
	// UserFilter 使用者搜尋 filter；`%s` 佔位恰一次且不得位於 OR／NOT 之下
	// （結構驗證於後續批次）
	UserFilter string `gorm:"size:500;not null;default:''" json:"user_filter"`
	// AttrEmail 電子郵件屬性名
	AttrEmail string `gorm:"size:100;not null;default:''" json:"attr_email"`
	// AttrFullName 顯示名屬性名（欄名刻意為 attr_fullname，與 env 鍵
	// LDAP_ATTR_FULLNAME 同形，非 GORM 預設的 attr_full_name）
	AttrFullName string `gorm:"column:attr_fullname;size:100;not null;default:''" json:"attr_fullname"`

	// SkipTLSVerify 跳過 TLS 憑證驗證；傳輸安全框架將其視為一級風險項
	// （RiskLDAPSkipVerify），存檔閘與清冊皆會浮現
	SkipTLSVerify bool `gorm:"not null;default:false" json:"skip_tls_verify"`
	// Enabled 啟用狀態；停用即等同「LDAP 未設定」語義（登入路徑不撥號）
	Enabled bool `gorm:"not null;default:false" json:"enabled"`
}

// TableName 指定資料表名
func (LDAPDirectory) TableName() string {
	return "ldap_directories"
}
