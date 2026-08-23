package model

import (
	"time"

	"gorm.io/gorm"
)

// AdmissionMode OIDC provider 的准入模式
type AdmissionMode string

const (
	// AdmissionPreboundOnly 僅允許已綁定外部身分者登入；不自動供應帳號（出廠預設，fail-close）
	AdmissionPreboundOnly AdmissionMode = "prebound_only"
	// AdmissionJITWithRules 允許自動供應，但每次認證都須通過 admission_rules 判定
	AdmissionJITWithRules AdmissionMode = "jit_with_rules"
)

// OIDCProvider OIDC 身分提供者設定（多實例並存）。
//
// 身分域不可變：Issuer 與 ClientID 建立後不可變更，且由服務層強制——
// 外部身分以 (issuer, client_id, subject) 為鍵，變更任一即等同換身分域，
// 會使既有使用者全部無法對應。Entra 的 sub 為 per-application pairwise，
// 換 ClientID 後同一人會拿到不同 subject，此約束因而是硬需求而非潔癖。
//
// 生命週期為原地治理：secret 輪替、停用/重新啟用、改顯示名皆原地更新；
// 有外部身分關聯者不可刪除（服務層回 409），僅能停用。
//
// 安全紅線：ClientSecretEnc 必須登記於 keyvault 的 envelopeMigrationTargets
// （internal/modules/keyvault/envelope_migration_service.go）——
// 該清單同時驅動 DEK 輪替重加密與退役金鑰銷毀前的引用掃描，漏登會使銷毀前
// 掃描看不見本表密文而誤判零引用。AST 守衛 envelope_targets_guard_test.go 強制此約束。
type OIDCProvider struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Name 管理端與登入頁顯示名（使用者看到的按鈕文字）
	Name string `gorm:"size:100;not null" json:"name"`

	// Issuer OIDC 簽發者 URL；endpoint 由執行期 discovery 解析，不落庫。
	// 與 ClientID 組成唯一鍵（partial unique index，排除軟刪列）
	Issuer string `gorm:"size:500;not null" json:"issuer"`
	// ClientID 用戶端識別；與 Issuer 同為身分域組成，建後不可變
	ClientID string `gorm:"size:255;not null" json:"client_id"`
	// ClientSecretEnc 用戶端密鑰（信封加密）。write-only：任何讀取回應皆不含此欄
	ClientSecretEnc string `gorm:"type:text" json:"-"`

	// Scopes 授權請求的 scope（空白分隔）。服務層強制注入 openid，
	// 附加項限允許清單（profile/email），未知 scope 於設定時即拒絕
	Scopes string `gorm:"size:255;not null;default:'openid profile email'" json:"scopes"`

	// AdmissionMode 准入模式；出廠 prebound_only（不自動供應）
	AdmissionMode AdmissionMode `gorm:"size:32;not null;default:'prebound_only'" json:"admission_mode"`
	// AdmissionRules 准入規則集（JSON）。規則鍵封閉，未知鍵於 CRUD 即拒絕；
	// 跨規則 AND、清單內 OR；claim 缺失/型別不符一律不匹配
	AdmissionRules string `gorm:"type:text" json:"admission_rules"`

	// ForceShared 管理者的收緊意圖（三值：nil=未表態、true=強制視為共用身分域）。
	//
	// 刻意用 *bool 且不加 default tag：GORM 對帶 default tag 的欄位遇零值會交由 DB
	// 填 default，bool 的 false 即零值，顯式寫 false 會被覆寫（已於真 postgres 實測）。
	// 三值語義用指標表達，nil 與 false 才能區分。
	//
	// effective issuer kind 不持久化，每次以固定優先序現算：
	// 內建共用清單 > ForceShared > 部署層 OIDC_DEDICATED_ISSUERS > 未知（一律共用）
	ForceShared *bool `gorm:"column:force_shared" json:"force_shared,omitempty"`

	// AuthEpoch provider 級憑證世代（單調遞增）。停用與 secret 輪替時推進，
	// 重新啟用不回退——使「停用後短時間重新啟用」不會復活攻擊者手上的既簽憑證。
	// 所有由此 provider 認證簽發的憑證記錄簽發當下值，驗證時比對現行值
	AuthEpoch int `gorm:"not null;default:0" json:"auth_epoch"`

	// Enabled 啟用狀態；停用即觸發全面失效流程（推進世代→撤憑證→終斷連線與訂閱）
	Enabled bool `gorm:"not null;default:false" json:"enabled"`
}

// TableName 指定資料表名
func (OIDCProvider) TableName() string {
	return "oidc_providers"
}
