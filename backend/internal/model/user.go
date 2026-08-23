package model

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// 認證來源常數（登入審計標註用，同時作為 users.provisioning_origin 值域）
const (
	// AuthSourceLocal 本地帳密認證
	AuthSourceLocal = "local"
	// AuthSourceLDAP LDAP 目錄認證
	AuthSourceLDAP = "ldap"
	// AuthSourceOIDC OIDC 身分提供者認證
	AuthSourceOIDC = "oidc"
)

// User 使用者模型
type User struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Username string `gorm:"uniqueIndex;not null;size:50" json:"username"`
	// Email 未知以 NULL 表達（非空字串）；唯一性僅約束非 NULL 值。
	// LDAP 供應遇 email 衝突時存 NULL，允許多個無 email 影子帳號並存
	Email    *string `gorm:"uniqueIndex;size:100" json:"email"`
	Password string  `gorm:"not null" json:"-"` // bcrypt hashed password
	FullName string  `gorm:"size:100" json:"full_name"`
	Active   bool    `gorm:"default:true" json:"active"`

	// LocalDisplayName 使用者自助顯示名：初始 NULL、
	// 不由 username/full_name/IdP 初始化、無唯一性約束；trim 後空字串寫回 NULL。
	// 僅用於裝飾/自我檢視場景，身分敏感場景一律 username（安全紅線）
	LocalDisplayName *string `gorm:"size:100" json:"local_display_name"`

	// LDAP 使用者標記
	IsLDAP bool `gorm:"default:false" json:"is_ldap"`

	// 身分三分：單一欄位無法同時承擔「帳號怎麼來的」、
	// 「能不能用本地密碼」、「本次怎麼登入的」三種判定——admin 把外部身分綁到既有
	// 本地帳號後即自相矛盾（判 local 則 OIDC 登入被密碼 gate 擋、判 oidc 則本地密碼
	// 登入跳過 gate）。故拆為：供應來源（本欄，不可變）、憑證外部化（下欄）、
	// 本次登入方式（執行期值，隨流程傳遞不落庫）。

	// ProvisioningOrigin 供應來源（local/ldap/oidc）：建立時寫入後不可變，
	// 僅供顯示、審計與統計，不參與授權判定
	ProvisioningOrigin string `gorm:"size:16;not null;default:'local'" json:"provisioning_origin"`

	// ExternalCredential 憑證由外部提供者管理，禁止一切本地密碼路徑。
	//
	// 語義刻意是「外部化＝true」而非「有本地密碼＝true」（於真 postgres 實測確認）：
	// GORM 對帶 default tag 的欄位遇零值會交由 DB 填 default，bool 的 false 即零值，
	// 故 `default:true` 的欄位顯式寫 false 會被覆寫成 true（連記憶體 struct 一併回寫，
	// db.Select 亦擋不住）。若採「有本地密碼」語義，所有影子帳號會靜默存成 true，
	// 密碼守衛全數空轉、LDAP 帳號還會被改判本地 bcrypt 路徑而登入全滅。
	// 反轉後零值（false）＝本地帳號＝多數情形，外部帳號寫 true（非零，必寫入）。
	ExternalCredential bool `gorm:"default:false" json:"external_credential"`

	// AuthProviderNames 該帳號已綁定的 OIDC provider 實例名（非持久化，列表查詢時填充）。
	//
	// 使用者列表的「來源」欄需要的是**實例名**（「Azure AD」「Okta」）而非籠統的
	// 「OIDC」——多 provider 並存下，「這個人從哪個 IdP 來」才是管理者要看的資訊。
	// 以 `gorm:"-"` 避免污染 schema：它是查詢時組出的視圖資料，不是帳號的屬性
	AuthProviderNames []string `gorm:"-" json:"auth_provider_names,omitempty"`

	// CredentialEpoch 使用者級憑證世代（單調遞增）。
	//
	// provider 級的 AuthEpoch 只能涵蓋「與某 provider 有關」的失效；下列操作與
	// provider 無關卻同樣必須使既有憑證失效，故需本欄：解除外部身分綁定（否則
	// 尚未兌換的 ticket／MFA pending／connect grant 可於撤銷掃描完成後才兌換，
	// 且身分重新綁回時舊憑證會復活）、帳號停用/刪除（監看訂閱不建 session 列且
	// providerID=0，按-provider 收線掃不到）、改為僅外部登入（清密碼卻不撤憑證，
	// 且已進入 MFA 待驗證者可於轉換後完成並因帳號已外部化而跳過密碼 gate）、改密。
	//
	// 自動鎖定刻意不推進：鎖定可由未認證第三方觸發（連續打錯密碼），既有設計
	// 明訂「協議會話不砍，避免鎖定成為遠端斷線武器」，推進世代會使其立即失效。
	//
	// 換發路徑一律簽發當下現查此值，不得繼承來源憑證——改密會推進世代，繼承舊值
	// 會使換發的 token 立即失效，強制改密者將永久卡在改密迴圈。
	CredentialEpoch int `gorm:"not null;default:0" json:"-"`

	// MFA (TOTP)：secret 以 AES 加密儲存，永不輸出至 JSON
	TOTPSecretEnc string `gorm:"size:512" json:"-"`
	TOTPEnabled   bool   `gorm:"default:false" json:"totp_enabled"`
	// TOTPLastStep 最後成功消耗的 TOTP time-step 索引（⌊unix/30⌋，PCI 8.5.1 防重放）：
	// 驗證僅接受 step > 此值，並以條件 UPDATE（CAS）原子推進，擋同碼跨 skew 窗重放
	TOTPLastStep *uint64 `json:"-"`

	// 帳號鎖定（PCI 8.3.4）：
	// 密碼失敗與 TOTP 失敗共用同一計數；locked_until 到期放行時計數一併歸零
	FailedLoginAttempts int        `gorm:"default:0" json:"-"`
	LockedUntil         *time.Time `json:"locked_until,omitempty"`

	// 強制改密（PCI 8.3.5/2.2.2）：
	// seed admin 預設 true；admin 重設後依政策 force_change_on_reset 設 true
	MustChangePassword bool       `gorm:"default:false" json:"must_change_password"`
	PasswordChangedAt  *time.Time `json:"password_changed_at,omitempty"`

	// 最後成功登入時間（登入成功時更新；閒置停用判定 8.2.6 據此）
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`

	// 閒置帳號自動停用豁免（PCI 8.2.6）：
	// per-user 永久有效豁免旗標；seed admin 預設豁免，避免唯一管理員因久未登入被自動停用鎖死系統
	InactivityExempt bool `gorm:"default:false" json:"inactivity_exempt"`

	// 關聯
	Roles []Role `gorm:"many2many:user_roles;" json:"roles,omitempty"`
	// 授權分組成員資格（與 Roles 正交，不影響端點權限）
	Groups []UserGroup `gorm:"many2many:user_group_members;" json:"groups,omitempty"`
}

// TableName 指定表名
func (User) TableName() string {
	return "users"
}

// DisplayName 集中的顯示名 resolver（單一事實源）：
// local_display_name || full_name || username——取第一個 trim 後非空者。
// 各消費端（UserInfo.display_name）一律走此方法，前後端不各寫 fallback 鏈。
// 僅供裝飾/自我檢視場景；身分敏感場景一律用 Username（安全紅線）
func (u *User) DisplayName() string {
	if u.LocalDisplayName != nil {
		if s := strings.TrimSpace(*u.LocalDisplayName); s != "" {
			return s
		}
	}
	if s := strings.TrimSpace(u.FullName); s != "" {
		return u.FullName
	}
	return u.Username
}

// IsExternal 帳號的憑證是否由外部提供者管理。
//
// fail-secure 三訊號取聯集：任一指出外部即視為外部。單欄漂移（例如 migration
// 半途、或某個建號路徑漏設欄位）因此不會打開本地密碼路徑，也不會誤把 LDAP
// 影子帳號判成本地帳號而讓它落入 bcrypt 比對。
//
// 所有密碼類判定（自助改密、admin 重設、本地登入分派、封印解封的初始管理員
// 驗證）一律經此方法，不得直讀單一欄位。
func (u *User) IsExternal() bool {
	return u.ExternalCredential || u.IsLDAP ||
		(u.ProvisioningOrigin != "" && u.ProvisioningOrigin != AuthSourceLocal)
}

// EmailString 以字串回傳 email，NULL（未知）回空字串。
// UserInfo/JWT 等既有以字串傳遞 email 的邊界統一經此 deref，避免 nil 解參
func (u *User) EmailString() string {
	if u.Email == nil {
		return ""
	}
	return *u.Email
}
