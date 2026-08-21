package model

import "time"

// OIDCFlowState 登入流程的伺服端狀態（idp-oidc-integration D4）。
//
// 本系統無 server-side session（純 JWT），故 state/nonce/PKCE verifier 落庫。
// 一次性消費：callback 以 state 查表並於單一原子操作中「僅在未過期時取用並失效」——
// 過期記錄即使清理排程尚未執行亦須拒絕（排程延遲不得擴大有效窗口）。
//
// BindingHash 是瀏覽器綁定（D4）：DB 保存 state 只證明「伺服器簽發且未用過」，
// 不證明 callback 發生在發起的瀏覽器。攻擊者可自行發起流程、以自己的 IdP 帳號完成授權
// 但攔住 callback，再把該 URL 交給受害者——state/nonce/PKCE 全部有效，受害者會被登入
// 攻擊者帳號（login CSRF），其後操作與審計全歸屬錯誤。故發起端產生 secret 存
// sessionStorage，begin 只送其雜湊，兌換時須提出原文。
//
// 刻意不帶使用者憑證世代：begin 階段尚未認證、不知使用者是誰。使用者世代自
// callback（身分確定後）簽發的 login ticket 起才進入憑證鏈。
type OIDCFlowState struct {
	// State 隨機值，同時為主鍵
	State string `gorm:"primarykey;size:64" json:"-"`

	Nonce        string `gorm:"size:64;not null" json:"-"`
	PKCEVerifier string `gorm:"size:128;not null" json:"-"`

	ProviderID uint `gorm:"not null;index" json:"provider_id"`
	// AuthEpoch 簽發當下的 provider 世代；callback 比對現行值，涵蓋
	// 「begin 之後、callback 之前 provider 被停用（並可能已重新啟用）」的窗口
	AuthEpoch int `gorm:"not null;default:0" json:"-"`

	// BindingHash 發起端瀏覽器 secret 的 SHA256
	BindingHash string `gorm:"size:64;not null" json:"-"`

	// RedirectNext 登入後導向目標；限同源相對路徑且須符合既有路由白名單，
	// 於 begin 時即驗證，並隨 ticket 傳遞（flow state 在 callback 時已被消費）
	RedirectNext string `gorm:"size:255" json:"-"`

	ExpiresAt time.Time `gorm:"not null;index" json:"-"`
	CreatedAt time.Time `json:"-"`
}

// TableName 指定資料表名
func (OIDCFlowState) TableName() string {
	return "oidc_flow_states"
}

// OIDCLoginTicket callback 至 SPA 的一次性交棒憑證（idp-oidc-integration D5）。
//
// callback 是瀏覽器對後端的 GET，無法直接回傳 JSON 形式的登入回應；而把 token 放進
// URL 會落入瀏覽器歷史與反向代理日誌。故 callback 完成全部驗證後產生本憑證，
// 以 URL fragment 交給 SPA（fragment 不送伺服器），SPA 讀取後立即以 replaceState 抹除，
// 再經 exchange 端點換取與一般登入完全同形的回應（含 MFA 分支）。
//
// DB 僅存雜湊；綁定不符時不消耗但累計失敗次數，達三次作廢——「消耗」與
// 「請回到原分頁重試」互斥（ticket 已被落錯的分頁消耗掉就救不回來）。
type OIDCLoginTicket struct {
	// TokenHash 交棒憑證的 SHA256，同時為主鍵（明文不落庫、不進日誌）
	TokenHash string `gorm:"primarykey;size:64" json:"-"`

	UserID     uint `gorm:"not null;index" json:"-"`
	ProviderID uint `gorm:"not null;index" json:"-"`

	// AuthEpoch / CredEpoch 簽發當下的 provider 與使用者世代，兌換時並列比對。
	// 兩者缺一即留下該類憑證的復活窗口
	AuthEpoch int `gorm:"not null;default:0" json:"-"`
	CredEpoch int `gorm:"not null;default:0" json:"-"`

	// AuthMethod 本次認證方式，隨會話全鏈傳遞（決定密碼類 gate 是否適用、審計標註）
	AuthMethod string `gorm:"size:32;not null" json:"-"`

	// FlowBindingHash 自 flow state 承接的瀏覽器綁定雜湊
	FlowBindingHash string `gorm:"size:64;not null" json:"-"`

	// RedirectNext 已驗證的登入後導向目標；兌換成功後回傳給 SPA，
	// 不得於兌換階段重新採信前端提交值
	RedirectNext string `gorm:"size:255" json:"-"`

	// BindingFailures 綁定不符的累計次數；以單一條件式 UPDATE 原子遞增，
	// 達三次即作廢，與成功兌換互斥
	BindingFailures int `gorm:"not null;default:0" json:"-"`

	ExpiresAt time.Time `gorm:"not null;index" json:"-"`
	CreatedAt time.Time `json:"-"`
}

// TableName 指定資料表名
func (OIDCLoginTicket) TableName() string {
	return "oidc_login_tickets"
}
