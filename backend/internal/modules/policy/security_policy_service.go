package policy

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 政策鍵常數（後續階段的鍵於各自實作時加入常數表）
const (
	PolicyLockoutMaxAttempts     = "lockout_max_attempts"
	PolicyLockoutDurationMinutes = "lockout_duration_minutes"
	PolicyPasswordMinLength      = "password_min_length"
	PolicyPasswordRequireAlnum   = "password_require_alnum"
	PolicyPasswordHistoryCount   = "password_history_count"
	PolicyPasswordMaxAgeDays     = "password_max_age_days"
	PolicyForceChangeOnReset     = "force_change_on_reset"
	PolicyMFARequired            = "mfa_required"
	PolicyWebIdleMinutes         = "web_idle_minutes"
	PolicyWebMaxSessionHours     = "web_max_session_hours"
	// PolicyRefreshCookieSecure refresh cookie 是否標記 Secure
	//（決策 8）：值即該 cookie 的 `Secure` 屬性本身，
	// 故用「屬性語句」型命名而非 `_enabled` 尾綴（那是功能開關的慣例）。
	// **無合規建議值**：正確取值由部署對外協定決定（https 開、刻意明文關），
	// 不是合規基準線——掛建議值會讓「套用本頁建議值」把明文部署翻成開啟，
	// 製造整站使用者的續期失敗
	PolicyRefreshCookieSecure = "refresh_cookie_secure"
	PolicySessionIdleMinutes  = "session_idle_minutes"
	PolicySessionMaxMinutes   = "session_max_minutes"
	PolicyInactiveDisableDays = "inactive_disable_days"

	// PolicyAssetSecretMaxAgeDays 資產帳號憑證的最長使用天數（全域預設）。
	//
	// **作用對象是資產帳號，不是平台使用者**——後者由
	// PolicyPasswordMaxAgeDays 管，兩者互不影響。本鍵不會使任何人被要求改密：
	// 它只是輪替證據報告判定「逾期」的基準線，改密的實際執行仍由改密計劃負責。
	// 改密計劃可逐一覆蓋此天數（計劃層 0＝沿用本鍵）。
	//
	// 出廠 0＝關閉（升級零行為變更）。關閉時報告照常產出，適用天數欄顯示
	// 未設定、逾期無從判定——那本身就是稽核要看見的發現，不該以擋住報告代替。
	PolicyAssetSecretMaxAgeDays = "asset_secret_max_age_days"

	// 日誌保留與審閱政策鍵（PCI Req 10）
	PolicyRetentionAuditLogDays       = "retention_audit_log_days"
	PolicyRetentionSessionCommandDays = "retention_session_command_days"
	PolicyRetentionAlertDays          = "retention_alert_days"
	PolicyRetentionRecordingDays      = "retention_recording_days"
	// PolicyOffsiteLocalRetentionDays 離機儲存啟用後，本機錄影副本的**快取期**。
	//
	// **不是保留期**：到期只刪本機檔，錄影仍可播（改自離機副本取回），
	// `has_recording` 與清除水位皆不動。真正的保留期是
	// `retention_recording_days`，兩者語義不同故**不納入跨鍵約束**
	// （cross_key_retention.go 的四鍵集合不變）——把快取期算進「檢查點必須
	// 活得比資料久」的關係裡，等於主張「本機檔清掉＝證據消失」，而那正好是
	// 本功能要否定的前提。
	//
	// 出廠 0＝不提前清；**無 PCI 建議值**：它是磁碟預算旋鈕，不是合規基準線，
	// 掛建議值會讓「套用本頁建議值」替部署方決定要留幾天本機副本。
	// 功能未啟用時本鍵無作用（設定頁明示）
	PolicyOffsiteLocalRetentionDays = "offsite_local_retention_days"
	// PolicyRetentionCheckpointDays 檢查點鏈自身的保留天數（audit-checkpoint-chain）。
	// 受跨鍵約束（cross_key_retention.go）：不得低於四個資料保留鍵的有效值
	PolicyRetentionCheckpointDays = "retention_checkpoint_days"
	// 封章觸發門檻（audit-checkpoint-chain）：兩者先到先觸發。
	// **調短即縮小「最近一次封章至今」的未保護窗口**（誠實邊界 R5），
	// 故必須是管理員在頁面上可調的項，而非只能改 env 重啟。
	// 兩鍵的單位與 env（AUDIT_CHECKPOINT_INTERVAL_SECONDS／
	// AUDIT_CHECKPOINT_ROW_THRESHOLD）刻意 1:1 對齊——SeedFromEnv 直接搬值，
	// 不做秒↔分換算，避免既有部署的設定在升級時被四捨五入成另一個意思
	PolicyAuditCheckpointIntervalSeconds = "audit_checkpoint_interval_seconds"
	PolicyAuditCheckpointRowThreshold    = "audit_checkpoint_row_threshold"
	// 鏈自動驗證三鍵：近期層窗口、
	// 全鏈層間隔、內容層掃描速率。**三者的值都會直接出現在驗證頁對稽核的陳述裡**
	//（「每次封存後重驗最近 N 天」「每 X 自動驗證整條鏈一次」「全歷史約每 Y 天
	// 重驗一輪」），故改這三個值等於改變本系統對外的陳述，必須是頁面上可見可調、
	// 且無法被調成實質關閉的項——不開 ZeroDisables，各自有界（見 policyDefs）
	PolicyAuditChainRecentVerifyDays      = "audit_chain_recent_verify_days"
	PolicyAuditChainVerifyIntervalSeconds = "audit_chain_verify_interval_seconds"
	// PolicyAuditChainVerifyRowsPerHour 內容層掃描**速率**（列/小時），不是每輪列數。
	// **本 change 唯一一顆「調小才危險」的旋鈕**：速率調小＝繞行週期等比拉長＝
	// 舊區間在被合法清除前永遠輪不到重驗，而畫面上仍顯示驗證在跑，故設 Min
	PolicyAuditChainVerifyRowsPerHour = "audit_chain_verify_rows_per_hour"
	// PolicyRetentionMaxPerRun 單次保留期清理的刪除上限。
	// 單位與 env `RETENTION_MAX_PER_RUN` 1:1（筆），SeedFromEnv 直接搬值不換算。
	// **調小才危險**：設成 1 使清理永遠追不上新增量，保留政策實質失效而畫面上
	// 仍顯示每日在跑，故本鍵設 Min（見 policyDefs 的下界理由）
	PolicyRetentionMaxPerRun = "retention_max_per_run"
	PolicyDailyReviewEnabled = "daily_review_enabled"
	PolicyFailureAlertEnabled     = "failure_alert_enabled"
	// 錄影 fail-close：簽發點前置錄影可寫性
	// 檢查失敗時拒發非 admin 連線 token
	PolicyRecordingFailCloseEnabled = "recording_failclose_enabled"

	// 金鑰管理政策鍵（PCI Req 3 自我要求）
	PolicyKeyCryptoperiodReminderDays = "key_cryptoperiod_reminder_days"
	// PolicyKeyRotationMaxPerRun 單次 DEK 輪替的重加密上限。
	// 單位與 env `KEY_ROTATION_MAX_PER_RUN` 1:1（筆），SeedFromEnv 直接搬值不換算。
	// **調小才危險**：設成 1 使換鑰永遠跑不完，金鑰輪替實質失效而清冊上仍顯示可輪替
	PolicyKeyRotationMaxPerRun = "key_rotation_max_per_run"

	// 叢集存取政策鍵。
	// PolicyK8sListTimeoutSeconds 單位與 env `K8S_LIST_TIMEOUT_SECONDS` 1:1（秒）。
	// **調小才危險**：設成 1 使負載稍高的叢集每次列表都逾時，K8s 功能實質不可用
	PolicyK8sListTimeoutSeconds = "k8s_list_timeout_seconds"

	// 傳輸安全政策鍵（PCI Req 4 自我要求）：
	// 六通道三段強制階梯＋同意效期
	PolicyTransportRDPLevel       = "transport_rdp_level"
	PolicyTransportVNCLevel       = "transport_vnc_level"
	PolicyTransportDBLevel        = "transport_db_level"
	PolicyTransportLDAPLevel      = "transport_ldap_level"
	PolicyTransportSyslogLevel    = "transport_syslog_level"
	PolicyTransportNotifyLevel    = "transport_notify_level"
	PolicyTransportConsentTTLDays = "transport_consent_ttl_days"

	// 存取政策鍵（PCI Req 7.2 最小權限的時間維度）：
	// 全域預設段位＋申請時長上限＋pending 超時時限
	PolicyAccessPolicyDefault              = "access_policy_default"
	PolicyAccessRequestMaxDurationMinutes  = "access_request_max_duration_minutes"
	PolicyAccessRequestPendingTimeoutHours = "access_request_pending_timeout_hours"
	// 最少核准人數：內控強化選項（雙人覆核慣例），
	// 非 PCI 要求（官方查證：dual control 僅金鑰管理 Req 3.7.6；存取核准
	// Req 7.2.3 單人即符合）——勿加 PCIValue
	PolicyAccessRequestMinApprovals = "access_request_min_approvals"

	// 破窗與撤銷政策鍵：
	// 破窗開關（預設關）＋固定短窗＋補審逾期時限＋撤銷即斷線（預設關）
	PolicyBreakGlassEnabled            = "break_glass_enabled"
	PolicyBreakGlassDurationMinutes    = "break_glass_duration_minutes"
	PolicyBreakGlassReviewTimeoutHours = "break_glass_review_timeout_hours"
	PolicyAccessRevokeDisconnect       = "access_revoke_disconnect"

	// 資料傳輸管控鍵（data-transfer-control，法源＝電支基準 §16-6／§21-8(七)，
	// 非 PCI 條文——勿加 PCIValue）：剪貼簿雙向＋SFTP 三動作。
	// 方向以「受管資產」為參照系：send＝送進資產、recv＝自資產收出。
	PolicyClipboardSendEnabled = "clipboard_send_enabled"
	PolicyClipboardRecvEnabled = "clipboard_recv_enabled"
	PolicyFileUploadEnabled    = "file_upload_enabled"
	PolicyFileDownloadEnabled  = "file_download_enabled"
	PolicyFileDeleteEnabled    = "file_delete_enabled"

	// 登入前告示兩鍵：登入頁在使用者通過認證之前顯示的常設文字。
	//
	// 兩鍵**無任何合規基準建議值**：內容由部署方自填，沒有一個放諸四海的正確
	// 字串可以拿來比對；掛建議值會讓「套用本頁建議值」替部署方寫他們的告示。
	// 出廠皆為空＝未設定，升級後登入頁零變化。
	// 標題單獨有值不會顯示——呈現與否只看內文（見公開讀取端點）。
	PolicyLoginBannerTitle = "login_banner_title"
	PolicyLoginBannerBody  = "login_banner_body"
)

// 傳輸強制等級三段枚舉值（弱→強；符合性 = 現值序位 >= PCI 值序位）
const (
	TransportLevelOff    = "off"
	TransportLevelWarn   = "warn"
	TransportLevelStrict = "strict"
)

// mfa_required 三態枚舉值（弱→強；符合性 = 現值序位 >= PCI 值序位）
const (
	MFARequiredOff       = "off"
	MFARequiredAdminOnly = "admin_only"
	MFARequiredAll       = "all"
)

// 政策值型別
const (
	PolicyTypeInt  = "int"
	PolicyTypeBool = "bool"
	PolicyTypeEnum = "enum"
	// PolicyTypeText 自由文字。與前三者的差別是它有**正規化**：
	// 寫入路徑會統一換行、去首尾空白後才落庫，故驗證入口回傳的是終值而非原值。
	// 長度以 Unicode code point 計，上限由 PolicyDef.MaxLength 逐鍵指定
	PolicyTypeText = "text"
)

// 比較方向（int 型）：min=值須 >= PCI 建議、max=值須 <= PCI 建議
const (
	DirectionMin = "min"
	DirectionMax = "max"
)

// PolicySeededBy 播種寫入時記於 UpdatedBy 的識別（既有值，勿改：存量列以此值
// 標示「這是啟動時播種的，不是人在頁面上設的」）
const PolicySeededBy = "env-init"

// 政策現值的來源分類（ValueSource 的值域）：決定運維日誌該把人指向哪裡改。
const (
	// PolicySourceAdmin 政策列由管理端寫入——改 env 不會生效，只有政策頁能改
	PolicySourceAdmin = "admin"
	// PolicySourceSeed 政策列由首次啟動的組態播種寫入
	PolicySourceSeed = "seed"
	// PolicySourceDefault 無政策列，出廠預設生效
	PolicySourceDefault = "default"
	// PolicySourceUnknown 政策列讀取失敗，來源無從判定
	PolicySourceUnknown = "unknown"
)

// defaultPolicyCacheTTL 政策快取存活時間。登入路徑讀政策頻率低，
// 短 TTL 即可；Update 走「更新即失效」不等 TTL
const defaultPolicyCacheTTL = 30 * time.Second

// defaultPolicyIntMax int 型政策的通用上界（LOCK-1）：任何以分鐘為單位餵進
// time.Duration(*time.Minute) 的值超過約 1.5e8 分鐘會使 int64 溢位成負，
// 令 lockedUntil 落到過去而靜默解鎖。1 年（525600 分）遠低於溢位點且對所有
// 計數/分鐘型政策都夠用；個別政策可用 PolicyDef.Max 再收緊
const defaultPolicyIntMax = 525600

var (
	// ErrPolicyUnknownKey 未定義的政策鍵
	ErrPolicyUnknownKey = errors.New("未定義的安全政策項")
	// ErrPolicyInvalidValue 政策值不合法（型別或範圍）
	ErrPolicyInvalidValue = errors.New("安全政策值不合法")
)

// PolicyUnknownKeyError 未定義的政策鍵，附鍵名。
//
// 批次更新一次送多鍵，不指名鍵時 admin 無從得知該改哪一項；handler 無法從
// sentinel 反推，故以具名欄位帶出轉為 apierror 的 {key} param。
// 該鍵來自請求 body（依定義不在政策表內），出 wire 前由 apierror 淨化限長。
type PolicyUnknownKeyError struct {
	// Key 請求中未被政策表認得的鍵
	Key string
}

func (e *PolicyUnknownKeyError) Error() string {
	return fmt.Sprintf("%s: %s", ErrPolicyUnknownKey.Error(), e.Key)
}

// Unwrap 讓 errors.Is 可比對底層 sentinel
func (e *PolicyUnknownKeyError) Unwrap() error { return ErrPolicyUnknownKey }

// PolicyInvalidValueError 政策值不合法，附鍵名與原因。
//
// Key 必出自靜態政策表（已通過 findDef），故 apierror 側以 ParamEnum 允許清單
// 承接。Reason 僅供伺服器端日誌與既有錯誤字串相容，不進 wire（是句子非受控值）。
type PolicyInvalidValueError struct {
	// Key 政策鍵（保證出自 policyDefs）
	Key string
	// Reason 不合法的原因（人話，僅伺服器端可見）
	Reason string
}

func (e *PolicyInvalidValueError) Error() string {
	return fmt.Sprintf("%s: %s %s", ErrPolicyInvalidValue.Error(), e.Key, e.Reason)
}

// Unwrap 讓 errors.Is 可比對底層 sentinel
func (e *PolicyInvalidValueError) Unwrap() error { return ErrPolicyInvalidValue }

// PolicyDef 政策定義（PCI 建議值常數表，2026-07-02 對官方文件核對定稿，
// 佐證：官方《PCI DSS v4.0.1》June 2024）。
// 各鍵的建議值與其對應條號另載於 openspec/specs/security-policy/spec.md。
type PolicyDef struct {
	Key     string `json:"key"`
	Type    string `json:"type"`
	Default string `json:"default"`
	// PCIValue PCI 建議值；空字串 = 無 PCI 建議（不做符合性評估）
	PCIValue string `json:"pci_value,omitempty"`
	// EPaymentValue 電支基準建議值（《電子支付機構資通安全檢查機制實施規範》；
	// 各鍵對應的條號見 EPaymentRequirement 欄，並由 epayment_baseline_test.go 逐項釘住）；
	// 空字串 = 無該基準建議（不做符合性評估，與 PCIValue 空值語義一致）。
	//
	// **與 PCIValue 平行、不互相覆寫**：兩基準在部分項目上方向相反（如密碼最小長度
	// 電支 6 寬於 PCI 12），任一覆寫另一都會使某一側的符合性評估失真
	EPaymentValue string `json:"epayment_value,omitempty"`
	// EPaymentRequirement 電支基準條號（如 15-8）
	EPaymentRequirement string `json:"epayment_requirement,omitempty"`
	// PCIReference PCIValue 是**參考值**而非條文明定值。
	//
	// 為真時，該條文以機構自行的目標風險分析決定頻率／門檻，未給固定數字，
	// PCIValue 是本產品採用的常見實務起始值。設定頁必須把這個性質標示出來
	// ——把參考值印成條文要求，會讓稽核以為那個數字有法源，而它沒有。
	//
	// 符合性評估與一鍵套用**照常作用**：值是給了的，只是出處性質不同。
	// 為真時 PCIValue 必非空（validatePolicyDefs 釘住）——沒有值的參考值
	// 不是一個有意義的宣告。
	PCIReference bool `json:"pci_reference,omitempty"`
	// Direction int 型比較方向（min/max）
	Direction string `json:"direction,omitempty"`
	// ZeroDisables 0=停用 sentinel：先判「不符建議」再比數值
	ZeroDisables bool `json:"zero_disables,omitempty"`
	// Max int 型上界（0 = 用 defaultPolicyIntMax）；防溢位與不合理極端值（LOCK-1）
	Max int `json:"max,omitempty"`
	// Min int 型下界（0 = 無下界）：**堵「調到極小＝實質關閉」的靜默路徑**。
	//
	// 判準是**危險方向朝哪邊**，不是「是不是數值型」。既有的速率／週期型鍵
	// （如封章週期、筆數門檻）危險方向是「調大」——設成 24 小時等於實質不封章
	// ——`Max` 正好蓋住，故不需要 `Min`；而預算／逾時型鍵（本欄的使用者）危險
	// 方向是「調小」：`RETENTION_MAX_PER_RUN=1` 使清理永遠追不上新增量、
	// `K8S_LIST_TIMEOUT_SECONDS=1` 使列表永遠逾時，機制實質停擺而**介面上仍顯示在跑**。
	// `ZeroDisables:false` 只擋 0，`1` 一路放行——現行結構對這個方向完全沒有防護。
	//
	// 與 ZeroDisables 正交（見 validatePolicyValue）：合法值域為
	// `{0 若 ZeroDisables} ∪ [Min, Max]`。兩者堵的是不同的門——ZeroDisables 決定
	// 「能不能明著關」，Min 決定「能不能偽裝成還開著而其實關了」。
	// 下界的意義是「低於此值該機制即失去意義」，取值須有結構性理由（如低於單一
	// 批次／掃描頁大小），不是隨手取整數
	Min int `json:"min,omitempty"`
	// MaxLength text 型的字元數上限，以 Unicode code point 計。
	//
	// **與 Max 分開一欄是刻意的**：Max 的語義是 int 值的上界，int 型鍵的窮舉
	// 守衛都以「Max 是一個數值上界」為前提。讓它兼差當字串長度上限，會讓那些
	// 守衛的前提變成兩種互斥的意思，而它們讀不出差別。
	// text 型必有正值；非 text 型必為零（validatePolicyDefs 雙向釘住）
	MaxLength int `json:"max_length,omitempty"`
	// Multiline text 型是否允許換行。false 時值內含 LF 即拒絕。
	// 非 text 型必為 false（validatePolicyDefs 釘住）
	Multiline bool `json:"multiline,omitempty"`
	// EnumOrder 枚舉序（弱→強）；enum 型符合性 = 現值序位 >= PCI 值序位
	EnumOrder []string `json:"enum_order,omitempty"`
	// Requirement PCI 條號（如 8.3.4）
	Requirement string `json:"requirement,omitempty"`
	// Label/Unit 供前端渲染；Unit 為 zh fallback，前端優先以 UnitKey 查譯
	Label string `json:"label"`
	Unit  string `json:"unit,omitempty"`
	// UnitKey 語義單位鍵（前端 i18n 錨點，值域見 unitKeyByZh）。由 init 依 Unit 衍生，
	// 不手填——確保 Unit≠"" 必有合法 UnitKey（rr-I5 invariant，杜絕漏填）
	UnitKey string `json:"unit_key,omitempty"`
}

// policyDefs 全部政策定義（順序即前端顯示順序）
var policyDefs = []PolicyDef{
	{
		Key: PolicyLockoutMaxAttempts, Type: PolicyTypeInt, Default: "10",
		PCIValue: "10", Direction: DirectionMax, ZeroDisables: true, Max: 1000,
		Requirement: "8.3.4", Label: "登入失敗鎖定次數上限", Unit: "次",
		EPaymentValue: "5", EPaymentRequirement: "4-7(五)",
	},
	{
		Key: PolicyLockoutDurationMinutes, Type: PolicyTypeInt, Default: "30",
		PCIValue: "30", Direction: DirectionMin, Max: 10080, // 上界 7 天，防 int64 溢位（LOCK-1）
		Requirement: "8.3.4", Label: "鎖定時長", Unit: "分鐘",
	},
	{
		Key: PolicyPasswordMinLength, Type: PolicyTypeInt, Default: "12",
		PCIValue: "12", Direction: DirectionMin, Max: 128, // bcrypt 上限 72 byte，128 字元已足
		Requirement: "8.3.6", Label: "密碼最小長度", Unit: "字元",
		// **本項電支基準寬於 PCI**（6 < 12）：套用電支基準時取嚴後仍為 12，
		// 不得下調（evaluateStrictest）。這是「套用不可無條件覆寫」的具體案例
		EPaymentValue: "6", EPaymentRequirement: "4-7(一)",
	},
	{
		Key: PolicyPasswordRequireAlnum, Type: PolicyTypeBool, Default: "true",
		PCIValue:    "true",
		Requirement: "8.3.6", Label: "密碼須含字母與數字",
	},
	{
		// 上界 24（使用者裁決 2026-08-19）：
		// 本鍵的值直接決定改密請求的成本——每多一筆歷史就多一次密碼雜湊比對。
		// 實測（cost=10，單次雜湊約 78ms）：設 100 時單一次改密約 **8.03 秒**，
		// 是登入的 103 倍；而改密端點對外暴露、一般認證帳號即可觸發。
		// 24 遠高於 PCI 建議的 4（一年每月改一次也才 12），足以涵蓋真實合規需求，
		// 而單次成本降到約 2 秒。**上界是防呆而非功能限制**：
		// 它擋的是「把值設到讓端點自己變成攻擊面」的組態。
		Key: PolicyPasswordHistoryCount, Type: PolicyTypeInt, Default: "4",
		PCIValue: "4", Direction: DirectionMin, ZeroDisables: true, Max: 24,
		Requirement: "8.3.7", Label: "禁止重用最近密碼筆數", Unit: "筆",
	},
	{
		// 密碼最長使用天數：登入時以
		// password_changed_at 判過期，逾期導強制改密。出廠 0=關閉（易用取向，
		// 升級零行為變更）；PCI 8.3.9 單因子情境建議 <=90 天，一鍵套用即開
		Key: PolicyPasswordMaxAgeDays, Type: PolicyTypeInt, Default: "0",
		PCIValue: "90", Direction: DirectionMax, ZeroDisables: true, Max: 3650, // 上界 10 年
		Requirement: "8.3.9", Label: "密碼最長使用天數", Unit: "天",
		// 電支 §15-8：人員／系統連線帳號至少每三個月變更一次
		EPaymentValue: "90", EPaymentRequirement: "15-8",
	},
	{
		// 資產帳號憑證最長使用天數：輪替證據報告據此判定逾期，計劃可覆蓋。
		// 出廠 0＝關閉（升級零行為變更）。
		//
		// **PCI 值標為參考值**：Requirement 8.6.3 要求此頻率由機構的目標風險
		// 分析決定，未定固定天數；90 借自 8.3.9 對使用者帳號的門檻，是本產品
		// 的預設起始值。電支 §15-8 則明定至少每三個月，故該側非參考值。
		Key: PolicyAssetSecretMaxAgeDays, Type: PolicyTypeInt, Default: "0",
		PCIValue: "90", PCIReference: true, Direction: DirectionMax,
		ZeroDisables: true, Max: 3650, // 上界 10 年，與平台使用者密碼同
		Requirement: "8.6.3", Label: "資產帳號憑證最長使用天數", Unit: "天",
		EPaymentValue: "90", EPaymentRequirement: "15-8",
	},
	{
		Key: PolicyForceChangeOnReset, Type: PolicyTypeBool, Default: "true",
		PCIValue:    "true",
		Requirement: "8.3.5", Label: "管理員重設後強制改密",
	},
	{
		Key: PolicyMFARequired, Type: PolicyTypeEnum, Default: MFARequiredOff,
		PCIValue:    MFARequiredAll, // PCI 8.4.2：CDE 全員 MFA（出廠 off 為易用取向）
		EnumOrder:   []string{MFARequiredOff, MFARequiredAdminOnly, MFARequiredAll},
		Requirement: "8.4.2", Label: "多因子驗證強制範圍",
	},
	{
		// Web 會話 sliding 閒置窗口：距上次活動逾此分鐘數則刷新被拒、須重登。
		// 出廠 60 為易用取向，PCI 8.3.10.1/8.2.8 建議 15
		Key: PolicyWebIdleMinutes, Type: PolicyTypeInt, Default: "60",
		PCIValue: "15", Direction: DirectionMax, ZeroDisables: true, Max: 10080, // 上界 7 天
		Requirement: "8.2.8", Label: "Web 工作階段閒置逾時", Unit: "分鐘",
		// 電支 §15-5：超過十分鐘未操作應限制個資顯示於螢幕。掛 web 閒置而非協議
		// 會話閒置——條文語境是操作畫面上的個資顯示
		EPaymentValue: "10", EPaymentRequirement: "15-5",
	},
	{
		// Web 會話絕對壽命：登入起算，持續活動也不得超過。0=不限
		//（ZeroDisables 僅放行 0 值；無 PCIValue 故不影響符合性評估）。
		// PCI 未規定絕對壽命門檻，不做符合性評估
		Key: PolicyWebMaxSessionHours, Type: PolicyTypeInt, Default: "12",
		ZeroDisables: true, Max: 8760, // 上界 1 年
		Label: "Web 工作階段最長時數", Unit: "小時",
	},
	{
		// refresh cookie 的 Secure 屬性（決策 8）：
		// 開啟時瀏覽器僅在 https 連線下保存與回送該 cookie，純 HTTP 下直接丟棄
		//（使用者每個 access token 壽命就得重新登入）。
		//
		// 出廠 true＝安全預設：未設定的部署取得傳輸保護，走明文者顯式關閉。
		// 初值可由部署組態播種（AUTH_REFRESH_COOKIE_SECURE → PUBLIC_BASE_URL
		// 的 scheme），播種後本頁為準、改 env 不再生效。
		//
		// **無 PCIValue／EPaymentValue 是刻意的**：本鍵的正確取值由部署對外協定
		// 決定，不是合規基準線。掛建議值會讓「套用本頁建議值」把明文部署的本鍵
		// 翻成開啟、製造整站續期失敗，還會虛構一個文件上不存在的條號對應。
		// 落在 Web 會話鍵群內（承載頁同區塊）：它決定的正是這個會話能不能續期
		Key: PolicyRefreshCookieSecure, Type: PolicyTypeBool, Default: "true",
		Label: "登入狀態僅在 https 連線保存",
	},
	{
		// 協議會話（SSH/k8s/DB/RDP/VNC）閒置逾時：出廠 60 為易用取向，
		// PCI 8.2.8 建議 15；既有部署以 SSH_IDLE_TIMEOUT_MINUTES 初始化（SeedFromEnv）
		Key: PolicySessionIdleMinutes, Type: PolicyTypeInt, Default: "60",
		PCIValue: "15", Direction: DirectionMax, ZeroDisables: true, Max: 10080, // 上界 7 天
		Requirement: "8.2.8", Label: "協議連線閒置逾時", Unit: "分鐘",
	},
	{
		// 協議會話最長時長：0=不限沿用既有預設；SSH_MAX_SESSION_MINUTES 初始化。
		// PCI 未規定，不做符合性評估（ZeroDisables 僅放行 0 值）
		Key: PolicySessionMaxMinutes, Type: PolicyTypeInt, Default: "0",
		ZeroDisables: true, Max: 525600, // 上界 1 年（分鐘）
		Label: "協議連線最長時長", Unit: "分鐘",
	},
	{
		// 閒置帳號自動停用天數：距最後登入逾此天數的帳號自動停用（8.2.6）。
		// 出廠 0=關閉（易用取向——突然停用是驚嚇型摩擦）；PCI 8.2.6 建議 ≤90 天，
		// 一鍵套用即開；0=停用 sentinel 先判不符
		Key: PolicyInactiveDisableDays, Type: PolicyTypeInt, Default: "0",
		PCIValue: "90", Direction: DirectionMax, ZeroDisables: true, Max: 3650, // 上界 10 年
		Requirement: "8.2.6", Label: "閒置帳號自動停用天數", Unit: "天",
	},
	{
		// 保留天數：min 型 = 保留須 >= 365 才符 10.5.1；
		// 0=永久保留（不清除）視為「未定義保留政策」判不符建議（引導設明確政策），
		// 可放寬不擋。出廠 0 = 日常模式不刪任何審計資料
		Key: PolicyRetentionAuditLogDays, Type: PolicyTypeInt, Default: "0",
		PCIValue: "365", Direction: DirectionMin, ZeroDisables: true, Max: 3650,
		Requirement: "10.5.1", Label: "操作日誌保留天數", Unit: "天",
		// 電支 §19-4／§24-1：至少保留 2 年（嚴於 PCI 的 1 年）
		EPaymentValue: "730", EPaymentRequirement: "19-4",
	},
	{
		Key: PolicyRetentionSessionCommandDays, Type: PolicyTypeInt, Default: "0",
		PCIValue: "365", Direction: DirectionMin, ZeroDisables: true, Max: 3650,
		Requirement: "10.5.1", Label: "指令流保留天數", Unit: "天",
	},
	{
		Key: PolicyRetentionAlertDays, Type: PolicyTypeInt, Default: "0",
		PCIValue: "365", Direction: DirectionMin, ZeroDisables: true, Max: 3650,
		Requirement: "10.5.1", Label: "告警記錄保留天數", Unit: "天",
	},
	{
		// 錄影保留：出廠 90 = 沿既有 recording cleanup 預設；
		// 初始值由 RECORDING_RETENTION_DAYS 播種（main.go SeedFromEnv），升級行為不變
		Key: PolicyRetentionRecordingDays, Type: PolicyTypeInt, Default: "90",
		PCIValue: "365", Direction: DirectionMin, ZeroDisables: true, Max: 3650,
		Requirement: "10.5.1", Label: "連線錄影保留天數", Unit: "天",
	},
	{
		// 離機儲存的本機快取期：
		// 出廠 0＝不提前清（升級後行為不變）。上界沿其餘保留鍵的 3650。
		//
		// **ZeroDisables 為真**：0 在此確有「停用」語義（不做本機快取清除），
		// 而非「無限大」。**無 PCIValue／Direction／Requirement**：它不是合規
		// 基準線上的項，理由見鍵常數的註解。
		Key: PolicyOffsiteLocalRetentionDays, Type: PolicyTypeInt, Default: "0",
		ZeroDisables: true, Max: 3650,
		Label: "離機後本機副本保留天數", Unit: "天",
	},
	{
		// 檢查點鏈保留天數（audit-checkpoint-chain）：出廠 0＝永久。
		//
		// **出廠 0 而非 3650**：四個資料保留鍵出廠為 0/0/0/90，
		// 而跨鍵約束把 0 讀成無限大——出廠 3650 會使**出廠狀態本身違反約束**，
		// 逼得跨鍵驗證只能退讓成「只驗本批次觸及的關係」，那道退讓留下一條
		// 繞過路徑（先設檢查點鍵有期值、之後單獨調升資料鍵）。出廠 0 使
		// 五鍵出廠即自洽（`RetentionCovers(0, 任意)` 恆真），全域驗永不誤擋。
		// 語義上也一致：資料永久保留，其證明就必須永久。
		//
		// **無 PCIValue 是刻意的**：本鍵沒有獨立的 PCI 建議值，其合規語義是
		//「檢查點必須活得比它所證明的資料久」——那是**跨鍵**關係，不是單鍵
		// 與某個常數的比較。掛一個假的 PCIValue 會讓它進「套用本頁建議值」
		// 並在偏離摘要裡與四個資料保留鍵並列，把跨鍵語義誤導成單鍵語義。
		// 約束落在 cross_key_retention.go（設定時擋）＋ retention 執行期保守跳過。
		//
		// Max 維持 3650（O5 判定，見 design）：與四個資料保留鍵同一天花板；
		// 資料鍵設到 3650 時本鍵仍有兩個合法值（3650＝等長、0＝永久且嚴格更久），
		// 放寬到 7300 只多出「比任何資料鍵久但非永久」這一段刻度，
		// 不值得讓日數型政策鍵出現第二種天花板
		Key: PolicyRetentionCheckpointDays, Type: PolicyTypeInt, Default: "0",
		ZeroDisables: true, Max: 3650,
		Label: "檢查點保留天數", Unit: "天",
	},
	{
		// 上界 86400 秒＝24 小時，且 ZeroDisables 不開（0 會被驗證擋下）：
		// 兩者合起來使本鍵無法被用來實質關閉封章——極大值或 0 都不合法
		Key: PolicyAuditCheckpointIntervalSeconds, Type: PolicyTypeInt, Default: "3600",
		Max:   86400,
		Label: "檢查點封存週期", Unit: "秒",
	},
	{
		// 上界 100 萬筆，同樣不可為 0；與週期先到先觸發
		Key: PolicyAuditCheckpointRowThreshold, Type: PolicyTypeInt, Default: "10000",
		Max:   1000000,
		Label: "檢查點封存筆數門檻", Unit: "筆",
	},
	{
		// 近期層窗口天數：每次封存後
		// 自動重驗「最近 N 天」的已封區間，使鏈尾異常在一個封章間隔內就被發現。
		//
		// **上界 30 的理由**：出廠設定下全鏈層在滿載 10 年鏈上約 36.5 天繞完一輪，
		// N 超過 30 天後近期層的覆蓋與全鏈層幾乎重疊，多出來的
		// 只有每次執行的成本；且窗口再大也不改變「全歷史終將重驗」這個由**第二層**
		// 承擔的保證——把 N 調大不能替代第二層。
		//
		// **不需要 Min**：危險方向朝大（成本），朝小則最小合法值 1 天仍含鏈尾最新
		// 區間，機制不會歸零；0 已由「非 ZeroDisables 的 int 不得為 0」擋下。
		//
		// **另受保留天數 clamp**（消費端，非跨鍵驗證）：有效值＝
		// min(N, retention_audit_log_days)，該鍵 0＝永久時不 clamp。承諾驗保留期
		// 以外的範圍是空頭支票；但把 N 設得比保留期長只是無效、不危險，
		// 不必擋使用者存檔（同 retention_checkpoint_days 註解對跨鍵驗證的保留）
		Key: PolicyAuditChainRecentVerifyDays, Type: PolicyTypeInt, Default: "7",
		Max:   30,
		Label: "鏈驗證近期窗口", Unit: "天",
	},
	{
		// 全鏈層驗證間隔。
		//
		// **上界 604800 秒（7 天）＋不開 ZeroDisables＝本鍵無法被用來實質關閉驗證**，
		// 逐字比照 audit_checkpoint_interval_seconds 的既有做法：極大值與 0 都不合法。
		// 一週是「週期性控制」在稽核語言中最鬆的常見節奏，更長的值會使
		// 「本系統每 X 自動驗證整條鏈一次」這句陳述本身變成負面證據。
		// **不存在需要更長間隔的營運理由**：一輪成本只有結構層數秒＋內容層零點幾秒，
		// 會設 30 天的唯一動機是疏於管理，而上界正是要擋這個。
		//
		// **無 PCIValue 是刻意的**：PCI 沒有針對「鏈驗證頻率」的建議值，掛一個假的
		// 會讓它進「套用本頁建議值」並在偏離摘要裡與真有條號的鍵並列
		// （同 retention_checkpoint_days／封章兩鍵的紀律）。
		//
		// **調長間隔不延長繞行週期**：每輪列預算＝速率 × 間隔，
		// 調長只放大單輪耗時與鏈尾異常在全鏈層的發現時延
		Key: PolicyAuditChainVerifyIntervalSeconds, Type: PolicyTypeInt, Default: "3600",
		Max:   604800,
		Label: "全鏈驗證週期", Unit: "秒",
	},
	{
		// 內容層掃描速率。
		// **是速率不是每輪列數**：每輪列預算＝速率 × 間隔，使繞行週期與資料庫
		// 佔空比對間隔選擇不變；若定成每輪固定列數，把間隔調到上界 7 天就會把
		// 繞行週期拉長 168 倍，而管理員從介面上只看見「驗得稀疏一點」。
		//
		// **下界 10000 的理由是結構性的**：滿載 10 年鏈約 8.76 億列，
		// 1 萬列/小時恰好是「繞行一輪≈一個完整保留期（Max 3650 天）」的那一點——
		// 再低於此，舊區間在被合法清除前**永遠輪不到重驗**，內容層對那段歷史
		// 實質關閉，而驗證頁上仍顯示掃描在推進。下界只擋「設成 1」這種實質關閉，
		// 不替管理員決定節流偏好（10000..5000000 之間仍是他的權衡，
		// 繞行週期預估值照實顯示在驗證頁上）。
		//
		// **上界 5000000**：出廠 100 萬列/小時的五倍，滿載時 DB 佔空比約 0.46%
		// （實測推算）；再高即超出可承受的生產庫佔用。
		// 不開 ZeroDisables：0 在此無「停用」的合法語義，掃描不得被關閉
		Key: PolicyAuditChainVerifyRowsPerHour, Type: PolicyTypeInt, Default: "1000000",
		Min: 10000, Max: 5000000,
		Label: "鏈驗證掃描速率", Unit: "筆/小時",
	},
	{
		// 單次保留期清理的刪除上限。
		// 出廠 100000 沿 env 預設，升級後行為不變。
		//
		// **下界 5000 的理由是結構性的，不是取整數**：清理迴圈以
		// `retentionBatchSize`＝5000 分批刪除（audit/retention_service.go:22），
		// 單輪上限低於一個批次，代表這輪連一個批次都刪不完——分批機制本身
		// 失去意義，且刪除速率必然低於任何實際部署的審計新增速率，
		// 到期資料只會越積越多。**保留政策因此實質失效，而畫面上每日仍在跑。**
		// 下界取「機制無疑已壞」的那一點，不替管理員決定節流偏好：
		// 小型部署刻意壓低吞吐仍有 5000..100000 的空間。
		//
		// 不開 ZeroDisables：0 在消費端語義是「無上限」而非「停用」，
		// 讓它走 Min 之外的分支只會多一種讀法
		Key: PolicyRetentionMaxPerRun, Type: PolicyTypeInt, Default: "100000",
		Min: 5000, Max: 10000000,
		Label: "單次清理刪除上限", Unit: "筆",
	},
	{
		// 每日審閱簽核（10.4.1）：出廠關（日常模式不加簽核義務），一鍵套用即開
		Key: PolicyDailyReviewEnabled, Type: PolicyTypeBool, Default: "false",
		PCIValue:    "true",
		Requirement: "10.4.1", Label: "每日審閱簽核",
	},
	{
		// 稽核失效告警通知（10.7.2）：失效事件記錄恆開，此鍵僅控制通知發送
		Key: PolicyFailureAlertEnabled, Type: PolicyTypeBool, Default: "false",
		PCIValue:    "true",
		Requirement: "10.7.2", Label: "稽核失效告警通知",
	},
	{
		// 錄影 fail-close：出廠關（升級不改變
		// 現狀）；開啟時簽發點前置錄影可寫性檢查失敗即拒非 admin 簽發（admin
		// 唯一例外留痕）。PCI 10.2 軌跡完整語脈（自我要求框架）
		Key: PolicyRecordingFailCloseEnabled, Type: PolicyTypeBool, Default: "false",
		PCIValue:    "true",
		Requirement: "10.2", Label: "錄影失敗擋新連線",
	},
	{
		// cryptoperiod 提醒：active 金鑰年齡逾此
		// 天數於金鑰清冊顯示提醒 banner。0=不提醒（出廠預設——輪替是保險能力
		// 非營運義務）；純提醒，永不觸發自動輪換、不外送通知。
		// PCI 3.7.4 cryptoperiod 治理精神（自我要求框架，產品不存 PAN）
		Key: PolicyKeyCryptoperiodReminderDays, Type: PolicyTypeInt, Default: "0",
		PCIValue: "365", Direction: DirectionMax, ZeroDisables: true, Max: 3650,
		Requirement: "3.7.4", Label: "金鑰輪替提醒天數", Unit: "天",
	},
	{
		// 單次 DEK 輪替的重加密上限。
		// 出廠 100000 沿 env 預設，升級後行為不變。
		//
		// **下界 500 的理由是結構性的**：重加密掃描以每頁 500 列讀取
		// （keyvault/envelope_migration_service.go:202），單輪上限低於一頁，
		// 代表一次觸發連一個掃描頁都推不完——換鑰永遠跑不完，而金鑰清冊上
		// 仍顯示可輪替。輪替是管理員手動觸發且可續跑的操作，故下界只取
		// 「一次觸發至少推得動一頁」這個結構底線，不替管理員決定每輪要跑多久。
		//
		// 上界與 retention 同取 1000 萬：兩者都是「筆數預算」型且共用
		// 續跑語義，天花板一致可避免同型鍵出現兩種刻度
		Key: PolicyKeyRotationMaxPerRun, Type: PolicyTypeInt, Default: "100000",
		Min: 500, Max: 10000000,
		Label: "單次換鑰重加密上限", Unit: "筆",
	},
	{
		// K8s pod 列表逾時。出廠 10 秒沿
		// `defaultListTimeout`（k8sproxy/client.go:26），升級後行為不變。
		//
		// **下界 3 秒的理由**：一次列表要走完 TLS 握手＋API server 查詢＋回傳，
		// 健康但有負載的叢集本來就可能花上一兩秒。逾時低於 3 秒時，正常叢集
		// 的正常回應也會被判逾時——**K8s 功能等於永遠不可用，而資產列表上
		// 仍顯示著這些叢集**。3 秒是「正常叢集仍答得完」的那一點。
		//
		// 上界 300 秒＝5 分鐘：再長則前端等待與連線持有失去意義（逾時本身
		// 是為了讓失敗快點浮現，不是無限等待）。不開 ZeroDisables——
		// 0 若解作「不逾時」會讓不可達叢集把請求永遠掛住
		Key: PolicyK8sListTimeoutSeconds, Type: PolicyTypeInt, Default: "10",
		Min: 3, Max: 300,
		Label: "叢集列表逾時", Unit: "秒",
	},
	// 傳輸安全六通道強制等級：出廠 off 零影響
	//（易用取向——RDP/VNC 的現場部署預設本就不驗證憑證，出廠即 strict 會讓既有資產
	// 全數連不上）；PCI 建議 warn 起
	//（Req 4 傳輸強加密自我要求，留痕比阻斷有價值）
	{
		Key: PolicyTransportRDPLevel, Type: PolicyTypeEnum, Default: TransportLevelOff,
		PCIValue:    TransportLevelWarn,
		EnumOrder:   []string{TransportLevelOff, TransportLevelWarn, TransportLevelStrict},
		Requirement: "4.2.1", Label: "RDP 傳輸強制等級",
	},
	{
		Key: PolicyTransportVNCLevel, Type: PolicyTypeEnum, Default: TransportLevelOff,
		PCIValue:    TransportLevelWarn,
		EnumOrder:   []string{TransportLevelOff, TransportLevelWarn, TransportLevelStrict},
		Requirement: "4.2.1", Label: "VNC 傳輸強制等級",
	},
	{
		Key: PolicyTransportDBLevel, Type: PolicyTypeEnum, Default: TransportLevelOff,
		PCIValue:    TransportLevelWarn,
		EnumOrder:   []string{TransportLevelOff, TransportLevelWarn, TransportLevelStrict},
		Requirement: "4.2.1", Label: "資料庫傳輸強制等級",
	},
	{
		// LDAP 修復動作在身分管理的目錄設定頁（url 改 ldaps://，即時生效不需重啟；
		// 設定自遷入 DB 後不再由部署層 env 供給）；strict 拒 LDAP
		// 登入時本地帳號不受影響
		Key: PolicyTransportLDAPLevel, Type: PolicyTypeEnum, Default: TransportLevelOff,
		PCIValue:    TransportLevelWarn,
		EnumOrder:   []string{TransportLevelOff, TransportLevelWarn, TransportLevelStrict},
		Requirement: "4.2.1", Label: "LDAP 傳輸強制等級",
	},
	{
		Key: PolicyTransportSyslogLevel, Type: PolicyTypeEnum, Default: TransportLevelOff,
		PCIValue:    TransportLevelWarn,
		EnumOrder:   []string{TransportLevelOff, TransportLevelWarn, TransportLevelStrict},
		Requirement: "4.2.1", Label: "syslog 傳輸強制等級",
	},
	{
		Key: PolicyTransportNotifyLevel, Type: PolicyTypeEnum, Default: TransportLevelOff,
		PCIValue:    TransportLevelWarn,
		EnumOrder:   []string{TransportLevelOff, TransportLevelWarn, TransportLevelStrict},
		Requirement: "4.2.1", Label: "通知傳輸強制等級",
	},
	{
		// 同意記憶效期：效期動態判定
		//（consented_at + 本值），政策改動立即全域生效；0=永不過期。
		// PCI 未規定同意效期門檻，不做符合性評估
		Key: PolicyTransportConsentTTLDays, Type: PolicyTypeInt, Default: "90",
		ZeroDisables: true, Max: 3650,
		Label: "傳輸風險同意效期", Unit: "天",
	},
	// 存取政策鍵群：出廠 open 零破壞（功能 opt-in）；
	// PCI Req 7.2 最小權限精神建議 approval（自我要求框架）
	{
		Key: PolicyAccessPolicyDefault, Type: PolicyTypeEnum, Default: model.AccessPolicyOpen,
		PCIValue:    model.AccessPolicyApproval,
		EnumOrder:   []string{model.AccessPolicyOpen, model.AccessPolicyReason, model.AccessPolicyApproval},
		Requirement: "7.2", Label: "全域預設存取政策段位",
	},
	{
		// 申請時長上限（防申請超長時窗繞道成永久授權）：max 型＝值須 ≤ 建議 1440（1 天）
		Key: PolicyAccessRequestMaxDurationMinutes, Type: PolicyTypeInt, Default: "1440",
		PCIValue: "1440", Direction: DirectionMax, Max: 525600, // 上界 1 年（分鐘）
		Label: "申請時長上限", Unit: "分鐘",
	},
	{
		// pending 超時作廢時限（防單卡死；scheduler 掃描＋讀取惰性過濾雙保險）
		Key: PolicyAccessRequestPendingTimeoutHours, Type: PolicyTypeInt, Default: "72",
		PCIValue: "72", Direction: DirectionMax, Max: 8760, // 上界 1 年（小時）
		Label: "申請待審超時時限", Unit: "小時",
	},
	{
		// 最少核准人數：達門檻才轉 approved；
		// 預設 1＝與單人核准零行為差異。無 PCIValue（內控強化，非 PCI 要求——
		// 不做符合性評估、不進「套用建議值」）；0 無效（int 型非 ZeroDisables 自動拒）
		Key: PolicyAccessRequestMinApprovals, Type: PolicyTypeInt, Default: "1",
		Max:   10,
		Label: "最少核准人數", Unit: "人",
	},
	{
		// 破窗緊急連線開關：繞過人審的通道採 opt-in，
		// 出廠關即建議值（關閉期間緊急通道＝admin 豁免）
		Key: PolicyBreakGlassEnabled, Type: PolicyTypeBool, Default: "false",
		PCIValue:    "false",
		Requirement: "7.2", Label: "破窗緊急連線",
	},
	{
		// 破窗票證時窗（六題 2 拍板固定短窗，不開放破窗人自填；要長走正常申請）
		Key: PolicyBreakGlassDurationMinutes, Type: PolicyTypeInt, Default: "60",
		PCIValue: "60", Direction: DirectionMax, Max: 1440, // 上界 1 天（分鐘）
		Requirement: "7.2", Label: "破窗票證時窗", Unit: "分鐘",
	},
	{
		// 破窗補審逾期時限：逾期未補審升級告警（每單至多一次）
		Key: PolicyBreakGlassReviewTimeoutHours, Type: PolicyTypeInt, Default: "24",
		PCIValue: "24", Direction: DirectionMax, Max: 720, // 上界 30 天（小時）
		Requirement: "7.2", Label: "破窗補審逾期時限", Unit: "小時",
	},
	{
		// 撤銷即斷線（H 決議）：出廠關＝只擋新連線（與到期語義一致）；
		// 建議開（撤權即時收線，Req 7.2 撤銷存取的即時性）
		Key: PolicyAccessRevokeDisconnect, Type: PolicyTypeBool, Default: "false",
		PCIValue:    "true",
		Requirement: "7.2", Label: "撤銷即斷線",
	},
	// 資料傳輸管控五鍵（data-transfer-control）：出廠允許（既有行為零變更），
	// 一律無 PCIValue——法源是電支基準而非 PCI 條文，掛假 PCIValue 會讓它進
	// 「套用本頁建議值」並被標成 PCI 要求（同 access_request_min_approvals 的紀律）。
	// 電支基準值皆為 false，由 G3 電支建議值雙軌承接。
	{
		Key: PolicyClipboardSendEnabled, Type: PolicyTypeBool, Default: "true",
		Label: "剪貼簿貼入資產",
	},
	{
		Key: PolicyClipboardRecvEnabled, Type: PolicyTypeBool, Default: "true",
		Label: "剪貼簿複製出資產",
	},
	{
		Key: PolicyFileUploadEnabled, Type: PolicyTypeBool, Default: "true",
		Label: "檔案上傳至資產",
	},
	{
		Key: PolicyFileDownloadEnabled, Type: PolicyTypeBool, Default: "true",
		Label: "檔案自資產下載",
	},
	{
		Key: PolicyFileDeleteEnabled, Type: PolicyTypeBool, Default: "true",
		Label: "刪除資產上的檔案",
	},
	// 登入前告示兩鍵。出廠空＝未設定；無任一基準建議值（見鍵常數處的理由）。
	// 上限 120／2000 取的是「一行標題」與「一段可讀完的告示」，
	// 不是儲存能力的極限——欄位本身放得下更多，限制在於登入頁的可讀性
	{
		Key: PolicyLoginBannerTitle, Type: PolicyTypeText, Default: "",
		MaxLength: 120, Label: "登入告示標題",
	},
	{
		Key: PolicyLoginBannerBody, Type: PolicyTypeText, Default: "",
		MaxLength: 2000, Multiline: true, Label: "登入告示內文",
	},
}

// unitKeyByZh 政策單位的 zh→語義鍵 canonical 映射（unit 閉集）。
// 前端以 unit_key 查 policyUnit.<unit_key>；此表為 unit_key 的單一事實源。
// 新增政策若用了不在此表的 Unit，init 期 validatePolicyDefs 會 panic（rr-I5）。
var unitKeyByZh = map[string]string{
	"次":  "count",
	"分鐘": "minutes",
	"字元": "chars",
	"筆":  "records",
	"秒":  "seconds",
	"小時": "hours",
	"天":  "days",
	"人":  "persons",
	// 筆/小時：速率型單位（audit_chain_verify_rows_per_hour）。與「筆」分開是
	// 因為它量的是**速率**而非批次大小——同字面的「筆」會讓管理員讀成每輪列數
	"筆/小時": "records_per_hour",
}

// init 依 Unit 衍生 UnitKey 並驗證 invariant——UnitKey 不手填、由此保證 Unit≠""↔合法 UnitKey。
func init() {
	for i := range policyDefs {
		if policyDefs[i].Unit == "" {
			continue
		}
		key, ok := unitKeyByZh[policyDefs[i].Unit]
		if !ok {
			panic(fmt.Sprintf("policyDefs[%s]: Unit %q 無對應 unit_key（請補 unitKeyByZh）", policyDefs[i].Key, policyDefs[i].Unit))
		}
		policyDefs[i].UnitKey = key
	}
	if err := validatePolicyDefs(); err != nil {
		panic(err)
	}
}

// PolicyView 政策項視圖（API 回傳：定義 + 現值 + 符合性）
type PolicyView struct {
	PolicyDef
	Value string `json:"value"`
	// Compliant 是否符合 PCI 建議；無 PCI 建議值時為 nil（前端顯示「無建議值」）
	Compliant *bool `json:"compliant"`
	// EPaymentCompliant 是否符合電支基準建議；無該基準建議值時為 nil。
	// 與 Compliant 各自獨立——同一項可能符合其一而偏離另一
	EPaymentCompliant *bool `json:"epayment_compliant"`
	// StrictestValue 兩基準取嚴後的建議值（供「套用電支基準」使用）。
	// 無任一基準值時為空字串。取嚴而非直接用 EPaymentValue 的理由見 evaluateStrictest
	StrictestValue string     `json:"strictest_value,omitempty"`
	UpdatedBy      string     `json:"updated_by,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

type policyCacheEntry struct {
	value     string
	expiresAt time.Time
}

// SecurityPolicyService 安全政策服務：typed accessor + TTL 快取（更新即失效）
type SecurityPolicyService struct {
	db       *gorm.DB
	cacheTTL time.Duration

	mu    sync.RWMutex
	cache map[string]policyCacheEntry
	// lastGood 每鍵最後一次成功從 DB 讀到的合法值：DB 讀取失敗時
	// 退回此值而非較寬鬆的出廠預設，避免 admin 收緊的政策在 DB 抖動時 fail-open
	lastGood map[string]string
	// generation 每次 Update 遞增：Get 於 DB 讀取前後比對，期間有 Update
	// 就放棄寫快取，防「Get 讀到舊值後把它釘回快取整個 TTL」的 lost-update 競態
	generation atomic.Uint64
}

// NewSecurityPolicyService 建立安全政策服務。
// 同時對政策常數表做啟動自檢：常數表打錯字（如 enum PCIValue 非成員、
// int 預設不可解析）會讓符合性評估靜默錯判，寧可啟動即 panic 也不上線
func NewSecurityPolicyService(db *gorm.DB) *SecurityPolicyService {
	if err := validatePolicyDefs(); err != nil {
		panic(fmt.Sprintf("安全政策常數表自檢失敗（開發期錯誤）: %v", err))
	}
	return &SecurityPolicyService{
		db:       db,
		cacheTTL: defaultPolicyCacheTTL,
		cache:    map[string]policyCacheEntry{},
		lastGood: map[string]string{},
	}
}

// validatePolicyDefs 常數表完整性自檢：每個 Default／PCIValue 都須通過該欄型別驗證，
// enum 的 Default／PCIValue 都須是 EnumOrder 成員；並斷言 Unit↔UnitKey
// invariant（rr-I5）：Unit≠""↔有合法 UnitKey 且與 canonical 映射一致、Unit==""不得有 UnitKey
func validatePolicyDefs() error {
	for i := range policyDefs {
		def := &policyDefs[i]
		if err := validatePolicyValue(def, def.Default); err != nil {
			return fmt.Errorf("%s Default=%q 非法: %w", def.Key, def.Default, err)
		}
		if def.PCIValue != "" {
			if err := validatePolicyValue(def, def.PCIValue); err != nil {
				return fmt.Errorf("%s PCIValue=%q 非法: %w", def.Key, def.PCIValue, err)
			}
		}
		// 參考值必有值：標了性質卻沒有數字，等於在設定頁上掛一個空標籤，
		// 而符合性評估與一鍵套用都會靜默略過該鍵
		if def.PCIReference && def.PCIValue == "" {
			return fmt.Errorf("%s 標為 PCI 參考值但無 PCIValue（參考值必有值）", def.Key)
		}
		if def.Type == PolicyTypeEnum {
			if def.PCIValue != "" && enumRank(def.EnumOrder, def.PCIValue) < 0 {
				return fmt.Errorf("%s PCIValue=%q 不在 EnumOrder", def.Key, def.PCIValue)
			}
			if enumRank(def.EnumOrder, def.Default) < 0 {
				return fmt.Errorf("%s Default=%q 不在 EnumOrder", def.Key, def.Default)
			}
		}
		// text 的結構自檢：上限缺漏會讓「以 code point 計長度」退化成沒有上限
		//（RuneCountInString > 0 恆成立時任何長度都收），而 MaxLength／Multiline
		// 掛在非 text 型上會被靜默忽略——兩個方向都得擋，否則守衛只看得到一半
		if def.Type == PolicyTypeText {
			if def.MaxLength <= 0 {
				return fmt.Errorf("%s Type=text 須設正的 MaxLength（否則長度上限形同不存在）", def.Key)
			}
		} else {
			if def.MaxLength != 0 {
				return fmt.Errorf("%s Type=%s 不得設 MaxLength（僅 text 型有字元上限）", def.Key, def.Type)
			}
			if def.Multiline {
				return fmt.Errorf("%s Type=%s 不得設 Multiline（僅 text 型有換行語義）", def.Key, def.Type)
			}
		}
		// Min 的結構自檢：非 int 型不得設 Min（無意義且會被靜默忽略）；
		// Min 須落在有效上界之內，否則該鍵的值域為空、任何值都存不進去
		if def.Min != 0 {
			if def.Type != PolicyTypeInt {
				return fmt.Errorf("%s Type=%s 不得設 Min（僅 int 型有下界）", def.Key, def.Type)
			}
			if def.Min < 0 {
				return fmt.Errorf("%s Min=%d 不得為負", def.Key, def.Min)
			}
			effectiveMax := def.Max
			if effectiveMax == 0 {
				effectiveMax = defaultPolicyIntMax
			}
			if def.Min > effectiveMax {
				return fmt.Errorf("%s Min=%d 高於有效上界 %d（值域為空）", def.Key, def.Min, effectiveMax)
			}
		}
		switch {
		case def.Unit == "" && def.UnitKey != "":
			return fmt.Errorf("%s Unit 空但有 UnitKey %q", def.Key, def.UnitKey)
		case def.Unit != "" && def.UnitKey == "":
			return fmt.Errorf("%s Unit %q 但無 UnitKey", def.Key, def.Unit)
		case def.Unit != "" && def.UnitKey != unitKeyByZh[def.Unit]:
			return fmt.Errorf("%s UnitKey %q 與 Unit %q 映射 %q 不一致", def.Key, def.UnitKey, def.Unit, unitKeyByZh[def.Unit])
		}
	}
	return nil
}

// FindPolicyDef 查政策定義供本包外讀取型別與 metadata；不存在回 nil。
//
// 回的是常數表元素的指標（表在 init 之後即唯讀），呼叫端只讀不寫。
// 存在的理由是審計層需要依鍵的**型別**決定變更詳情怎麼記，而它拿到的只有鍵名。
func FindPolicyDef(key string) *PolicyDef { return findDef(key) }

// findDef 查政策定義；不存在回 nil
func findDef(key string) *PolicyDef {
	for i := range policyDefs {
		if policyDefs[i].Key == key {
			return &policyDefs[i]
		}
	}
	return nil
}

// Get 取政策現值（快取 → DB → 出廠預設）。未定義的鍵回空字串
func (s *SecurityPolicyService) Get(key string) string {
	def := findDef(key)
	if def == nil {
		return ""
	}

	s.mu.RLock()
	entry, ok := s.cache[key]
	s.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.value
	}

	// 記錄 DB 讀取前的世代，讀完若已被 Update 遞增則放棄寫快取
	gen := s.generation.Load()

	value := def.Default
	cacheable := true
	var row model.SecurityPolicy
	err := s.db.Where("key = ?", key).First(&row).Error
	switch {
	case err == nil:
		// 存量列走同一個正規化入口：手動改庫寫進來的 CRLF 或首尾空白，
		// 讀出來時與寫入路徑收斂到同一個終值
		if normalized, verr := normalizePolicyValue(def, row.Value); verr == nil {
			value = normalized
			s.mu.Lock()
			s.lastGood[key] = value
			s.mu.Unlock()
		} else {
			// 存量列值不合法（手動改庫等）：退回最後已知良好值，無則預設；不快取（等修）
			value = s.lastGoodOrDefault(key, def)
			cacheable = false
		}
	case errors.Is(err, gorm.ErrRecordNotFound):
		// 無列 = 出廠預設生效
	default:
		// DB 讀取失敗：退回最後成功讀到的合法值而非較寬鬆的出廠預設，
		// 避免 admin 收緊的政策在 DB 抖動時悄悄 fail-open；且不快取（下次重試 DB）
		value = s.lastGoodOrDefault(key, def)
		cacheable = false
		log.Printf("[SecurityPolicy] 讀取政策 %s 失敗，暫用最後已知值 %q: %v", key, value, err)
	}

	if cacheable {
		s.mu.Lock()
		if s.generation.Load() == gen {
			s.cache[key] = policyCacheEntry{value: value, expiresAt: time.Now().Add(s.cacheTTL)}
		}
		s.mu.Unlock()
	}
	return value
}

// lastGoodOrDefault 取最後已知良好值，無則出廠預設（呼叫端自行加鎖或處於單一讀路徑）
func (s *SecurityPolicyService) lastGoodOrDefault(key string, def *PolicyDef) string {
	s.mu.RLock()
	v, ok := s.lastGood[key]
	s.mu.RUnlock()
	if ok {
		return v
	}
	return def.Default
}

// GetInt 取 int 型政策值；解析失敗回該鍵預設值
func (s *SecurityPolicyService) GetInt(key string) int {
	v, err := strconv.Atoi(s.Get(key))
	if err != nil {
		def := findDef(key)
		if def == nil {
			return 0
		}
		fallback, _ := strconv.Atoi(def.Default)
		return fallback
	}
	return v
}

// GetBool 取 bool 型政策值
func (s *SecurityPolicyService) GetBool(key string) bool {
	return s.Get(key) == "true"
}

// PolicyChange 一筆政策變更（供批次更新回報審計）
type PolicyChange struct {
	Key      string
	OldValue string
	NewValue string
}

// SeedFromEnv 以環境變數初始化政策列：部署可用 env 決定初值。
// 僅在 DB 尚無該鍵列時寫入——使用者透過政策頁設定過的值永不被 env 覆蓋；
// env 未設或非法值則維持出廠預設（非法值記警告不擋啟動）。
//
// **不套用跨鍵約束**（audit-checkpoint-chain 7.3）。理由是**故障方向**，
// 與升級相容無關（檢查點鍵出廠 0，原註解所述的
//「出廠 3650 使 `RECORDING_RETENTION_DAYS=0` 違規」前提已不存在）：
// 播種被擋時該鍵無列而退回出廠值，`RECORDING_RETENTION_DAYS=3650` 的部署
// 會靜默退回 90 天並**開始刪本應保留更久的錄影**——擋種子的失敗方向是刪資料。
// 放行則只產生一個違規狀態且不損失證據：retention 執行期偵測到違規即跳過
// 鏈修剪（保守方向），且 admin 一旦於政策頁動到任一相關鍵就會被要求修正。
//
// 觸發面很窄：檢查點鍵無 env 播種，出廠 0 使任何資料鍵值皆合規，
// 故僅「admin 已設檢查點鍵有期值、錄影鍵仍無列、且部署帶該 env」時才會發生
func (s *SecurityPolicyService) SeedFromEnv(key, envVar string) {
	raw := os.Getenv(envVar)
	if raw == "" {
		return
	}
	s.SeedValue(key, raw, "環境變數 "+envVar+"="+raw)
}

// SeedValue 以呼叫端算出的值播種政策列，規則與 SeedFromEnv 完全相同
//（僅在該鍵尚無列時寫入、過 validate、updatedBy 記 env-init、不套跨鍵約束、
// 非法值記警告不擋啟動）。
//
// **為何需要它**：SeedFromEnv 只受理「env 原值直接搬」，而部分鍵的種子是
// **推導結果**而非某個 env 的原值——例如 refresh_cookie_secure 的初值來自
// `AUTH_REFRESH_COOKIE_SECURE` 與 `PUBLIC_BASE_URL` 的 scheme 兩層優先序。
// origin 只是給日誌的來源說明（如「環境變數 X=y」），不入庫。
//
// **有列即不動是本方法唯一不可退讓的性質**：管理員在政策頁的線上修正，
// 若被下次重啟的播種悄悄改回，等於部署檔在背後推翻了管理端的決定。
func (s *SecurityPolicyService) SeedValue(key, value, origin string) {
	if value == "" {
		return
	}
	def := findDef(key)
	if def == nil {
		return
	}
	var count int64
	if err := s.db.Model(&model.SecurityPolicy{}).Where("key = ?", key).Count(&count).Error; err != nil {
		log.Printf("[SecurityPolicy] 播種查詢失敗 (key=%s): %v", key, err)
		return
	}
	if count > 0 {
		return
	}
	if err := validatePolicyValue(def, value); err != nil {
		log.Printf("[SecurityPolicy] 政策 %s 的播種值 %q（來源 %s）非法，忽略（沿用出廠預設 %s）: %v",
			key, value, origin, def.Default, err)
		return
	}
	if _, err := s.updateBatch(map[string]string{key: value}, PolicySeededBy, false); err != nil {
		log.Printf("[SecurityPolicy] 播種寫入失敗 (key=%s): %v", key, err)
		return
	}
	log.Printf("[SecurityPolicy] 政策 %s 以 %s 初始化為 %s", key, origin, value)
}

// ValueSource 回報該鍵現值的來源分類（啟動日誌歸因用，見 PolicySource* 常數）。
//
// 分類判準是政策列的存在與其 UpdatedBy：**播種與管理端設定必須分得開**，
// 否則日誌指的復原路徑會指錯地方（改 env 對已被管理端設定過的鍵無效）。
func (s *SecurityPolicyService) ValueSource(key string) string {
	var row model.SecurityPolicy
	switch err := s.db.Where("key = ?", key).First(&row).Error; {
	case err == nil:
		if row.UpdatedBy == PolicySeededBy {
			return PolicySourceSeed
		}
		return PolicySourceAdmin
	case errors.Is(err, gorm.ErrRecordNotFound):
		return PolicySourceDefault
	default:
		// 讀不到就說讀不到：把 DB 故障說成「出廠預設」會讓日誌的歸因變成猜測
		log.Printf("[SecurityPolicy] 查詢政策 %s 的來源失敗: %v", key, err)
		return PolicySourceUnknown
	}
}

// Update 更新單一政策值（驗證 → upsert → 快取失效），回傳舊值供審計
func (s *SecurityPolicyService) Update(key, value, updatedBy string) (string, error) {
	changes, err := s.UpdateBatch(map[string]string{key: value}, updatedBy)
	if err != nil {
		return "", err
	}
	if len(changes) == 0 {
		return value, nil // 無變更（新舊相同）
	}
	return changes[0].OldValue, nil
}

// UpdateBatch 於單一交易內批次更新政策（中途失敗全回滾，不半套生效）。
// 回傳實際有變動的鍵（舊≠新）供呼叫端審計；舊值在交易內讀取，不受快取競態污染
func (s *SecurityPolicyService) UpdateBatch(updates map[string]string, updatedBy string) ([]PolicyChange, error) {
	return s.updateBatch(updates, updatedBy, true)
}

// updateBatch 批次更新；crossKey 控制是否套用跨鍵約束驗證。
//
// **唯一 crossKey=false 的入口是 SeedFromEnv**（見該函式的說明）：它是升級相容
// 路徑，保住既有部署的行為優先於新約束；由此產生的違規狀態不會造成證據損失，
// retention 執行期偵測到違規即保守跳過鏈修剪
func (s *SecurityPolicyService) updateBatch(updates map[string]string, updatedBy string, crossKey bool) ([]PolicyChange, error) {
	// 先整批驗證鍵與值（任何一項不合法即整批拒絕）。
	// 驗證回傳的終值取代原值進入後續流程——落庫、審計 old→new 與跨鍵驗證讀到的
	// 必須是同一個字串，否則管理員存的與系統存的會在文字型鍵上分岔
	normalized := make(map[string]string, len(updates))
	for key, value := range updates {
		def := findDef(key)
		if def == nil {
			return nil, &PolicyUnknownKeyError{Key: key}
		}
		final, err := normalizePolicyValue(def, value)
		if err != nil {
			return nil, err
		}
		normalized[key] = final
	}
	updates = normalized
	// 單鍵驗證通過後才做跨鍵驗證（它讀的是「已知型別合法」的終值）
	if crossKey {
		if err := s.validateCrossKeyRetention(updates); err != nil {
			return nil, err
		}
	}

	var changes []PolicyChange
	err := s.db.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		for key, value := range updates {
			// 交易內讀舊值（審計 old→new 的真值，不讀快取）
			oldValue := findDef(key).Default
			var existing model.SecurityPolicy
			switch err := tx.Where("key = ?", key).First(&existing).Error; {
			case err == nil:
				oldValue = existing.Value
			case errors.Is(err, gorm.ErrRecordNotFound):
				// 無列 = 舊值為出廠預設
			default:
				return fmt.Errorf("讀取政策 %s 舊值失敗: %w", key, err)
			}

			row := model.SecurityPolicy{Key: key, Value: value, UpdatedBy: updatedBy, UpdatedAt: now}
			if err := tx.Save(&row).Error; err != nil {
				return fmt.Errorf("寫入安全政策 %s 失敗: %w", key, err)
			}
			if oldValue != value {
				changes = append(changes, PolicyChange{Key: key, OldValue: oldValue, NewValue: value})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// 交易提交後才失效快取並遞增世代（更新即失效；令進行中的 Get 放棄寫舊值）
	s.generation.Add(1)
	s.mu.Lock()
	for key := range updates {
		delete(s.cache, key)
	}
	s.mu.Unlock()

	return changes, nil
}

// List 全部政策項視圖（含現值與符合性），依常數表順序
func (s *SecurityPolicyService) List() []PolicyView {
	// 一次撈全部政策列，避免逐鍵查詢
	var rows []model.SecurityPolicy
	rowByKey := map[string]model.SecurityPolicy{}
	if err := s.db.Find(&rows).Error; err == nil {
		for _, r := range rows {
			rowByKey[r.Key] = r
		}
	}

	views := make([]PolicyView, 0, len(policyDefs))
	for _, def := range policyDefs {
		value := def.Default
		view := PolicyView{PolicyDef: def, Value: value}
		row, hasRow := rowByKey[def.Key]
		normalized, verr := normalizePolicyValue(&def, row.Value)
		if hasRow && verr == nil {
			view.Value = normalized
			view.UpdatedBy = row.UpdatedBy
			updatedAt := row.UpdatedAt
			view.UpdatedAt = &updatedAt
		}
		view.Compliant = evaluateCompliance(&def, view.Value)
		view.EPaymentCompliant = evaluateEPaymentCompliance(&def, view.Value)
		view.StrictestValue = evaluateStrictest(&def)
		views = append(views, view)
	}
	return views
}

// DeviationCount 與 PCI 建議偏離項數（政策頁摘要條）。
//
// **語義維持不變**：新增電支基準後仍只計 PCI
// 偏離，不改為兩基準合計——既有前端與其 fixture 依賴這個數字的既有意義
func (s *SecurityPolicyService) DeviationCount() int {
	count := 0
	for _, v := range s.List() {
		if v.Compliant != nil && !*v.Compliant {
			count++
		}
	}
	return count
}

// EPaymentDeviationCount 與電支基準建議偏離項數。與 DeviationCount 各自獨立：
// 同一項可能符合其一而偏離另一，合計會使兩者都不可解讀
func (s *SecurityPolicyService) EPaymentDeviationCount() int {
	count := 0
	for _, v := range s.List() {
		if v.EPaymentCompliant != nil && !*v.EPaymentCompliant {
			count++
		}
	}
	return count
}

// validatePolicyValue 驗證政策值的型別與範圍（不需要終值的呼叫端用這支）
func validatePolicyValue(def *PolicyDef, value string) error {
	_, err := normalizePolicyValue(def, value)
	return err
}

// normalizePolicyValue 驗證政策值並回傳可落庫的終值。
//
// **正規化與驗證同一個入口**：文字型政策值會被統一換行、去首尾空白，若兩件事
// 分成兩支函式，任何一條寫入路徑只呼叫其中一支就會讓「驗過的東西」與
// 「存進去的東西」不是同一個字串。除文字型外，終值恆等於原值。
func normalizePolicyValue(def *PolicyDef, value string) (string, error) {
	switch def.Type {
	case PolicyTypeText:
		return normalizeTextPolicyValue(def, value)
	}
	return value, validateScalarPolicyValue(def, value)
}

// normalizeTextPolicyValue 文字型政策值的正規化與驗證。
//
// 順序有意義：先確認是合法 UTF-8，再統一換行與去空白，最後才逐字元檢查與計長
// ——反過來做的話，長度會把稍後要被剝掉的空白算進去，而管理員看到的字數與
// 伺服器算的不一致。
//
// 不做 HTML 轉義、不剝除標記：存的是資料，「不渲染成標記」是呈現層的責任。
// 零寬與雙向控制字元（Cf）不擋——內容由管理員撰寫且舊值新值全文入審計。
func normalizeTextPolicyValue(def *PolicyDef, value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", &PolicyInvalidValueError{Key: def.Key, Reason: "須為合法 UTF-8"}
	}
	v := strings.ReplaceAll(value, "\r\n", "\n")
	v = strings.ReplaceAll(v, "\r", "\n")
	v = strings.TrimSpace(v)
	for _, r := range v {
		switch {
		case r == '\t':
			// TAB 是排版字元，不是控制序列的一部分，一律放行
		case r == '\n':
			if !def.Multiline {
				return "", &PolicyInvalidValueError{Key: def.Key, Reason: "不可含換行"}
			}
		case unicode.IsControl(r):
			// Cc（C0、DEL、C1）：終端逸出序列與畫面控制的載體。
			// C1 也擋——U+0085 在若干解碼路徑上等同換行，放行等於讓單行鍵換行
			return "", &PolicyInvalidValueError{Key: def.Key, Reason: "不可含控制字元"}
		}
	}
	if n := utf8.RuneCountInString(v); n > def.MaxLength {
		return "", &PolicyInvalidValueError{
			Key:    def.Key,
			Reason: fmt.Sprintf("字元數 %d 超過上限 %d", n, def.MaxLength),
		}
	}
	// 正規化後為空＝未設定，是合法值
	return v, nil
}

// validateScalarPolicyValue 非文字型（int／bool／enum）政策值的型別與範圍驗證
func validateScalarPolicyValue(def *PolicyDef, value string) error {
	switch def.Type {
	case PolicyTypeInt:
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return &PolicyInvalidValueError{Key: def.Key, Reason: "須為非負整數"}
		}
		if n == 0 && !def.ZeroDisables {
			return &PolicyInvalidValueError{Key: def.Key, Reason: "不可為 0"}
		}
		// 下界：堵「調到極小＝實質關閉」的靜默路徑。
		// **0 不在此檢查範圍內**——0 的去留已由上一段的 ZeroDisables 決定，
		// 兩者正交：ZeroDisables 管「能不能明著關」，Min 管「能不能偽裝成還開著」。
		// 故 Min:10 且 ZeroDisables:true 時值域為 {0} ∪ [10, Max]，1-9 非法；
		// 這個不連續值域是刻意的，讀作「要嘛明著關掉，要嘛開著就得有意義」
		if def.Min > 0 && n != 0 && n < def.Min {
			return &PolicyInvalidValueError{Key: def.Key, Reason: fmt.Sprintf("不可低於 %d", def.Min)}
		}
		// 上界（LOCK-1）：防 int64 溢位與不合理極端值；未指定 Max 用通用天花板
		max := def.Max
		if max == 0 {
			max = defaultPolicyIntMax
		}
		if n > max {
			return &PolicyInvalidValueError{Key: def.Key, Reason: fmt.Sprintf("不可超過 %d", max)}
		}
	case PolicyTypeBool:
		if value != "true" && value != "false" {
			return &PolicyInvalidValueError{Key: def.Key, Reason: "須為 true/false"}
		}
	case PolicyTypeEnum:
		for _, allowed := range def.EnumOrder {
			if value == allowed {
				return nil
			}
		}
		return &PolicyInvalidValueError{Key: def.Key, Reason: "不在允許值中"}
	default:
		return &PolicyInvalidValueError{Key: def.Key, Reason: "未知型別 " + def.Type}
	}
	return nil
}

// evaluateCompliance 對 PCI 建議值的符合性（既有語義，呼叫端不變）。
func evaluateCompliance(def *PolicyDef, value string) *bool {
	return evaluateComplianceAgainst(def, value, def.PCIValue)
}

// evaluateEPaymentCompliance 對電支基準建議值的符合性。
// 與 PCI 走**同一個比較器**——比較邏輯只有一份，兩基準各跑一次
// （複製比較邏輯會使兩側日後漂移）。
func evaluateEPaymentCompliance(def *PolicyDef, value string) *bool {
	return evaluateComplianceAgainst(def, value, def.EPaymentValue)
}

// evaluateComplianceAgainst 符合性比較器，基準值由呼叫端指定：
// - 基準值為空 → nil（不評估）
// - 0=停用 sentinel → 一律不符（先判，避免 0<=10 誤判合規）
// - int: min 型須 >= 基準、max 型須 <= 基準
// - bool: 等值
// - enum: 現值序位 >= 基準值序位（枚舉序弱→強）
func evaluateComplianceAgainst(def *PolicyDef, value, baseline string) *bool {
	if baseline == "" {
		return nil
	}
	result := false
	switch def.Type {
	case PolicyTypeInt:
		n, err := strconv.Atoi(value)
		base, baseErr := strconv.Atoi(baseline)
		if err != nil || baseErr != nil {
			return &result
		}
		if def.ZeroDisables && n == 0 {
			return &result
		}
		if def.Direction == DirectionMin {
			result = n >= base
		} else {
			result = n <= base
		}
	case PolicyTypeBool:
		result = value == baseline
	case PolicyTypeEnum:
		// 任一序位為 -1（值或基準值不在序列）一律判不符：否則
		// 基準值打錯字使其 rank=-1，任何合法值 >= -1 都會被誤報成合規
		rankValue := enumRank(def.EnumOrder, value)
		rankBase := enumRank(def.EnumOrder, baseline)
		result = rankValue >= 0 && rankBase >= 0 && rankValue >= rankBase
	}
	return &result
}

// evaluateStrictest 回傳兩基準中**較嚴**的建議值，供「套用電支基準」使用。
//
// **為何不能直接套用 EPaymentValue**：兩基準在
// 部分項目上方向相反——密碼最小長度 PCI 要求 >=12、電支只要求 >=6。若「套用電支
// 基準」實作為無條件覆寫，一個已設 12 的系統會被改成 6，**「套用合規基準」這個
// 動作反而降低了系統安全性**。取嚴交集才是「同時滿足兩基準」的正確語義。
//
// 較嚴的判定依型別與方向：
// - int min 型（值須 >= 基準）：基準值較大者較嚴
// - int max 型（值須 <= 基準）：基準值較小者較嚴
// - bool：任一基準要求 true 即取 true（true 為較嚴側）
// - enum：序位較高者較嚴（枚舉序弱→強）
//
// 任一基準缺值時回傳另一者；兩者皆缺回空字串（呼叫端據此略過該項）。
func evaluateStrictest(def *PolicyDef) string {
	pci, ep := def.PCIValue, def.EPaymentValue
	if pci == "" {
		return ep
	}
	if ep == "" {
		return pci
	}

	switch def.Type {
	case PolicyTypeInt:
		p, pErr := strconv.Atoi(pci)
		e, eErr := strconv.Atoi(ep)
		if pErr != nil || eErr != nil {
			return pci // 基準值不可解析時退回 PCI（既有行為），不臆測
		}
		if def.Direction == DirectionMin {
			if e > p {
				return ep
			}
			return pci
		}
		if e < p {
			return ep
		}
		return pci
	case PolicyTypeBool:
		if pci == "true" || ep == "true" {
			return "true"
		}
		return pci
	case PolicyTypeEnum:
		rp, re := enumRank(def.EnumOrder, pci), enumRank(def.EnumOrder, ep)
		if re > rp {
			return ep
		}
		return pci
	}
	return pci
}

// enumRank 枚舉序位；不在序列中回 -1（必不符）
func enumRank(order []string, value string) int {
	for i, v := range order {
		if v == value {
			return i
		}
	}
	return -1
}
