package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"
)

// 出廠預設密鑰（2.2.2）：release 模式偵測到仍為這些值即拒絕啟動。
// 導出供啟動自檢與測試比對，單一事實源
const (
	DefaultJWTSecret     = "change-me-in-production-dev-secret" // >=32 bytes（JWT_SECRET 長度下限）
	DefaultEncryptionKey = "dev-key-for-testing-only-ok32bts"
)

// AdminInitialPasswordMinLength ADMIN_INITIAL_PASSWORD 長度下限，比照 password_min_length
// （PCI 8.3.6，安全政策預設 12）。此為初始 bootstrap 密碼，首登即強制改密退役。
const AdminInitialPasswordMinLength = 12

// DefaultAdminInitialPassword .env.example 出貨 placeholder（deployment-hardening）。
// 刻意長於下限且列入 denylist：release 空 DB 啟動時因命中 denylist（非長度）而 fail-close，
// 逼部署者換為自訂高熵值；長於下限確保測試覆蓋的是 denylist 判定。
const DefaultAdminInitialPassword = "change-me-admin-initial-password-in-env"

// legacyDefaultAdminPassword 歷史出廠管理員密碼；ValidateAdminInitialPassword 一併 denylist，
// 避免部署者把已公開的舊預設值當成初始密碼。legacy 既有安裝掃描於 repository 層另行比對。
const legacyDefaultAdminPassword = "admin123"

// ValidateAdminInitialPassword 檢查 bootstrap 初始密碼的 byte 契約（deployment-hardening D8）。
// 回空字串＝合格；否則回不洩密的違規原因。驗證與後續 bcrypt SHALL 使用完全相同的 bytes，
// 故此處只檢查、不改寫值（呼叫端不得先 TrimSpace），以免 operator 實際輸入與 hash 的 bytes 不一致。
func ValidateAdminInitialPassword(pw string) string {
	if pw == "" {
		return "未設定"
	}
	if pw == DefaultAdminInitialPassword || pw == legacyDefaultAdminPassword {
		return "仍為出貨預設值或 placeholder"
	}
	for _, r := range pw {
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsControl(r) {
			return "含控制字元或換行（請確認未含尾端換行）"
		}
	}
	if pw != strings.TrimSpace(pw) {
		return "含前後空白"
	}
	if len(pw) < AdminInitialPasswordMinLength {
		return "長度不足"
	}
	return ""
}

// 資料庫驅動的合法值（DB_DRIVER）。導出供 InitDatabase 的分支、啟動組態驗證與
// 測試共用同一份字面，避免三處各抄一次而分歧。
//
// **DBDriverPostgres 是唯一的正式部署目標**；DBDriverSQLite 只服務單元測試——
// 版本化 migration 一律 PG 語法，設 sqlite 啟動必在遷移階段崩潰，不可用於部署。
const (
	DBDriverPostgres = "postgres"
	DBDriverSQLite   = "sqlite"
)

// ValidateDatabaseDriver 驗證 DB_DRIVER 的取值；回 nil 即可用。
//
// **為何是 fail-close 而非留預設值**：原本 `getEnv("DB_DRIVER", "sqlite")` 的預設值
// 與「PostgreSQL 是唯一正式部署目標」直接矛盾。它的實際危害不是「sqlite 部署會壞掉」
// 而是**壞得離真因很遠**——未設該變數的手動啟動會靜默取 sqlite，連線階段一路
// 開檔成功（gorm.Open 對 sqlite 檔不做任何 schema 判定），直到 RunMigrations
// 套用 baseline 的 PG 專屬 DDL 才丟出一串語法錯；操作者看到的是
// SQL 錯誤，而真因是三層之外的一個沒設的環境變數。任何預設值都必然對某一方
// 選錯邊，故不選：缺值即拒絕啟動，並在訊息裡直接給做法。
//
// 訊息刻意回答三個問題（不然「DB_DRIVER 未設定」對操作者等於沒說）：
// 正式部署該設什麼、compose 使用者為何不會遇到（因而遇到的人正處於什麼情境）、
// 以及為什麼不能圖方便填 sqlite。
func ValidateDatabaseDriver(driver string) error {
	switch driver {
	case DBDriverPostgres, DBDriverSQLite:
		return nil
	case "":
		return fmt.Errorf(
			"DB_DRIVER 未設定，且本變數無出廠預設值：正式部署請設 DB_DRIVER=%s（PostgreSQL 是唯一正式部署目標）。"+
				"以 docker compose 啟動者不會遇到本錯誤——docker-compose.yml 與 docker-compose.dev.yml 的 backend "+
				"environment: 皆已提供 DB_DRIVER=%s，它屬 compose 拓撲常數故刻意不列於 .env.example；"+
				"看到本訊息代表此行程是以裸二進位或自製編排（k8s manifest、systemd unit 等）啟動，請在該處補上同一個值。"+
				"切勿改填 %s：那只服務單元測試，版本化 migration 一律 PG 語法，會在遷移階段崩潰",
			DBDriverPostgres, DBDriverPostgres, DBDriverSQLite)
	default:
		return fmt.Errorf(
			"DB_DRIVER=%q 不是支援的資料庫驅動：正式部署請設 %s；%s 僅供單元測試（版本化 migration 一律 PG 語法，"+
				"設它啟動必在遷移階段崩潰，不可用於部署）",
			driver, DBDriverPostgres, DBDriverSQLite)
	}
}

// Config 儲存應用程式設定
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	Security  SecurityConfig
	Guacamole GuacamoleConfig
	// LDAP 欄位已移除（ldap-settings-migration D2/2.11）：目錄設定的執行期
	// 事實源是 ldap_directories 表，不再有啟動時的 env 快照。九個 LDAP_* 鍵
	// 僅由首次啟動的 seed 路徑（service/ldap_seed_migration.go）讀取
	Features FeatureFlags
	// Seal B 模式解封端點組態（kek-provider-modularization D6.4）：速率、
	// 可信代理、來源網段與獨立監聽位址。不含任何金鑰材料。
	Seal SealConfig
	// OIDC 身分提供者整合組態（idp-oidc-integration）
	OIDC OIDCConfig
}

// OIDCConfig OIDC 整合的部署層設定（idp-oidc-integration D3/D12）。
//
// provider 本身的設定（issuer/client_id/secret/規則）存 DB 由管理端維護；
// 此處只放**部署層**才該決定的三件事
type OIDCConfig struct {
	// PublicBaseURL 對外基準網址，用於組出 redirect_uri 與 callback 導回位址。
	//
	// **不從 request Host 推導**：反向代理多層轉發下推導必然出錯，且該值會被
	// 寫進交給 IdP 的 redirect_uri，錯誤時使用者會被導向錯誤主機。未設定時
	// 有 provider 啟用即標記「設定不完整」並於登入頁隱藏（fail-close）
	PublicBaseURL string

	// DedicatedIssuers 部署層宣告的專屬 issuer（逗號分隔）。
	//
	// 這是 Okta／自架 IdP 的**必要**逃生口——它們不發 hd/tid 類組織歸屬 claim，
	// 而系統對未知 issuer 一律 fail-close 視為共用（要求組織歸屬規則），
	// 若無此宣告，其自動供應在本設計下不可組態。
	// 置於部署層而非管理端 API：宣告「此 issuer 只服務本組織」需要部署層權限，
	// admin 帳號自身不得放寬安全規則。內建共用清單優先於本宣告。
	DedicatedIssuers []string

	// AllowedInternalHosts 允許出站的內部主機名（逗號分隔）。
	// 內網 IdP 場景以此顯式放行，而非提供「關閉位址檢查」的布林開關
	AllowedInternalHosts []string
}

// ServerConfig 伺服器設定
type ServerConfig struct {
	Port string
	Mode string // debug, release, test
	// CORSAllowedOrigins CORS 來源 allowlist（CORS_ALLOWED_ORIGINS 逗號分隔）；
	// 空 = 未設定：dev 模式全開、release 模式僅同源（7.3/D9）
	CORSAllowedOrigins []string
	// MetricsToken 指標端點（`/metrics`）的 bearer token（observability-lite D3）。
	//
	// **空 = 免認證曝光**，此為預設且刻意：該端點不在 `/api` 之下，正式版 edge
	// 只代理 `/api` 與 `/ws`，故預設部署下自外部打不到——安全性由拓撲承擔。
	// 要對外暴露（跨機採集）的部署方須自行加 edge location，**該動作即是設本值的
	// 觸發點**，兩者在 runbook 中為同一步，不給「只開洞不設 token」的中間狀態。
	MetricsToken string
}

// DatabaseConfig 資料庫設定
type DatabaseConfig struct {
	// Driver 資料庫驅動（DB_DRIVER）。**無出廠預設值**：未設即空字串，
	// 由 ValidateDatabaseDriver 於啟動組態段 fail-close（見該函式的理由說明）。
	// 合法值只有 DBDriverPostgres（唯一正式部署目標）與 DBDriverSQLite（僅單元測試）。
	// 原註解列的 mysql 從未被 InitDatabase 接受，已移除以免誤導
	Driver   string
	Host     string
	Port     int
	Database string
	Username string
	Password string
	SSLMode  string
}

// SecurityConfig 安全性設定
type SecurityConfig struct {
	JWTSecret     string
	EncryptionKey string // AES-256 需要 32 bytes
	// AdminInitialPassword 全新（空 DB）部署建立初始 admin 的密碼（deployment-hardening CPG-001）。
	// 僅空 DB seed 時使用，首登強制改密後退役；非空 DB 啟動忽略其值（僅告警提醒移除）。
	AdminInitialPassword string
	// RefreshCookie refresh 憑證 cookie 的 Secure 旗標推導結果
	// （refresh-token-httponly-cookie 決策 2）。啟動時定值，不逐請求重算。
	RefreshCookie RefreshCookieSecureDerivation
}

// RefreshCookieSecureDerivation refresh cookie 的 `Secure` 旗標推導結果與其來源。
//
// **來源一併保留**是為了啟動日誌能歸因：兩個誤設方向都會產生難以歸因的故障，
// 而瀏覽器丟棄 Set-Cookie 是靜默行為，錯誤訊息本身指不出成因。
type RefreshCookieSecureDerivation struct {
	Secure bool
	// Source 推導依據，取下列三個常數之一
	Source string
}

// refresh cookie Secure 推導的三個來源標記（決策 2 的優先序）。
const (
	// RefreshCookieSecureFromEnv 由 AUTH_REFRESH_COOKIE_SECURE 顯式覆寫
	RefreshCookieSecureFromEnv = "AUTH_REFRESH_COOKIE_SECURE"
	// RefreshCookieSecureFromBaseURL 由 PUBLIC_BASE_URL 的 scheme 推導
	RefreshCookieSecureFromBaseURL = "PUBLIC_BASE_URL"
	// RefreshCookieSecureFromDefault 兩者皆未提供有效訊息時的預設（false）
	RefreshCookieSecureFromDefault = "default"
)

// DeriveRefreshCookieSecure 依決策 2 的優先序推導 refresh cookie 的 Secure 旗標。
//
// 為何不寫死（兩個方向都有真實失敗模式）：
//   - 寫死 true：純 HTTP 部署下瀏覽器**靜默**丟棄 Set-Cookie，使用者陷入
//     「登入成功 → access token 到期 → 刷新失敗 → 被登出」的迴圈，且無錯誤訊息可歸因。
//   - 寫死 false：生產 HTTPS 環境放棄降級攻擊防護（誘導一次 http 請求即可竊取 cookie）。
//
// 純函式（不自行讀 env）：推導規則要能逐格測試，而測試不得污染行程 env。
func DeriveRefreshCookieSecure(explicit, publicBaseURL string) RefreshCookieSecureDerivation {
	// 1. 顯式覆寫最高優先。無法解析的值視同未設——靜默採信一個拼錯的布林
	//    等於讓部署者以為自己關掉（或打開）了保護
	if explicit != "" {
		if v, err := strconv.ParseBool(strings.TrimSpace(explicit)); err == nil {
			return RefreshCookieSecureDerivation{Secure: v, Source: RefreshCookieSecureFromEnv}
		}
	}
	// 2. PUBLIC_BASE_URL 的 scheme
	if u := strings.TrimSpace(publicBaseURL); u != "" {
		lower := strings.ToLower(u)
		switch {
		case strings.HasPrefix(lower, "https://"):
			return RefreshCookieSecureDerivation{Secure: true, Source: RefreshCookieSecureFromBaseURL}
		case strings.HasPrefix(lower, "http://"):
			return RefreshCookieSecureDerivation{Secure: false, Source: RefreshCookieSecureFromBaseURL}
		}
	}
	// 3. 未設（本地／開發形態）
	return RefreshCookieSecureDerivation{Secure: false, Source: RefreshCookieSecureFromDefault}
}

// LoadRefreshCookieSecure 自 env 推導 refresh cookie 的 Secure 旗標
// （部署期常數，沿 LoadSeal 的慣例）。
//
// 三值語義故用 lookupRaw：getEnvBool 的「無效值回落預設」會把「顯式設定」
// 與「未設」壓成同一種結果，而本推導的第一順位正是「有沒有顯式設定」。
func LoadRefreshCookieSecure() RefreshCookieSecureDerivation {
	return DeriveRefreshCookieSecure(
		lookupRaw("AUTH_REFRESH_COOKIE_SECURE"), getEnv("PUBLIC_BASE_URL", ""))
}

// GuacamoleConfig Guacamole 設定
type GuacamoleConfig struct {
	Host string
	Port int
}

// LDAPConfig LDAP 認證器的撥號參數（search-then-bind 模式）。
//
// **自 ldap-settings-migration 起不再由 env 供給**：執行期事實源是
// ldap_directories 表，本結構僅作為「一次登入的撥號參數」傳入認證器
// （service.newLDAPAuthenticatorFromSnapshot 由 LDAPDialSnapshot 填入）。
// 型別留在 config 套件是為了不動既有認證器與其撥號接縫測試；
// 它已不是設定來源，Config 亦不再持有此欄位
type LDAPConfig struct {
	Enabled      bool
	URL          string // 例：ldap://host:389 或 ldaps://host:636
	BindDN       string // service account DN，用於搜尋用戶
	BindPassword string
	BaseDN       string // 用戶搜尋基準 DN
	UserFilter   string // 搜尋過濾器模板，%s 代入（已轉義的）登入帳號
	AttrEmail    string // 對應 email 的目錄屬性
	AttrFullName string // 對應全名的目錄屬性
	// SkipTLSVerify 僅供測試環境（自簽憑證）；生產環境必須保持 false
	SkipTLSVerify bool
}

// FeatureFlags 功能開關配置
//
// **權限檢查不在此列**（security-backlog-settlement D5）：它於所有模式無條件生效，
// 開關本身已移除。安全紅線中「任何組態都不該關」者，正確處置是不提供開關，
// 而非提供後於 release 模式強制——後者使開發與測試組態成為「權限缺陷測不出來」
// 的環境，且每新增一個消費點就多一條需要記得強制的路徑
type FeatureFlags struct {
	// 審計日誌系統
	AuditLogEnabled     bool
	AsyncAuditEnabled   bool
	AuditFallbackToFile bool

	// 異常連線偵測
	AnomalyDetectionEnabled bool

	// 告警通知系統
	AlertingEnabled bool
}

// Load 從環境變數載入設定
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port:               getEnv("PORT", "8080"),
			Mode:               getEnv("GIN_MODE", "debug"),
			CORSAllowedOrigins: parseCSV(getEnv("CORS_ALLOWED_ORIGINS", "")),
			MetricsToken:       getEnv("METRICS_TOKEN", ""),
		},
		Database: DatabaseConfig{
			// DB_DRIVER **不再有出廠預設值回落**：原預設 "sqlite" 與「PostgreSQL 是
			// 唯一正式部署目標」直接矛盾。三值語義、缺值即空，交由
			// ValidateDatabaseDriver 在啟動組態段 fail-close（沿 ENCRYPTION_KEY 的慣例）。
			// Load 本身維持純 env→struct 映射、不 fatal：它是可被測試呼叫的純函式，
			// 在此 fatal 會使任何呼叫 Load 的測試在缺該變數的環境下直接殺掉行程
			Driver:   lookupRaw("DB_DRIVER"),
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvInt("DB_PORT", 5432),
			Database: getEnv("DB_NAME", "custodexa.db"),
			Username: getEnv("DB_USER", ""),
			Password: getEnv("DB_PASSWORD", ""),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		Security: SecurityConfig{
			JWTSecret: getEnv("JWT_SECRET", DefaultJWTSecret),
			// ENCRYPTION_KEY **不再有出廠預設值回落**（kek-provider-modularization D2.0／D3）：
			// 金鑰類鍵一律三值語義、不經預設注入。未設即由 DecideKEK 依矩陣 fail-close，
			// 沿 JWT_SECRET 的既有處置慣例。此欄僅存原始讀值供守衛比對，
			// **實際使用的 KEK 材料一律取自 KEKDecision**。
			EncryptionKey:        lookupRaw("ENCRYPTION_KEY"),
			AdminInitialPassword: getEnv("ADMIN_INITIAL_PASSWORD", ""),
			RefreshCookie:        LoadRefreshCookieSecure(),
		},
		Guacamole: GuacamoleConfig{
			Host: getEnv("GUACD_HOST", "localhost"),
			Port: getEnvInt("GUACD_PORT", 4822),
		},
		OIDC: OIDCConfig{
			PublicBaseURL:        getEnv("PUBLIC_BASE_URL", ""),
			DedicatedIssuers:     parseCSV(getEnv("OIDC_DEDICATED_ISSUERS", "")),
			AllowedInternalHosts: parseCSV(getEnv("OIDC_ALLOWED_INTERNAL_HOSTS", "")),
		},
		// LDAP 段刻意不在此讀 env（ldap-settings-migration 2.11）：設定已遷入
		// ldap_directories 表，啟動時再讀一份 env 快照只會製造第二個事實源。
		// 首次啟動的一次性 seed 由 post-unseal 佇列以字面 key 直接讀 env
		// （service/ldap_seed_migration.go），解析語義與此處的 getEnv 系列同源
		Features: FeatureFlags{
			// 審計日誌系統（默認啟用：全操作審計為安全紅線）
			AuditLogEnabled:     getEnvBool("FEATURE_AUDIT_LOG_ENABLED", true),
			AsyncAuditEnabled:   getEnvBool("FEATURE_ASYNC_AUDIT_ENABLED", true),
			AuditFallbackToFile: getEnvBool("FEATURE_AUDIT_FALLBACK_TO_FILE", true),

			// 異常連線偵測（默認禁用）
			AnomalyDetectionEnabled: getEnvBool("FEATURE_ANOMALY_DETECTION_ENABLED", false),

			// 告警通知系統（默認禁用）
			AlertingEnabled: getEnvBool("FEATURE_ALERTING_ENABLED", false),
		},
		Seal: LoadSeal(),
	}
}

// IsReleaseMode 是否為生產（release）模式
func (c *Config) IsReleaseMode() bool {
	return c.Server.Mode == "release"
}

// releaseSecurityFloorMembers 回傳「release 模式下不得由 feature flag 關閉」的安全紅線清單
// （deployment-hardening「release 安全底線不得由 feature flag 關閉」）。
//
// **入列判準（兩條都成立才進）**：(1) 旗標為 false 時某個安全機制停止運作；
// (2) 停止的事實在使用者可見面上與「機制正常但確實沒有事件」同形，即**無訊號**。
// 判準二是本清單存在的理由——有訊號的降級（例如 FEATURE_AUDIT_FALLBACK_TO_FILE
// 關閉時以專屬原因碼上報丟棄筆數）是部署者的合法選擇，不在此列；無訊號的取消
// 則會讓稽核讀到「沒有事件」而非「審計被關了」，那比沒有審計更糟。
//
// 每個成員以 env 鍵名與取址函式成對登記：鍵名供啟動日誌具名列出（部署者要能看見
// 自己的設定被拒絕），取址函式使強制落在**旗標值的決定處**這一個收口點。
// SHALL NOT 改以「在各消費點分別加 IsReleaseMode 判斷」達成——審計旗標的消費點
// 現有六處以上（中間件掛載、路由註冊、AuditLogService.logAt、AsyncSink、
// SealReplaySink、啟動日誌），逐點守衛會讓新增的消費點預設不受保護。
//
// **刻意寫成函式而非套件層 var**：`cmd/server` 的 lifecycle manifest 守衛要求
// 所有套件層 var 逐條登記於 manifest（具時序語義者才有登記價值），而本清單是
// 一份不可變的常數表、與啟動時序無關。回傳新 slice 的代價可忽略——呼叫點是
// 啟動期一次與測試。
type releaseFloorFlag struct {
	EnvKey string
	Field  func(*FeatureFlags) *bool
}

func releaseSecurityFloorMembers() []releaseFloorFlag {
	return []releaseFloorFlag{
		// **權限控制不在此列**：其開關已移除（security-backlog-settlement D5），
		// 路由一律帶 RequirePermission。不存在的開關無需 release 模式強制
		//
		// 全操作審計：關閉即審計中間件不掛、/audit-logs 不註冊、寫入路徑短路，
		// 而稽核工作台／檢查點驗證頁只會顯示「沒有事件」——無任何停用訊號
		{"FEATURE_AUDIT_LOG_ENABLED", func(f *FeatureFlags) *bool { return &f.AuditLogEnabled }},
	}
}

// EnforceReleaseSecurityFloor 於 release 模式把安全紅線類 feature flag 強制為啟用，
// 回傳**實際被強制**（原值為 false）的 env 鍵名清單，供啟動日誌具名列出。
//
// 非 release 模式一律不動任何值並回傳 nil：本強制保護的是出貨到生產的部署，
// 而條件註冊、旗標關閉語義在開發與測試組態中仍須可觸發（路由 golden 的
// dev-auditoff 兩格、api-docs 的條件註冊 scenario、audit 服務層的關閉語義單測
// 全部依賴 dev 可關）。**不得順手擴大為全模式強制**——那會靜默廢掉上述覆蓋。
//
// 呼叫點必須先於任何旗標消費，含啟動時的功能開關狀態輸出：否則日誌印的是環境
// 變數字面值而非生效值，顯示面與生效面不一致本身就是本 change 要消滅的形態。
func (c *Config) EnforceReleaseSecurityFloor() []string {
	if !c.IsReleaseMode() {
		return nil
	}
	var forced []string
	for _, item := range releaseSecurityFloorMembers() {
		p := item.Field(&c.Features)
		if !*p {
			*p = true
			forced = append(forced, item.EnvKey)
		}
	}
	return forced
}

// DefaultSecretViolations 回傳仍為出廠預設值的密鑰名稱清單（2.2.2）。
// 空清單 = 全部已改。供 release 啟動自檢：非空即 fatal。
//
// **模式感知（kek-provider-modularization D3，SHALL NOT 以整體放寬取代）**：
// kek 為 nil 或 env 模式時，「KEK 材料等於出廠預設值」仍判為違規（PCI 2.2.2
// 紅線不放寬）；非 env 模式（ui／kms／hsm）下「本地 KEK 鑰未設」是**合法組態**，
// SHALL NOT 列為違規——否則 B／C 模式在 release 下永不可啟動。
//
// **回報實際來源鍵名（codex high #1 的殘留紀律）**：違規清單一律回報
// `KEKDecision.MaterialSource`，而非硬編鍵名字面——否則操作者會去改一個
// 不是問題的鍵。KEK 材料鍵已收斂為單一 `ENCRYPTION_KEY`（雙鍵與 legacy
// 解密鑰回落皆已拆除），故此處來源必為該鍵或空。
func (c *Config) DefaultSecretViolations(kek *KEKDecision) []string {
	var v []string
	if c.Security.JWTSecret == DefaultJWTSecret {
		v = append(v, "JWT_SECRET")
	}
	if kek == nil {
		// 判定尚未產生（早期呼叫端）：直接檢 KEK 材料鍵原始讀值。
		// **編碼無關比對**（kek-encoding-and-unseal-entry 決策 5）：材料可為原字元、
		// 十六進位或 base64 三種寫法，字串比對會被 `hex(預設值)` 直接繞過。
		if IsDefaultEncryptionKeyMaterial(c.Security.EncryptionKey) {
			v = append(v, EnvKeyEncryptionKey)
		}
		return v
	}
	if !kek.UsesLocalMaterial() {
		// ui／kms／hsm：本地鑰未設是合法組態（模式感知，非整體放寬）
		return v
	}
	// **legacy 材料格已移除**（release-transitional-cleanup D10）：無 legacy 解密
	// 路徑後，`ENCRYPTION_KEY` 僅作為 KEK 材料被檢查。
	// env 模式下 KEK 材料等於出廠預設仍判違規（紅線不放寬）。
	// 比對解碼後的金鑰，使 hex／base64 寫法同樣被判為出廠預設值。
	if kek.MaterialSource != "" && IsDefaultEncryptionKeyMaterial(kek.Material) {
		v = append(v, kek.MaterialSource)
	}
	return v
}

// parseCSV 逗號分隔字串切為去空白、去空項的字串切片
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// lookupRaw 三值語義讀取（無預設值鍵專用）：未設回空字串，不套任何預設值。
// 與 getEnv 的差別是**不注入預設**——金鑰類鍵（ENCRYPTION_KEY）SHALL NOT 有出廠
// 預設值回落；DB_DRIVER 同理（任何預設值都必然與「唯一正式目標」或「測試用驅動」
// 其中一方矛盾，靜默選邊比拒絕啟動更糟）。
//
// 本函式已登記為 env 漂移守衛的已知讀取函式（env_drift_test.go identReaderArg0）：
// 否則經此讀取的 key 會自「產品碼消費集合」消失，守衛對它形同不存在。
func lookupRaw(key string) string {
	v, _ := os.LookupEnv(key)
	return v
}

// getEnv 取得環境變數，如果不存在則使用預設值
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt 取得整數型環境變數，如果不存在或無效則使用預設值
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getEnvBool 取得布林型環境變數，如果不存在或無效則使用預設值
// 支持: true/false, 1/0, yes/no, on/off (不區分大小寫)
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}
