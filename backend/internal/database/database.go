package database

import (
	"fmt"
	"log"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB 全域資料庫實例
var DB *gorm.DB

// InitDatabase 初始化資料庫連線
func InitDatabase(cfg *config.Config) error {
	var dialector gorm.Dialector
	var err error

	// 根據驅動選擇 dialector
	switch cfg.Database.Driver {
	case config.DBDriverSQLite:
		dialector = sqlite.Open(cfg.Database.Database)
	case config.DBDriverPostgres:
		dsn := fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			cfg.Database.Host,
			cfg.Database.Port,
			cfg.Database.Username,
			cfg.Database.Password,
			cfg.Database.Database,
			cfg.Database.SSLMode,
		)
		dialector = postgres.Open(dsn)
	default:
		// DB_DRIVER 缺值或不支援。**訊息一律取自 config.ValidateDatabaseDriver**
		// （單一事實源）：`cmd/server` 已在組態段先擋一次，但 cmd/test_migration
		// 等其餘入口只經此處，兩份訊息各寫一次必然分歧。
		if err := config.ValidateDatabaseDriver(cfg.Database.Driver); err != nil {
			return err
		}
		// 走到這裡代表驗證認可了某個值、但上面沒有對應 case——不是使用者組態問題，
		// 是清單與分支分歧。訊息指向該修的地方，不要讓它看起來像設定錯誤。
		return fmt.Errorf("資料庫驅動 %q 通過 config.ValidateDatabaseDriver 但 InitDatabase 無對應分支：兩處清單已分歧，請同步",
			cfg.Database.Driver)
	}

	// 連線資料庫
	//
	// **GORM 日誌等級依部署模式分流（release 只記錯誤）。**
	// `logger.Info` 會把**每一條 SQL 連同其參數值**寫到 stdout——在本產品中那不只是
	// 吵：稽核紀錄（`audit_logs`／`session_commands`）與憑證雜湊的內容會沿著這條路徑
	// **複寫出保留期與檢查點簽章鏈的保護範圍之外**。那份副本不受任何完整性控制，
	// 也不隨保留政策清除，等於在產品自己的護欄外再開一份明文。
	//
	// release 取 `logger.Error`：連線與查詢失敗仍會留下訊號（診斷能力不失），
	// 但不再逐條輸出 SQL 與參數。非 release（debug／test）維持 `Info` 以利開發。
	gormLogLevel := logger.Info
	if cfg.IsReleaseMode() {
		gormLogLevel = logger.Error
	}
	DB, err = gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(gormLogLevel),
	})
	if err != nil {
		return fmt.Errorf("無法連線資料庫: %w", err)
	}

	log.Printf("資料庫連線成功 (驅動: %s)", cfg.Database.Driver)
	return nil
}

// schemaParityModels 全部由 baseline 建表的 model（單一事實源）。
//
// **本清單不再被執行，只被驗證**（migration-baseline-compression D3）：
// 開機 AutoMigrate 已移除，schema 的唯一事實源是 baseline 的 DDL。這份清單自
// 「要建哪些表」轉為「baseline 必須與哪些 model 對得上」的比對來源，兩層守衛消費它：
//
//	第 1 層 schema_parity_test.go        離線欄位 parity（不需資料庫、不可被 skip）
//	第 2 層 index_declaration_parity_test.go  pg 上的型別／可空／預設／索引／約束 parity
//
// 移除 AutoMigrate 後，「model 改了而 baseline 沒改」成為本 change 新產生的最高頻
// 漂移形態；這兩層就是它的守衛。清單漏一個 model＝該 model 的漂移不再被檢查，
// 故新增 model 時必須同步登記於此。
var schemaParityModels = []interface{}{
	&model.User{},
	&model.Role{},
	&model.Asset{},
	&model.AssetGroup{},
	&model.Session{},
	&model.AuditLog{},                // 審計日誌
	&model.Snippet{},                 // terminal-snippets: 命令片段
	&model.AssetHostKey{},            // host-key-verification: TOFU host key
	&model.ClipboardEvent{},          // clipboard-audit: 剪貼簿內容留存
	&model.ChangeSecretPlan{},        // change-secret: 改密計劃
	&model.ChangeSecretRecord{},      // change-secret: 改密記錄
	&model.ChangeSecretCandidate{},   // change-secret-ssh-deepening: 未驗證候選憑證（一帳號至多一筆）
	&model.SecurityPolicy{},          // auth-hardening: 安全政策 key-value
	&model.PasswordHistory{},         // auth-hardening: 密碼歷史（8.3.7）
	&model.RefreshToken{},            // auth-hardening: Web 會話 refresh 憑證（8.2.8/D6）
	&model.AccessReview{},            // audit-workflows: 週期性存取複審簽核（7.2.4/D2）
	&model.DailyReviewLog{},          // audit-log-compliance: 每日審閱簽核（10.4.1）
	&model.AuditFailureEvent{},       // audit-log-compliance: 審計機制失效事件（10.7.2/10.7.3）
	&model.SyslogSetting{},           // audit-log-compliance: syslog 轉發設定（10.3.3）
	&model.ExportSigningKey{},        // audit-log-compliance: 匯出簽章金鑰（10.3.4/F5）
	&model.IntegrityBaseline{},       // audit-log-compliance: 完整性啟用基準（10.3.4，防清空規避）
	&model.AuditCheckpoint{},         // audit-checkpoint-chain: 簽章檢查點鏈（偵測「列被刪」）
	&model.CheckpointSigningKey{},    // audit-checkpoint-chain: 檢查點鏈 Ed25519 簽章鑰（自始帶版本欄）
	&model.AuditCheckpointTrim{},     // audit-checkpoint-chain: 鏈修剪記錄（殘鏈的新起點錨定，不隨被修剪點消失）
	&model.DataKey{},                 // key-management-envelope: 信封加密金鑰表（KEK 包裹的 DEK/HMAC 鑰）
	&model.TransmissionConsent{},     // transmission-security-policy: 傳輸風險同意記錄（D3）
	&model.UserGroup{},               // user-group-authorization: 使用者群組（授權主體）
	&model.AssetNode{},               // asset-node-tree: 資產×節點成員（多歸屬 M2M）
	&model.AssetAccount{},            // asset-multi-account: 資產帳號（憑證自內嵌欄位遷出）
	&model.OIDCProvider{},            // idp-oidc-integration: OIDC provider 設定（多實例）
	&model.UserExternalIdentity{},    // idp-oidc-integration: 外部身分（issuer+client_id+subject）
	&model.OIDCFlowState{},           // idp-oidc-integration: 登入流程狀態（一次性）
	&model.OIDCLoginTicket{},         // idp-oidc-integration: callback→SPA 交棒憑證（一次性）
	&model.AuditRetentionWatermark{}, // auditor-workbench: 保留期清除水位（永不清除，逐類別一列）
	// audit-chain-scheduled-verification: 兩層自動驗證的營運狀態（單列）。
	// **明示為營運狀態而非證據**：本表不在鏈的覆蓋範圍內，可由 DB 直寫改寫成
	// 「最近驗過且通過」；它承載的是「機制到底有沒有在跑」這個 watchdog 盲點，
	// 以及未結案失敗區間集合（結案的唯一合法依據）
	&model.AuditChainVerifyState{},
	// ldap-settings-migration：壓縮前本 model **刻意排除**於 AutoMigrate 清單之外，
	// 因為 GORM 不產出 inline CHECK，先建出的表會使 migration 的
	// `CREATE TABLE IF NOT EXISTS` 靜默略過，`CHECK (singleton = 1)` 在生產缺席。
	// AutoMigrate 消失後該排除理由一併消失：表由 baseline 建立，CHECK 就在建表語句裡。
	// 原守衛（TestLDAPDirectoryNotInAutoMigrateList）的保護對象改由兩條承接——
	// baseline 的 CHECK 專屬斷言（第 2 層 parity）與「產品程式碼零 AutoMigrate」的 AST 守衛。
	&model.LDAPDirectory{},
}

// SchemaParityModels 回傳 schemaParityModels 的副本。
//
// **不是生產路徑**：本函式沒有任何產品程式碼消費者，存在的理由是**跨套件的
// 單元測試**——它們在 sqlite `:memory:` 上以 GORM 建表（baseline 是 postgres 專屬
// DDL，sqlite 跑不動），需要同一份 model 清單才不會各自抄一份而漏表。
//
// 回傳副本而非 slice 本身：呼叫端若不慎改寫，受害的是全庫 parity 守衛的比對基準。
func SchemaParityModels() []interface{} {
	out := make([]interface{}, len(schemaParityModels))
	copy(out, schemaParityModels)
	return out
}

// Close 關閉資料庫連線
func Close() error {
	if DB != nil {
		sqlDB, err := DB.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}
