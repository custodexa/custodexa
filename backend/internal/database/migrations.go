package database

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

// SchemaMigration 追蹤已執行的 migrations
type SchemaMigration struct {
	Version   string    `gorm:"primaryKey;size:50"`
	AppliedAt time.Time `gorm:"not null"`
}

// TableName 指定表名
func (SchemaMigration) TableName() string {
	return "schema_migrations"
}

// Migration 定義單個 migration
type Migration struct {
	Version string
	Name    string
	Up      func(*gorm.DB) error
	Down    func(*gorm.DB) error
}

// migrations 所有可用的 migrations（按版本順序）。
//
// **baseline ＋ 其後的增量**：壓縮前的 49 條增量 migration 已
// 退場，其最終 schema 形狀併入 baseline，其存量回填在全新資料庫上一律零列。
// 「不提供就地升級」的 fail-close 只針對**壓縮前**的資料庫（見 RunMigrations）；
// baseline 之後的新表／新欄回歸標準增量形態，全新庫依序跑 baseline→增量，
// 既有（已套 baseline 的）庫只補增量。
var migrations = []Migration{
	{
		Version: BaselineVersion,
		Name:    "schema_baseline",
		Up:      applyBaseline,
		Down:    refuseBaselineRollback,
	},
	{
		// 證據包非同步匯出 job 表
		Version: "20260824_audit_export_jobs",
		Name:    "audit_export_jobs",
		Up:      applyAuditExportJobs,
		Down:    rollbackAuditExportJobs,
	},
	{
		// 離機儲存：offsite_profiles 設定世代表（含信封加密憑證）、
		// offsite_objects 保管帳冊、兩張擁有表的指標與快取欄。
		// **Down 為資料追蹤不可逆**（見 migration_evidence_offsite.go 檔頭）
		Version: "20260825_evidence_offsite",
		Name:    "evidence_offsite",
		Up:      applyEvidenceOffsite,
		Down:    rollbackEvidenceOffsite,
	},
	{
		// 來源位址追查：users.allowed_cidrs、user_source_ips 基準表、兩條索引、
		// command_alerts kind 值域擴充與冷啟動回填。**Down 銷毀資料、開發庫限定**
		// （見 migration_source_ip_forensics.go 檔頭）
		Version: "20260826_source_ip_forensics",
		Name:    "source_ip_forensics",
		Up:      applySourceIPForensics,
		Down:    rollbackSourceIPForensics,
	},
	{
		// 查詢主控台：assets.allowed_databases、sessions.db_console、
		// session_commands 十一個結果事實欄、三條 CHECK、三個索引。
		// **Down 有損**（刪政策欄與稽核證據欄，生產無回滾入口；
		// 見 migration_db_query_console.go 檔頭的 Down 契約）
		Version: "20260826_db_query_console",
		Name:    "db_query_console",
		Up:      applyDBQueryConsole,
		Down:    rollbackDBQueryConsole,
	},
	{
		// 政策值欄位放寬為 text，容納文字型政策鍵。純型別擴張、無資料回填；
		// Down 收窄回 varchar(128)，存量超長時由資料庫報錯並回滾整個交易
		//（見 migration_security_policies_value_text.go 檔頭的 Down 契約）
		Version: "20260903_security_policies_value_text",
		Name:    "security_policies_value_text",
		Up:      applySecurityPoliciesValueText,
		Down:    rollbackSecurityPoliciesValueText,
	},
}

// schemaDDLStatements 全部 schema DDL：baseline ＋ baseline 之後的增量建表／加欄。
//
// **parity 守衛的解析對象**（schema_parity_test.go 第 1 層；pg 兩層測試以
// applyBaseline＋applyMigrationsAfterBaseline 建出同一形狀）：schema 事實源自
// 增量 migration 出現起即為「baseline＋增量」的串接，守衛只看 baseline 會讓
// 增量表的漂移整張脫離射程。**不供執行**——執行面由 RunMigrations 依已套用
// 集合分別跑，兩者串接執行會在全新庫上重複建表。回填語句不在此列（不是 schema）。
func schemaDDLStatements() []string {
	out := append(baselineSchemaStatements(), auditExportJobsDDL()...)
	out = append(out, evidenceOffsiteDDL()...)
	out = append(out, sourceIPForensicsDDL()...)
	return append(out, dbQueryConsoleDDL()...)
}

// applyMigrationsAfterBaseline 依序執行 baseline 之後的全部增量（pg parity
// 測試在 applyBaseline 後補齊終態形狀用；生產路徑一律走 RunMigrations）。
func applyMigrationsAfterBaseline(db *gorm.DB) error {
	for _, m := range migrations[1:] {
		if err := m.Up(db); err != nil {
			return fmt.Errorf("增量 %s 失敗: %w", m.Version, err)
		}
	}
	return nil
}

// LDAPSeedMarkerVersion LDAP env→DB seed 的執行標記（寫入 schema_migrations 的 version）。
//
// **定義於 repository 而非 service**：本標記由 service 的 seed
// 寫入，兩端必須是同一個字串。repository 不得依賴 service（現行相依方向是
// service → repository，反向即循環），故常數落在兩者都可依賴的下層，service 端以
// `ldapSeedMarker = database.LDAPSeedMarkerVersion` 引用，杜絕字面值各寫一份而漂移。
//
// 它**不是** migrations 清單裡的版本項（seed 不是 versioned migration，而是
// post-unseal 佇列項），只是共用 schema_migrations 表做冪等標記。
const LDAPSeedMarkerVersion = "20260804_ldap_env_seeded"

// runtimeMarkerVersions 由執行期寫入 schema_migrations、但**不是** migration 的版本值。
//
// 這些列永遠不會出現在 `migrations` 陣列裡（它們是模組自己的冪等標記，借用
// schema_migrations 當 marker 表）。fail-close 的未知版本判定必須先扣掉它們，
// 否則**每一個跑過 LDAP env seed 的全新安裝，都會在第二次啟動時被自己的
// fail-close 擋住**——marker 是第一次啟動後才寫入的。
//
// 新增執行期 marker 而未登記於此，即為上述形態的復發。守衛：
// `runtime_marker_registry_test.go` 的 TestRuntimeMarkerVersionsCoverAllWriters。
// OffsiteSeedMarkerVersion 離機儲存設定 env→DB seed 的執行標記。
//
// 定義於 repository 的理由同 LDAPSeedMarkerVersion（寫入端在 internal/offsite，
// 而 repository 不得依賴上層，故常數落在兩端都可依賴的下層）。
//
// **語義是「已完成評估」而非「已建立資料」**：實際 seed、env 未設定而跳過、
// 表非空而跳過三種**終局**皆寫入；只有基礎設施失敗與 env 組態矛盾不寫，
// 留待下次啟動重試。marker 隨資料庫備份還原——「marker 在而 offsite_profiles
// 零列」是真實可達的部署狀態，其終局＝未設定，只能經管理介面重新設定
// （營運文件明載；env 不再回灌）。
const OffsiteSeedMarkerVersion = "20260825_offsite_env_seeded"

var runtimeMarkerVersions = []string{
	LDAPSeedMarkerVersion,
	OffsiteSeedMarkerVersion,
}

// schemaMigrationsBootstrapDDL 追蹤表自身的建立語句。
//
// **這是產品程式碼中唯一的 `IF NOT EXISTS`**：schema_migrations 有雞生蛋問題
// ——必須先於「讀取已套用集合」而存在，故它不能由 baseline 建立（baseline 的執行
// 與否正是要靠讀它來判定）。除此之外，baseline 的 DDL 一律無條件。
//
// 欄位形狀與壓縮前由 GORM 依 SchemaMigration model 自動建出的產物逐欄相同
// （varchar(50) NOT NULL / timestamptz NOT NULL / PK on version），
// 使既有安裝與全新安裝在這張表上不分歧。
const schemaMigrationsBootstrapDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version varchar(50) NOT NULL,
	applied_at timestamp with time zone NOT NULL,
	CONSTRAINT schema_migrations_pkey PRIMARY KEY (version)
)`

// unknownAppliedVersions 已套用集合中，既非本版程式碼宣告、也非執行期 marker 的版本值。
func unknownAppliedVersions(applied map[string]bool) []string {
	known := make(map[string]bool, len(migrations)+len(runtimeMarkerVersions))
	for _, m := range migrations {
		known[m.Version] = true
	}
	for _, v := range runtimeMarkerVersions {
		known[v] = true
	}
	var out []string
	for v := range applied {
		if !known[v] {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// legacySchemaError 既有（壓縮前）資料庫的拒絕啟動訊息。
//
// 形態沿 config.ValidateDatabaseDriver 的既有慣例：陳述現況 → 為什麼擋 →
// 具體怎麼做 → 澄清常見誤解。不含任何連線字串、密碼或主機位址。
func legacySchemaError(unknown []string) error {
	shown := unknown
	const maxShown = 10
	suffix := ""
	if len(shown) > maxShown {
		shown = shown[:maxShown]
		suffix = fmt.Sprintf("（另有 %d 筆未列出）", len(unknown)-maxShown)
	}
	return fmt.Errorf(
		"拒絕啟動：資料庫的 schema_migrations 內有 %d 筆本版程式碼不認得的 migration 版本%s：%s\n"+
			"  本版本以單一 schema baseline（%s）作為 schema 的唯一事實源，"+
			"壓縮前的逐條 migration 已不存在，因此**不提供既有資料庫的就地升級路徑**。\n"+
			"  處置：建立一個全新的空資料庫並讓服務對它啟動（開發環境即重建 dev 資料庫；"+
			"正式環境請依 docs/ops/upgrade-sop.md 評估，該文件明載本版不提供 migration 回滾）。\n"+
			"  這**不是資料庫損毀**：資料仍在原處，只是本版程式碼無法沿用它的 schema。\n"+
			"  **不要手動刪除 schema_migrations 的列來繞過本檢查**："+
			"那會讓 baseline 在既有 schema 上執行，而 baseline 的建表語句是無條件的，"+
			"第一句 CREATE TABLE 就會撞上既有表而中止，留下的是一個既非舊版也非新版的資料庫。",
		len(unknown), suffix, strings.Join(shown, ", "), BaselineVersion)
}

// RunMigrations 執行所有未執行的 migrations
func RunMigrations() error {
	log.Println("開始執行 database migrations...")

	// 1. 確保 schema_migrations 表存在
	if err := DB.Exec(schemaMigrationsBootstrapDDL).Error; err != nil {
		return fmt.Errorf("創建 schema_migrations 表失敗: %w", err)
	}

	// 2. 獲取已執行的 migrations
	var appliedMigrations []SchemaMigration
	if err := DB.Find(&appliedMigrations).Error; err != nil {
		return fmt.Errorf("查詢已執行 migrations 失敗: %w", err)
	}

	appliedVersions := make(map[string]bool)
	for _, m := range appliedMigrations {
		appliedVersions[m.Version] = true
	}

	// 3. fail-close：既有（壓縮前）資料庫一律拒絕啟動。
	//
	// **判定必須在任何 Up 之前**：走到這裡尚未產生任何寫入，故拒絕啟動時資料庫
	// 一個位元都沒動。若讓 baseline 對既有庫跑下去，最好的結果是建表衝突而中止，
	// 最壞的結果是種子重複寫入而告警靜默翻倍。
	//
	// 已套用 baseline 的資料庫不在此列：那時的未知版本屬降版情境，
	// 沿既有的單向比對語義忽略。
	if unknown := unknownAppliedVersions(appliedVersions); len(unknown) > 0 && !appliedVersions[BaselineVersion] {
		return legacySchemaError(unknown)
	}

	// 4. 執行未執行的 migrations
	executedCount := 0
	for _, migration := range migrations {
		if appliedVersions[migration.Version] {
			log.Printf("  跳過已執行的 migration: %s (%s)", migration.Version, migration.Name)
			continue
		}

		log.Printf("  執行 migration: %s (%s)", migration.Version, migration.Name)

		// 在 transaction 中執行 migration
		if err := DB.Transaction(func(tx *gorm.DB) error {
			// 執行 Up 函數
			if err := migration.Up(tx); err != nil {
				return err
			}

			// 記錄到 schema_migrations
			record := SchemaMigration{
				Version:   migration.Version,
				AppliedAt: time.Now(),
			}
			if err := tx.Create(&record).Error; err != nil {
				return fmt.Errorf("記錄 migration 失敗: %w", err)
			}

			return nil
		}); err != nil {
			return fmt.Errorf("執行 migration %s 失敗: %w", migration.Version, err)
		}

		log.Printf("  Migration %s 執行成功", migration.Version)
		executedCount++
	}

	if executedCount == 0 {
		log.Println("所有 migrations 都已執行，無需更新")
	} else {
		log.Printf("成功執行 %d 個 migration(s)", executedCount)
	}

	return nil
}

// RollbackMigration 回滾指定版本的 migration（謹慎使用）。
//
// **本版本沒有任何可回滾的 migration**：唯一的 migration 是 schema baseline，
// 其 Down 一律回拒絕錯誤（見 baseline.go 的 refuseBaselineRollback）。本函式保留
// 供 baseline 之後的增量 migration 使用，屆時仍走同一條「Down 成功才刪版本列」的路徑。
func RollbackMigration(version string) error {
	log.Printf("開始回滾 migration: %s", version)

	// 查找 migration
	var targetMigration *Migration
	for i := range migrations {
		if migrations[i].Version == version {
			targetMigration = &migrations[i]
			break
		}
	}

	if targetMigration == nil {
		return fmt.Errorf("找不到 migration 版本: %s", version)
	}

	// 檢查是否已執行
	var record SchemaMigration
	if err := DB.Where("version = ?", version).First(&record).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("migration %s 尚未執行，無法回滾", version)
		}
		return fmt.Errorf("查詢 migration 記錄失敗: %w", err)
	}

	// 在 transaction 中執行回滾
	if err := DB.Transaction(func(tx *gorm.DB) error {
		// 執行 Down 函數
		if err := targetMigration.Down(tx); err != nil {
			return err
		}

		// 刪除 migration 記錄
		if err := tx.Delete(&record).Error; err != nil {
			return fmt.Errorf("刪除 migration 記錄失敗: %w", err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("回滾 migration 失敗: %w", err)
	}

	log.Printf("Migration %s 回滾成功", version)
	return nil
}
