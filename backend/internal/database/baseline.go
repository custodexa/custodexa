package database

import (
	"errors"
	"fmt"
	"log"

	"gorm.io/gorm"
)

// BaselineVersion schema baseline 的 migration 版本號。
//
// 本版本是**全新安裝的唯一 schema 事實源**：47 張表的最終形狀、162 條索引、
// 10 條 CHECK 與 12 條內建告警規則種子，全部由這一條 migration 建立。
// 壓縮前的 49 條增量 migration 與開機 AutoMigrate 一併退場
// （migration-baseline-compression）。
const BaselineVersion = "20260816_schema_baseline"

// baselineGroup baseline DDL 的一個語義域。
//
// 切分成域是**單檔行數上限**（800）的產物，不是執行語義的一部分：
// 三段（建表／外鍵／索引）各自跨域串接後才送進資料庫，故域的先後不影響結果。
type baselineGroup struct {
	Name        string
	Tables      []string
	ForeignKeys []string
	Indexes     []string
}

// baselineGroups baseline 的全部 DDL 來源。
//
// **新增域時必須同步兩處**：本清單，以及 `cmd/server/command_alert_write_guard_test.go`
// 的 `baselineSchemaFiles`（該守衛以具名檔清單界定「schema 定義檔」的豁免範圍，
// 漏列會使該檔的建表 SQL 被判為繞過告警落地面的原生寫入——**大聲失敗**，不是靜默放行）。
var baselineGroups = []baselineGroup{
	{"identity", baselineIdentityTables, baselineIdentityForeignKeys, baselineIdentityIndexes},
	{"asset", baselineAssetTables, baselineAssetForeignKeys, baselineAssetIndexes},
	{"authz", baselineAuthzTables, baselineAuthzForeignKeys, baselineAuthzIndexes},
	{"audit", baselineAuditTables, baselineAuditForeignKeys, baselineAuditIndexes},
	{"platform", baselinePlatformTables, baselinePlatformForeignKeys, baselinePlatformIndexes},
}

// baselineSchemaStatements 依「全部建表 → 全部外鍵 → 全部索引」串接的執行序。
//
// 外鍵一律後置，故建表順序不受參照關係限制；索引後置則使建表階段不必為索引
// 的依賴排序。三段的邊界也是等價驗證時定位差異的座標。
func baselineSchemaStatements() []string {
	var out []string
	for _, g := range baselineGroups {
		out = append(out, g.Tables...)
	}
	for _, g := range baselineGroups {
		out = append(out, g.ForeignKeys...)
	}
	for _, g := range baselineGroups {
		out = append(out, g.Indexes...)
	}
	return out
}

// applyBaseline 建立整個 schema 並寫入內建告警規則種子。
//
// 呼叫端（RunMigrations）已把本函式與 schema_migrations 的記錄包在單一交易內，
// 而 PostgreSQL 的 DDL 可交易 → 全成或全不成，不會留下半套 schema。
//
// **DDL 一律無條件**：在非空 schema 上跑必須立刻炸。`IF NOT EXISTS` 的靜默 no-op
// 正是 2026-08-12 索引事故的成因，也是等價驗證最容易假綠的地方。
func applyBaseline(db *gorm.DB) error {
	stmts := baselineSchemaStatements()
	// 防假綠下界：DDL 清單若因重構而變成空集合，迴圈零次仍會「成功」，
	// 而失敗要等到第一個查詢才會以「表不存在」的形態出現在生產。
	if len(stmts) < 150 {
		return fmt.Errorf("baseline DDL 只有 %d 條（下界 150）：schema 定義清單已失真，拒絕在殘缺的 baseline 上建庫", len(stmts))
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 baseline DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	if err := seedBuiltinAlertRules(db); err != nil {
		return err
	}
	log.Printf("  baseline schema 已建立：%d 條 DDL、%d 條內建告警規則", len(stmts), len(builtinAlertRules))
	return nil
}

// errBaselineRollbackRefused baseline 的 Down。
//
// **刻意不 drop 任何東西**：baseline 建的是整個 schema，「回滾」它等於刪掉全部
// 使用者、資產、授權與審計證據。一個看起來像回滾入口、實際上是資料庫毀滅按鈕的
// 東西比沒有入口更危險，故本函式一律回錯，把退路指回還原備份。
var errBaselineRollbackRefused = errors.New(
	"拒絕回滾 schema baseline：本版本建立的是整個資料庫 schema，回滾它等同丟棄全部資料表" +
		"（使用者、資產、授權與審計證據一併消失），而非還原到某個較舊的 schema 形狀。" +
		"本產品不提供 migration 回滾；升級失敗的唯一退路是還原升級前的資料庫備份" +
		"（程序見 docs/ops/backup-and-restore.md）。")

func refuseBaselineRollback(*gorm.DB) error {
	return errBaselineRollbackRefused
}
