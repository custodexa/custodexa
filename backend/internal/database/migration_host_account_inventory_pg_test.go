package database

import (
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/testgate"
)

// TestHostAccountInventoryMigrationPostgres 主機帳號盤點兩張表在真的 postgres 上的形狀：
// 三條關鍵索引存在，且未結束盤點的部分唯一索引擋下同資產第二筆 running。
func TestHostAccountInventoryMigrationPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "host_account_inventory_test"
	db := freshSchema(t, dsn, pgSchema)
	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	if err := applyMigrationsAfterBaseline(db); err != nil {
		t.Fatalf("增量 migration 失敗: %v", err)
	}
	for _, idx := range []string{
		"uniq_host_account_scans_active",
		"idx_host_account_findings_asset_user",
		"idx_host_account_findings_open_privileged",
	} {
		var n int64
		if err := db.Raw(`SELECT count(*) FROM pg_indexes WHERE schemaname = ? AND indexname = ?`, pgSchema, idx).Scan(&n).Error; err != nil {
			t.Fatalf("查索引 %s 失敗: %v", idx, err)
		}
		if n != 1 {
			t.Fatalf("索引 %s 不存在", idx)
		}
	}
	ins := `INSERT INTO host_account_scans (asset_id, platform, identity_mode, identity_account_id, initiated_by, status, privileged_groups)
	        VALUES (7, 'posix', 'default_account', 3, 1, ?, 'root')`
	if err := db.Exec(ins, "running").Error; err != nil {
		t.Fatalf("第一筆 running 寫入失敗: %v", err)
	}
	err := db.Exec(ins, "running").Error
	if err == nil || !strings.Contains(err.Error(), "uniq_host_account_scans_active") {
		t.Fatalf("同資產第二筆 running 應被部分唯一索引擋下，got %v", err)
	}
	if err := db.Exec(ins, "succeeded").Error; err != nil {
		t.Fatalf("已結束的列不受部分唯一索引限制，got %v", err)
	}
	if err := db.Exec(`INSERT INTO host_account_scans (asset_id, platform, identity_mode, identity_account_id, initiated_by, status, privileged_groups)
	        VALUES (8, 'posix', 'default_account', 3, 1, 'bogus', 'root')`).Error; err == nil {
		t.Fatal("status CHECK 應拒絕值域外的值")
	}
}
