package database

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

// TestHostKeyMismatchMigration 主機金鑰不符觀察紀錄增量：建表與唯一索引、既有 asset_host_keys 不動、
// 新表 0 列、欄位集合與設計相同、重複（資產、指紋）被唯一索引拒絕、RunMigrations 第二次不改內容。
// postgres 子測試為 PG-gated（依 testgate 設定），走真 DDL。
func TestHostKeyMismatchMigration(t *testing.T) {
	wantColumns := []string{
		"asset_id", "first_allowed_at", "first_seen_at", "host", "id", "last_seen_at",
		"observed_algorithm", "observed_fingerprint", "observed_public_key", "port", "recorded_fingerprint", "seen_count",
	}

	t.Run("DDL 宣告：表、欄位與唯一索引", func(t *testing.T) {
		ddl := hostKeyMismatchDDL()
		if len(ddl) != 2 {
			t.Fatalf("應為建表＋唯一索引兩條，實有 %d", len(ddl))
		}
		for _, col := range wantColumns {
			if !strings.Contains(ddl[0], "\n\t\t"+col+" ") && !strings.Contains(ddl[0], "\t\t"+col+" ") {
				t.Errorf("建表語句缺欄位 %s", col)
			}
		}
		if !strings.Contains(ddl[1], "CREATE UNIQUE INDEX idx_asset_host_key_mismatches_asset_fp") ||
			!strings.Contains(ddl[1], "(asset_id, observed_fingerprint)") {
			t.Errorf("唯一索引宣告不符: %s", ddl[1])
		}
		found := false
		for _, v := range MigrationVersions() {
			if v == "20261025_host_key_mismatch" {
				found = true
			}
		}
		if !found {
			t.Fatal("migration 版本未登記")
		}
		if rollbackHostKeyMismatch(nil) == nil {
			t.Fatal("本 migration 不提供回滾")
		}
	})

	t.Run("postgres：真 DDL 升級、既有記錄不動、唯一索引生效、RunMigrations 第二次不改內容", func(t *testing.T) {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		db := freshSchema(t, dsn, fmt.Sprintf("hk_mm_%d", time.Now().UnixNano()))
		last := -1
		for i, m := range migrations {
			if m.Version == "20261025_host_key_mismatch" {
				last = i
			}
		}
		if last < 0 {
			t.Fatal("找不到本增量")
		}
		for _, m := range migrations[:last] {
			if err := m.Up(db); err != nil {
				t.Fatal(m.Version, err)
			}
		}
		for i := 1; i <= 3; i++ {
			if err := db.Exec(`INSERT INTO asset_host_keys(asset_id, algorithm, fingerprint, public_key, host, port, created_at, updated_at) VALUES(?, 'ssh-ed25519', ?, 'pk', '10.0.0.1', 22, now(), now())`,
				i, fmt.Sprintf("SHA256:fp%d", i)).Error; err != nil {
				t.Fatal(err)
			}
		}
		before := dumpTables(t, db, "asset_host_keys")
		if err := migrations[last].Up(db); err != nil {
			t.Fatal(err)
		}
		if after := dumpTables(t, db, "asset_host_keys"); after != before {
			t.Fatalf("升級改動了既有 asset_host_keys\nbefore=%s\nafter=%s", before, after)
		}
		var n int64
		if err := db.Raw(`SELECT count(*) FROM asset_host_key_mismatches`).Scan(&n).Error; err != nil || n != 0 {
			t.Fatalf("新表應為 0 列: n=%d err=%v", n, err)
		}
		var cols []string
		if err := db.Raw(`SELECT column_name FROM information_schema.columns WHERE table_name = 'asset_host_key_mismatches' ORDER BY column_name`).Scan(&cols).Error; err != nil {
			t.Fatal(err)
		}
		sort.Strings(cols)
		if strings.Join(cols, ",") != strings.Join(wantColumns, ",") {
			t.Fatalf("欄位集合 %v，應為 %v", cols, wantColumns)
		}
		insert := func() error {
			return db.Exec(`INSERT INTO asset_host_key_mismatches(asset_id, host, port, recorded_fingerprint, observed_algorithm, observed_fingerprint, observed_public_key, first_seen_at, last_seen_at, seen_count)
				VALUES(1, '10.0.0.1', 22, 'SHA256:fp1', 'ssh-ed25519', 'SHA256:other', 'pk', now(), now(), 1)`).Error
		}
		if err := insert(); err != nil {
			t.Fatalf("第一筆觀察應可寫入: %v", err)
		}
		if err := insert(); err == nil {
			t.Fatal("重複（資產、指紋）應被唯一索引拒絕")
		}
		var idx int64
		if err := db.Raw(`SELECT count(*) FROM pg_indexes WHERE tablename = 'asset_host_key_mismatches' AND indexname = 'idx_asset_host_key_mismatches_asset_fp'`).Scan(&idx).Error; err != nil || idx != 1 {
			t.Fatalf("缺少唯一索引: n=%d err=%v", idx, err)
		}

		run := freshSchema(t, dsn, fmt.Sprintf("hk_mm_run_%d", time.Now().UnixNano()))
		prev := DB
		DB = run
		t.Cleanup(func() { DB = prev })
		if err := RunMigrations(); err != nil {
			t.Fatalf("第一次 RunMigrations: %v", err)
		}
		first := dumpTables(t, run, "schema_migrations", "asset_host_key_mismatches")
		if err := RunMigrations(); err != nil {
			t.Fatalf("第二次 RunMigrations: %v", err)
		}
		if second := dumpTables(t, run, "schema_migrations", "asset_host_key_mismatches"); second != first {
			t.Fatalf("第二次 RunMigrations 改動了內容")
		}
	})
}
