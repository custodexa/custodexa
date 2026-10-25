package database

import (
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 升級前的兩張表（只建本增量會碰到的欄）＋一列存量檢查點與一列存量修剪錨。
func openCheckpointV4TestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE audit_checkpoints (id integer primary key, seq integer NOT NULL, perm_state_snapshot text, perm_format bigint, perm_event_seq bigint, perm_event_head varchar(64), perm_reconciled boolean, perm_signature varchar(128))`,
		`CREATE TABLE audit_checkpoint_trims (id integer primary key, last_trimmed_seq integer NOT NULL)`,
		`INSERT INTO audit_checkpoints (id, seq) VALUES (1, 1)`,
		`INSERT INTO audit_checkpoint_trims (id, last_trimmed_seq) VALUES (1, 3)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("%.60s: %v", stmt, err)
		}
	}
	return db
}

func TestCheckpointV4AttestationMigration(t *testing.T) {
	t.Run("上行：加起點欄、卸附證簽章欄、修剪錨三欄、存量錨為第一版", func(t *testing.T) {
		db := openCheckpointV4TestDB(t)
		if err := applyCheckpointV4Attestation(db); err != nil {
			t.Fatal(err)
		}
		m := db.Migrator()
		if !m.HasColumn("audit_checkpoints", "perm_origin") || m.HasColumn("audit_checkpoints", "perm_signature") {
			t.Fatal("audit_checkpoints 應有 perm_origin、無 perm_signature")
		}
		for _, col := range []string{"format", "perm_history", "unverified_count"} {
			if !m.HasColumn("audit_checkpoint_trims", col) {
				t.Fatalf("audit_checkpoint_trims 缺 %s", col)
			}
		}
		var format int
		if err := db.Raw(`SELECT format FROM audit_checkpoint_trims WHERE id = 1`).Scan(&format).Error; err != nil || format != 1 {
			t.Fatalf("存量修剪錨 format = %d（%v），want 1（原載荷照驗）", format, err)
		}
		var origin *bool
		if err := db.Raw(`SELECT perm_origin FROM audit_checkpoints WHERE id = 1`).Scan(&origin).Error; err != nil || origin != nil {
			t.Fatalf("存量檢查點 perm_origin 應為 NULL（不回填），got %v（%v）", origin, err)
		}
	})

	t.Run("附證痕跡查詢走部分索引（述詞與索引逐字相同）", func(t *testing.T) {
		db := openCheckpointV4TestDB(t)
		if err := applyCheckpointV4Attestation(db); err != nil {
			t.Fatal(err)
		}
		var plan []struct {
			ID, Parent, Notused int
			Detail              string
		}
		if err := db.Raw(`EXPLAIN QUERY PLAN SELECT EXISTS (SELECT 1 FROM audit_checkpoints WHERE ` + model.CheckpointPermTracePredicate + `)`).Scan(&plan).Error; err != nil {
			t.Fatal(err)
		}
		var details []string
		for _, p := range plan {
			details = append(details, p.Detail)
		}
		if !strings.Contains(strings.Join(details, "\n"), "idx_audit_checkpoints_perm_trace") {
			t.Fatalf("查詢計畫未採用部分索引：%v", details)
		}
	})

	t.Run("版本已登記且 Down 不提供", func(t *testing.T) {
		found := false
		for _, v := range MigrationVersions() {
			found = found || v == "20261018_checkpoint_v4_attestation"
		}
		if !found {
			t.Fatal("migration 版本未登記")
		}
		if rollbackCheckpointV4Attestation(nil) == nil {
			t.Fatal("本 migration 不提供回滾")
		}
	})
}

// TestCheckpointV4AttestationMigrationPostgres baseline＋全部增量之後的終態：欄位形狀、
// 部分索引述詞，以及附證痕跡查詢在關閉循序掃描時可走該索引。
func TestCheckpointV4AttestationMigrationPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, "checkpoint_v4_attestation_test")
	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	if err := applyMigrationsAfterBaseline(db); err != nil {
		t.Fatalf("增量 migration 失敗: %v", err)
	}
	m := db.Migrator()
	if !m.HasColumn("audit_checkpoints", "perm_origin") || m.HasColumn("audit_checkpoints", "perm_signature") {
		t.Fatal("audit_checkpoints 應有 perm_origin、無 perm_signature")
	}
	var def string
	if err := db.Raw(`SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_audit_checkpoints_perm_trace'`).Scan(&def).Error; err != nil || def == "" {
		t.Fatalf("部分索引不存在（%v）", err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SET LOCAL enable_seqscan = off`).Error; err != nil {
			return err
		}
		var plan []string
		if err := tx.Raw(`EXPLAIN SELECT EXISTS (SELECT 1 FROM audit_checkpoints WHERE ` + model.CheckpointPermTracePredicate + `)`).Scan(&plan).Error; err != nil {
			return err
		}
		if !strings.Contains(strings.Join(plan, "\n"), "idx_audit_checkpoints_perm_trace") {
			t.Errorf("查詢計畫未採用部分索引：%v", plan)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var format string
	if err := db.Raw(`SELECT column_default FROM information_schema.columns WHERE table_name = 'audit_checkpoint_trims' AND column_name = 'format' AND table_schema = current_schema()`).Scan(&format).Error; err != nil || format != "1" {
		t.Fatalf("audit_checkpoint_trims.format 預設值 = %q（%v），want 1", format, err)
	}
}
