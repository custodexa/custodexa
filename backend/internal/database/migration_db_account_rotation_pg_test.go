package database

import (
	"testing"

	"github.com/custodexa/backend/internal/testgate"
)

// 改密紀錄傳輸風險欄的升級實測（PG-gated；未設 TEST_PG_DSN 即 skip，
// REQUIRE_INTEGRATION=1 時 skip 轉 fail）：在上一版 schema 寫入既有紀錄，
// 套用本 migration 後欄位存在且既有列為空字串。
func TestDBAccountRotationMigrationPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, "db_account_rotation_upgrade_test")
	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	const version = "20261102_db_account_rotation"
	var target *Migration
	for i := 1; i < len(migrations); i++ {
		if migrations[i].Version == version {
			target = &migrations[i]
			break
		}
		if err := migrations[i].Up(db); err != nil {
			t.Fatalf("增量 %s 失敗: %v", migrations[i].Version, err)
		}
	}
	if target == nil {
		t.Fatalf("未登記 %s", version)
	}
	if err := db.Exec(`INSERT INTO change_secret_records (plan_id, asset_id, status, error, executed_at)
		VALUES (1, 1, 'success', '', now())`).Error; err != nil {
		t.Fatalf("寫入既有紀錄失敗: %v", err)
	}
	if err := target.Up(db); err != nil {
		t.Fatalf("套用 %s 失敗: %v", version, err)
	}
	var col struct {
		DataType   string
		MaxLen     int
		Nullable   string
		ColDefault string
	}
	if err := db.Raw(`SELECT data_type, character_maximum_length AS max_len, is_nullable AS nullable,
		column_default AS col_default FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'change_secret_records' AND column_name = 'transport_risk'`).
		Scan(&col).Error; err != nil {
		t.Fatalf("查欄位失敗: %v", err)
	}
	if col.DataType != "character varying" || col.MaxLen != 32 || col.Nullable != "NO" {
		t.Fatalf("transport_risk 欄位形狀不符: %+v", col)
	}
	t.Logf("transport_risk: %+v", col)
	var risks []string
	if err := db.Raw(`SELECT transport_risk FROM change_secret_records`).Scan(&risks).Error; err != nil {
		t.Fatalf("讀既有紀錄失敗: %v", err)
	}
	if len(risks) != 1 || risks[0] != "" {
		t.Fatalf("既有紀錄的 transport_risk 應為空字串, got %q", risks)
	}
	if err := target.Down(db); err == nil {
		t.Fatal("本 migration 不提供 Down，應回拒絕錯誤")
	}
}
