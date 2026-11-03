package database

import (
	"testing"

	"github.com/custodexa/backend/internal/testgate"
)

// 改密紀錄執行方式四欄的升級實測（PG-gated；未設 TEST_PG_DSN 即 skip，
// REQUIRE_INTEGRATION=1 時 skip 轉 fail）：升級前已有兩筆改密紀錄，套用本 migration 後
// 兩筆皆為自改且專用帳號三欄為零值或空字串；新插入而未指定這四欄的列同樣取預設。
func TestChangeSecretExecutionMethodMigrationPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, "change_secret_execution_method_upgrade_test")
	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	const version = "20261103_change_secret_execution_method"
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
	for i := 1; i <= 2; i++ {
		if err := db.Exec(`INSERT INTO change_secret_records (plan_id, asset_id, status, error, executed_at)
			VALUES (?, ?, 'success', '', now())`, i, i).Error; err != nil {
			t.Fatalf("寫入既有紀錄 %d 失敗: %v", i, err)
		}
	}
	if err := target.Up(db); err != nil {
		t.Fatalf("套用 %s 失敗: %v", version, err)
	}

	type colShape struct {
		ColumnName string
		DataType   string
		MaxLen     int
		Nullable   string
		ColDefault string
	}
	var cols []colShape
	if err := db.Raw(`SELECT column_name, data_type, COALESCE(character_maximum_length, 0) AS max_len, is_nullable AS nullable,
		column_default AS col_default FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'change_secret_records'
		AND column_name IN ('execution_method','executor_account_id','executor_username','executor_credential_id')
		ORDER BY column_name`).Scan(&cols).Error; err != nil {
		t.Fatalf("查欄位失敗: %v", err)
	}
	if len(cols) != 4 {
		t.Fatalf("應有四個新欄, got %+v", cols)
	}
	for _, c := range cols {
		if c.Nullable != "NO" {
			t.Fatalf("%s 應為 NOT NULL: %+v", c.ColumnName, c)
		}
		t.Logf("%+v", c)
	}

	check := func(label string, wantRows int) {
		t.Helper()
		var rows []struct {
			ExecutionMethod      string
			ExecutorAccountID    int64
			ExecutorUsername     string
			ExecutorCredentialID int64
		}
		if err := db.Raw(`SELECT execution_method, executor_account_id, executor_username, executor_credential_id
			FROM change_secret_records ORDER BY id`).Scan(&rows).Error; err != nil {
			t.Fatalf("%s 讀取失敗: %v", label, err)
		}
		if len(rows) != wantRows {
			t.Fatalf("%s 應有 %d 列, got %d", label, wantRows, len(rows))
		}
		for _, r := range rows {
			if r.ExecutionMethod != "self" || r.ExecutorAccountID != 0 || r.ExecutorUsername != "" || r.ExecutorCredentialID != 0 {
				t.Fatalf("%s 預設值不符: %+v", label, r)
			}
		}
	}
	check("既有兩筆", 2)

	if err := db.Exec(`INSERT INTO change_secret_records (plan_id, asset_id, status, error, executed_at)
		VALUES (3, 3, 'failed', '', now())`).Error; err != nil {
		t.Fatalf("套用後插入未指定四欄的列失敗: %v", err)
	}
	check("新插入未指定四欄", 3)

	if err := target.Down(db); err == nil {
		t.Fatal("本 migration 不提供 Down，應回拒絕錯誤")
	}
}
