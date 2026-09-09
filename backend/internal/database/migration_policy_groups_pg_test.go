package database

import (
	"testing"

	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
)

// 政策組增量的**結構面實測**（PG-gated；未設 TEST_PG_DSN 即 skip，
// REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
//
// 與 migration_policy_groups_test.go 不重疊：那一檔問「宣告面對不對、約束的語義
// 對不對」，本檔問「這條 migration 在真的 postgres 上跑不跑得起來、Down 之後能
// 不能再 Up」。只有 sqlite 那一段會漏掉方言（bigserial、`::character varying`
// 預設、複合主鍵的語法）；只有結構測會漏掉約束的語義。

// policyGroupsObjects 本增量產生的資料庫物件計數（Down／Up 的比對基準）。
func policyGroupsObjects(t *testing.T, db *gorm.DB, pgSchema string) (tables, indexes int64) {
	t.Helper()
	scan := func(sql string, dst *int64, args ...interface{}) {
		if err := db.Raw(sql, args...).Scan(dst).Error; err != nil {
			t.Fatalf("計數失敗（%s）: %v", sql, err)
		}
	}
	scan(`SELECT count(*) FROM information_schema.tables
	      WHERE table_schema = ? AND table_type = 'BASE TABLE'
	      AND table_name IN ('policy_groups','policy_clauses',
	                         'policy_clause_controls','policy_clause_annotations')`,
		&tables, pgSchema)
	scan(`SELECT count(*) FROM pg_indexes WHERE schemaname = ?
	      AND tablename IN ('policy_groups','policy_clauses',
	                        'policy_clause_controls','policy_clause_annotations')`,
		&indexes, pgSchema)
	return tables, indexes
}

// TestMigrationPolicyGroupsDownThenUpPostgres Down 之後能再 Up。
//
// **Down 是有損的**（見 migration_policy_groups.go 檔頭的 Down 契約）：本測試
// 斷言的是**結構可還原**，不是資料可還原——後者沒有反向，也不該假裝有。
func TestMigrationPolicyGroupsDownThenUpPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "policy_groups_down_up_test"
	db := freshSchema(t, dsn, pgSchema)
	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	if err := applyMigrationsAfterBaseline(db); err != nil {
		t.Fatalf("增量 migration 失敗: %v", err)
	}
	tablesBefore, indexesBefore := policyGroupsObjects(t, db, pgSchema)
	if tablesBefore != 4 {
		t.Fatalf("Up 之後政策組表數 = %d, want 4", tablesBefore)
	}
	// 四條主鍵索引加一條 (group_code, policy_key) 唯一索引
	if indexesBefore != 5 {
		t.Fatalf("Up 之後政策組索引數 = %d, want 5", indexesBefore)
	}

	var uniqueIdx int64
	if err := db.Raw(`SELECT count(*) FROM pg_indexes WHERE schemaname = ?
		AND indexname = 'idx_policy_clause_controls_group_key'`, pgSchema).
		Scan(&uniqueIdx).Error; err != nil {
		t.Fatalf("查唯一索引失敗: %v", err)
	}
	if uniqueIdx != 1 {
		t.Fatal("(group_code, policy_key) 的唯一索引不存在：同組內同一個鍵可被寫入" +
			"兩個互相矛盾的要求，而症狀只會表現為判定結果不穩定")
	}

	if err := rollbackPolicyGroups(db); err != nil {
		t.Fatalf("Down 失敗: %v", err)
	}
	tablesAfterDown, indexesAfterDown := policyGroupsObjects(t, db, pgSchema)
	if tablesAfterDown != 0 || indexesAfterDown != 0 {
		t.Fatalf("Down 之後仍有殘留（表 %d、索引 %d）：反序清理不完整，"+
			"殘留物會讓下一次 Up 的無條件 DDL 撞上既有物件",
			tablesAfterDown, indexesAfterDown)
	}

	if err := applyPolicyGroups(db); err != nil {
		t.Fatalf("Down 之後再 Up 失敗（無條件 DDL 撞上殘留物即為此形態）: %v", err)
	}
	tablesAfterUp, indexesAfterUp := policyGroupsObjects(t, db, pgSchema)
	if tablesAfterUp != tablesBefore || indexesAfterUp != indexesBefore {
		t.Fatalf("再 Up 之後的物件數不同：表 %d→%d、索引 %d→%d",
			tablesBefore, tablesAfterUp, indexesBefore, indexesAfterUp)
	}
}
