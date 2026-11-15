package database

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
)

// 使用者群組名稱部分唯一索引的升級與回滾實測（PG-gated；未設 TEST_PG_DSN 即 skip，
// REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
//
//	TEST_PG_DSN="host=... user=... password=... dbname=... sslmode=disable" \
//	  REQUIRE_INTEGRATION=1 go test ./internal/database -run 'UserGroupNameLiveUniqueMigration'

const userGroupNameLiveUniqueVersion = "20261115_user_group_name_live_unique"

// ugnUpgradedSchema 建出本 migration 之前的 schema（baseline 與其前的全部增量），回傳本 migration。
func ugnUpgradedSchema(t *testing.T, schemaName string) (*gorm.DB, *Migration) {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, schemaName)
	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	var target *Migration
	for i := 1; i < len(migrations); i++ {
		if migrations[i].Version == userGroupNameLiveUniqueVersion {
			target = &migrations[i]
			break
		}
		if err := migrations[i].Up(db); err != nil {
			t.Fatalf("增量 %s 失敗: %v", migrations[i].Version, err)
		}
	}
	if target == nil {
		t.Fatalf("未登記 %s", userGroupNameLiveUniqueVersion)
	}
	return db, target
}

func ugnIndexDef(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var def string
	if err := db.Raw(`SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'idx_user_groups_name'`).
		Scan(&def).Error; err != nil {
		t.Fatalf("讀取索引定義失敗: %v", err)
	}
	return def
}

func ugnInsert(t *testing.T, db *gorm.DB, name string, deleted bool) error {
	t.Helper()
	var deletedAt any
	if deleted {
		deletedAt = time.Now()
	}
	return db.Exec(`INSERT INTO user_groups (name, description, created_at, updated_at, deleted_at) VALUES (?, '', now(), now(), ?)`,
		name, deletedAt).Error
}

func ugnRowCount(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Raw(`SELECT count(*) FROM user_groups`).Scan(&n).Error; err != nil {
		t.Fatalf("計數失敗: %v", err)
	}
	return n
}

// TestUserGroupNameLiveUniqueMigrationPostgres 升級：既有資料（含已刪除的群組）原樣保留；
// 升級後已刪除群組的名稱可重建、現存群組的名稱仍不可重複；索引定義為部分唯一。
func TestUserGroupNameLiveUniqueMigrationPostgres(t *testing.T) {
	db, target := ugnUpgradedSchema(t, "ugn_live_unique_upgrade_test")
	if def := ugnIndexDef(t, db); strings.Contains(def, "WHERE") {
		t.Fatalf("前提：升級前應為涵蓋全部列的唯一索引，實際 %s", def)
	}
	if err := ugnInsert(t, db, "ops", false); err != nil {
		t.Fatal(err)
	}
	if err := ugnInsert(t, db, "retired", true); err != nil {
		t.Fatal(err)
	}
	// 前提：升級前已刪除群組仍佔用名稱
	if err := ugnInsert(t, db, "retired", false); err == nil || !dberr.IsUniqueViolation(err) {
		t.Fatalf("前提：升級前同名重建應撞唯一索引，得 %v", err)
	}

	if err := target.Up(db); err != nil {
		t.Fatalf("套用 %s 失敗: %v", target.Version, err)
	}
	want := "CREATE UNIQUE INDEX idx_user_groups_name ON ugn_live_unique_upgrade_test.user_groups USING btree (name) WHERE (deleted_at IS NULL)"
	if def := ugnIndexDef(t, db); def != want {
		t.Fatalf("升級後索引定義\n  實際 %s\n  期望 %s", def, want)
	}
	if n := ugnRowCount(t, db); n != 2 {
		t.Fatalf("升級不應增刪列，得 %d 列", n)
	}
	var keptName string
	if err := db.Raw(`SELECT name FROM user_groups WHERE deleted_at IS NOT NULL`).Scan(&keptName).Error; err != nil || keptName != "retired" {
		t.Fatalf("已刪除列的名稱應保留原樣：%q %v", keptName, err)
	}
	if err := ugnInsert(t, db, "retired", false); err != nil {
		t.Fatalf("升級後已刪除群組的名稱應可重建: %v", err)
	}
	if err := ugnInsert(t, db, "ops", false); err == nil || !dberr.IsUniqueViolation(err) {
		t.Fatalf("現存群組的名稱仍應撞唯一索引，得 %v", err)
	}
}

// TestUserGroupNameLiveUniqueMigrationDownPostgres 回滾走正式入口 RollbackMigration（同一交易內 Down 與版本紀錄移除），
// 三種資料：無衝突時成功並還原為涵蓋全部列的唯一索引；已刪除與現存同名、兩筆已刪除同名時失敗、指出原因，
// 新索引與版本紀錄維持不變。
func TestUserGroupNameLiveUniqueMigrationDownPostgres(t *testing.T) {
	cases := []struct {
		name     string
		seed     func(t *testing.T, db *gorm.DB)
		wantFail bool
	}{
		{"no_conflict", func(t *testing.T, db *gorm.DB) {
			for _, r := range []struct {
				n string
				d bool
			}{{"alpha", false}, {"beta", true}} {
				if err := ugnInsert(t, db, r.n, r.d); err != nil {
					t.Fatal(err)
				}
			}
		}, false},
		{"deleted_and_live_same_name", func(t *testing.T, db *gorm.DB) {
			for _, d := range []bool{true, false} {
				if err := ugnInsert(t, db, "dup", d); err != nil {
					t.Fatal(err)
				}
			}
		}, true},
		{"two_deleted_same_name", func(t *testing.T, db *gorm.DB) {
			for i := 0; i < 2; i++ {
				if err := ugnInsert(t, db, "gone", true); err != nil {
					t.Fatal(err)
				}
			}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			schemaName := "ugn_down_" + tc.name
			db, target := ugnUpgradedSchema(t, schemaName)
			if err := target.Up(db); err != nil {
				t.Fatalf("套用失敗: %v", err)
			}
			if err := db.Exec(schemaMigrationsBootstrapDDL).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, now())`, target.Version).Error; err != nil {
				t.Fatal(err)
			}
			tc.seed(t, db)
			before := ugnRowCount(t, db)
			partialDef := ugnIndexDef(t, db)

			prev := DB
			DB = db
			t.Cleanup(func() { DB = prev })
			err := RollbackMigration(target.Version)

			var versionRows int64
			if qerr := db.Raw(`SELECT count(*) FROM schema_migrations WHERE version = ?`, target.Version).Scan(&versionRows).Error; qerr != nil {
				t.Fatal(qerr)
			}
			if n := ugnRowCount(t, db); n != before {
				t.Fatalf("回滾不應增刪資料列：前 %d、後 %d", before, n)
			}
			if tc.wantFail {
				if err == nil {
					t.Fatal("有同名列時回滾應失敗")
				}
				if !strings.Contains(err.Error(), "多列") || !strings.Contains(err.Error(), "備份") {
					t.Fatalf("失敗訊息應指出同名列與還原備份：%v", err)
				}
				if def := ugnIndexDef(t, db); def != partialDef {
					t.Fatalf("失敗後索引應維持部分唯一：%s", def)
				}
				if versionRows != 1 {
					t.Fatalf("失敗後版本紀錄應保留，得 %d 列", versionRows)
				}
				t.Logf("回滾被拒（預期）：%v", err)
				return
			}
			if err != nil {
				t.Fatalf("無衝突時回滾應成功: %v", err)
			}
			want := "CREATE UNIQUE INDEX idx_user_groups_name ON " + schemaName + ".user_groups USING btree (name)"
			if def := ugnIndexDef(t, db); def != want {
				t.Fatalf("回滾後索引定義\n  實際 %s\n  期望 %s", def, want)
			}
			if versionRows != 0 {
				t.Fatalf("回滾成功後版本紀錄應移除，得 %d 列", versionRows)
			}
			if err := ugnInsert(t, db, "beta", false); err == nil || !dberr.IsUniqueViolation(err) {
				t.Fatalf("回滾後已刪除群組的名稱應再次被佔用，得 %v", err)
			}
		})
	}
}

// TestUserGroupNameLiveUniqueMigrationDownConcurrentPostgres 兩個連線交錯：另一個交易已寫入（尚未提交）
// 與已刪除群組同名的現存列時開始回滾。回滾必須等該交易結束後才做同名檢查，並以檢查的結論回錯（指出
// 同名列與還原備份），而不是檢查時看不到、走到重建索引才以一般 DDL 錯誤失敗；索引與版本紀錄維持不變。
func TestUserGroupNameLiveUniqueMigrationDownConcurrentPostgres(t *testing.T) {
	db, target := ugnUpgradedSchema(t, "ugn_down_concurrent")
	if err := target.Up(db); err != nil {
		t.Fatalf("套用失敗: %v", err)
	}
	if err := db.Exec(schemaMigrationsBootstrapDDL).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, now())`, target.Version).Error; err != nil {
		t.Fatal(err)
	}
	if err := ugnInsert(t, db, "dup", true); err != nil {
		t.Fatal(err)
	}
	partialDef := ugnIndexDef(t, db)

	// 連線 B：寫入同名的現存列，先不提交
	writer := db.Begin()
	if writer.Error != nil {
		t.Fatal(writer.Error)
	}
	committed := false
	t.Cleanup(func() {
		if !committed {
			writer.Rollback()
		}
	})
	if err := ugnInsert(t, writer, "dup", false); err != nil {
		t.Fatalf("連線 B 寫入失敗: %v", err)
	}

	// 連線 A：回滾（正式入口）
	prev := DB
	DB = db
	t.Cleanup(func() { DB = prev })
	done := make(chan error, 1)
	go func() { done <- RollbackMigration(target.Version) }()

	// 等到回滾在 user_groups 上等鎖（被 B 的未提交寫入擋住），才讓 B 提交
	deadline := time.Now().Add(15 * time.Second)
	for {
		var waiting int64
		if err := writer.Raw(`SELECT count(*) FROM pg_locks WHERE NOT granted AND relation = 'user_groups'::regclass`).
			Scan(&waiting).Error; err != nil {
			t.Fatalf("查詢等鎖失敗: %v", err)
		}
		if waiting > 0 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("前提：回滾應被連線 B 的未提交寫入擋住，卻已結束：%v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("前提：等不到回滾在 user_groups 上等鎖")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := writer.Commit().Error; err != nil {
		t.Fatalf("連線 B 提交失敗: %v", err)
	}
	committed = true

	var err error
	select {
	case err = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("回滾未在時限內結束")
	}
	if err == nil {
		t.Fatal("並發寫入同名現存列後回滾應失敗")
	}
	t.Logf("回滾被拒：%v", err)
	if !strings.Contains(err.Error(), "多列") || !strings.Contains(err.Error(), "備份") {
		t.Fatalf("應由同名檢查回錯（指出同名列與還原備份），而不是走到重建索引才失敗：%v", err)
	}
	if def := ugnIndexDef(t, db); def != partialDef {
		t.Fatalf("失敗後索引應維持部分唯一：%s", def)
	}
	var versionRows int64
	if qerr := db.Raw(`SELECT count(*) FROM schema_migrations WHERE version = ?`, target.Version).Scan(&versionRows).Error; qerr != nil {
		t.Fatal(qerr)
	}
	if versionRows != 1 {
		t.Fatalf("失敗後版本紀錄應保留，得 %d 列", versionRows)
	}
	if n := ugnRowCount(t, db); n != 2 {
		t.Fatalf("資料列應為已刪除與連線 B 寫入的現存列共 2 列，得 %d", n)
	}
}
