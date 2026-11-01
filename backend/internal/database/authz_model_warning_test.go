package database

import (
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// TestAuthzUpgradeWarning 擋：資料在遷移當下已不具還原資格（無本地超管、懸空指派）卻沒有留痕，
// 或健康資料被誤警示，或同一份資料每次重跑都警示。升級本身不被擋（遷移照樣成功）。
func TestAuthzUpgradeWarning(t *testing.T) {
	drain := func() { TakeAuthzUpgradeWarning() }

	t.Run("零本地超管與懸空指派：遷移成功，暫存一次警示", func(t *testing.T) {
		drain()
		db := newAuthzSQLite(t)
		seed117(t, db, true)
		if err := db.Exec(`UPDATE users SET active = ? WHERE username IN ('root', 'root2')`, false).Error; err != nil {
			t.Fatal(err)
		}
		if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
			t.Fatalf("遷移不得因此失敗: %v", err)
		}
		w, ok := TakeAuthzUpgradeWarning()
		if !ok || w.LocalSuperAdmins != 0 || w.DanglingAssignments != 2 {
			t.Fatalf("警示 = %+v ok=%v, want 零超管且懸空 2", w, ok)
		}
		if _, again := TakeAuthzUpgradeWarning(); again {
			t.Error("警示取走後仍殘留")
		}
		// 重跑：報告已存在，不再警示
		if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
			t.Fatal(err)
		}
		if _, again := TakeAuthzUpgradeWarning(); again {
			t.Error("重跑再度警示同一份資料")
		}
	})

	t.Run("健康資料：不警示", func(t *testing.T) {
		drain()
		db := newAuthzSQLite(t)
		seed117(t, db, false)
		// 夾具刻意帶懸空指派；健康資料要先拿掉它們
		if err := db.Exec(`DELETE FROM user_roles WHERE role_id NOT IN (SELECT id FROM roles WHERE deleted_at IS NULL)`).Error; err != nil {
			t.Fatal(err)
		}
		if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
			t.Fatal(err)
		}
		if w, ok := TakeAuthzUpgradeWarning(); ok {
			t.Errorf("健康資料被警示: %+v", w)
		}
	})

	t.Run("全新庫（零使用者）：不警示", func(t *testing.T) {
		drain()
		db := newAuthzSQLite(t)
		if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
			t.Fatalf("全新庫遷移失敗: %v", err)
		}
		if w, ok := TakeAuthzUpgradeWarning(); ok {
			t.Errorf("全新庫被警示: %+v", w)
		}
	})

	t.Run("有使用者、零超管、零懸空：警示", func(t *testing.T) {
		drain()
		db := newAuthzSQLite(t)
		seed117(t, db, false)
		if err := db.Exec(`DELETE FROM user_roles WHERE role_id NOT IN (SELECT id FROM roles WHERE deleted_at IS NULL)`).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Exec(`UPDATE users SET active = ? WHERE username IN ('root', 'root2')`, false).Error; err != nil {
			t.Fatal(err)
		}
		if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
			t.Fatal(err)
		}
		w, ok := TakeAuthzUpgradeWarning()
		if !ok || w.LocalSuperAdmins != 0 || w.DanglingAssignments != 0 {
			t.Fatalf("警示 = %+v ok=%v, want 零超管零懸空仍警示", w, ok)
		}
	})

	t.Run("計數失敗：整筆回滾", func(t *testing.T) {
		drain()
		db := newAuthzSQLite(t)
		seed117(t, db, false)
		armed := false
		fired := 0
		if err := db.Callback().Raw().After("gorm:raw").Register("warn_arm", func(tx *gorm.DB) {
			if strings.Contains(tx.Statement.SQL.String(), "UPDATE authz_state") {
				armed = true
			}
		}); err != nil {
			t.Fatal(err)
		}
		if err := db.Callback().Query().After("gorm:query").Register("warn_count_fault", func(tx *gorm.DB) {
			if armed && tx.Statement.Table == "users" {
				fired++
				_ = tx.AddError(gorm.ErrInvalidDB)
			}
		}); err != nil {
			t.Fatal(err)
		}
		err := db.Transaction(func(tx *gorm.DB) error {
			return applyAuthzModelData(tx, planAuthzModelReport)
		})
		if err == nil {
			t.Fatal("計數失敗卻回報遷移成功")
		}
		if fired < 1 {
			t.Fatal("注入的計數錯誤未被觸發")
		}
		var raw *string
		if err := db.Raw(`SELECT model_migration_report FROM authz_state WHERE id = 1`).Scan(&raw).Error; err == nil && raw != nil {
			t.Errorf("計數失敗後報告仍被寫入: %s", *raw)
		}
		var marked int64
		db.Model(&model.Role{}).Where("builtin_key IS NOT NULL").Count(&marked)
		if marked != 0 {
			t.Errorf("計數失敗後內建角色標記未回滾（%d 列）", marked)
		}
		if w, ok := TakeAuthzUpgradeWarning(); ok {
			t.Errorf("計數失敗後殘留暫存警示: %+v", w)
		}
	})

	t.Run("只剩軟刪除使用者：不警示", func(t *testing.T) {
		drain()
		db := newAuthzSQLite(t)
		seed117(t, db, false)
		if err := db.Exec(`DELETE FROM user_roles WHERE role_id NOT IN (SELECT id FROM roles WHERE deleted_at IS NULL)`).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Exec(`UPDATE users SET deleted_at = CURRENT_TIMESTAMP`).Error; err != nil {
			t.Fatal(err)
		}
		var all, live int64
		db.Unscoped().Model(&model.User{}).Count(&all)
		db.Model(&model.User{}).Count(&live)
		if all <= 0 || live != 0 {
			t.Fatalf("夾具未落在軟刪除分支：Unscoped=%d 預設=%d", all, live)
		}
		if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
			t.Fatal(err)
		}
		if w, ok := TakeAuthzUpgradeWarning(); ok {
			t.Errorf("只剩軟刪除使用者被警示: %+v", w)
		}
	})

	t.Run("判準", func(t *testing.T) {
		cases := []struct {
			rep   AuthzMigrationReport
			users int64
			want  bool
		}{
			{AuthzMigrationReport{LocalSuperAdmins: 1}, 1, false},
			{AuthzMigrationReport{LocalSuperAdmins: 0}, 1, true},
			{AuthzMigrationReport{LocalSuperAdmins: 2, DanglingAssignments: 1}, 1, true},
			{AuthzMigrationReport{LocalSuperAdmins: 0}, 0, false},
			{AuthzMigrationReport{LocalSuperAdmins: 0, DanglingAssignments: 1}, 0, true},
		}
		for _, c := range cases {
			if _, got := authzWarningFor(c.rep, c.users); got != c.want {
				t.Errorf("%+v users=%d: got %v want %v", c.rep, c.users, got, c.want)
			}
		}
	})
}
