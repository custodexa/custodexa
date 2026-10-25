package database

import "testing"

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

	t.Run("判準", func(t *testing.T) {
		cases := []struct {
			rep  AuthzMigrationReport
			want bool
		}{
			{AuthzMigrationReport{LocalSuperAdmins: 1}, false},
			{AuthzMigrationReport{LocalSuperAdmins: 0}, true},
			{AuthzMigrationReport{LocalSuperAdmins: 2, DanglingAssignments: 1}, true},
		}
		for _, c := range cases {
			if _, got := authzWarningFor(c.rep); got != c.want {
				t.Errorf("%+v: got %v want %v", c.rep, got, c.want)
			}
		}
	})
}
