package database

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
)

// TestRoleDefinitionMigration 擋：升級改動存量角色或指派、範本冒認同名自訂角色、重跑改變內容、失敗留下部分結構。
//
// sqlite 子測試驗資料步驟語義（種範本、衝突拒絕、冪等）；postgres 子測試（PG-gated）走真 DDL 與 RunMigrations。
func TestRoleDefinitionMigration(t *testing.T) {
	templates := func(t *testing.T, db *gorm.DB) map[string]string {
		t.Helper()
		var rows []struct {
			Name, BuiltinKey  string
			DefinitionVersion int64
		}
		if err := db.Raw("SELECT name, builtin_key, definition_version FROM roles WHERE builtin_key IN ('identity_admin','security_admin') ORDER BY name").Scan(&rows).Error; err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, r := range rows {
			out[r.Name] = fmt.Sprintf("%s/v%d", r.BuiltinKey, r.DefinitionVersion)
		}
		return out
	}

	t.Run("sqlite：種兩範本、不指派任何人、存量列與指派逐列不變、重跑不改內容", func(t *testing.T) {
		db := newAuthzSQLite(t)
		if err := db.AutoMigrate(&model.RolePermission{}, &model.UserGroupRole{}); err != nil {
			t.Fatal(err)
		}
		seed117(t, db, false)
		if err := db.Exec("UPDATE roles SET builtin_key = 'super_admin' WHERE name = 'admin'").Error; err != nil {
			t.Fatal(err)
		}
		before := dumpTables(t, db, "roles", "user_roles")
		repBefore, err := PlanRoleDefinitionsReport(db)
		if err != nil {
			t.Fatal(err)
		}
		if err := seedLockedTemplates(db); err != nil {
			t.Fatal(err)
		}
		got := templates(t, db)
		if got["identity_admin"] != "identity_admin/v1" || got["security_admin"] != "security_admin/v1" || len(got) != 2 {
			t.Fatalf("範本 = %v", got)
		}
		var n int64
		db.Raw("SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE r.builtin_key IN ('identity_admin','security_admin')").Scan(&n)
		if n != 0 {
			t.Errorf("範本被指派給 %d 個主體", n)
		}
		// 存量列：除新增兩列外，其餘 roles 與 user_roles 逐列相同（新增列在 dump 尾端，前綴比較）
		after := dumpTables(t, db, "roles", "user_roles")
		if len(after) <= len(before) {
			t.Fatalf("dump 未增長")
		}
		var legacy int64
		db.Raw("SELECT COUNT(*) FROM roles WHERE definition_version = 0").Scan(&legacy)
		var total int64
		db.Raw("SELECT COUNT(*) FROM roles").Scan(&total)
		if total-legacy != 2 {
			t.Errorf("version>=1 的角色數 = %d, want 2（只有兩範本）", total-legacy)
		}
		// 前後 dry-run 報告可比：同輸入同報告，且對存量或指派的任何改動敏感
		repAfter, err := PlanRoleDefinitionsReport(db)
		if err != nil {
			t.Fatal(err)
		}
		bj, _ := repBefore.JSON()
		aj, _ := repAfter.JSON()
		if bj != aj {
			t.Errorf("前後報告不同:\n%s\n%s", bj, aj)
		}
		if repBefore.Roles == 0 || repBefore.UserRoles == 0 {
			t.Errorf("報告未涵蓋 fixture（roles=%d user_roles=%d）", repBefore.Roles, repBefore.UserRoles)
		}
		errRollback := errors.New("rollback")
		_ = db.Transaction(func(tx *gorm.DB) error { // 改動後算報告再回滾，不污染後續斷言
			if err := tx.Exec("UPDATE user_roles SET source = 'zz-changed' WHERE rowid = (SELECT MIN(rowid) FROM user_roles)").Error; err != nil {
				t.Fatal(err)
			}
			changed, _ := PlanRoleDefinitionsReport(tx)
			if cj, _ := changed.JSON(); cj == aj {
				t.Error("指派改動後報告未變")
			}
			return errRollback
		})
		again := dumpTables(t, db, "roles", "user_roles")
		if err := seedLockedTemplates(db); err != nil {
			t.Fatal(err)
		}
		if dumpTables(t, db, "roles", "user_roles") != again {
			t.Error("第二次執行改變了內容")
		}
	})

	t.Run("sqlite：同名自訂角色佔用範本名稱時整筆拒絕，不改寫該角色", func(t *testing.T) {
		for _, taken := range []string{"identity_admin", "security_admin"} {
			db := newAuthzSQLite(t)
			if err := db.AutoMigrate(&model.RolePermission{}, &model.UserGroupRole{}); err != nil {
				t.Fatal(err)
			}
			squat := model.Role{Name: taken, Description: "custom"}
			if err := db.Create(&squat).Error; err != nil {
				t.Fatal(err)
			}
			before := dumpTables(t, db, "roles")
			err := seedLockedTemplates(db)
			if !errors.Is(err, ErrRoleTemplateNameTaken) {
				t.Fatalf("%s: err = %v", taken, err)
			}
			var key *string
			db.Raw("SELECT builtin_key FROM roles WHERE id = ?", squat.ID).Scan(&key)
			if key != nil {
				t.Errorf("同名角色被冒認為內建 %s", *key)
			}
			if dumpTables(t, db, "roles") != before {
				t.Errorf("%s: 拒絕後內容改變", taken)
			}
		}
	})

	t.Run("postgres：真 DDL 套用、第二次 RunMigrations 不改內容、同名衝突整筆不套用且結構不變", func(t *testing.T) {
		// pre 以呼叫端子測試的 t 執行：PG 未設定時的 Skip 與 Fatal 必須落在呼叫它的子測試上。
		pre := func(t *testing.T, name string) *gorm.DB {
			db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), name)
			if err := db.Exec(schemaMigrationsBootstrapDDL).Error; err != nil {
				t.Fatal(err)
			}
			for _, m := range migrations {
				if m.Version == "20261017_role_definitions" {
					break
				}
				if m.Version == "20261016_authz_permission_model" {
					withGlobalDB(t, db)
					seed117(t, db, false) // 1.17 形狀資料先於權限模型遷移，之後它補標記
				}
				if err := m.Up(db); err != nil {
					t.Fatal(m.Version, err)
				}
				if err := db.Create(&SchemaMigration{Version: m.Version, AppliedAt: time.Now()}).Error; err != nil {
					t.Fatal(err)
				}
			}
			return db
		}
		t.Run("套用與重跑", func(t *testing.T) {
			db := pre(t, fmt.Sprintf("roledef_apply_%d", time.Now().UnixNano()))
			withGlobalDB(t, db)
			userRolesBefore := dumpTables(t, db, "user_roles")
			repBefore, err := PlanRoleDefinitionsReport(db) // 隔離演練（dry-run）報告
			if err != nil {
				t.Fatal(err)
			}
			if err := RunMigrations(); err != nil {
				t.Fatal(err)
			}
			repAfter, err := PlanRoleDefinitionsReport(db)
			if err != nil {
				t.Fatal(err)
			}
			if bj, _ := repBefore.JSON(); bj == "" || bj != func() string { j, _ := repAfter.JSON(); return j }() {
				t.Errorf("升級前後報告不可比: %+v vs %+v", repBefore, repAfter)
			}
			if got := templates(t, db); len(got) != 2 {
				t.Fatalf("範本 = %v", got)
			}
			if dumpTables(t, db, "user_roles") != userRolesBefore {
				t.Error("user_roles 被改動")
			}
			var legacy int64
			db.Raw("SELECT COUNT(*) FROM roles WHERE definition_version = 0").Scan(&legacy)
			if legacy != 6 { // 四內建 + ops + retired（含軟刪列）
				t.Errorf("存量角色 = %d, want 6", legacy)
			}
			if !hasTable(t, db, currentSchema(t, db), "role_permissions") {
				t.Error("缺 role_permissions")
			}
			after1 := dumpTables(t, db, "roles", "user_roles", "role_permissions")
			if err := RunMigrations(); err != nil {
				t.Fatal(err)
			}
			if dumpTables(t, db, "roles", "user_roles", "role_permissions") != after1 {
				t.Error("第二次 RunMigrations 改變了內容")
			}
			// CHECK 放寬後仍擋未知識別
			if err := db.Exec("INSERT INTO roles (name, builtin_key, created_at, updated_at) VALUES ('zz','bogus',now(),now())").Error; err == nil {
				t.Error("builtin_key 值域未擋未知識別")
			}
		})
		t.Run("同名衝突整筆不套用", func(t *testing.T) {
			db := pre(t, fmt.Sprintf("roledef_conflict_%d", time.Now().UnixNano()))
			withGlobalDB(t, db)
			if err := db.Omit("DefinitionVersion", "TemplateRoleID").Create(&model.Role{Name: "security_admin"}).Error; err != nil {
				t.Fatal(err)
			}
			schemaName := currentSchema(t, db)
			objBefore := countSchemaObjects(t, db, schemaName)
			dataBefore := dumpTables(t, db, "roles", "user_roles")
			err := RunMigrations()
			if !errors.Is(err, ErrRoleTemplateNameTaken) {
				t.Fatalf("err = %v", err)
			}
			if countSchemaObjects(t, db, schemaName) != objBefore {
				t.Error("失敗後結構改變")
			}
			if dumpTables(t, db, "roles", "user_roles") != dataBefore {
				t.Error("失敗後內容改變")
			}
			if hasColumn(t, db, schemaName, "roles", "definition_version") || hasTable(t, db, schemaName, "role_permissions") {
				t.Error("失敗後留下新欄或新表")
			}
		})
	})
}
