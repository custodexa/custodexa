package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestAuthzModelMigration 擋：升級時內建身分指定錯誤或報告不一致仍套用；不可逆面。
//
// sqlite 子測試驗資料步驟語義（補列、標記、報告、冪等）；postgres 子測試（PG-gated）
// 走真 DDL 與 RunMigrations，驗整筆不套用與回滾的結構面。

func newAuthzSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}, &model.AuthzState{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func seedRoleRows(t *testing.T, db *gorm.DB, names ...string) map[string]uint {
	t.Helper()
	ids := map[string]uint{}
	for _, s := range builtinRoleSeeds() {
		for _, n := range names {
			if s.Name == n {
				r := s
				if err := db.Omit("BuiltinKey", "DefinitionVersion", "TemplateRoleID").Create(&r).Error; err != nil { // 遷移前的形狀沒有 builtin_key 欄
					t.Fatalf("建角色 %s: %v", n, err)
				}
				ids[n] = r.ID
			}
		}
	}
	return ids
}

type fxUser struct {
	name     string
	roles    []string // 角色名稱
	source   string   // user_roles.source
	mutate   func(u *model.User)
	wantAdmn bool // 預期計為本地超管
}

// seed117 1.17 形狀 fixture：涵蓋本地超管的各個排除條件、映射來源、未知角色與懸空指派。
func seed117(t *testing.T, db *gorm.DB, missingRoleRow bool) (ids map[string]uint, wantLocalAdmins int64) {
	t.Helper()
	ids = seedRoleRows(t, db, "admin", "user", "auditor", "approver")
	ops := model.Role{Name: "ops", Description: "legacy custom"}
	gone := model.Role{Name: "retired", Description: "deleted"}
	for _, r := range []*model.Role{&ops, &gone} {
		if err := db.Omit("BuiltinKey", "DefinitionVersion", "TemplateRoleID").Create(r).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Delete(&gone).Error; err != nil {
		t.Fatal(err)
	}
	ids["ops"], ids["retired"] = ops.ID, gone.ID

	users := []fxUser{
		{name: "root", roles: []string{"admin", "user"}, source: model.RoleSourceManual, wantAdmn: true},
		{name: "root2", roles: []string{"admin"}, source: model.RoleSourceBoth, wantAdmn: true},
		{name: "mapped-admin", roles: []string{"admin"}, source: model.RoleSourceMapped},
		{name: "ext-admin", roles: []string{"admin"}, source: model.RoleSourceManual,
			mutate: func(u *model.User) { u.ProvisioningOrigin = model.AuthSourceOIDC }},
		{name: "ldap-admin", roles: []string{"admin"}, source: model.RoleSourceManual,
			mutate: func(u *model.User) { u.IsLDAP = true }},
		{name: "nopw-admin", roles: []string{"admin"}, source: model.RoleSourceManual,
			mutate: func(u *model.User) { u.Password = "  " }},
		{name: "off-admin", roles: []string{"admin"}, source: model.RoleSourceManual,
			mutate: func(u *model.User) { u.Active = false }},
		{name: "aud", roles: []string{"auditor"}, source: model.RoleSourceManual},
		{name: "aud-mapped", roles: []string{"auditor"}, source: model.RoleSourceMapped},
		{name: "u1", roles: []string{"user"}, source: model.RoleSourceManual},
		{name: "apv", roles: []string{"approver"}, source: model.RoleSourceManual},
		{name: "opsman", roles: []string{"ops"}, source: model.RoleSourceManual},
		{name: "ghost", roles: []string{"retired"}, source: model.RoleSourceManual},
	}
	for _, fu := range users {
		u := model.User{Username: fu.name, Password: "hash", Active: true, ProvisioningOrigin: model.AuthSourceLocal}
		if fu.mutate != nil {
			fu.mutate(&u)
		}
		if err := db.Create(&u).Error; err != nil {
			t.Fatalf("建使用者 %s: %v", fu.name, err)
		}
		if fu.name == "off-admin" { // Active 零值會被 default:true 吃掉，需明確更新
			db.Model(&u).Update("active", false)
		}
		if fu.wantAdmn {
			wantLocalAdmins++
		}
		for _, rn := range fu.roles {
			if err := db.Omit("ScopeKind").Create(&model.UserRole{RoleID: ids[rn], UserID: u.ID, Source: fu.source}).Error; err != nil {
				t.Fatalf("指派 %s/%s: %v", fu.name, rn, err)
			}
		}
	}
	// 指向不存在角色的指派（懸空）；PG 有外鍵，造不出這種列，只留指向已刪除角色的那筆
	if !missingRoleRow {
		return ids, wantLocalAdmins
	}
	if err := db.Omit("ScopeKind").Create(&model.UserRole{RoleID: 9999, UserID: 1, Source: model.RoleSourceManual}).Error; err != nil {
		t.Fatal(err)
	}
	return ids, wantLocalAdmins
}

// dumpTables 對照用快照：表內容逐列序列化。
func dumpTables(t *testing.T, db *gorm.DB, tables ...string) string {
	t.Helper()
	var sb strings.Builder
	for _, tb := range tables {
		var rows []map[string]any
		if err := db.Table(tb).Order("1, 2").Find(&rows).Error; err != nil {
			t.Fatalf("dump %s: %v", tb, err)
		}
		b, _ := json.Marshal(rows)
		sb.WriteString(tb + "=" + string(b) + "\n")
	}
	return sb.String()
}

func builtinKeys(t *testing.T, db *gorm.DB) map[string]string {
	t.Helper()
	var roles []model.Role
	if err := db.Unscoped().Find(&roles).Error; err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range roles {
		k := ""
		if r.BuiltinKey != nil {
			k = *r.BuiltinKey
		}
		out[r.Name] = k
	}
	return out
}

func TestAuthzModelMigration(t *testing.T) {
	wantKeys := map[string]string{"admin": "super_admin", "auditor": "auditor", "user": "user", "approver": "approver"}

	t.Run("sqlite", func(t *testing.T) {
		t.Run("全新庫依種子補列並標記", func(t *testing.T) {
			db := newAuthzSQLite(t)
			if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
				t.Fatalf("資料步驟: %v", err)
			}
			got := builtinKeys(t, db)
			for n, k := range wantKeys {
				if got[n] != k {
					t.Errorf("角色 %s builtin_key=%q, want %q", n, got[n], k)
				}
			}
			var roles []model.Role
			db.Order("id").Find(&roles) // 順序須與 seedRoles 相同（ID 相同）
			if len(roles) != 4 {
				t.Fatalf("角色列數 %d, want 4", len(roles))
			}
			for i, s := range builtinRoleSeeds() {
				if roles[i].Name != s.Name || roles[i].Description != s.Description {
					t.Errorf("補列 %d = %q/%q, want 種子 %q/%q", i, roles[i].Name, roles[i].Description, s.Name, s.Description)
				}
			}
			rep, err := ReadAuthzMigrationReport(db)
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(rep.SeededRoles) != "[admin user auditor approver]" || rep.LocalSuperAdmins != 0 || rep.DanglingAssignments != 0 || len(rep.UnknownRoles) != 0 {
				t.Errorf("全新庫報告 = %+v", rep)
			}
		})

		t.Run("1.17 形狀資料標記與報告", func(t *testing.T) {
			db := newAuthzSQLite(t)
			ids, wantAdmins := seed117(t, db, true)
			before := dumpTables(t, db, "user_roles", "users")
			if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
				t.Fatalf("資料步驟: %v", err)
			}
			got := builtinKeys(t, db)
			for n, k := range wantKeys {
				if got[n] != k {
					t.Errorf("角色 %s builtin_key=%q, want %q", n, got[n], k)
				}
			}
			if got["ops"] != "" || got["retired"] != "" {
				t.Errorf("未知或已刪除角色被標記: %v", got)
			}
			var admin model.Role
			db.First(&admin, ids["admin"])
			if admin.Name != "admin" || admin.BuiltinKey == nil || *admin.BuiltinKey != "super_admin" {
				t.Errorf("既有 admin 列被改動: %+v", admin)
			}
			if after := dumpTables(t, db, "user_roles", "users"); after != before {
				t.Errorf("遷移改動了指派或使用者資料:\nbefore=%s\nafter=%s", before, after)
			}
			rep, err := ReadAuthzMigrationReport(db)
			if err != nil {
				t.Fatal(err)
			}
			// admin：root、root2(both)、mapped-admin、ext、ldap、nopw、off ＝ 7 筆，mapped 1、both 1
			want := map[string][3]int64{"admin": {7, 1, 1}, "auditor": {2, 1, 0}, "user": {2, 0, 0}, "approver": {1, 0, 0}}
			for _, tc := range rep.Templates {
				w := want[tc.Name]
				if tc.Direct != w[0] || tc.Mapped != w[1] || tc.Both != w[2] {
					t.Errorf("範本 %s = %+v, want direct/mapped/both %v", tc.Name, tc, w)
				}
			}
			if rep.LocalSuperAdmins != wantAdmins {
				t.Errorf("本地超管數 %d, want %d", rep.LocalSuperAdmins, wantAdmins)
			}
			if len(rep.UnknownRoles) != 1 || rep.UnknownRoles[0] != (AuthzUnknownRole{Name: "ops", Assignments: 1}) {
				t.Errorf("未知角色 = %+v, want ops×1", rep.UnknownRoles)
			}
			if rep.DanglingAssignments != 2 { // ghost→已刪除角色、9999→不存在
				t.Errorf("懸空指派 %d, want 2", rep.DanglingAssignments)
			}
			if len(rep.SeededRoles) != 0 {
				t.Errorf("四角色俱全不該補列: %v", rep.SeededRoles)
			}
		})

		t.Run("缺哪個補哪個", func(t *testing.T) {
			db := newAuthzSQLite(t)
			seedRoleRows(t, db, "admin", "user", "auditor")
			if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
				t.Fatal(err)
			}
			rep, _ := ReadAuthzMigrationReport(db)
			if len(rep.SeededRoles) != 1 || rep.SeededRoles[0] != "approver" {
				t.Errorf("seeded=%v, want [approver]", rep.SeededRoles)
			}
		})

		t.Run("資料步驟重跑狀態不變", func(t *testing.T) {
			db := newAuthzSQLite(t)
			seed117(t, db, true)
			if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
				t.Fatal(err)
			}
			first := dumpTables(t, db, "roles", "user_roles", "users", "authz_state")
			if err := applyAuthzModelData(db, planAuthzModelReport); err != nil {
				t.Fatalf("第二次: %v", err)
			}
			if second := dumpTables(t, db, "roles", "user_roles", "users", "authz_state"); second != first {
				t.Errorf("重跑改變了狀態:\nfirst=%s\nsecond=%s", first, second)
			}
		})

		t.Run("軟刪除內建列整筆不套用", func(t *testing.T) {
			db := newAuthzSQLite(t)
			seed117(t, db, true)
			if err := db.Where("name = ?", "auditor").Delete(&model.Role{}).Error; err != nil {
				t.Fatal(err)
			}
			before := dumpTables(t, db, "roles", "user_roles", "authz_state")
			err := applyAuthzModelData(db, planAuthzModelReport)
			if !errors.Is(err, ErrAuthzBuiltinRoleUnusable) {
				t.Fatalf("err = %v, want ErrAuthzBuiltinRoleUnusable", err)
			}
			if !strings.Contains(err.Error(), "auditor") {
				t.Errorf("錯誤訊息未指出角色: %v", err)
			}
			if after := dumpTables(t, db, "roles", "user_roles", "authz_state"); after != before {
				t.Errorf("前置檢查失敗仍改動資料:\nbefore=%s\nafter=%s", before, after)
			}
		})

		t.Run("套用前後報告不同即回滾", func(t *testing.T) {
			db := newAuthzSQLite(t)
			seed117(t, db, true)
			before := dumpTables(t, db, "roles", "user_roles", "authz_state")
			calls := 0
			drift := func(d *gorm.DB) (AuthzMigrationReport, error) {
				rep, err := planAuthzModelReport(d)
				calls++
				if calls == 2 {
					rep.LocalSuperAdmins++
				}
				return rep, err
			}
			err := db.Transaction(func(tx *gorm.DB) error { return applyAuthzModelData(tx, drift) })
			if err == nil || !strings.Contains(err.Error(), "報告不一致") {
				t.Fatalf("err = %v, want 報告不一致", err)
			}
			if after := dumpTables(t, db, "roles", "user_roles", "authz_state"); after != before {
				t.Errorf("回滾後狀態不同:\nbefore=%s\nafter=%s", before, after)
			}
		})

		t.Run("報告決定性且保存可讀", func(t *testing.T) {
			a, b := newAuthzSQLite(t), newAuthzSQLite(t)
			seed117(t, a, true)
			seed117(t, b, true)
			ra, err := planAuthzModelReport(a)
			if err != nil {
				t.Fatal(err)
			}
			rb, _ := planAuthzModelReport(b)
			ja, _ := ra.comparable()
			jb, _ := rb.comparable()
			if ja != jb {
				t.Errorf("相同輸入報告不同:\n%s\n%s", ja, jb)
			}
			if err := applyAuthzModelData(a, planAuthzModelReport); err != nil {
				t.Fatal(err)
			}
			saved, err := ReadAuthzMigrationReport(a)
			if err != nil {
				t.Fatal(err)
			}
			if js, _ := saved.comparable(); js != ja {
				t.Errorf("保存的報告與套用前規劃不同:\n%s\n%s", js, ja)
			}
			var st model.AuthzState
			if err := a.First(&st).Error; err != nil || st.ID != 1 || st.Version != 0 || st.ModelMigratedAt == nil {
				t.Errorf("authz_state = %+v, err=%v", st, err)
			}
		})
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := testgate.Value(t, testgate.EnvPGDSN)

		t.Run("全新庫與第二次為 no-op", func(t *testing.T) {
			db := freshSchema(t, dsn, fmt.Sprintf("authz_model_fresh_%d", time.Now().UnixNano()))
			withGlobalDB(t, db)
			if err := RunMigrations(); err != nil {
				t.Fatalf("RunMigrations: %v", err)
			}
			wantAll := map[string]string{"identity_admin": "identity_admin", "security_admin": "security_admin"} // 角色定義增量種的兩範本
			for k, v := range wantKeys {
				wantAll[k] = v
			}
			if got := builtinKeys(t, db); fmt.Sprint(got) != fmt.Sprint(wantAll) {
				t.Errorf("builtin_key = %v, want %v", got, wantAll)
			}
			first := dumpTables(t, db, "roles", "authz_state", "schema_migrations")
			if err := RunMigrations(); err != nil {
				t.Fatalf("第二次 RunMigrations: %v", err)
			}
			if second := dumpTables(t, db, "roles", "authz_state", "schema_migrations"); second != first {
				t.Errorf("第二次 RunMigrations 改變狀態:\n%s\n%s", first, second)
			}
			rep, err := ReadAuthzMigrationReport(db)
			if err != nil || len(rep.SeededRoles) != 4 {
				t.Errorf("報告 = %+v, err=%v", rep, err)
			}
		})

		t.Run("1.17 形狀升級且兩次演練報告相同", func(t *testing.T) {
			var reports []string
			for i := 0; i < 2; i++ {
				db := newAuthzPrePG(t, fmt.Sprintf("authz_model_117_%d_%d", i, time.Now().UnixNano()))
				withGlobalDB(t, db)
				seed117(t, db, false)
				if err := RunMigrations(); err != nil {
					t.Fatalf("RunMigrations: %v", err)
				}
				if got := builtinKeys(t, db); got["admin"] != "super_admin" || got["ops"] != "" {
					t.Errorf("builtin_key = %v", got)
				}
				rep, err := ReadAuthzMigrationReport(db)
				if err != nil {
					t.Fatal(err)
				}
				js, _ := rep.comparable()
				reports = append(reports, js)
				// 新欄預設值：既有指派一律 global
				var n int64
				db.Model(&model.UserRole{}).Where("scope_kind <> ?", "global").Count(&n)
				if n != 0 {
					t.Errorf("存量指派有 %d 列非 global", n)
				}
			}
			if reports[0] != reports[1] {
				t.Errorf("同輸入兩次演練報告不同:\n%s\n%s", reports[0], reports[1])
			}
		})

		t.Run("軟刪除內建列整筆不套用結構與內容不變", func(t *testing.T) {
			db := newAuthzPrePG(t, fmt.Sprintf("authz_model_softdel_%d", time.Now().UnixNano()))
			withGlobalDB(t, db)
			seed117(t, db, false)
			if err := db.Where("name = ?", "approver").Delete(&model.Role{}).Error; err != nil {
				t.Fatal(err)
			}
			schemaName := currentSchema(t, db)
			objBefore := countSchemaObjects(t, db, schemaName)
			dataBefore := dumpTables(t, db, "roles", "user_roles")
			err := RunMigrations()
			if !errors.Is(err, ErrAuthzBuiltinRoleUnusable) {
				t.Fatalf("err = %v, want ErrAuthzBuiltinRoleUnusable", err)
			}
			if objAfter := countSchemaObjects(t, db, schemaName); objAfter != objBefore {
				t.Errorf("結構改變: %+v → %+v", objBefore, objAfter)
			}
			if dataAfter := dumpTables(t, db, "roles", "user_roles"); dataAfter != dataBefore {
				t.Errorf("內容改變")
			}
			if hasColumn(t, db, schemaName, "roles", "builtin_key") || hasTable(t, db, schemaName, "authz_state") {
				t.Error("失敗後仍留下新欄或新表")
			}
			var n int64
			db.Table("schema_migrations").Where("version = ?", "20261016_authz_permission_model").Count(&n)
			if n != 0 {
				t.Error("失敗後仍記錄了版本")
			}
		})

		t.Run("報告不一致時 DDL 一併回滾", func(t *testing.T) {
			db := newAuthzPrePG(t, fmt.Sprintf("authz_model_drift_%d", time.Now().UnixNano()))
			withGlobalDB(t, db)
			seed117(t, db, false)
			schemaName := currentSchema(t, db)
			objBefore := countSchemaObjects(t, db, schemaName)
			calls := 0
			drift := func(d *gorm.DB) (AuthzMigrationReport, error) {
				rep, err := planAuthzModelReport(d)
				if calls++; calls == 2 {
					rep.DanglingAssignments++
				}
				return rep, err
			}
			err := db.Transaction(func(tx *gorm.DB) error { return applyAuthzPermissionModelWith(tx, drift) })
			if err == nil || !strings.Contains(err.Error(), "報告不一致") {
				t.Fatalf("err = %v", err)
			}
			if objAfter := countSchemaObjects(t, db, schemaName); objAfter != objBefore {
				t.Errorf("回滾後結構不同: %+v → %+v", objBefore, objAfter)
			}
			if hasColumn(t, db, schemaName, "user_roles", "scope_kind") {
				t.Error("回滾後 user_roles.scope_kind 仍存在")
			}
		})
	})
}

// newAuthzPrePG 以真 DDL 建到本 migration 之前，並登記之前的全部版本（1.17 形狀）。
func newAuthzPrePG(t *testing.T, name string) *gorm.DB {
	t.Helper()
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), name)
	target := -1
	for i, m := range migrations {
		if m.Version == "20261016_authz_permission_model" {
			target = i
		}
	}
	if target < 0 {
		t.Fatal("migration 20261016_authz_permission_model 未登記")
	}
	if err := db.Exec(schemaMigrationsBootstrapDDL).Error; err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations[:target] {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
		if err := db.Create(&SchemaMigration{Version: m.Version, AppliedAt: time.Now()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func currentSchema(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var s string
	if err := db.Raw("SELECT current_schema()").Scan(&s).Error; err != nil {
		t.Fatal(err)
	}
	return s
}

func hasColumn(t *testing.T, db *gorm.DB, schema, table, col string) bool {
	t.Helper()
	var n int64
	db.Raw(`SELECT count(*) FROM information_schema.columns WHERE table_schema = ? AND table_name = ? AND column_name = ?`,
		schema, table, col).Scan(&n)
	return n > 0
}

func hasTable(t *testing.T, db *gorm.DB, schema, table string) bool {
	t.Helper()
	var n int64
	db.Raw(`SELECT count(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = ?`, schema, table).Scan(&n)
	return n > 0
}
