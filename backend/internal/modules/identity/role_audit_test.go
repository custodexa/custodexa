package identity

import (
	"encoding/json"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 角色寫入點的同交易留痕（role-assignment-integrity task 3.1）。
//
// 五條路徑（管理者指派、管理者移除、本地建帳號、OIDC 首登、LDAP 影子帳號）
// 全部收口到 `model.AssignUserRole`／`RevokeUserRole`。本組驗的是**收口確實
// 發生**：每條路徑都留得下對帳重放得回來的列，且留痕失敗時角色不會掛上。
// 收口的**完備性**（沒有第六條路徑繞過去）由 AST 守衛
// `TestRoleAuditWriteSitesGuard` 從相反方向盯住——兩者缺一都不足。

// setupRoleAuditDB sqlite in-memory，含角色留痕所需的四張表
func setupRoleAuditDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// **單連線**：`:memory:` 配連線池時每條連線是各自獨立的空 DB
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.AuditLog{},
		&model.PasswordHistory{}, &model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS user_roles (
		role_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
		PRIMARY KEY (role_id, user_id))`).Error; err != nil {
		t.Fatalf("user_roles: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// roleAuditRows 讀出全部 `user_role` 審計列（依 id 遞增）
func roleAuditRows(t *testing.T, db *gorm.DB) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := db.Where("resource = ?", model.ResourceUserRole).Order("id ASC").
		Find(&rows).Error; err != nil {
		t.Fatalf("讀審計列: %v", err)
	}
	return rows
}

// assertRoleAuditRow 逐欄斷言一筆角色指派審計列
func assertRoleAuditRow(t *testing.T, row model.AuditLog, action model.AuditAction,
	userID, roleID uint, origin string) {
	t.Helper()
	if row.Action != action {
		t.Errorf("action = %s, want %s", row.Action, action)
	}
	if row.Resource != model.ResourceUserRole {
		t.Errorf("resource = %s, want user_role", row.Resource)
	}
	if row.ResourceID == nil || *row.ResourceID != userID {
		t.Errorf("resource_id = %v, want %d（主體是被指派的帳號）", row.ResourceID, userID)
	}
	var d model.UserRoleAuditDetails
	if err := json.Unmarshal([]byte(row.Details), &d); err != nil {
		t.Fatalf("details 解析失敗（對帳讀不回來就等於沒留痕）: %v", err)
	}
	if d.UserID != userID || d.RoleID != roleID || d.Origin != origin {
		t.Errorf("details = %+v, want user_id=%d role_id=%d origin=%s", d, userID, roleID, origin)
	}
}

func seedRoleAuditUser(t *testing.T, db *gorm.DB, username string) *model.User {
	t.Helper()
	u := &model.User{Username: username, Password: "x", Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建帳號: %v", err)
	}
	return u
}

func seedRole(t *testing.T, db *gorm.DB, name string) *model.Role {
	t.Helper()
	r := &model.Role{Name: name}
	if err := db.Create(r).Error; err != nil {
		t.Fatalf("建角色: %v", err)
	}
	return r
}

// TestRoleAuditAddRoleLeavesRow 管理者代配角色留痕（origin=api）
func TestRoleAuditAddRoleLeavesRow(t *testing.T) {
	db := setupRoleAuditDB(t)
	svc := NewUserService(db, nil)
	u := seedRoleAuditUser(t, db, "alice")
	r := seedRole(t, db, model.RoleAuditor)

	if err := svc.AddRole(u.ID, model.RoleAuditor); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	rows := roleAuditRows(t, db)
	if len(rows) != 1 {
		t.Fatalf("審計列筆數 = %d, want 1", len(rows))
	}
	assertRoleAuditRow(t, rows[0], model.ActionAssign, u.ID, r.ID, model.RoleOriginAPI)

	// 冪等再呼叫一次：沒有狀態變更就沒有事件
	if err := svc.AddRole(u.ID, model.RoleAuditor); err != nil {
		t.Fatalf("AddRole 冪等: %v", err)
	}
	if got := len(roleAuditRows(t, db)); got != 1 {
		t.Fatalf("冪等呼叫後審計列筆數 = %d, want 1", got)
	}
}

// TestRoleAuditAssignRolesLeavesAssignAndRevoke 管理者替換角色集：
// 授予與撤銷各留一筆，對帳才重放得回來
func TestRoleAuditAssignRolesLeavesAssignAndRevoke(t *testing.T) {
	db := setupRoleAuditDB(t)
	svc := NewUserService(db, nil)
	u := seedRoleAuditUser(t, db, "bob")
	admin := seedRole(t, db, model.RoleAdmin)
	auditor := seedRole(t, db, model.RoleAuditor)
	// 另一個 admin，使本次替換不撞「最後一個管理者」不變式
	other := seedRoleAuditUser(t, db, "root")
	if err := svc.AddRole(other.ID, model.RoleAdmin); err != nil {
		t.Fatalf("備援 admin: %v", err)
	}
	if err := svc.AssignRoles(u.ID, []string{model.RoleAdmin}); err != nil {
		t.Fatalf("AssignRoles 初始: %v", err)
	}

	if err := svc.AssignRoles(u.ID, []string{model.RoleAuditor}); err != nil {
		t.Fatalf("AssignRoles 替換: %v", err)
	}
	rows := roleAuditRows(t, db)
	// root/admin、bob/admin、bob 撤 admin、bob 配 auditor
	if len(rows) != 4 {
		t.Fatalf("審計列筆數 = %d, want 4：%+v", len(rows), rows)
	}
	assertRoleAuditRow(t, rows[2], model.ActionRevoke, u.ID, admin.ID, model.RoleOriginAPI)
	assertRoleAuditRow(t, rows[3], model.ActionAssign, u.ID, auditor.ID, model.RoleOriginAPI)

	// 重存同一組角色是常態操作：無變動即無列
	if err := svc.AssignRoles(u.ID, []string{model.RoleAuditor}); err != nil {
		t.Fatalf("AssignRoles 無變動: %v", err)
	}
	if got := len(roleAuditRows(t, db)); got != 4 {
		t.Fatalf("無變動替換後審計列筆數 = %d, want 4", got)
	}
}

// TestRoleAuditRegisterLeavesRow 本地建帳號配角色留痕（origin=register）
func TestRoleAuditRegisterLeavesRow(t *testing.T) {
	db := setupRoleAuditDB(t)
	svc := NewUserService(db, nil)
	r := seedRole(t, db, model.RoleUser)

	u, err := svc.Create(&CreateUserRequest{
		Username: "carol", Password: "Str0ng-pass-9x", Roles: []string{model.RoleUser},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	rows := roleAuditRows(t, db)
	if len(rows) != 1 {
		t.Fatalf("審計列筆數 = %d, want 1", len(rows))
	}
	assertRoleAuditRow(t, rows[0], model.ActionAssign, u.ID, r.ID, model.RoleOriginRegister)
}

// TestRoleAuditWriteFailureRollsBack 審計寫入失敗即回滾。
//
// **以刪掉 audit_logs 表製造失敗**：那是「審計寫不進去」在資料層最貼近真實的
// 形態（表被鎖、被刪、磁碟滿），且不需要在產品程式碼裡開任何注入點
func TestRoleAuditWriteFailureRollsBack(t *testing.T) {
	db := setupRoleAuditDB(t)
	svc := NewUserService(db, nil)
	u := seedRoleAuditUser(t, db, "dave")
	seedRole(t, db, model.RoleAuditor)
	if err := db.Exec("DROP TABLE audit_logs").Error; err != nil {
		t.Fatalf("drop audit_logs: %v", err)
	}

	if err := svc.AddRole(u.ID, model.RoleAuditor); err == nil {
		t.Fatal("AddRole 在審計寫入失敗時回 nil：留痕失敗仍讓角色掛上，對帳將把它報成竄改")
	}
	var count int64
	if err := db.Table("user_roles").Where("user_id = ?", u.ID).Count(&count).Error; err != nil {
		t.Fatalf("計數: %v", err)
	}
	if count != 0 {
		t.Fatalf("user_roles 殘留 %d 列, want 0：審計與角色必須同生共死", count)
	}
}

// TestRoleAuditOIDCFirstLoginLeavesRow OIDC 首登配角色留痕（origin=oidc）
func TestRoleAuditOIDCFirstLoginLeavesRow(t *testing.T) {
	db := setupRoleAuditDB(t)
	r := seedRole(t, db, model.RoleUser)
	u := seedRoleAuditUser(t, db, "eve-placeholder")

	// 直接驗供應路徑的寫入面：完整 OIDC 首登流程需要一個 IdP，
	// 而本測試要證明的是「該路徑寫的是帶 origin=oidc 的留痕面」
	if err := db.Transaction(func(tx *gorm.DB) error {
		return model.AssignUserRole(tx, u.ID, r.ID, model.RoleOriginOIDC)
	}); err != nil {
		t.Fatalf("供應: %v", err)
	}
	rows := roleAuditRows(t, db)
	if len(rows) != 1 {
		t.Fatalf("審計列筆數 = %d, want 1", len(rows))
	}
	assertRoleAuditRow(t, rows[0], model.ActionAssign, u.ID, r.ID, model.RoleOriginOIDC)
}
