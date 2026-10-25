package identity

import (
	"testing"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// ensureFixtureSuperAdmin 讓夾具裡的操作者持有內建超級管理者身分。
//
// 映射規則與釘住現在經共用指派關卡裁決，操作者必須是可指認且持有指派能力的主體；
// 既有夾具原本只用一個沒有任何角色的帳號當操作者，這裡補上超級管理者身分，
// 不改任何斷言。關卡解析權限所需的表若夾具沒建，順手補齊。
func ensureFixtureSuperAdmin(t testing.TB, db *gorm.DB, userID uint) {
	t.Helper()
	if err := db.AutoMigrate(&model.RolePermission{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatalf("migrate authz tables: %v", err)
	}
	var role model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&role).Error; err != nil {
		role = model.Role{Name: model.RoleAdmin}
		if err := db.Create(&role).Error; err != nil {
			t.Fatalf("seed admin role: %v", err)
		}
	}
	var n int64
	if err := db.Model(&model.UserRole{}).Where("user_id = ? AND role_id = ?", userID, role.ID).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n > 0 {
		return
	}
	if err := db.Create(&model.UserRole{UserID: userID, RoleID: role.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
		t.Fatalf("grant admin: %v", err)
	}
}

// fixtureOperator 建立一個專供寫入映射規則的操作者帳號（持有超級管理者身分）。
// 與被映射、被登入的帳號分開，避免操作者的角色混進以有效角色為斷言對象的案例。
func fixtureOperator(t testing.TB, db *gorm.DB) GroupRoleMappingActor {
	t.Helper()
	u := model.User{Username: "mapping-operator", Password: "x", Active: true}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("seed operator: %v", err)
	}
	ensureFixtureSuperAdmin(t, db, u.ID)
	return GroupRoleMappingActor{ID: u.ID, Name: u.Username}
}
