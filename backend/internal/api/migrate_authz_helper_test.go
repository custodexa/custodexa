package api

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// migrateWithAuthz 先遷移一般 model，再遷移授權相關關聯表（user_roles、user_group_members、
// user_group_roles、role_binding_nodes）。
//
// user_roles／user_group_members 同時被 User／Role／UserGroup 的 many2many 標籤隱式宣告：
// 與這些 model 同批遷移時，關聯表會先以兩欄形態建出，之後缺 scope_kind 等欄位，
// 解析器查詢即以 no such column 失敗。分兩批遷移可確保關聯表以完整 model 為準。
func migrateWithAuthz(db *gorm.DB, models ...interface{}) error {
	var rest, tail []interface{}
	for _, m := range models {
		switch m.(type) {
		case *model.UserRole, *model.UserGroupMember, *model.UserGroupRole, *model.RoleBindingNode:
			tail = append(tail, m)
		default:
			rest = append(rest, m)
		}
	}
	if len(rest) > 0 {
		if err := db.AutoMigrate(rest...); err != nil {
			return err
		}
	}
	if len(tail) > 0 {
		return db.AutoMigrate(tail...)
	}
	return nil
}

// grantLegacyRole 在測試庫為使用者建立一筆全域直接指派（角色列不存在則以保留名稱建立，
// 由 model.Role 的 BeforeCreate 帶入內建識別）。AuthMiddleware 已改為每個請求自資料庫解析
// 主體，不再信任 token 內的 role claim，經真 AuthMiddleware 的測試須先把角色寫進表。
func grantLegacyRole(tb testing.TB, db *gorm.DB, userID uint, roleName string) {
	tb.Helper()
	var role model.Role
	if err := db.Where("name = ?", roleName).First(&role).Error; err != nil {
		role = model.Role{Name: roleName}
		if err := db.Create(&role).Error; err != nil {
			tb.Fatalf("seed role %s: %v", roleName, err)
		}
	}
	if err := db.Create(&model.UserRole{UserID: userID, RoleID: role.ID, Source: model.RoleSourceManual}).Error; err != nil {
		tb.Fatalf("grant role %s to user %d: %v", roleName, userID, err)
	}
}
