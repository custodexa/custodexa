package authz

import (
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
