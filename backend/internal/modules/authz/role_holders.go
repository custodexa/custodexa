package authz

import (
	"fmt"

	"gorm.io/gorm"
)

// RoleHolder 一位經使用者群組取得某角色的持有者。
type RoleHolder struct {
	RoleID uint
	UserID uint
}

// GroupRoleHolders 經使用者群組取得角色的（角色、使用者）對：群組與帳號都只算未刪除者。
// 與主體解析的群組路徑同一條件（群組未刪、群組帶有該角色、使用者是成員）；唯讀。
func GroupRoleHolders(tx *gorm.DB) ([]RoleHolder, error) {
	var rows []RoleHolder
	err := tx.Raw(`SELECT DISTINCT user_group_roles.role_id AS role_id, user_group_members.user_id AS user_id
 FROM user_group_members
 JOIN user_groups ON user_groups.id = user_group_members.user_group_id AND user_groups.deleted_at IS NULL
 JOIN user_group_roles ON user_group_roles.user_group_id = user_group_members.user_group_id
 JOIN users ON users.id = user_group_members.user_id AND users.deleted_at IS NULL`).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("讀取群組角色持有者失敗: %w", err)
	}
	return rows, nil
}
