package authz

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// ManagementRoles 角色是否屬管理類（以全域範圍的指派判定，與建立資格同一判準）。不存在或已刪除的角色不列入結果。
func ManagementRoles(tx *gorm.DB, roleIDs []uint) (map[uint]bool, error) {
	out := map[uint]bool{}
	if len(roleIDs) == 0 {
		return out, nil
	}
	var rows []assignmentRow
	if err := tx.Raw(`SELECT roles.id AS role_id, roles.name AS role_name, roles.builtin_key AS builtin_key, roles.definition_version AS def_version
 FROM roles WHERE roles.id IN ? AND roles.deleted_at IS NULL ORDER BY roles.id`, roleIDs).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取角色失敗: %w", err)
	}
	custom, err := customPermissionsOf(tx, ProductCatalogue(), rows)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		a := Assignment{RoleID: r.RoleID, RoleName: r.RoleName, Via: ViaDirect, Scope: model.ScopeKindGlobal}
		if r.BuiltinKey != nil {
			a.BuiltinKey = *r.BuiltinKey
		} else if r.DefVersion >= 1 {
			a.Custom, a.Permissions = true, custom[r.RoleID]
		}
		out[r.RoleID] = assignmentIsManagement(a)
	}
	return out, nil
}
