package authz

import (
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 使用者群組角色指派（資料表由 authz 所有）的讀取面。寫入面隨群組角色指派服務在 identity，
// 經本檔的交易內函式進出，不讓 identity 直接碰這張表。

// UserGroupRoleIDs 群組目前帶的角色編號（升冪）。groupID 為 0 回空集合。
func UserGroupRoleIDs(tx *gorm.DB, groupID uint) ([]uint, error) {
	if groupID == 0 {
		return nil, nil
	}
	var ids []uint
	if err := tx.Model(&model.UserGroupRole{}).Where("user_group_id = ?", groupID).Order("role_id").Pluck("role_id", &ids).Error; err != nil {
		return nil, fmt.Errorf("讀取群組角色指派失敗: %w", err)
	}
	return ids, nil
}

// GroupRoleBinding 群組的一筆角色指派（讀取面）。
type GroupRoleBinding struct {
	RoleID   uint   `json:"role_id"`
	RoleName string `json:"role_name"`
	Scope    string `json:"scope"`
	// NodeIDs 只在節點範圍列出現（照實回傳，含已刪除節點的編號）；全域列沒有此鍵。
	NodeIDs []uint `json:"node_ids,omitempty" gorm:"-"`
}

// UserGroupRoleBindings 群組目前的角色指派（含角色名，依角色編號排序）。
func UserGroupRoleBindings(tx *gorm.DB, groupID uint) ([]GroupRoleBinding, error) {
	var rows []GroupRoleBinding
	if err := tx.Raw(`SELECT g.role_id AS role_id, r.name AS role_name, g.scope_kind AS scope
 FROM user_group_roles g JOIN roles r ON r.id = g.role_id AND r.deleted_at IS NULL
 WHERE g.user_group_id = ? ORDER BY g.role_id`, groupID).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取群組角色指派失敗: %w", err)
	}
	hasNodes := false
	for i := range rows {
		hasNodes = hasNodes || rows[i].Scope == model.ScopeKindNodes
	}
	if !hasNodes {
		return rows, nil
	}
	nodes, err := UserGroupRoleScopes(tx, groupID)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Scope == model.ScopeKindNodes {
			rows[i].NodeIDs = nodes[rows[i].RoleID]
		}
	}
	return rows, nil
}

// ReplaceUserGroupRoleRows 於呼叫端交易內寫入群組角色指派的差量（新增列先以全域建立，範圍另由
// SetUserGroupRoleScope 設定；被移除的指派同時清除其節點範圍列）。
// 版本推進、審計與事件由呼叫端在同一交易內處理。
func ReplaceUserGroupRoleRows(tx *gorm.DB, groupID uint, add, remove []uint) error {
	if len(remove) > 0 {
		var scoped []uint
		if err := tx.Model(&model.UserGroupRole{}).
			Where("user_group_id = ? AND role_id IN ? AND scope_kind = ?", groupID, remove, model.ScopeKindNodes).
			Pluck("role_id", &scoped).Error; err != nil {
			return fmt.Errorf("讀取群組節點範圍角色失敗: %w", err)
		}
		if err := tx.Where("user_group_id = ? AND role_id IN ?", groupID, remove).Delete(&model.UserGroupRole{}).Error; err != nil {
			return fmt.Errorf("移除群組角色指派失敗: %w", err)
		}
		if len(scoped) > 0 {
			if err := ClearBindingNodes(tx, model.BindingSubjectUserGroup, groupID, scoped...); err != nil {
				return err
			}
		}
	}
	for _, id := range add {
		row := model.UserGroupRole{UserGroupID: groupID, RoleID: id, ScopeKind: model.ScopeKindGlobal}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("寫入群組角色指派失敗: %w", err)
		}
	}
	return nil
}

// MembersLosingRoles 群組成員中，因這些角色從本群組移除而**失去**該角色的人：
// 排除經直接指派仍持有、或經其他群組仍持有者。回傳依使用者編號升冪（取鎖順序）。
func MembersLosingRoles(tx *gorm.DB, groupID uint, removed []uint) ([]uint, error) {
	seen := map[uint]bool{}
	for _, roleID := range removed {
		var ids []uint
		if err := tx.Raw(`SELECT m.user_id FROM user_group_members m
 WHERE m.user_group_id = ?
 AND m.user_id NOT IN (SELECT user_id FROM user_roles WHERE role_id = ?)
 AND m.user_id NOT IN (SELECT m2.user_id FROM user_group_members m2
   JOIN user_group_roles g2 ON g2.user_group_id = m2.user_group_id AND g2.role_id = ?
   WHERE m2.user_group_id <> ?)`, groupID, roleID, roleID, groupID).Scan(&ids).Error; err != nil {
			return nil, fmt.Errorf("計算失去角色的成員失敗: %w", err)
		}
		for _, id := range ids {
			seen[id] = true
		}
	}
	out := make([]uint, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
