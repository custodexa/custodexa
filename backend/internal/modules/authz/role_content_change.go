package authz

import (
	"errors"
	"fmt"
	"sort"

	"gorm.io/gorm"

)

// 角色內容修改的授權變更分類。
//
// 指派不變而角色的權限集合改變時，指派鍵比較（ClassifyGrantChange）看不到差異，
// 所以角色內容另以權限集合差判定：新增鍵視為增加、移除鍵視為減少，只改名稱或說明不產生任何標記。
// 寫入與預覽的 role_definition 種類都呼叫同一組函式。

// RoleContentChange 一次角色權限集合修改的集合差。
type RoleContentChange struct {
	// Added／Removed 修改後新增與移除的權限鍵（升冪、去重）。
	Added, Removed []Permission
	// ManagementAdded 新增鍵中屬管理類者（與授權變更分類器的管理類判定同一組）。
	ManagementAdded []Permission
}

// Empty 沒有任何集合差。
func (c RoleContentChange) Empty() bool { return len(c.Added) == 0 && len(c.Removed) == 0 }

// ClassifyRoleContentChange 比對修改前後的權限集合。
func ClassifyRoleContentChange(before, after []Permission) RoleContentChange {
	b, a := make(map[Permission]bool, len(before)), make(map[Permission]bool, len(after))
	for _, k := range before {
		b[k] = true
	}
	for _, k := range after {
		a[k] = true
	}
	var out RoleContentChange
	for k := range a {
		if b[k] {
			continue
		}
		out.Added = append(out.Added, k)
		if permissionIsManagement(k) {
			out.ManagementAdded = append(out.ManagementAdded, k)
		}
	}
	for k := range b {
		if !a[k] {
			out.Removed = append(out.Removed, k)
		}
	}
	for _, s := range [][]Permission{out.Added, out.Removed, out.ManagementAdded} {
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	}
	return out
}

func permissionIsManagement(k Permission) bool {
	def, ok := LookupPermission(k)
	return ok && def.Category == CategoryManage && isManagementGroup(def.Group)
}

// RoleContentImpact 角色此刻的持有與引用事實（交易內現值）。
type RoleContentImpact struct {
	// HolderIDs 持有者：未刪除帳號中，直接、使用者群組、映射任一來源取得該角色者，同一帳號一次；升冪。
	HolderIDs []uint
	// GroupBindings 被使用者群組指派的列數。
	GroupBindings int64
	// MappingRules 指向該角色的未刪除映射規則數（含已停用）。
	MappingRules int64
}

// Referenced 有任何持有者或引用。
func (i RoleContentImpact) Referenced() bool {
	return len(i.HolderIDs) > 0 || i.GroupBindings > 0 || i.MappingRules > 0
}

// RoleMappingRuleCounter 指向某角色的未刪除映射規則數（含已停用）。映射規則屬身分模組的資料，
// 由組裝端注入；缺少時回錯而不當成零（缺了就會漏報管理類發放）。
type RoleMappingRuleCounter func(tx *gorm.DB, roleID uint) (int64, error)

// ErrRoleMappingCounterMissing 未注入映射規則計數。
var ErrRoleMappingCounterMissing = errors.New("角色映射規則計數未注入")

// LoadRoleContentImpact 讀取角色的持有者與引用。唯讀。
func LoadRoleContentImpact(tx *gorm.DB, roleID uint, mappingRules RoleMappingRuleCounter) (RoleContentImpact, error) {
	if mappingRules == nil {
		return RoleContentImpact{}, ErrRoleMappingCounterMissing
	}
	var ids []uint
	if err := tx.Raw(`SELECT user_roles.user_id FROM user_roles
 JOIN users ON users.id = user_roles.user_id AND users.deleted_at IS NULL
 WHERE user_roles.role_id = ?
 UNION
 SELECT m.user_id FROM user_group_members m
 JOIN user_groups g ON g.id = m.user_group_id AND g.deleted_at IS NULL
 JOIN user_group_roles r ON r.user_group_id = m.user_group_id
 JOIN users ON users.id = m.user_id AND users.deleted_at IS NULL
 WHERE r.role_id = ?`, roleID, roleID).Scan(&ids).Error; err != nil {
		return RoleContentImpact{}, fmt.Errorf("讀取角色持有者失敗: %w", err)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := RoleContentImpact{HolderIDs: ids}
	n, err := CountUserGroupRoleBindings(tx, roleID)
	if err != nil {
		return RoleContentImpact{}, err
	}
	out.GroupBindings = n
	m, err := mappingRules(tx, roleID)
	if err != nil {
		return RoleContentImpact{}, err
	}
	out.MappingRules = m
	return out, nil
}

// RoleContentOperation 一次角色內容修改將觸發的告警分類（寫入與預覽共用）。
type RoleContentOperation struct {
	// SelfDirection 操作者本人是持有者時的方向；有新增鍵（含有增有減）為增加，只有移除鍵為減少。
	SelfDirection GrantDirection
	// ManagementGranted 新增鍵含管理類，且有操作者以外的持有者、或群組指派、或映射規則引用該角色。
	ManagementGranted bool
	// Marks 審計標記，值域 GrantMarkSelfAuthorization／GrantMarkManagementGrant。
	Marks []string
}

// ClassifyRoleContentOperation 由集合差與持有／引用事實求出整筆修改的分類。
func ClassifyRoleContentOperation(change RoleContentChange, impact RoleContentImpact, operatorID uint) RoleContentOperation {
	var op RoleContentOperation
	others := 0
	self := false
	for _, id := range impact.HolderIDs {
		if id == operatorID && operatorID != 0 {
			self = true
		} else {
			others++
		}
	}
	if self {
		switch {
		case len(change.Added) > 0:
			op.SelfDirection = GrantIncrease
		case len(change.Removed) > 0:
			op.SelfDirection = GrantDecrease
		}
	}
	if op.SelfDirection != GrantNone {
		op.Marks = append(op.Marks, GrantMarkSelfAuthorization)
	}
	if len(change.ManagementAdded) > 0 && (others > 0 || impact.GroupBindings > 0 || impact.MappingRules > 0) {
		op.ManagementGranted = true
		op.Marks = append(op.Marks, GrantMarkManagementGrant)
	}
	return op
}
