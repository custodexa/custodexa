package authz

import (
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 節點範圍列（role_binding_nodes）的交易內讀寫面。資料表由 authz 擁有，identity 協調交易、
// 經本檔的函式進出，不直寫。呼叫端 SHALL 在取得拓撲序列化鎖之後呼叫寫入函式。

// BindingNodeIDs 一筆指派目前的節點集合（升冪）。
func BindingNodeIDs(tx *gorm.DB, subjectKind string, subjectID, roleID uint) ([]uint, error) {
	var ids []uint
	if err := tx.Model(&model.RoleBindingNode{}).
		Where("subject_kind = ? AND subject_id = ? AND role_id = ?", subjectKind, subjectID, roleID).
		Order("node_id").Pluck("node_id", &ids).Error; err != nil {
		return nil, fmt.Errorf("讀取節點範圍失敗: %w", err)
	}
	return ids, nil
}

// SubjectBindingNodes 一個主體全部指派的節點集合（角色編號 → 升冪節點集合）。
func SubjectBindingNodes(tx *gorm.DB, subjectKind string, subjectID uint) (map[uint][]uint, error) {
	var rows []model.RoleBindingNode
	if err := tx.Where("subject_kind = ? AND subject_id = ?", subjectKind, subjectID).
		Order("role_id, node_id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取節點範圍失敗: %w", err)
	}
	out := map[uint][]uint{}
	for _, r := range rows {
		out[r.RoleID] = append(out[r.RoleID], r.NodeID)
	}
	return out, nil
}

// UserBindingNodeSets 全部使用者直接指派的節點集合（鍵為 [使用者編號, 角色編號]，節點升冪）。
// 供角色指派對帳的現況快照使用；只讀。
func UserBindingNodeSets(tx *gorm.DB) (map[[2]uint][]uint, error) {
	var rows []model.RoleBindingNode
	if err := tx.Where("subject_kind = ?", model.BindingSubjectUser).
		Order("subject_id, role_id, node_id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取節點範圍失敗: %w", err)
	}
	out := map[[2]uint][]uint{}
	for _, r := range rows {
		k := [2]uint{r.SubjectID, r.RoleID}
		out[k] = append(out[k], r.NodeID)
	}
	return out, nil
}

// SubjectHasBindingNodes 主體是否有任何節點範圍列。
func SubjectHasBindingNodes(tx *gorm.DB, subjectKind string, subjectID uint) (bool, error) {
	var n int64
	if err := tx.Model(&model.RoleBindingNode{}).
		Where("subject_kind = ? AND subject_id = ?", subjectKind, subjectID).Count(&n).Error; err != nil {
		return false, fmt.Errorf("讀取節點範圍失敗: %w", err)
	}
	return n > 0, nil
}

// ReplaceBindingNodes 把一筆指派的節點集合換成 nodeIDs（去重）；空集合即清空。
func ReplaceBindingNodes(tx *gorm.DB, subjectKind string, subjectID, roleID uint, nodeIDs []uint) error {
	if err := tx.Where("subject_kind = ? AND subject_id = ? AND role_id = ?", subjectKind, subjectID, roleID).
		Delete(&model.RoleBindingNode{}).Error; err != nil {
		return fmt.Errorf("清除節點範圍失敗: %w", err)
	}
	seen := map[uint]bool{}
	for _, id := range nodeIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		row := model.RoleBindingNode{SubjectKind: subjectKind, SubjectID: subjectID, RoleID: roleID, NodeID: id}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("寫入節點範圍失敗: %w", err)
		}
	}
	return nil
}

// ClearBindingNodes 清除主體指定角色的節點範圍列；roleIDs 為空則清除該主體全部。
func ClearBindingNodes(tx *gorm.DB, subjectKind string, subjectID uint, roleIDs ...uint) error {
	q := tx.Where("subject_kind = ? AND subject_id = ?", subjectKind, subjectID)
	if len(roleIDs) > 0 {
		q = q.Where("role_id IN ?", roleIDs)
	}
	if err := q.Delete(&model.RoleBindingNode{}).Error; err != nil {
		return fmt.Errorf("清除節點範圍失敗: %w", err)
	}
	return nil
}

// SetUserGroupRoleScope 設定群組一筆既有指派的範圍種類，並依 nodeIDs 同步節點範圍列：
// nodeIDs 為 nil 即全域（清列），否則為節點範圍。
func SetUserGroupRoleScope(tx *gorm.DB, groupID, roleID uint, nodeIDs []uint) error {
	kind := model.ScopeKindGlobal
	if nodeIDs != nil {
		kind = model.ScopeKindNodes
	}
	if err := tx.Model(&model.UserGroupRole{}).Where("user_group_id = ? AND role_id = ?", groupID, roleID).
		Update("scope_kind", kind).Error; err != nil {
		return fmt.Errorf("更新群組指派範圍失敗: %w", err)
	}
	return ReplaceBindingNodes(tx, model.BindingSubjectUserGroup, groupID, roleID, nodeIDs)
}

// UserGroupRoleScopes 群組目前全部指派的節點集合（角色編號 → 節點集合；全域指派不在表中）。
func UserGroupRoleScopes(tx *gorm.DB, groupID uint) (map[uint][]uint, error) {
	return SubjectBindingNodes(tx, model.BindingSubjectUserGroup, groupID)
}

// SameNodeSet 兩個節點集合是否相同（不計順序與重複）。
func SameNodeSet(a, b []uint) bool {
	na, nb := normalizeNodes(a), normalizeNodes(b)
	if len(na) != len(nb) {
		return false
	}
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}

func normalizeNodes(in []uint) []uint {
	seen := map[uint]bool{}
	out := make([]uint, 0, len(in))
	for _, id := range in {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// UserGroupNodeScopedRoleIDs 群組以節點範圍持有的角色編號（升冪）。只讀 user_group_roles，
// 不碰節點範圍列表，使沒有節點範圍的存量資料路徑不多出一次讀取。
func UserGroupNodeScopedRoleIDs(tx *gorm.DB, groupID uint) ([]uint, error) {
	var ids []uint
	if err := tx.Model(&model.UserGroupRole{}).
		Where("user_group_id = ? AND scope_kind = ?", groupID, model.ScopeKindNodes).
		Order("role_id").Pluck("role_id", &ids).Error; err != nil {
		return nil, fmt.Errorf("讀取群組節點範圍角色失敗: %w", err)
	}
	return ids, nil
}

// RoleRange 一筆指派的範圍：Global 為全系統，否則為 NodeIDs 節點集合。
type RoleRange struct {
	Global  bool
	NodeIDs []uint
}

// UserOtherRoleRanges 使用者在一個角色上，除了被排除的那一筆以外的全部指派範圍：
// 經成員關係取得的群組指派（exceptGroupID 為 0 時不排除任何群組），以及 includeDirect 時的直接指派。
// 供範圍縮小時判斷其他指派是否補回涵蓋。
func UserOtherRoleRanges(tx *gorm.DB, userID, roleID, exceptGroupID uint, includeDirect bool) ([]RoleRange, error) {
	var out []RoleRange
	if includeDirect {
		var kinds []string
		if err := tx.Table("user_roles").Where("user_id = ? AND role_id = ?", userID, roleID).
			Pluck("scope_kind", &kinds).Error; err != nil {
			return nil, fmt.Errorf("讀取角色指派範圍失敗: %w", err)
		}
		for _, k := range kinds {
			if k != model.ScopeKindNodes {
				out = append(out, RoleRange{Global: true})
				continue
			}
			ids, err := BindingNodeIDs(tx, model.BindingSubjectUser, userID, roleID)
			if err != nil {
				return nil, err
			}
			out = append(out, RoleRange{NodeIDs: ids})
		}
	}
	var rows []model.UserGroupRole
	if err := tx.Joins("JOIN user_group_members ON user_group_members.user_group_id = user_group_roles.user_group_id").
		Where("user_group_members.user_id = ? AND user_group_roles.role_id = ? AND user_group_roles.user_group_id <> ?",
			userID, roleID, exceptGroupID).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取群組角色指派範圍失敗: %w", err)
	}
	for _, g := range rows {
		if g.ScopeKind != model.ScopeKindNodes {
			out = append(out, RoleRange{Global: true})
			continue
		}
		ids, err := BindingNodeIDs(tx, model.BindingSubjectUserGroup, g.UserGroupID, roleID)
		if err != nil {
			return nil, err
		}
		out = append(out, RoleRange{NodeIDs: ids})
	}
	return out, nil
}
