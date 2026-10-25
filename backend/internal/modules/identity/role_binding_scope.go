package identity

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 角色指派的節點範圍寫入（整組替換入口）。
//
// 範圍語義：role_nodes 的鍵不存在即保留現有範圍（新增的角色為全域）；null 改為全域；
// 非空陣列改為該節點集合。同一角色來源兼具管理者與映射（both）時，替換入口對它帶的 role_nodes
// 照常作用於該列；只由映射持有的角色帶 role_nodes 一律忽略。

// NodeRangeNoEffect 寫入後以節點範圍持有、而範圍不會產生能力的一個角色。
// Role 與該入口 role_nodes 的鍵同形（使用者入口為角色名，群組入口為角色編號的十進位字串）。
type NodeRangeNoEffect struct {
	Role   string `json:"role"`
	Reason string `json:"reason"`
}

// applyUserRoleScopes 把管理者指派集內各角色的範圍寫成請求要求的樣子。
// added 為本次新建的角色（其餘為保留）；before 為寫入前全部節點範圍列。
// 保留的角色範圍有變時：同交易留一筆只改範圍的審計、推進權限版本一次（新建的角色已在建立時推進）；
// 回傳 narrowed 表示有角色的範圍縮小到使本人失去原本涵蓋的節點（呼叫端據此推進憑證世代）。
func (s *UserService) applyUserRoleScopes(tx *gorm.DB, userID uint, target []model.Role, added []uint,
	before map[uint][]uint, req map[string]RoleNodesValue) (narrowed bool, err error) {
	isAdded := map[uint]bool{}
	for _, id := range added {
		isAdded[id] = true
	}
	changed := false
	for _, r := range target {
		cur, curNodes := before[r.ID], len(before[r.ID]) > 0
		wantNodes, want := curNodes, cur
		if isAdded[r.ID] {
			wantNodes, want = false, nil
		}
		if v, has := req[r.Name]; has {
			wantNodes, want = !v.Global, v.NodeIDs
		}
		if wantNodes == curNodes && (!wantNodes || authz.SameNodeSet(want, cur)) {
			continue
		}
		kind := model.ScopeKindGlobal
		if wantNodes {
			kind = model.ScopeKindNodes
		} else {
			want = nil
		}
		if err := model.SetUserRoleScope(tx, userID, r.ID, kind); err != nil {
			return false, err
		}
		if err := authz.ReplaceBindingNodes(tx, model.BindingSubjectUser, userID, r.ID, want); err != nil {
			return false, err
		}
		if isAdded[r.ID] {
			continue
		}
		changed = true
		if err := model.RecordUserRoleRangeChange(tx, userID, r.ID, model.RoleOriginAPI, cur, want); err != nil {
			return false, err
		}
		others, err := authz.UserOtherRoleRanges(tx, userID, r.ID, 0, false)
		if err != nil {
			return false, err
		}
		shrunk, err := s.assignmentGuard().rangeNarrowed(tx,
			authz.RoleRange{Global: !curNodes, NodeIDs: cur}, authz.RoleRange{Global: !wantNodes, NodeIDs: want}, others)
		if err != nil {
			return false, err
		}
		narrowed = narrowed || shrunk
	}
	if changed {
		return narrowed, authz.AdvanceVersion(tx)
	}
	return false, nil
}

// rangeNarrowed 一筆指派的範圍由 old 改為 now 之後，本人是否失去了原本涵蓋的節點：
// 以 now 與本人其餘指派（others）合起來的涵蓋，檢查 old 涵蓋的每個未刪除節點是否仍被涵蓋。
// 任一全域範圍即不縮小；old 為全域而其餘都是節點範圍即縮小。已刪除的節點不計。
func (g *AssignmentGuard) rangeNarrowed(tx *gorm.DB, old, now authz.RoleRange, others []authz.RoleRange) (bool, error) {
	keep := append(append([]authz.RoleRange{}, others...), now)
	kept := map[uint]bool{}
	for _, k := range keep {
		if k.Global {
			return false, nil
		}
		for _, n := range k.NodeIDs {
			kept[n] = true
		}
	}
	if old.Global {
		return true, nil
	}
	for _, b := range old.NodeIDs {
		cover, exists, err := g.nodeCover(tx, b)
		if err != nil {
			return false, fmt.Errorf("查詢節點涵蓋失敗: %w", err)
		}
		if !exists {
			continue
		}
		covered := false
		for _, c := range cover {
			if kept[c] {
				covered = true
				break
			}
		}
		if !covered {
			return true, nil
		}
	}
	return false, nil
}

// userNodeRangeNoEffect 對象目前以節點範圍持有、而範圍不生效的全部角色（依角色名排序）。
func userNodeRangeNoEffect(tx *gorm.DB, userID uint) ([]NodeRangeNoEffect, error) {
	var roles []model.Role
	if err := tx.Joins("JOIN user_roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ? AND user_roles.scope_kind = ?", userID, model.ScopeKindNodes).
		Order("roles.name").Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("讀取節點範圍角色失敗: %w", err)
	}
	return noEffectOf(tx, roles, func(r model.Role) string { return r.Name })
}

// groupNodeRangeNoEffect 群組目前以節點範圍持有、而範圍不生效的全部角色（依角色編號排序）。
func groupNodeRangeNoEffect(tx *gorm.DB, groupID uint) ([]NodeRangeNoEffect, error) {
	ids, err := authz.UserGroupNodeScopedRoleIDs(tx, groupID)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	var roles []model.Role
	if err := tx.Where("id IN ?", ids).Order("id").Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("讀取節點範圍角色失敗: %w", err)
	}
	return noEffectOf(tx, roles, func(r model.Role) string { return fmt.Sprintf("%d", r.ID) })
}

func noEffectOf(tx *gorm.DB, roles []model.Role, key func(model.Role) string) ([]NodeRangeNoEffect, error) {
	var out []NodeRangeNoEffect
	for _, r := range roles {
		class, reason, err := RoleNodeScopability(tx, r)
		if err != nil {
			return nil, err
		}
		// 已存在的節點指派之後角色被改成不能限定：該指派對新權限點同樣不生效，也一併如實列出
		if class == authz.NodeScopabilityNoEffect {
			out = append(out, NodeRangeNoEffect{Role: key(r), Reason: string(reason)})
		}
	}
	return out, nil
}

// resetNodeScopeOnDemotion 來源由並存降為僅映射時，管理者那份的節點範圍隨之失效：
// 同交易改回全域並清節點列（映射不帶範圍），並留一筆範圍變更審計。屬擴大，版本由呼叫端推進，不推進憑證世代。
func resetNodeScopeOnDemotion(tx *gorm.DB, userID, roleID uint) error {
	var kinds []string
	if err := tx.Table("user_roles").Where("user_id = ? AND role_id = ?", userID, roleID).
		Pluck("scope_kind", &kinds).Error; err != nil {
		return fmt.Errorf("讀取角色指派範圍失敗: %w", err)
	}
	if len(kinds) == 0 || kinds[0] != model.ScopeKindNodes {
		return nil
	}
	prior, err := authz.BindingNodeIDs(tx, model.BindingSubjectUser, userID, roleID)
	if err != nil {
		return err
	}
	if err := model.SetUserRoleScope(tx, userID, roleID, model.ScopeKindGlobal); err != nil {
		return err
	}
	if err := authz.ClearBindingNodes(tx, model.BindingSubjectUser, userID, roleID); err != nil {
		return err
	}
	return model.RecordUserRoleRangeChange(tx, userID, roleID, model.RoleOriginAPI, prior, nil)
}

// userRoleIsNodeScoped 一筆直接指派是否為節點範圍（只讀 user_roles）。
func userRoleIsNodeScoped(tx *gorm.DB, userID, roleID uint) (bool, error) {
	var kinds []string
	if err := tx.Table("user_roles").Where("user_id = ? AND role_id = ?", userID, roleID).
		Pluck("scope_kind", &kinds).Error; err != nil {
		return false, fmt.Errorf("讀取角色指派範圍失敗: %w", err)
	}
	return len(kinds) > 0 && kinds[0] == model.ScopeKindNodes, nil
}
