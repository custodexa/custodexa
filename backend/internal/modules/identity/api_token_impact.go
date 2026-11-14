package identity

import (
	"fmt"
	"sort"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 角色指派預覽中的 API token 影響摘要：以變更前後的「有效角色聯集」計算，含經群組與映射取得的來源；
// 不以提交的直接角色清單差異計算。被收回的角色另有群組或映射來源時，該角色變更後仍有效，token 不算受影響；
// 加回的角色原本就經群組或映射有效時，同樣不算恢復。token 的有效角色是授權角色與帳號當下有效角色的交集，
// 所以帳號重新取得 token 被授權過的角色時，該 token 立即恢復這個角色，預覽要把它列出。

// APITokenImpactEntry 一把受影響的 token。
type APITokenImpactEntry struct {
	ID         uint              `json:"id"`
	Name       string            `json:"name"`
	LosesRoles []APITokenRoleRef `json:"loses_roles"`
	// RegainsRoles 變更後重新生效的授權角色（變更前不生效、變更後生效）
	RegainsRoles []APITokenRoleRef `json:"regains_roles"`
	// RemainingRoles 變更後仍生效的授權角色全集（含重新生效的）
	RemainingRoles   []APITokenRoleRef `json:"remaining_roles"`
	BecomesSuspended bool              `json:"becomes_suspended"`
	// BecomesActive 變更前因授權角色全部不生效而暫停、變更後恢復可用
	BecomesActive bool `json:"becomes_active"`
}

// APITokenImpact 帳號的 token 在這次變更後的影響。
type APITokenImpact struct {
	// TotalUsable 尚可使用的 token 數（未撤銷、未到期、未因還原失效；暫停中的也算）
	TotalUsable int                   `json:"total_usable"`
	Affected    []APITokenImpactEntry `json:"affected"`
	// SuspendedCount 這次變更使其暫停的 token 數（affected 中 becomes_suspended 為真者；變更前就已暫停的不計）
	SuspendedCount int `json:"suspended_count"`
	// EligibleAfter 變更後帳號是否仍有建立資格（至少一個有效的管理類角色）
	EligibleAfter bool `json:"eligible_after"`
}

// ImpactOfDirectRoles 以「管理者指派集替換為 newManualRoleIDs」預估帳號 token 的影響（唯讀）。
// 變更後的有效角色＝經群組取得的角色 ∪ 經映射取得的直接角色 ∪ 新的管理者指派集（已刪除的角色不列入）。
func (s *APITokenService) ImpactOfDirectRoles(userID uint, newManualRoleIDs []uint) (*APITokenImpact, error) {
	sum, err := authz.SummarizeGrants(s.db, userID)
	if err != nil {
		return nil, err
	}
	var rows []model.UserRole
	if err := s.db.Where("user_id = ?", userID).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取角色指派失敗: %w", err)
	}
	keepsDirect := map[uint]bool{}
	for _, r := range rows {
		if r.Source == model.RoleSourceMapped || r.Source == model.RoleSourceBoth {
			keepsDirect[r.RoleID] = true
		}
	}
	before, after := map[uint]bool{}, map[uint]bool{}
	for _, e := range sum.Entries {
		if !(e.Scope == model.ScopeKindGlobal || (e.Scope == model.ScopeKindNodes && len(e.Nodes) > 0)) {
			continue
		}
		before[e.RoleID] = true
		if e.Via == authz.ViaGroup || keepsDirect[e.RoleID] {
			after[e.RoleID] = true
		}
	}
	management, err := authz.ManagementRoles(s.db, append(uniqueRoleIDs(newManualRoleIDs), keysOf(before)...))
	if err != nil {
		return nil, err
	}
	for _, id := range uniqueRoleIDs(newManualRoleIDs) {
		if _, exists := management[id]; exists {
			after[id] = true
		}
	}
	out := &APITokenImpact{Affected: []APITokenImpactEntry{}}
	for id := range after {
		if management[id] {
			out.EligibleAfter = true
		}
	}
	tokens, err := s.ListForUser(userID)
	if err != nil {
		return nil, err
	}
	for _, t := range tokens {
		switch t.Status {
		case APITokenStatusRevoked, APITokenStatusExpired, APITokenStatusInvalidatedByRestore:
			continue
		}
		out.TotalUsable++
		entry := APITokenImpactEntry{ID: t.ID, Name: t.Name, LosesRoles: []APITokenRoleRef{}, RegainsRoles: []APITokenRoleRef{},
			RemainingRoles: []APITokenRoleRef{}}
		effectiveBefore := 0
		for _, g := range t.GrantedRoles {
			if before[g.RoleID] {
				effectiveBefore++
			}
			switch {
			case after[g.RoleID]:
				entry.RemainingRoles = append(entry.RemainingRoles, g.APITokenRoleRef)
				if !before[g.RoleID] {
					entry.RegainsRoles = append(entry.RegainsRoles, g.APITokenRoleRef)
				}
			case before[g.RoleID]:
				entry.LosesRoles = append(entry.LosesRoles, g.APITokenRoleRef)
			}
		}
		if len(entry.LosesRoles) == 0 && len(entry.RegainsRoles) == 0 {
			continue
		}
		entry.BecomesSuspended = effectiveBefore > 0 && len(entry.RemainingRoles) == 0
		// 帳號停用而暫停的 token 不因角色恢復而可用
		entry.BecomesActive = effectiveBefore == 0 && len(entry.RemainingRoles) > 0 &&
			t.Status != APITokenStatusSuspendedAccountDisabled
		if entry.BecomesSuspended {
			out.SuspendedCount++
		}
		out.Affected = append(out.Affected, entry)
	}
	return out, nil
}

func keysOf(m map[uint]bool) []uint {
	out := make([]uint, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
