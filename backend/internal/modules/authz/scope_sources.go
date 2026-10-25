package authz

import "github.com/custodexa/backend/internal/model"

// sourceFilter 生效來源的過濾方式：單筆判定、一般三態與「只取節點範圍指派」變體都經同一個過濾函式。
type sourceFilter uint8

const (
	sourcesAll      sourceFilter = iota + 1 // 全部生效來源（Decide、ScopeSetFor）
	sourcesNodeOnly                         // 只取節點範圍來源，忽略全域來源（NodeScopeOnlySetFor）
)

// scopeSources 權限點的全部生效來源，供單筆判定使用（等於 effectiveSources 的 sourcesAll）。
func (p *Principal) scopeSources(perm Permission) (global bool, nodeSets [][]uint) {
	return effectiveSources(p, perm, sourcesAll)
}

// effectiveSources 權限點的生效來源；來源與 Has 在同一處記錄（Principal.grant），不另算一套。
// global 為真表示至少一個全域來源（全域指派、agent 固定範本、零指派相容），sourcesNodeOnly 時恆為假；
// nodeSets 是每個節點範圍來源（一筆指派）各自的有效節點，不併集。
func effectiveSources(p *Principal, perm Permission, filter sourceFilter) (global bool, nodeSets [][]uint) {
	g, idx := p.sourceAssignments(perm)
	for _, i := range idx {
		nodeSets = append(nodeSets, p.Assignments[i].LiveNodeIDs)
	}
	return g && filter == sourcesAll, nodeSets
}

// sourceAssignments 權限點的生效來源：是否有全域來源，以及節點範圍來源在 Assignments 的索引。
func (p *Principal) sourceAssignments(perm Permission) (global bool, nodeIdx []int) {
	if p == nil {
		return false, nil
	}
	for _, idx := range p.srcs[perm] {
		if idx == implicitGlobalSource {
			global = true
			continue
		}
		if p.Assignments[idx].Scope == model.ScopeKindGlobal {
			global = true
			continue
		}
		nodeIdx = append(nodeIdx, idx)
	}
	return global, nodeIdx
}
