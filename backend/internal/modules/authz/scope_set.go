package authz

import (
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 範圍集合述詞：主體 × 權限點 → 集合（不限／空／條件），供列表與計數在分頁之前過濾。
// 集合與單筆判定（decideOn）出自同一份來源（effectiveSources），實存目標上「在集合內 ⇔ Decide 放行」。
// 本檔函式不取鎖、不寫表、不快取；主體一律在呼叫方交易內重解。

// ScopeSetState 範圍集合的狀態；零值不是合法狀態。
type ScopeSetState uint8

const (
	ScopeSetUnlimited   ScopeSetState = iota + 1 // 超管或有全域來源
	ScopeSetEmpty                                // 沒有生效來源
	ScopeSetConditional                          // 只有節點範圍來源
)

// String 狀態名稱（log 與測試用）。
func (s ScopeSetState) String() string {
	switch s {
	case ScopeSetUnlimited:
		return "unlimited"
	case ScopeSetEmpty:
		return "empty"
	case ScopeSetConditional:
		return "conditional"
	}
	return "invalid"
}

// ScopeSet 範圍集合。只能由 authz 建立；根節點不匯出，呼叫方只能經 ApplyScopeSet 套到查詢上。
// 零值 ScopeSet{} 的 State() 為 0，呼叫方當錯誤處理，不得當不限或空。
type ScopeSet struct {
	state  ScopeSetState
	roots  []uint // 只在 Conditional 時有值：各節點範圍來源有效節點的聯集
	reason ScopeReason
}

// State 集合狀態。
func (s ScopeSet) State() ScopeSetState { return s.state }

// Reason 空集合的原因（無生效來源為 no_effective_binding，變體下有能力但無節點範圍來源為 out_of_scope）；
// 其他狀態為空字串。
func (s ScopeSet) Reason() ScopeReason { return s.reason }

// ScopeQueryKind 套用集合的查詢種類（決定以哪個主鍵過濾）。
type ScopeQueryKind string

const (
	ScopeQueryAsset ScopeQueryKind = "asset" // 主鍵 assets.id
	ScopeQueryNode  ScopeQueryKind = "node"  // 主鍵 asset_groups.id
)

var (
	errScopeSetInvalid  = errors.New("authz: invalid scope set")
	errScopeQueryNil    = errors.New("authz: scope set applied to nil query")
	errScopeQueryKind   = errors.New("authz: unknown scope query kind")
	errScopeSetNilPerms = errors.New("authz: scope node counts without permissions")
)

func unlimitedSet() ScopeSet { return ScopeSet{state: ScopeSetUnlimited} }

func emptySet(r ScopeReason) ScopeSet { return ScopeSet{state: ScopeSetEmpty, reason: r} }

// resolveInTx nil 檢查後在 tx 內重解主體（與 Decide 同：只取 UserID 與 Facts）。
func (e *ScopeEvaluator) resolveInTx(tx *gorm.DB, principal *Principal) (*Principal, error) {
	if principal == nil {
		return nil, ErrScopeNilPrincipal
	}
	if tx == nil {
		return nil, errScopeNilTx
	}
	return ResolveUserOnWithCatalogue(tx, e.cat, principal.UserID, principal.Facts)
}

// ScopeSetFor 主體對權限點的一般三態集合：超管或任一全域來源為不限；沒有生效來源為空；
// 只有節點範圍來源為條件（各來源有效節點的子樹）。
func (e *ScopeEvaluator) ScopeSetFor(tx *gorm.DB, principal *Principal, perm Permission) (ScopeSet, error) {
	p, err := e.resolveInTx(tx, principal)
	if err != nil {
		return ScopeSet{}, err
	}
	return scopeSetOn(p, perm, sourcesAll), nil
}

// NodeScopeOnlySetFor 「只取節點範圍指派」變體：忽略全域來源（含超管身分），只回該權限點節點範圍來源的
// 有效子樹（條件）或空。超管與 ViewShortcut 的全量由呼叫方先行分流，不經此變體。
func (e *ScopeEvaluator) NodeScopeOnlySetFor(tx *gorm.DB, principal *Principal, perm Permission) (ScopeSet, error) {
	p, err := e.resolveInTx(tx, principal)
	if err != nil {
		return ScopeSet{}, err
	}
	return scopeSetOn(p, perm, sourcesNodeOnly), nil
}

// scopeSetOn 在已解析的主體上計算集合；順序與 decideOn 相同（超管、能力、全域來源、節點範圍來源）。
func scopeSetOn(p *Principal, perm Permission, filter sourceFilter) ScopeSet {
	if filter == sourcesAll && p.IsSuperAdmin() {
		return unlimitedSet()
	}
	if !p.Has(perm) {
		return emptySet(ScopeReasonNoEffectiveBinding)
	}
	global, nodeSets := effectiveSources(p, perm, filter)
	if global {
		return unlimitedSet()
	}
	seen := map[uint]struct{}{}
	var roots []uint
	for _, set := range nodeSets {
		for _, n := range set {
			if _, ok := seen[n]; !ok {
				seen[n] = struct{}{}
				roots = append(roots, n)
			}
		}
	}
	if len(roots) == 0 { // 變體下只有全域來源：有能力但沒有節點範圍來源
		return emptySet(ScopeReasonOutOfScope)
	}
	return ScopeSet{state: ScopeSetConditional, roots: roots}
}

// ApplyScopeSet 把集合加到查詢上（分頁與計數之前呼叫）：不限回原查詢；空與拓撲未注入的條件加 1 = 0；
// 條件加「主鍵 IN 子樹子查詢」。q 應以 kind 對應的表為主表（assets／asset_groups）。
func (e *ScopeEvaluator) ApplyScopeSet(tx *gorm.DB, q *gorm.DB, set ScopeSet, kind ScopeQueryKind) (*gorm.DB, error) {
	if q == nil {
		return nil, errScopeQueryNil
	}
	if kind != ScopeQueryAsset && kind != ScopeQueryNode {
		return nil, fmt.Errorf("%w: %q", errScopeQueryKind, kind)
	}
	switch set.state {
	case ScopeSetUnlimited:
		return q, nil
	case ScopeSetEmpty:
		return q.Where("1 = 0"), nil
	case ScopeSetConditional:
	default:
		return nil, errScopeSetInvalid
	}
	if e.topo == nil { // 與 decideOn 第 6 步同結論：只經節點範圍來源者範圍拒絕
		return q.Where("1 = 0"), nil
	}
	if tx == nil {
		return nil, errScopeNilTx
	}
	if kind == ScopeQueryAsset {
		return q.Where("assets.id IN (?)", e.topo.SubtreeAssetIDs(tx, set.roots)), nil
	}
	return q.Where("asset_groups.id IN (?)", e.topo.SubtreeNodeIDs(tx, set.roots)), nil
}

// ManagementScopeNodeCounts 管理範圍的節點數：仍存在與已刪除（含已不存在）各自去重後的數量。
type ManagementScopeNodeCounts struct {
	Live, Deleted int
}

// ManagementScopeNodeCountsFor 主體全部含 perms 任一鍵的節點範圍指派（直接與經群組）所綁節點，
// 以節點 ID 去重，回仍存在與已刪除的節點數。哪些指派「含該鍵」與 Has 同一規則（Principal.grant）：
// 以各指派的全部綁定節點（含已刪）代替有效節點重算一次來源，故節點全刪的指派仍被計入已刪數；
// 綁定節點直接讀 role_binding_nodes × asset_groups，不經只回未刪節點的 liveNodesOf。
func (e *ScopeEvaluator) ManagementScopeNodeCountsFor(tx *gorm.DB, principal *Principal, perms []Permission) (ManagementScopeNodeCounts, error) {
	if len(perms) == 0 {
		return ManagementScopeNodeCounts{}, errScopeSetNilPerms
	}
	p, err := e.resolveInTx(tx, principal)
	if err != nil {
		return ManagementScopeNodeCounts{}, err
	}
	live, deleted, err := e.managementScopeNodesOn(tx, p, perms)
	if err != nil {
		return ManagementScopeNodeCounts{}, err
	}
	return ManagementScopeNodeCounts{Live: len(live), Deleted: len(deleted)}, nil
}

// managementScopeNodesOn 計數投影的節點集合（已解析主體）：仍存在與已刪除各自去重；
// 資產頁的管理範圍摘要與計數投影共用本函式。
func (e *ScopeEvaluator) managementScopeNodesOn(tx *gorm.DB, p *Principal, perms []Permission) (map[uint]struct{}, map[uint]struct{}, error) {
	if len(perms) == 0 {
		return nil, nil, errScopeSetNilPerms
	}
	bound := make(map[int][]boundNode)
	withBound := make([]Assignment, len(p.Assignments))
	copy(withBound, p.Assignments)
	for i, a := range p.Assignments {
		if a.Scope != model.ScopeKindNodes {
			continue
		}
		kind, id := model.BindingSubjectUser, p.UserID
		if a.Via == ViaGroup {
			kind, id = model.BindingSubjectUserGroup, a.GroupID
		}
		nodes, err := boundNodesOf(tx, kind, id, a.RoleID)
		if err != nil {
			return nil, nil, err
		}
		bound[i] = nodes
		ids := make([]uint, len(nodes))
		for j, n := range nodes {
			ids[j] = n.NodeID
		}
		withBound[i].LiveNodeIDs = ids
	}
	hp := NewPrincipalOn(e.cat, p.UserID, p.Facts, withBound)
	live, deleted := map[uint]struct{}{}, map[uint]struct{}{}
	for _, perm := range perms {
		_, idx := hp.sourceAssignments(perm)
		for _, i := range idx {
			for _, n := range bound[i] {
				if n.Live == 1 {
					live[n.NodeID] = struct{}{}
				} else {
					deleted[n.NodeID] = struct{}{}
				}
			}
		}
	}
	return live, deleted, nil
}

type boundNode struct {
	NodeID uint
	Live   int
}

// boundNodesOf 指派綁定的全部節點與其存活狀態（節點列已軟刪或不存在皆為非存活）。
func boundNodesOf(db *gorm.DB, subjectKind string, subjectID, roleID uint) ([]boundNode, error) {
	var rows []boundNode
	if err := db.Raw(`SELECT role_binding_nodes.node_id AS node_id,
 CASE WHEN asset_groups.id IS NOT NULL AND asset_groups.deleted_at IS NULL THEN 1 ELSE 0 END AS live
 FROM role_binding_nodes LEFT JOIN asset_groups ON asset_groups.id = role_binding_nodes.node_id
 WHERE role_binding_nodes.subject_kind = ? AND role_binding_nodes.subject_id = ? AND role_binding_nodes.role_id = ?
 ORDER BY role_binding_nodes.node_id`, subjectKind, subjectID, roleID).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("解析指派綁定節點失敗: %w", err)
	}
	return rows, nil
}
