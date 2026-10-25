package authz

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
)

// 節點寫入（建立、改名、改描述、搬移、刪除）的交易內範圍判定，實作 asset 的消費者側窄介面。
//
// 呼叫方先在同一交易取拓撲序列化鎖，再呼叫本檔方法；主體在交易內重解（傳入主體的指派一律忽略）。
// 只看含節點管理權限點的指派：每筆指派的有效範圍節點各自成一組，不以其他指派的範圍放行。
//
//   - 建立：父節點在某組範圍內（含範圍節點本身）；根層只限超級管理者與全域持有者。
//   - 改名、改描述、刪除：目標是某組範圍節點的嚴格子孫；目標只因自身是範圍節點而在範圍內時限超級管理者。
//   - 搬移：來源同上，目的父節點在某組範圍內；搬到根層只限超級管理者與全域持有者；
//     被搬移子樹含任何指派的範圍節點時只限超級管理者（全域持有者亦拒）。
//
// 範圍外、已刪除與不存在一律回同一個範圍拒絕值（由共用出口寫成與不存在相同的回應）；
// 範圍內但限超級管理者回 ErrNodeWriteSuperAdminOnly；根層動作回 ErrNodeWriteRootLevelGlobalOnly。

var (
	// ErrNodeWriteSuperAdminOnly 目標在範圍內，但這個動作只限超級管理者（或根層動作只限超級管理者與全域持有者）。
	ErrNodeWriteSuperAdminOnly = errors.New("authz: node write reserved for super admin")
	// ErrNodeWriteRootLevelGlobalOnly 根層建立與搬到根層：只限超級管理者與全域持有節點管理權限點者。
	// 審計依據記為缺少全域的節點管理權限點（與自身範圍根、含範圍節點子樹的限超級管理者分開）。
	ErrNodeWriteRootLevelGlobalOnly = errors.New("authz: root-level node write requires global node management")
	// ErrNodeWriteNoCapability 交易內重解後主體已不持有節點管理權限點。
	ErrNodeWriteNoCapability = errors.New("authz: node write without capability")

	errNodeWriteScopeUnwired = errors.New("authz: node write scope without evaluator or topology")
	// errNodeWriteScopeInconsistent 判定器放行節點目標，同一交易內卻讀不到該節點（持拓撲鎖時不應發生）。
	errNodeWriteScopeInconsistent = errors.New("authz: node write scope decision inconsistent with topology")
)

// NodeWriteScope 節點寫入的範圍判定。零值不可用；以 NewNodeWriteScope 建立。
type NodeWriteScope struct {
	e *ScopeEvaluator
}

// NewNodeWriteScope 以判定器（目錄與拓撲）建立。
func NewNodeWriteScope(e *ScopeEvaluator) *NodeWriteScope { return &NodeWriteScope{e: e} }

// nodeWriteSubject 交易內重解後的主體在節點管理權限點上的來源。
type nodeWriteSubject struct {
	super  bool
	global bool
	sets   [][]uint // 每筆節點範圍指派的有效範圍節點
}

func (w *NodeWriteScope) subject(ctx context.Context, tx *gorm.DB) (nodeWriteSubject, error) {
	if w == nil || w.e == nil || w.e.topo == nil {
		return nodeWriteSubject{}, errNodeWriteScopeUnwired
	}
	p, err := w.e.resolveInTx(tx, PrincipalFromContext(ctx))
	if err != nil {
		return nodeWriteSubject{}, err
	}
	subj, ok := nodeWriteSubjectOf(p)
	if !ok {
		return nodeWriteSubject{}, ErrNodeWriteNoCapability
	}
	return subj, nil
}

// nodeWriteSubjectOf 已解析主體在節點管理權限點上的來源；不持有該權限點回 ok=false。
// 寫入判定與樹讀取的列級旗標共用本函式與下列規則函式，規則只有一份。
func nodeWriteSubjectOf(p *Principal) (nodeWriteSubject, bool) {
	if p.IsSuperAdmin() {
		return nodeWriteSubject{super: true}, true
	}
	if !p.Has(PermAssetGroupManage) {
		return nodeWriteSubject{}, false
	}
	global, sets := effectiveSources(p, PermAssetGroupManage, sourcesAll)
	return nodeWriteSubject{global: global, sets: sets}, true
}

// unrestricted 超級管理者或全域持有者：只受含範圍節點子樹的規則與既有結構檢查限制。
func (s nodeWriteSubject) unrestricted() bool { return s.super || s.global }

// inScope 節點（以自身＋未刪除祖先表示；空＝不存在或已刪）在某組範圍內。
func (s nodeWriteSubject) inScope(cover []uint) bool {
	return len(cover) > 0 && intersectsAny(cover, s.sets)
}

// strictDescendant 節點的祖先（不含自身）與某組範圍交集。
func (s nodeWriteSubject) strictDescendant(nodeID uint, cover []uint) bool {
	return intersectsAny(withoutID(cover, nodeID), s.sets)
}

// isScopeRoot 節點是某組範圍的範圍節點。
func (s nodeWriteSubject) isScopeRoot(nodeID uint) bool {
	for _, set := range s.sets {
		for _, id := range set {
			if id == nodeID {
				return true
			}
		}
	}
	return false
}

// canCreateUnder 在 cover 所表示的父節點下建立。
func (s nodeWriteSubject) canCreateUnder(cover []uint) bool {
	return s.unrestricted() || s.inScope(cover)
}

// canEdit 改名、改描述、刪除。
func (s nodeWriteSubject) canEdit(nodeID uint, cover []uint) bool {
	return s.unrestricted() || (s.inScope(cover) && s.strictDescendant(nodeID, cover))
}

// canMoveSource 搬移的來源端（含子樹規則；目的另判）。scopeSubtree＝被搬移子樹含任何指派的範圍節點。
func (s nodeWriteSubject) canMoveSource(nodeID uint, cover []uint, scopeSubtree bool) bool {
	if s.super {
		return true
	}
	if scopeSubtree {
		return false
	}
	return s.canEdit(nodeID, cover)
}

func intersects(a, b []uint) bool {
	m := make(map[uint]struct{}, len(a))
	for _, x := range a {
		m[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := m[y]; ok {
			return true
		}
	}
	return false
}

func intersectsAny(cover []uint, sets [][]uint) bool {
	for _, s := range sets {
		if intersects(cover, s) {
			return true
		}
	}
	return false
}

// nodeInScope 節點自身與未刪除祖先；不存在、已刪或不在任一組範圍內回範圍拒絕值。
// 是否在範圍內與拒絕值都由判定器對節點目標判出（同一交易、同一權限點），拒絕值不在本檔自行組出；
// 呼叫方已排除超級管理者與全域持有者，判定器在此只走節點範圍來源（與 nodeWriteSubject.inScope 同源）。
func (w *NodeWriteScope) nodeInScope(ctx context.Context, tx *gorm.DB, nodeID uint) ([]uint, error) {
	res, denied, err := w.e.DecideWithDenial(tx, PrincipalFromContext(ctx), PermAssetGroupManage, NodeTarget(nodeID))
	if err != nil {
		return nil, err
	}
	if denied != nil {
		return nil, denied
	}
	if res.Outcome != ScopeAllow {
		return nil, ErrNodeWriteNoCapability
	}
	cover, exists, err := w.e.topo.NodeCoverNodes(tx, nodeID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errNodeWriteScopeInconsistent
	}
	return cover, nil
}

// AuthorizeNodeCreate 在 parentID 下建立節點（nil＝根層）。
func (w *NodeWriteScope) AuthorizeNodeCreate(ctx context.Context, tx *gorm.DB, parentID *uint) error {
	subj, err := w.subject(ctx, tx)
	if err != nil {
		return err
	}
	if subj.unrestricted() {
		return nil
	}
	if parentID == nil {
		return ErrNodeWriteRootLevelGlobalOnly
	}
	_, err = w.nodeInScope(ctx, tx, *parentID)
	return err
}

// AuthorizeNodeEdit 改名、改描述與刪除：目標須是某組範圍節點的嚴格子孫。
func (w *NodeWriteScope) AuthorizeNodeEdit(ctx context.Context, tx *gorm.DB, nodeID uint) error {
	subj, err := w.subject(ctx, tx)
	if err != nil {
		return err
	}
	if subj.unrestricted() {
		return nil
	}
	cover, err := w.nodeInScope(ctx, tx, nodeID)
	if err != nil {
		return err
	}
	if !subj.canEdit(nodeID, cover) {
		return ErrNodeWriteSuperAdminOnly
	}
	return nil
}

// AuthorizeNodeMove 把 nodeID 搬到 newParentID 之下（nil＝根層）。
// 判定順序：來源與目的的範圍（同形拒絕）→ 嚴格子孫、根層、含範圍節點的子樹（限超級管理者）。
func (w *NodeWriteScope) AuthorizeNodeMove(ctx context.Context, tx *gorm.DB, nodeID uint, newParentID *uint) (asset.NodeMoveScope, error) {
	subj, err := w.subject(ctx, tx)
	if err != nil {
		return asset.NodeMoveScope{}, err
	}
	if subj.super {
		return asset.NodeMoveScope{}, nil
	}
	if subj.global {
		return asset.NodeMoveScope{}, w.rejectScopeSubtree(tx, nodeID)
	}
	srcCover, err := w.nodeInScope(ctx, tx, nodeID)
	if err != nil {
		return asset.NodeMoveScope{}, err
	}
	var dstCover []uint
	if newParentID != nil {
		if dstCover, err = w.nodeInScope(ctx, tx, *newParentID); err != nil {
			return asset.NodeMoveScope{}, err
		}
	}
	srcAncestors := withoutID(srcCover, nodeID)
	if !subj.strictDescendant(nodeID, srcCover) {
		return asset.NodeMoveScope{}, ErrNodeWriteSuperAdminOnly
	}
	if newParentID == nil {
		return asset.NodeMoveScope{}, ErrNodeWriteRootLevelGlobalOnly
	}
	if err := w.rejectScopeSubtree(tx, nodeID); err != nil {
		return asset.NodeMoveScope{}, err
	}
	// 跨指派：沒有任一筆指派同時使來源嚴格子孫成立、目的在其範圍內（只看集合是否存在，與順序無關）
	cross := true
	for _, s := range subj.sets {
		if intersects(srcAncestors, s) && intersects(dstCover, s) {
			cross = false
			break
		}
	}
	return asset.NodeMoveScope{ViaNodeScope: true, CrossAssignment: cross}, nil
}

// rejectScopeSubtree 被搬移子樹含任何指派的範圍節點時只限超級管理者。
func (w *NodeWriteScope) rejectScopeSubtree(tx *gorm.DB, nodeID uint) error {
	has, err := subtreeHasScopeNodes(tx, w.e.topo, nodeID)
	if err != nil {
		return err
	}
	if has {
		return ErrNodeWriteSuperAdminOnly
	}
	return nil
}
