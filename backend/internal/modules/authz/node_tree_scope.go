package authz

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 節點樹與平面節點列表的範圍化讀取投影。
//
//   - 範圍化檢視者：經節點範圍指派持有任一資產或資產帳號權限點，或經節點範圍指派持有節點管理權限點；
//     只看指派紀錄與角色內容，不論範圍節點是否仍有效。其餘主體走現行路徑，回應不變。
//   - 管理可視：資產檢視權限點與節點管理權限點以「只取節點範圍指派」變體取得的有效子樹聯集；
//     全域來源不構成管理可視（全域主體不因持有某權限點而見全量樹）。
//   - 列級旗標：由節點寫入的同一組規則函式算出（node_write_scope.go），只看節點管理權限點。
//   - 按權限點的投影：NodeScopeProjection 回權限點的有效範圍子樹與定位祖先；全域持有者回不限，不以 nil 表示。
//
// 本檔不取鎖、不寫表；主體一律在呼叫方給的連線上重解。

var errNodeTreeScopeUnwired = errors.New("authz: node tree scope without evaluator, topology or database")

// nodeTreeViewerPerms 構成節點樹範圍化檢視者的資產與資產帳號權限點（另加節點管理權限點）。
var nodeTreeViewerPerms = []Permission{
	PermAssetView, PermAssetCreate, PermAssetUpdate, PermAssetDelete, PermAssetTest,
	PermAccountRotate, PermAssetGroupManage,
}

// nodeTreeManagePerms 構成樹的管理可視的權限點。
var nodeTreeManagePerms = []Permission{PermAssetView, PermAssetGroupManage}

// NodeProjection 權限點的節點投影。State 為不限時 Selectable 與 Locators 皆空，呼叫方視每個節點為可選；
// 為空時沒有可選節點；為條件時 Selectable 是有效範圍子樹的未刪除節點，Locators 是範圍節點的
// 未刪除祖先中不在 Selectable 內者（只作定位）。零值 State 不是合法結果。
type NodeProjection struct {
	State      ScopeSetState
	Selectable map[uint]bool
	Locators   map[uint]bool
}

// NodeScopeProjection 主體對權限點的節點投影（一般三態：超管與全域來源為不限）。
func (e *ScopeEvaluator) NodeScopeProjection(tx *gorm.DB, principal *Principal, perm Permission) (NodeProjection, error) {
	p, err := e.resolveInTx(tx, principal)
	if err != nil {
		return NodeProjection{}, err
	}
	return e.projectionOn(tx, scopeSetOn(p, perm, sourcesAll))
}

func (e *ScopeEvaluator) projectionOn(tx *gorm.DB, set ScopeSet) (NodeProjection, error) {
	switch set.state {
	case ScopeSetUnlimited:
		return NodeProjection{State: ScopeSetUnlimited}, nil
	case ScopeSetEmpty:
		return emptyProjection(), nil
	case ScopeSetConditional:
	default:
		return NodeProjection{}, errScopeSetInvalid
	}
	if e.topo == nil { // 與 ApplyScopeSet 同結論：拓撲未注入的條件集合視為空
		return emptyProjection(), nil
	}
	sel, loc, err := e.subtreeWithLocators(tx, set.roots)
	if err != nil {
		return NodeProjection{}, err
	}
	if len(sel) == 0 {
		return emptyProjection(), nil
	}
	return NodeProjection{State: ScopeSetConditional, Selectable: sel, Locators: loc}, nil
}

func emptyProjection() NodeProjection {
	return NodeProjection{State: ScopeSetEmpty, Selectable: map[uint]bool{}, Locators: map[uint]bool{}}
}

// subtreeWithLocators 範圍節點的子樹（未刪除）與其未刪除祖先中不在子樹內者。
func (e *ScopeEvaluator) subtreeWithLocators(tx *gorm.DB, roots []uint) (map[uint]bool, map[uint]bool, error) {
	var ids []uint
	if err := e.topo.SubtreeNodeIDs(tx, roots).Scan(&ids).Error; err != nil {
		return nil, nil, err
	}
	sel := make(map[uint]bool, len(ids))
	for _, id := range ids {
		sel[id] = true
	}
	loc := map[uint]bool{}
	for _, r := range roots {
		cover, exists, err := e.topo.NodeCoverNodes(tx, r)
		if err != nil {
			return nil, nil, err
		}
		if !exists {
			continue
		}
		for _, id := range cover {
			if !sel[id] {
				loc[id] = true
			}
		}
	}
	return sel, loc, nil
}

// assignmentRolePermissions 一筆指派的角色內容（不看範圍是否生效）：鎖定管理範本取程式集合、
// 自訂角色取明確集合、其他內建角色取其範本。
func assignmentRolePermissions(a Assignment) []Permission {
	switch {
	case IsLockedManagementTemplate(a.BuiltinKey):
		return TemplatePermissions(a.BuiltinKey)
	case a.Custom:
		return a.Permissions
	case a.BuiltinKey != "":
		return TemplatePermissions(a.BuiltinKey)
	}
	return nil
}

// isNodeTreeScopedViewer 主體是否為節點樹的範圍化檢視者（只看節點範圍指派的角色內容）。
func isNodeTreeScopedViewer(p *Principal) bool {
	if p == nil || p.Facts.SubjectKind == model.KindAgent {
		return false
	}
	for _, a := range p.Assignments {
		if a.Scope != model.ScopeKindNodes {
			continue
		}
		for _, perm := range assignmentRolePermissions(a) {
			for _, v := range nodeTreeViewerPerms {
				if perm == v {
					return true
				}
			}
		}
	}
	return false
}

// hasNodeScopeSource 主體經節點範圍指派持有權限點（該指派在權限點上生效）。
func hasNodeScopeSource(p *Principal, perm Permission) bool {
	_, idx := p.sourceAssignments(perm)
	return len(idx) > 0
}

// NodeTreeScopeReader 節點樹與平面列表的範圍化讀取；由組裝根以判定器與資料庫建立。
type NodeTreeScopeReader struct {
	e  *ScopeEvaluator
	db *gorm.DB
}

// NewNodeTreeScopeReader 以判定器（目錄與拓撲）與讀取連線建立。
func NewNodeTreeScopeReader(e *ScopeEvaluator, db *gorm.DB) *NodeTreeScopeReader {
	return &NodeTreeScopeReader{e: e, db: db}
}

// NodeTreeView 範圍化檢視者的管理可視與旗標來源。
type NodeTreeView struct {
	// ManageNodes 管理可視子樹的未刪除節點；ManageLocators 其範圍節點的未刪除祖先（只作定位）。
	ManageNodes    map[uint]bool
	ManageLocators map[uint]bool
	// ManageAssets 管理可視子樹內掛載的未刪除資產。
	ManageAssets map[uint]bool
	// CanCreateRoot 根層建立：超級管理者與全域持有節點管理權限點者。
	CanCreateRoot bool

	r      *NodeTreeScopeReader
	subj   nodeWriteSubject
	hasCap bool
}

func (r *NodeTreeScopeReader) resolve(ctx context.Context) (*Principal, error) {
	if r == nil || r.e == nil || r.e.topo == nil || r.db == nil {
		return nil, errNodeTreeScopeUnwired
	}
	return r.e.resolveInTx(r.db, PrincipalFromContext(ctx))
}

// TreeView 範圍化檢視者回管理可視與旗標來源；非範圍化檢視者回 nil（呼叫方走現行路徑）。
func (r *NodeTreeScopeReader) TreeView(ctx context.Context) (*NodeTreeView, error) {
	p, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if !isNodeTreeScopedViewer(p) {
		return nil, nil
	}
	seen := map[uint]bool{}
	var roots []uint
	for _, perm := range nodeTreeManagePerms {
		set := scopeSetOn(p, perm, sourcesNodeOnly)
		if set.state != ScopeSetConditional {
			continue // 空（含範圍全刪）不回退全量
		}
		for _, id := range set.roots {
			if !seen[id] {
				seen[id] = true
				roots = append(roots, id)
			}
		}
	}
	view := &NodeTreeView{ManageNodes: map[uint]bool{}, ManageLocators: map[uint]bool{}, ManageAssets: map[uint]bool{}, r: r}
	if len(roots) > 0 {
		sel, loc, err := r.e.subtreeWithLocators(r.db, roots)
		if err != nil {
			return nil, err
		}
		view.ManageNodes, view.ManageLocators = sel, loc
		var assetIDs []uint
		if err := r.e.topo.SubtreeAssetIDs(r.db, roots).Scan(&assetIDs).Error; err != nil {
			return nil, err
		}
		for _, id := range assetIDs {
			view.ManageAssets[id] = true
		}
	}
	view.subj, view.hasCap = nodeWriteSubjectOf(p)
	view.CanCreateRoot = view.hasCap && view.subj.unrestricted()
	return view, nil
}

// Flags 每個節點的列級旗標（LocatorOnly 由呼叫方依連線可視直掛資產補上）。
// 規則與寫入判定相同：can_create_child 同建立、can_rename／can_delete 同改名與刪除、
// can_move 只看來源端與含範圍節點的子樹。
func (v *NodeTreeView) Flags(nodeIDs []uint) (map[uint]asset.NodeRowFlags, error) {
	out := make(map[uint]asset.NodeRowFlags, len(nodeIDs))
	for _, id := range nodeIDs {
		f := asset.NodeRowFlags{Manageable: v.ManageNodes[id]}
		if v.hasCap {
			cover, _, err := v.r.e.topo.NodeCoverNodes(v.r.db, id)
			if err != nil {
				return nil, err
			}
			f.ScopeRoot = v.subj.isScopeRoot(id)
			f.CanCreateChild = v.subj.canCreateUnder(cover)
			f.CanRename = v.subj.canEdit(id, cover)
			f.CanDelete = f.CanRename
			if v.subj.super || f.CanRename {
				scopeSubtree, err := subtreeHasScopeNodes(v.r.db, v.r.e.topo, id)
				if err != nil {
					return nil, err
				}
				f.CanMove = v.subj.canMoveSource(id, cover, scopeSubtree)
			}
		}
		out[id] = f
	}
	return out, nil
}

// PurposeProjection 用途參數的節點投影：主體是節點樹的範圍化檢視者、或經節點範圍指派持有該權限點時
// 回投影；其餘主體回 nil（呼叫方帶參數與不帶參數回應相同）。
func (r *NodeTreeScopeReader) PurposeProjection(ctx context.Context, perm Permission) (*NodeProjection, error) {
	p, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if !isNodeTreeScopedViewer(p) && !hasNodeScopeSource(p, perm) {
		return nil, nil
	}
	proj, err := r.e.projectionOn(r.db, scopeSetOn(p, perm, sourcesAll))
	if err != nil {
		return nil, err
	}
	return &proj, nil
}
