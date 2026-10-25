package authz

import (
	"context"
	"errors"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 資產頁的範圍化讀取投影。
//
//   - 範圍化檢視者（資產頁）：經節點範圍指派持有任一資產或資產帳號權限點（不含節點管理權限點）；
//     只看指派紀錄與角色內容，不論範圍節點是否仍有效。標記只決定回應帶不帶呈現欄位，不授予能力。
//   - 管理可視：檢視捷徑主體（超管、稽核員）為全部未刪除資產；其他主體為資產檢視權限點的
//     「只取節點範圍指派」變體子樹內的資產。全域資產檢視不構成管理可視。
//   - 逐操作有效範圍：每個動作依它自己的權限點的一般三態集合（超管與全域來源為全系統）。
//
// 本檔不取鎖、不寫表；主體一律在呼叫方給的連線上重解。

var errAssetScopeUnwired = errors.New("authz: asset scope without evaluator, topology or database")

// isAssetScopedViewer 主體是否為資產頁的範圍化檢視者：與節點樹同一份權限點清單，但不含節點管理權限點。
func isAssetScopedViewer(p *Principal) bool {
	if p == nil || p.Facts.SubjectKind == model.KindAgent {
		return false
	}
	for _, a := range p.Assignments {
		if a.Scope != model.ScopeKindNodes {
			continue
		}
		for _, perm := range assignmentRolePermissions(a) {
			if perm == PermAssetGroupManage {
				continue
			}
			for _, v := range nodeTreeViewerPerms {
				if perm == v {
					return true
				}
			}
		}
	}
	return false
}

// ManagementVisibleScope 管理可視的資產集合。只能由 authz 建立；呼叫方經 ApplyManagementVisible
// 套到資產查詢、或經 CountManagementVisible 取去重台數，不取得 SQL 字串。零值不是合法結果。
type ManagementVisibleScope struct {
	built bool
	all   bool
	set   ScopeSet
}

// All 是否為全部未刪除資產（檢視捷徑主體）。
func (m ManagementVisibleScope) All() bool { return m.all }

// managementVisibleOn 兩個入口共用的分流：檢視捷徑主體為全部；其他主體為資產檢視的只取節點範圍變體。
func managementVisibleOn(p *Principal) ManagementVisibleScope {
	if p.ViewShortcut() {
		return ManagementVisibleScope{built: true, all: true}
	}
	return ManagementVisibleScope{built: true, set: scopeSetOn(p, PermAssetView, sourcesNodeOnly)}
}

// ManagementVisibleScopeFor 正式請求的管理可視（主體在呼叫方交易內重解）。
func (e *ScopeEvaluator) ManagementVisibleScopeFor(tx *gorm.DB, principal *Principal) (ManagementVisibleScope, error) {
	p, err := e.resolveInTx(tx, principal)
	if err != nil {
		return ManagementVisibleScope{}, err
	}
	return managementVisibleOn(p), nil
}

// ManagementVisibleScopeForAssignments 以指派集合為輸入的管理可視（預覽計數用）。是否構成檢視捷徑
// 由同一組指派經正式判定的同一實作得出，不接受呼叫端傳入。
func (e *ScopeEvaluator) ManagementVisibleScopeForAssignments(tx *gorm.DB, set AssignmentSet) (ManagementVisibleScope, error) {
	p, err := e.assignmentPrincipal(tx, set)
	if err != nil {
		return ManagementVisibleScope{}, err
	}
	return managementVisibleOn(p), nil
}

// ApplyManagementVisible 把管理可視加到以 assets 為主表的查詢上（分頁與計數之前呼叫）。
func (e *ScopeEvaluator) ApplyManagementVisible(tx *gorm.DB, q *gorm.DB, m ManagementVisibleScope) (*gorm.DB, error) {
	if !m.built {
		return nil, errScopeSetInvalid
	}
	if q == nil {
		return nil, errScopeQueryNil
	}
	if m.all {
		return q, nil
	}
	return e.ApplyScopeSet(tx, q, m.set, ScopeQueryAsset)
}

// CountManagementVisible 管理可視的未刪除資產台數（以資產識別碼去重）。
func (e *ScopeEvaluator) CountManagementVisible(tx *gorm.DB, m ManagementVisibleScope) (int64, error) {
	ids, err := e.managementVisibleIDs(tx, m)
	if err != nil {
		return 0, err
	}
	return int64(len(ids)), nil
}

func (e *ScopeEvaluator) managementVisibleIDs(tx *gorm.DB, m ManagementVisibleScope) ([]uint, error) {
	if tx == nil {
		return nil, errScopeNilTx
	}
	q, err := e.ApplyManagementVisible(tx, tx.Model(&model.Asset{}), m)
	if err != nil {
		return nil, err
	}
	var ids []uint
	if err := q.Distinct("assets.id").Pluck("assets.id", &ids).Error; err != nil {
		return nil, err
	}
	return ids, nil
}

// nodeScope 物化後的節點範圍：不限時 nodes 為 nil。
type nodeScope struct {
	state  ScopeSetState
	reason ScopeReason
	nodes  map[uint]bool
}

// split 資產的歸屬節點分成範圍內（保持原順序）與範圍外筆數。
func (n nodeScope) split(nodeIDs []uint) ([]uint, int) {
	if n.state == ScopeSetUnlimited {
		return append([]uint(nil), nodeIDs...), 0
	}
	in := make([]uint, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		if n.nodes[id] {
			in = append(in, id)
		}
	}
	return in, len(nodeIDs) - len(in)
}

func (e *ScopeEvaluator) materialize(tx *gorm.DB, set ScopeSet) (nodeScope, error) {
	switch set.state {
	case ScopeSetUnlimited:
		return nodeScope{state: ScopeSetUnlimited}, nil
	case ScopeSetEmpty:
		return nodeScope{state: ScopeSetEmpty, reason: set.reason, nodes: map[uint]bool{}}, nil
	case ScopeSetConditional:
	default:
		return nodeScope{}, errScopeSetInvalid
	}
	out := nodeScope{state: ScopeSetConditional, nodes: map[uint]bool{}}
	if e.topo == nil {
		return out, nil
	}
	var ids []uint
	if err := e.topo.SubtreeNodeIDs(tx, set.roots).Scan(&ids).Error; err != nil {
		return nodeScope{}, err
	}
	for _, id := range ids {
		out.nodes[id] = true
	}
	return out, nil
}

// 列級動作的原因碼（不含名稱）。
const (
	AssetActionReasonNoCapability    = "no_capability"
	AssetActionReasonOutOfScope      = "out_of_scope"
	AssetActionReasonOutOfScopeNodes = disclosure.FlagReasonOutOfScopeNodes
)

// AssetAction 一個動作的可操作結果；OutOfScopeNodes 只在原因為範圍外歸屬時有值（純整數，
// 由接入層轉成揭露值輸出）。
type AssetAction struct {
	Allowed         bool
	Reason          string
	OutOfScopeNodes int
}

// AssetRowActions 一列資產的五個動作。
type AssetRowActions struct {
	Edit, Disable, Delete, TestConnection, ManageAccounts AssetAction
}

// ManagementScopeNode 管理範圍中仍存在的節點與其由根起的名稱路徑。
type ManagementScopeNode struct {
	ID   uint
	Path string
}

// ManagementScopeSummary 管理範圍摘要：仍存在與已刪除（含不存在）的範圍節點數，及仍存在節點依路徑排序。
type ManagementScopeSummary struct {
	EffectiveNodeCount int
	InactiveNodeCount  int
	Nodes              []ManagementScopeNode
}

// AssetScopeView 範圍化檢視者在資產頁的投影來源；只對範圍化檢視者建立。
type AssetScopeView struct {
	Visible ManagementVisibleScope
	Summary ManagementScopeSummary

	super bool
	view  nodeScope
	ops   map[Permission]nodeScope
}

// MaskNodes 依管理可視範圍遮蔽歸屬：回範圍內節點（原順序）與範圍外筆數。
func (v *AssetScopeView) MaskNodes(nodeIDs []uint) ([]uint, int) { return v.view.split(nodeIDs) }

// Actions 一列資產（以其全部歸屬節點）的五個動作；每個鍵依自己的權限點判定。
func (v *AssetScopeView) Actions(nodeIDs []uint) AssetRowActions {
	return AssetRowActions{
		Edit:           v.action(PermAssetUpdate, nodeIDs, false),
		Disable:        v.action(PermAssetUpdate, nodeIDs, true),
		Delete:         v.action(PermAssetDelete, nodeIDs, true),
		TestConnection: v.action(PermAssetTest, nodeIDs, false),
		ManageAccounts: v.action(PermAssetUpdate, nodeIDs, false),
	}
}

// action 單一動作；guard 為刪除與停用另套的歸屬規則。規則與寫入判定共用 decideAssetOp（asset_write_scope.go）。
func (v *AssetScopeView) action(perm Permission, nodeIDs []uint, guard bool) AssetAction {
	return decideAssetOp(v.ops[perm], nodeIDs, guard)
}

// assetViewOn 在已解析的主體上建立投影；非範圍化檢視者回 nil。
func (e *ScopeEvaluator) assetViewOn(tx *gorm.DB, p *Principal) (*AssetScopeView, error) {
	if !isAssetScopedViewer(p) {
		return nil, nil
	}
	v := &AssetScopeView{Visible: managementVisibleOn(p), super: p.IsSuperAdmin(), ops: map[Permission]nodeScope{}}
	if v.Visible.all {
		v.view = nodeScope{state: ScopeSetUnlimited}
	} else {
		ns, err := e.materialize(tx, v.Visible.set)
		if err != nil {
			return nil, err
		}
		v.view = ns
	}
	for _, perm := range []Permission{PermAssetUpdate, PermAssetDelete, PermAssetTest} {
		ns, err := e.materialize(tx, scopeSetOn(p, perm, sourcesAll))
		if err != nil {
			return nil, err
		}
		v.ops[perm] = ns
	}
	sum, err := e.managementScopeSummaryOn(tx, p)
	if err != nil {
		return nil, err
	}
	v.Summary = sum
	return v, nil
}

// managementScopeSummaryOn 帶標記權限點的節點範圍指派（直接與經群組）所綁節點，去重後分仍存在與已刪除；
// 仍存在者附由根起的路徑（與資產歸屬路徑同一來源），依路徑排序。
func (e *ScopeEvaluator) managementScopeSummaryOn(tx *gorm.DB, p *Principal) (ManagementScopeSummary, error) {
	perms := make([]Permission, 0, len(nodeTreeViewerPerms))
	for _, perm := range nodeTreeViewerPerms {
		if perm != PermAssetGroupManage {
			perms = append(perms, perm)
		}
	}
	live, deleted, err := e.managementScopeNodesOn(tx, p, perms)
	if err != nil {
		return ManagementScopeSummary{}, err
	}
	sum := ManagementScopeSummary{EffectiveNodeCount: len(live), InactiveNodeCount: len(deleted), Nodes: []ManagementScopeNode{}}
	if len(live) == 0 {
		return sum, nil
	}
	paths, err := asset.NodePathMap(tx)
	if err != nil {
		return ManagementScopeSummary{}, err
	}
	for id := range live {
		sum.Nodes = append(sum.Nodes, ManagementScopeNode{ID: id, Path: paths[id]})
	}
	sort.Slice(sum.Nodes, func(i, j int) bool {
		if sum.Nodes[i].Path != sum.Nodes[j].Path {
			return sum.Nodes[i].Path < sum.Nodes[j].Path
		}
		return sum.Nodes[i].ID < sum.Nodes[j].ID
	})
	return sum, nil
}

// AssetScopeReader 資產頁的範圍化讀取；由組裝根以判定器與資料庫建立。
type AssetScopeReader struct {
	e  *ScopeEvaluator
	db *gorm.DB
}

// NewAssetScopeReader 以判定器（目錄與拓撲）與讀取連線建立。
func NewAssetScopeReader(e *ScopeEvaluator, db *gorm.DB) *AssetScopeReader {
	return &AssetScopeReader{e: e, db: db}
}

func (r *AssetScopeReader) resolve(ctx context.Context) (*Principal, error) {
	if r == nil || r.e == nil || r.e.topo == nil || r.db == nil {
		return nil, errAssetScopeUnwired
	}
	return r.e.resolveInTx(r.db, PrincipalFromContext(ctx))
}

// View 範圍化檢視者回投影；非範圍化檢視者回 nil（呼叫方走現行路徑）。
func (r *AssetScopeReader) View(ctx context.Context) (*AssetScopeView, error) {
	p, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return r.e.assetViewOn(r.db, p)
}

// ManagementVisibleIDs 投影的管理可視資產識別碼（去重）。
func (r *AssetScopeReader) ManagementVisibleIDs(v *AssetScopeView) ([]uint, error) {
	if r == nil || r.e == nil || r.db == nil || v == nil {
		return nil, errAssetScopeUnwired
	}
	return r.e.managementVisibleIDs(r.db, v.Visible)
}

// ManagementVisibleAsset 單一資產是否在主體的管理可視內（未刪除才算）；非範圍化檢視者恆為否。
func (r *AssetScopeReader) ManagementVisibleAsset(ctx context.Context, assetID uint) (bool, *AssetScopeView, error) {
	v, err := r.View(ctx)
	if err != nil || v == nil {
		return false, v, err
	}
	q, err := r.e.ApplyManagementVisible(r.db, r.db.Model(&model.Asset{}).Where("assets.id = ?", assetID), v.Visible)
	if err != nil {
		return false, nil, err
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return false, nil, err
	}
	return n > 0, v, nil
}

// AssetViewScopeDenial 由判定器以資產檢視權限點對單一資產判出的範圍拒絕值（讀取連線、主體重解）。
// 放行或能力拒絕（例如該權限點在目錄仍為保留、主體不持有）回 nil：呼叫方走現行「不存在」路徑，
// 不自行組出拒絕值。讀取失敗回錯誤，不得當成不存在。
func (r *AssetScopeReader) AssetViewScopeDenial(ctx context.Context, assetID uint) (*ErrScopeDenied, error) {
	if r == nil || r.e == nil || r.db == nil {
		return nil, errAssetScopeUnwired
	}
	// 不存在（含已刪除）不是範圍拒絕：判定器對不存在的目標同樣判出範圍拒絕值，這裡先排除，
	// 讓呼叫方走現行「不存在」路徑、不留範圍拒絕原因（對外兩者同形）。
	var n int64
	if err := r.db.Model(&model.Asset{}).Where("id = ?", assetID).Count(&n).Error; err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	_, denied, err := r.e.DecideWithDenial(r.db, PrincipalFromContext(ctx), PermAssetView, AssetTarget(assetID))
	if err != nil {
		return nil, err
	}
	return denied, nil
}

// HasOpScope 動作權限點的有效範圍是否涵蓋這組歸屬節點（不套刪停的歸屬規則）。
func (v *AssetScopeView) HasOpScope(perm Permission, nodeIDs []uint) bool {
	s, ok := v.ops[perm]
	if !ok {
		return false
	}
	switch s.state {
	case ScopeSetUnlimited:
		return true
	case ScopeSetConditional:
		in, _ := s.split(nodeIDs)
		return len(in) > 0
	}
	return false
}
