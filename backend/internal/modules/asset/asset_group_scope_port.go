package asset

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// 節點寫入的範圍判定、引用查詢、涵蓋快照與刪除級聯參與者（消費者側窄介面）。
//
// asset 不 import authz：四個介面都在此宣告意圖，由組裝根注入 authz 的實作。全部方法都在
// 呼叫方交易內執行、不開交易、不提交；判定與查詢只在取得拓撲序列化鎖之後呼叫，
// 讀到的是取鎖前已提交的狀態。
//
// 判定回傳的錯誤（範圍拒絕、限超級管理者、無能力）是 authz 定義的值，本模組不解讀也不改寫，
// 原樣經交易回滾交回 handler，由 handler 交共用出口。

// NodeWriteScopePort 節點寫入的交易內範圍判定。主體由呼叫方放在 ctx（本模組不讀取）。
type NodeWriteScopePort interface {
	// AuthorizeNodeCreate 在 parentID 下建立節點（nil＝根層）。
	AuthorizeNodeCreate(ctx context.Context, tx *gorm.DB, parentID *uint) error
	// AuthorizeNodeEdit 改名、改描述與刪除共用的判定（目標須是範圍節點的嚴格子孫）。
	AuthorizeNodeEdit(ctx context.Context, tx *gorm.DB, nodeID uint) error
	// AuthorizeNodeMove 把 nodeID 搬到 newParentID 之下（nil＝根層）。
	AuthorizeNodeMove(ctx context.Context, tx *gorm.DB, nodeID uint, newParentID *uint) (NodeMoveScope, error)
}

// NodeMoveScope 搬移判定的附帶結果，供搬移審計使用。
type NodeMoveScope struct {
	// ViaNodeScope 搬移經節點範圍指派授權（非超級管理者、非全域持有者）。
	ViaNodeScope bool
	// CrossAssignment 只在 ViaNodeScope 時有意義：沒有任一筆指派同時涵蓋來源與目的。
	CrossAssignment bool
}

// NodeReference 一筆引用節點的角色指派（主體種類＋主體＋角色）。
type NodeReference struct {
	SubjectKind string
	SubjectID   uint
	SubjectName string
	RoleID      uint
	RoleName    string
	// MemberCount 群組主體的成員數（只作提示）；使用者主體為 nil。
	MemberCount *int
}

// NodeReferences 節點的引用彙總。Count＝不同指派的筆數；Items 依（主體種類, 主體, 角色）升冪、去重。
type NodeReferences struct {
	Count int
	Items []NodeReference
}

// NodeScopeReferencePort 節點刪除前的範圍引用查詢（直接讀指派原始關係，不看主體啟停）。
type NodeScopeReferencePort interface {
	NodeScopeReferences(tx *gorm.DB, nodeID uint) (NodeReferences, error)
}

// CoverageSnapshotPort 拓撲變更前後的涵蓋快照（連線授權、審核範圍、管理範圍三種來源）。
type CoverageSnapshotPort interface {
	CoverageSnapshot(tx *gorm.DB, assetIDs []uint) (CoverageSnapshot, error)
}

// NodeDeleteCascadeParticipant 節點刪除交易內的級聯參與者：在引用與空節點檢查通過後、節點軟刪之前呼叫。
// 參與者只寫自己模組的表；回錯誤即整筆回滾。
type NodeDeleteCascadeParticipant interface {
	NodeDeleteCascade(tx *gorm.DB, nodeID uint, parentID *uint) error
}

var (
	// ErrNodeWriteScopePortMissing 節點寫入的範圍判定未注入：寧可拒絕，也不在沒有判定的情況下寫入。
	ErrNodeWriteScopePortMissing = errors.New("asset: node write scope port not injected")
	// ErrNodeScopeReferencePortMissing 範圍引用查詢未注入：節點刪除拒絕（不得當作沒有引用）。
	ErrNodeScopeReferencePortMissing = errors.New("asset: node scope reference port not injected")
	// ErrCoverageSnapshotPortMissing 涵蓋快照未注入：搬移拒絕（不得無涵蓋差異審計完成）。
	ErrCoverageSnapshotPortMissing = errors.New("asset: coverage snapshot port not injected")
)

// NodeScopeReferencedError 節點仍被管理範圍引用，刪除被擋。Path 為節點路徑（目標已通過範圍判定）。
type NodeScopeReferencedError struct {
	Path       string
	References NodeReferences
}

// Error 固定字串，不含名稱或識別碼。
func (e *NodeScopeReferencedError) Error() string {
	return "asset: node is referenced by management scopes"
}

// SetNodeWriteScopePort 注入節點寫入的範圍判定（組裝時）。
func (s *AssetGroupService) SetNodeWriteScopePort(p NodeWriteScopePort) { s.nodeScope = p }

// SetNodeScopeReferencePort 注入節點刪除前的範圍引用查詢（組裝時）。
func (s *AssetGroupService) SetNodeScopeReferencePort(p NodeScopeReferencePort) { s.nodeRefs = p }

// SetCoverageSnapshotPort 注入搬移用的涵蓋快照（組裝時）。
func (s *AssetGroupService) SetCoverageSnapshotPort(p CoverageSnapshotPort) { s.coverage = p }

// AddNodeDeleteCascade 註冊節點刪除的級聯參與者（組裝時；依註冊順序呼叫）。
func (s *AssetGroupService) AddNodeDeleteCascade(p NodeDeleteCascadeParticipant) {
	if p != nil {
		s.cascades = append(s.cascades, p)
	}
}

func (s *AssetGroupService) authorizeCreateTx(ctx context.Context, tx *gorm.DB, parentID *uint) error {
	if s.nodeScope == nil {
		return ErrNodeWriteScopePortMissing
	}
	return s.nodeScope.AuthorizeNodeCreate(ctx, tx, parentID)
}

func (s *AssetGroupService) authorizeEditTx(ctx context.Context, tx *gorm.DB, nodeID uint) error {
	if s.nodeScope == nil {
		return ErrNodeWriteScopePortMissing
	}
	return s.nodeScope.AuthorizeNodeEdit(ctx, tx, nodeID)
}

func (s *AssetGroupService) authorizeMoveTx(ctx context.Context, tx *gorm.DB, nodeID uint, newParentID *uint) (NodeMoveScope, error) {
	if s.nodeScope == nil {
		return NodeMoveScope{}, ErrNodeWriteScopePortMissing
	}
	return s.nodeScope.AuthorizeNodeMove(ctx, tx, nodeID, newParentID)
}

// checkNodeReferencesTx 刪除前的引用阻擋（含超級管理者）：有任何引用即回 *NodeScopeReferencedError。
func (s *AssetGroupService) checkNodeReferencesTx(tx *gorm.DB, nodeID uint) error {
	if s.nodeRefs == nil {
		return ErrNodeScopeReferencePortMissing
	}
	refs, err := s.nodeRefs.NodeScopeReferences(tx, nodeID)
	if err != nil {
		return err
	}
	if refs.Count == 0 {
		return nil
	}
	paths, err := NodePathMap(tx)
	if err != nil {
		return err
	}
	return &NodeScopeReferencedError{Path: paths[nodeID], References: refs}
}

// runNodeDeleteCascadesTx 依註冊順序呼叫額外的級聯參與者。
func (s *AssetGroupService) runNodeDeleteCascadesTx(tx *gorm.DB, nodeID uint, parentID *uint) error {
	for _, p := range s.cascades {
		if err := p.NodeDeleteCascade(tx, nodeID, parentID); err != nil {
			return err
		}
	}
	return nil
}
