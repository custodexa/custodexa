package authz

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
)

// 單台覆寫清單的範圍投影，實作 asset 的消費者側窄介面。
//
// 只依存取政策權限點的有效指派：以 ScopeSetFor 取單一權限點的三態集合，列表以 ApplyScopeSet 投影，
// 歸屬節點以同一份集合物化後經 nodeScope.split 遮蔽並計範圍外筆數。不套資產頁的管理可視集合，
// 也不採「任一資產能力有節點範圍指派即為範圍化檢視者」：全域持有存取政策權限點、另經節點範圍
// 持其他能力者，在本清單是全域檢視者。主體在呼叫方給的連線上重解（傳入主體的指派一律忽略）。

var errAccessPolicyOverrideScopeUnwired = errors.New("authz: access policy override scope without evaluator")

// HoldsViaNodeScope 主體是否有經節點範圍指派取得的 perm 生效來源（不論另有無全域來源）。
// 只看已解析主體的來源記錄，不讀資料庫；用來判定是否需要取該權限點的投影，範圍本身仍以投影為準。
func HoldsViaNodeScope(p *Principal, perm Permission) bool {
	_, idx := p.sourceAssignments(perm)
	return len(idx) > 0
}

// AccessPolicyOverrideScope 覆寫清單的範圍投影來源。零值不可用；以 NewAccessPolicyOverrideScope 建立。
type AccessPolicyOverrideScope struct {
	e *ScopeEvaluator
}

// NewAccessPolicyOverrideScope 以判定器（目錄與拓撲）建立。
func NewAccessPolicyOverrideScope(e *ScopeEvaluator) *AccessPolicyOverrideScope {
	return &AccessPolicyOverrideScope{e: e}
}

var _ asset.AccessPolicyOverrideScopePort = (*AccessPolicyOverrideScope)(nil)

// AccessPolicyProjection 請求主體（ctx）在 db 上的存取政策權限點投影。
func (s *AccessPolicyOverrideScope) AccessPolicyProjection(ctx context.Context, db *gorm.DB) (asset.AccessPolicyProjection, error) {
	if s == nil || s.e == nil {
		return nil, errAccessPolicyOverrideScopeUnwired
	}
	set, err := s.e.ScopeSetFor(db, PrincipalFromContext(ctx), PermAccessPolicyManage)
	if err != nil {
		return nil, err
	}
	nodes, err := s.e.materialize(db, set)
	if err != nil {
		return nil, err
	}
	return &AccessPolicyOverrideProjection{e: s.e, db: db, set: set, nodes: nodes}, nil
}

// AccessPolicyOverrideProjection 一次請求的集合與物化範圍；查詢走建立投影時的連線。
// 匯出是為了讓收查詢句柄的 ApplyAssets 進入跨模組交易句柄登記的掃描範圍。
type AccessPolicyOverrideProjection struct {
	e     *ScopeEvaluator
	db    *gorm.DB
	set   ScopeSet
	nodes nodeScope
}

func (p *AccessPolicyOverrideProjection) Scoped() bool { return p.set.State() != ScopeSetUnlimited }

func (p *AccessPolicyOverrideProjection) ApplyAssets(q *gorm.DB) (*gorm.DB, error) {
	return p.e.ApplyScopeSet(p.db, q, p.set, ScopeQueryAsset)
}

func (p *AccessPolicyOverrideProjection) SplitNodes(nodeIDs []uint) ([]uint, int) {
	return p.nodes.split(nodeIDs)
}
