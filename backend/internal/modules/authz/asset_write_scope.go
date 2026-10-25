package authz

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
)

// 資產寫入（建立、更新、停用、刪除）的交易內範圍判定，實作 asset 的消費者側窄介面。
//
// 呼叫方先在同一交易取拓撲序列化鎖，再呼叫本檔方法；主體在交易內重解（傳入主體的指派一律忽略）。
// 每個操作依自己的權限點的一般三態集合（超管與全域來源為全系統）；規則與資產頁的列級旗標共用
// decideAssetOp，只有一份。
//
//   - 建立：不限照現行（節點存在性由服務驗證）；條件範圍下歸屬不得為空，且每個節點都須在範圍內
//     （範圍外、已刪除、不存在同一個節點範圍拒絕值）。
//
// 範圍拒絕值一律由判定器對目標（資產或節點）在同一交易、同一權限點判出，本檔不自行組出；
// 物化集合判為範圍外而判定器未判出範圍拒絕，即回內部不一致錯誤（持拓撲鎖時不應發生），不放行。
//   - 更新：資產至少有一個歸屬在編輯能力範圍內，否則資產範圍拒絕（與不存在同形）。
//   - 停用、刪除：同上，另套歸屬規則——條件範圍下仍有範圍外歸屬即回範圍外歸屬錯誤（帶筆數）。
//     未分組資產：不限者照現行可刪停；條件範圍下沒有範圍內歸屬，即不在範圍。
//   - 存取政策覆寫：更新依存取政策權限點對資產判定（同「更新」的規則）；新資產的目的節點至少一個
//     在存取政策權限點的範圍內（AccessPolicyCoversNodes）。
//   - 節點合併：送出的每個節點都須在編輯能力範圍內；帶範圍化檢視者標記的主體只替換
//     「看得到（管理可視遮蔽後）∩ 編輯能力範圍內」的既有歸屬，其餘保留。

var (
	errAssetWriteScopeUnwired = errors.New("authz: asset write scope without evaluator or topology")
	// errAssetWriteScopeInconsistent 物化集合判為範圍外，判定器對同一目標卻未判出範圍拒絕。
	errAssetWriteScopeInconsistent = errors.New("authz: asset write scope decision inconsistent with topology")
)

// AssetWriteCapabilityError 交易內重解後主體不持有該操作的權限點（能力拒絕；Perm 供 handler 組依據）。
type AssetWriteCapabilityError struct {
	Perm Permission
}

// Error 固定字串，不含權限點或名稱。
func (e *AssetWriteCapabilityError) Error() string { return "authz: asset write without capability" }

// AssetWriteScope 資產寫入的範圍判定。零值不可用；以 NewAssetWriteScope 建立。
type AssetWriteScope struct {
	e *ScopeEvaluator
}

// NewAssetWriteScope 以判定器（目錄與拓撲）建立。
func NewAssetWriteScope(e *ScopeEvaluator) *AssetWriteScope { return &AssetWriteScope{e: e} }

var _ asset.AssetWriteScopePort = (*AssetWriteScope)(nil)

// decideAssetOp 單一操作對一組歸屬的判定；guard 為刪除與停用另套的歸屬規則。寫入判定與列級旗標共用。
func decideAssetOp(s nodeScope, nodeIDs []uint, guard bool) AssetAction {
	switch s.state {
	case ScopeSetUnlimited:
		return AssetAction{Allowed: true}
	case ScopeSetConditional:
		in, out := s.split(nodeIDs)
		if len(in) == 0 {
			return AssetAction{Reason: AssetActionReasonOutOfScope}
		}
		if guard && out > 0 {
			return AssetAction{Reason: AssetActionReasonOutOfScopeNodes, OutOfScopeNodes: out}
		}
		return AssetAction{Allowed: true}
	}
	if s.reason == ScopeReasonNoEffectiveBinding || s.state == 0 {
		return AssetAction{Reason: AssetActionReasonNoCapability}
	}
	return AssetAction{Reason: AssetActionReasonOutOfScope}
}

// scopeDenial 由判定器對 target 判出範圍拒絕值（同一交易、同一權限點）；判定器未判出範圍拒絕即為不一致。
func (w *AssetWriteScope) scopeDenial(ctx context.Context, tx *gorm.DB, perm Permission, target ScopeTarget) error {
	_, denied, err := w.e.DecideWithDenial(tx, PrincipalFromContext(ctx), perm, target)
	if err != nil {
		return err
	}
	if denied != nil {
		return denied
	}
	return errAssetWriteScopeInconsistent
}

// assetOpError 把資產 assetID 的判定結果轉成寫入錯誤；放行回 nil。範圍外的拒絕值由判定器對資產目標判出。
func (w *AssetWriteScope) assetOpError(ctx context.Context, tx *gorm.DB, a AssetAction, perm Permission, assetID uint) error {
	if a.Allowed {
		return nil
	}
	switch a.Reason {
	case AssetActionReasonNoCapability:
		return &AssetWriteCapabilityError{Perm: perm}
	case AssetActionReasonOutOfScopeNodes:
		return &asset.AssetOutOfScopeNodesError{Count: a.OutOfScopeNodes}
	}
	return w.scopeDenial(ctx, tx, perm, AssetTarget(assetID))
}

func (w *AssetWriteScope) principal(ctx context.Context, tx *gorm.DB) (*Principal, error) {
	if w == nil || w.e == nil || w.e.topo == nil {
		return nil, errAssetWriteScopeUnwired
	}
	return w.e.resolveInTx(tx, PrincipalFromContext(ctx))
}

func (w *AssetWriteScope) opScope(tx *gorm.DB, p *Principal, perm Permission) (nodeScope, error) {
	return w.e.materialize(tx, scopeSetOn(p, perm, sourcesAll))
}

func assetWritePerm(op asset.AssetWriteOp) (Permission, bool) {
	switch op {
	case asset.AssetWriteDelete:
		return PermAssetDelete, true
	case asset.AssetWriteAccessPolicy:
		return PermAccessPolicyManage, false
	}
	return PermAssetUpdate, op == asset.AssetWriteDisable
}

// AccessPolicyCoversNodes 每組目的節點是否至少一個在存取政策權限點的範圍內（與資產範圍判定同義：
// 任一歸屬在範圍即在範圍）。範圍不限者恆為真；沒有生效來源或零節點者（範圍不限除外）為假。
// 呼叫方以假值整筆或整批拒絕，形狀與不持該權限點者相同。
func (w *AssetWriteScope) AccessPolicyCoversNodes(ctx context.Context, tx *gorm.DB, nodeSets [][]uint) ([]bool, error) {
	p, err := w.principal(ctx, tx)
	if err != nil {
		return nil, err
	}
	s, err := w.opScope(tx, p, PermAccessPolicyManage)
	if err != nil {
		return nil, err
	}
	out := make([]bool, len(nodeSets))
	for i, ids := range nodeSets {
		if s.state == ScopeSetUnlimited {
			out[i] = true
			continue
		}
		in, _ := s.split(ids)
		out[i] = len(in) > 0
	}
	return out, nil
}

// AuthorizeAssetCreate 以 nodeIDs 為初始歸屬建立資產。
func (w *AssetWriteScope) AuthorizeAssetCreate(ctx context.Context, tx *gorm.DB, nodeIDs []uint) error {
	p, err := w.principal(ctx, tx)
	if err != nil {
		return err
	}
	s, err := w.opScope(tx, p, PermAssetCreate)
	if err != nil {
		return err
	}
	switch {
	case s.state == ScopeSetUnlimited:
		return nil
	case s.state == ScopeSetEmpty && s.reason == ScopeReasonNoEffectiveBinding:
		return &AssetWriteCapabilityError{Perm: PermAssetCreate}
	case len(nodeIDs) == 0:
		return asset.ErrAssetNodeRequired
	}
	for _, id := range nodeIDs {
		if !s.nodes[id] {
			return w.scopeDenial(ctx, tx, PermAssetCreate, NodeTarget(id))
		}
	}
	return nil
}

// AuthorizeAssetWrite 對現行歸屬為 current 的資產 assetID 執行 op。
func (w *AssetWriteScope) AuthorizeAssetWrite(ctx context.Context, tx *gorm.DB, op asset.AssetWriteOp, assetID uint, current []uint) error {
	p, err := w.principal(ctx, tx)
	if err != nil {
		return err
	}
	perm, guard := assetWritePerm(op)
	s, err := w.opScope(tx, p, perm)
	if err != nil {
		return err
	}
	return w.assetOpError(ctx, tx, decideAssetOp(s, current, guard), perm, assetID)
}

// MergeAssetNodes 資產 assetID 更新送出 requested 時的新歸屬：新＝requested ∪ (current − I)，I＝current ∩ 可見 ∩ 編輯範圍。
// 不帶範圍化檢視者標記的主體照現行整組取代（此時編輯範圍必為不限，否則目標判定已拒絕）。
func (w *AssetWriteScope) MergeAssetNodes(ctx context.Context, tx *gorm.DB, assetID uint, current, requested []uint) ([]uint, error) {
	p, err := w.principal(ctx, tx)
	if err != nil {
		return nil, err
	}
	u, err := w.opScope(tx, p, PermAssetUpdate)
	if err != nil {
		return nil, err
	}
	if err := w.assetOpError(ctx, tx, decideAssetOp(u, current, false), PermAssetUpdate, assetID); err != nil {
		return nil, err
	}
	limited := u.state != ScopeSetUnlimited
	if limited {
		for _, id := range requested {
			if !u.nodes[id] {
				return nil, w.scopeDenial(ctx, tx, PermAssetUpdate, NodeTarget(id))
			}
		}
	}
	if !isAssetScopedViewer(p) {
		return append([]uint(nil), requested...), nil
	}
	visible, err := w.visibleNodes(tx, p, current)
	if err != nil {
		return nil, err
	}
	replaceable := map[uint]bool{}
	for _, id := range visible {
		if !limited || u.nodes[id] {
			replaceable[id] = true
		}
	}
	merged := make([]uint, 0, len(requested)+len(current))
	seen := map[uint]bool{}
	for _, id := range requested {
		if !seen[id] {
			seen[id] = true
			merged = append(merged, id)
		}
	}
	for _, id := range current {
		if !replaceable[id] && !seen[id] {
			seen[id] = true
			merged = append(merged, id)
		}
	}
	if limited && len(merged) == 0 {
		return nil, asset.ErrAssetNodeRequired
	}
	return merged, nil
}

// visibleNodes 主體在此資產上看得到的歸屬：一律以管理可視遮蔽計算（檢視捷徑主體為全部）。
// 只經連線可視的列不另判（會多保留既有歸屬，不放寬）。
func (w *AssetWriteScope) visibleNodes(tx *gorm.DB, p *Principal, current []uint) ([]uint, error) {
	m := managementVisibleOn(p)
	if m.all {
		return append([]uint(nil), current...), nil
	}
	ns, err := w.e.materialize(tx, m.set)
	if err != nil {
		return nil, err
	}
	in, _ := ns.split(current)
	return in, nil
}
