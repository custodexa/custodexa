package authz

import (
	"errors"

	"gorm.io/gorm"
)

// 範圍判定器：型別、建構介面與同一筆指派的判定。

// ScopeTopology 拓撲唯讀介面（由 asset 端以結構相容實作，asset 不 import authz）。
type ScopeTopology interface {
	// AssetCoverNodes 資產的掛載節點加未刪除祖先；未刪除的資產才 exists。
	AssetCoverNodes(tx *gorm.DB, assetID uint) (nodeIDs []uint, exists bool, err error)
	// NodeCoverNodes 節點自身加未刪除祖先；已刪除的節點 exists=false。
	NodeCoverNodes(tx *gorm.DB, nodeID uint) (nodeIDs []uint, exists bool, err error)
	// AccountAsset 帳號所屬的資產。
	AccountAsset(tx *gorm.DB, accountID uint) (assetID uint, exists bool, err error)
	// CandidateAccount 改密候選所屬的帳號；不存在的候選 exists=false。
	CandidateAccount(tx *gorm.DB, candidateID uint) (accountID uint, exists bool, err error)
	// SubtreeAssetIDs 回子查詢：節點子樹內的資產。
	SubtreeAssetIDs(tx *gorm.DB, roots []uint) *gorm.DB
	// SubtreeNodeIDs 回子查詢：節點子樹內的節點。
	SubtreeNodeIDs(tx *gorm.DB, roots []uint) *gorm.DB
	CredentialOwnershipTopology
}

// CredentialOwnershipTopology 憑證歸屬的唯讀事實（同由 asset 端的拓撲讀取器實作；authz 不直接讀憑證與掛載表）。
type CredentialOwnershipTopology interface {
	// CredentialOwnership 憑證的歸屬種類與歸屬節點；已刪除或不存在 exists=false，未回填的歸屬 kind 為空。
	CredentialOwnership(tx *gorm.DB, credentialID uint) (kind string, nodeID *uint, exists bool, err error)
	// CredentialFirstMountAsset 憑證最早一筆未刪除掛載所屬的資產；沒有掛載回 0。
	CredentialFirstMountAsset(tx *gorm.DB, credentialID uint) (assetID uint, err error)
	// CredentialsFirstMountedOn 回子查詢：最早一筆未刪除掛載落在 assetIDs（子查詢）上的憑證。
	CredentialsFirstMountedOn(tx *gorm.DB, assetIDs *gorm.DB) *gorm.DB
	// CredentialsByID 回以 credentials 為主表、限定在 ids 內且未刪除的查詢。
	CredentialsByID(tx *gorm.DB, ids []uint) *gorm.DB
}

// ResolvedScopeTarget 目標解析結果。
type ResolvedScopeTarget struct {
	Exists     bool
	Layer      ScopeDeniedLayer // Exists=false 時哪一層不成立
	CoverNodes []uint           // 目標的掛載節點加未刪除祖先（節點目標為自身加未刪除祖先）；帳號層不成立時帶所屬資產的涵蓋節點，供判定器先判資產範圍
}

// ScopeTargetResolver 目標解析器。
type ScopeTargetResolver func(tx *gorm.DB, topo ScopeTopology, t ScopeTarget) (ResolvedScopeTarget, error)

// ScopeTargetResolverRegistration 建構判定器時登記後段種類的解析器。
type ScopeTargetResolverRegistration struct {
	Kind    ScopeTargetKind
	Resolve ScopeTargetResolver
}

// ErrScopeNilPrincipal 沒有主體就要求範圍判定。
var ErrScopeNilPrincipal = errors.New("authz: scope decision without principal")

var errScopeNilTx = errors.New("authz: scope decision without transaction")

// ScopeEvaluator 範圍判定器；建構後不可變。
type ScopeEvaluator struct {
	cat       Catalogue
	topo      ScopeTopology
	resolvers map[ScopeTargetKind]ScopeTargetResolver
}

// NewScopeEvaluator 建構判定器；cat 與 extra 在建構時複製。
func NewScopeEvaluator(cat Catalogue, topo ScopeTopology, extra ...ScopeTargetResolverRegistration) *ScopeEvaluator {
	rs := builtinScopeResolvers()
	for _, r := range extra {
		rs[r.Kind] = r.Resolve
	}
	return &ScopeEvaluator{cat: cat, topo: topo, resolvers: rs}
}

// Decide 判定主體對目標是否持有權限點（順序見 decideOn）。tx 為呼叫方交易：
// 主體在 tx 內重解，目標與拓撲也在 tx 內讀；本函式不取鎖、不寫表、不快取。
// 讀取失敗回錯誤，呼叫方不得視為放行或不存在。
//
// 呼叫方的交易若要與拓撲寫入序列化，先以 LockScopeTopologyTx 取鎖、再呼叫本函式：交易維持
// Read Committed，取鎖後的每個語句都讀得到取鎖前已提交的變更；取鎖前讀到的主體只作輸入檢查，
// 傳進來也不會被沿用。
func (e *ScopeEvaluator) Decide(tx *gorm.DB, principal *Principal, perm Permission, target ScopeTarget) (ScopeResult, error) {
	res, _, err := e.decideResolved(tx, principal, perm, target)
	return res, err
}

// DecideWithDenial 與 Decide 同一判定路徑（交易、重解主體與讀取規則皆同），另回範圍拒絕的錯誤值：
// 範圍拒絕時為 *ErrScopeDenied（目標種類、判定得出的不成立層次、原因），放行與能力拒絕時為 nil。
// 讀取失敗回 (ScopeResult{}, nil, err)；拒絕不放在 err 裡，err 仍只代表讀取失敗，不得當成不存在。
//
// 帳號目標要分辨「資產不成立」與「帳號不成立」時，以本函式取層次，不依目標種類推定：
// 資產在範圍內而帳號不屬於它時是帳號層，只看種類會誤標成資產層。
// 呼叫方要把拒絕當 error 往上傳時，只在非 nil 時轉型，避免帶型別的 nil 介面值。
func (e *ScopeEvaluator) DecideWithDenial(tx *gorm.DB, principal *Principal, perm Permission, target ScopeTarget) (ScopeResult, *ErrScopeDenied, error) {
	res, layer, err := e.decideResolved(tx, principal, perm, target)
	if err != nil {
		return ScopeResult{}, nil, err
	}
	if res.Outcome != ScopeDenyScope {
		return res, nil, nil
	}
	return res, NewErrScopeDenied(target.Kind, layer, res.Reason), nil
}

// decideResolved 檢查輸入、在 tx 內重解主體後交給 decideOn；Decide 與 DecideWithDenial 共用。
func (e *ScopeEvaluator) decideResolved(tx *gorm.DB, principal *Principal, perm Permission, target ScopeTarget) (ScopeResult, ScopeDeniedLayer, error) {
	if principal == nil {
		return ScopeResult{}, "", ErrScopeNilPrincipal
	}
	if tx == nil {
		return ScopeResult{}, "", errScopeNilTx
	}
	// 只取伺服器端脈絡；傳入主體的指派與能力一律忽略，以 tx 內狀態為準
	p, err := ResolveUserOnWithCatalogue(tx, e.cat, principal.UserID, principal.Facts)
	if err != nil {
		return ScopeResult{}, "", err
	}
	return e.decideOn(tx, p, perm, target)
}

// decideOn 在已解析的主體上判定；回傳的層次只在範圍拒絕時有值（供組出 ErrScopeDenied）。
// 順序：超管、能力（與 Has 同源）、全域來源（不解析目標）、節點範圍來源（逐指派）。
func (e *ScopeEvaluator) decideOn(tx *gorm.DB, p *Principal, perm Permission, target ScopeTarget) (ScopeResult, ScopeDeniedLayer, error) {
	if p == nil {
		return ScopeResult{}, "", ErrScopeNilPrincipal
	}
	if p.IsSuperAdmin() {
		return ScopeResult{Outcome: ScopeAllow}, "", nil
	}
	global, nodeSets := p.scopeSources(perm)
	if !p.Has(perm) { // Has 為真 ⇔ 至少一個來源；兩者同源，這裡以 Has 為準
		return ScopeResult{Outcome: ScopeDenyCapability, Reason: ScopeReasonNoEffectiveBinding}, "", nil
	}
	if global {
		return ScopeResult{Outcome: ScopeAllow}, "", nil
	}
	denyScope := func(r ScopeReason, layer ScopeDeniedLayer) (ScopeResult, ScopeDeniedLayer, error) {
		return ScopeResult{Outcome: ScopeDenyScope, Reason: r}, layer, nil
	}
	if e.topo == nil {
		return denyScope(ScopeReasonTopologyUnavailable, defaultScopeLayer(target.Kind))
	}
	resolve := e.resolvers[target.Kind]
	if resolve == nil {
		return denyScope(ScopeReasonResolverMissing, ScopeLayerTarget)
	}
	rt, err := resolve(tx, e.topo, target)
	if err != nil {
		return ScopeResult{}, "", err
	}
	covered := func() bool {
		cover := make(map[uint]struct{}, len(rt.CoverNodes))
		for _, n := range rt.CoverNodes {
			cover[n] = struct{}{}
		}
		for _, set := range nodeSets { // 每個來源各自比對，不把多個來源的節點併成一個集合
			for _, n := range set {
				if _, ok := cover[n]; ok {
					return true
				}
			}
		}
		return false
	}
	if !rt.Exists {
		// 帳號層不成立時解析器仍帶回所屬資產的涵蓋節點：資產在範圍外就標資產層，
		// 使範圍外資產不因帳號是否屬於它而出現層次差異。其餘不成立的解析結果無涵蓋節點
		if rt.Layer == ScopeLayerAccount && !covered() {
			return denyScope(ScopeReasonOutOfScope, ScopeLayerAsset)
		}
		return denyScope(ScopeReasonOutOfScope, rt.Layer)
	}
	if covered() {
		return ScopeResult{Outcome: ScopeAllow}, "", nil
	}
	return denyScope(ScopeReasonOutOfScope, rt.Layer)
}

// defaultScopeLayer 解析前（拓撲缺席）拒絕時標示的層次：內建種類取其主層，其餘為單層目標。
func defaultScopeLayer(k ScopeTargetKind) ScopeDeniedLayer {
	switch k {
	case ScopeTargetAsset, ScopeTargetAssetAccount:
		return ScopeLayerAsset
	case ScopeTargetNode:
		return ScopeLayerNode
	}
	return ScopeLayerTarget
}
