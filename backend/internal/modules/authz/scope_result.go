package authz

// 節點範圍授權的判定結果、原因碼、拒絕錯誤與目標種類。
//
// 與路由層的 Decision 是不同型別，不互相轉換。結果不帶權限鍵、目標、節點、使用者、
// 群組、ID 清單、SQL 或錯誤字串；呼叫端需要的 required 由出口依呼叫端權限點填寫。

// ScopeOutcome 判定的三分類。零值不是合法結果。
type ScopeOutcome uint8

const (
	ScopeAllow          ScopeOutcome = iota + 1 // "allow"
	ScopeDenyCapability                         // "deny_capability"
	ScopeDenyScope                              // "deny_scope"
)

// String 回傳穩定的機器字串；零值與未知值回 "invalid"。
func (o ScopeOutcome) String() string {
	switch o {
	case ScopeAllow:
		return "allow"
	case ScopeDenyCapability:
		return "deny_capability"
	case ScopeDenyScope:
		return "deny_scope"
	}
	return "invalid"
}

// ScopeReason 受控原因碼。
type ScopeReason string

const (
	ScopeReasonNone                ScopeReason = ""                     // 只配 ScopeAllow
	ScopeReasonNoEffectiveBinding  ScopeReason = "no_effective_binding" // 只配 ScopeDenyCapability
	ScopeReasonOutOfScope          ScopeReason = "out_of_scope"         // 不存在、已刪除、範圍外三者同一值
	ScopeReasonResolverMissing     ScopeReason = "resolver_missing"
	ScopeReasonTopologyUnavailable ScopeReason = "topology_unavailable"
)

// ScopeResult 一次範圍判定的結果。零值（Outcome 0）不是合法結果，呼叫方遇到即當錯誤，不得當放行。
type ScopeResult struct {
	Outcome ScopeOutcome
	Reason  ScopeReason
}

// ScopeDeniedLayer 目標不成立的層次。
type ScopeDeniedLayer string

const (
	ScopeLayerAsset   ScopeDeniedLayer = "asset"
	ScopeLayerAccount ScopeDeniedLayer = "account"
	ScopeLayerNode    ScopeDeniedLayer = "node"
	ScopeLayerTarget  ScopeDeniedLayer = "target" // 後段登記種類（憑證、授權規則、審核範圍等）的單層目標
)

// ErrScopeDenied 服務層以 errors.As 判斷的範圍拒絕，不是 apierror 碼。
type ErrScopeDenied struct {
	Kind   ScopeTargetKind
	Layer  ScopeDeniedLayer
	Reason ScopeReason // 只取 ScopeDenyScope 的三個原因之一（out_of_scope、resolver_missing、topology_unavailable）
}

// Error 固定字串，不含任何 ID 或名稱。
func (e *ErrScopeDenied) Error() string { return "authz: scope denied" }

// ScopeDeniedTargetKind 目標種類的機器字串。不 import authz 的模組以介面辨識拒絕值的目標種類
// （例如批次服務只把資產種類的拒絕計入無法操作、憑證服務把掛載所在資產的拒絕改成掛載不存在），
// 不必也不得自行建構拒絕值。
func (e *ErrScopeDenied) ScopeDeniedTargetKind() string { return string(e.Kind) }

// NewErrScopeDenied 建立範圍拒絕錯誤。
func NewErrScopeDenied(kind ScopeTargetKind, layer ScopeDeniedLayer, reason ScopeReason) *ErrScopeDenied {
	return &ErrScopeDenied{Kind: kind, Layer: layer, Reason: reason}
}

// ScopeTargetKind 目標種類。
type ScopeTargetKind string

const (
	ScopeTargetAsset        ScopeTargetKind = "asset"
	ScopeTargetAssetAccount ScopeTargetKind = "asset_account"
	ScopeTargetNode         ScopeTargetKind = "node"
)

// ScopeTarget 判定的目標。
type ScopeTarget struct {
	Kind      ScopeTargetKind
	AssetID   uint // asset、asset_account
	AccountID uint // asset_account
	NodeID    uint // node
	RefID     uint // 後段登記的種類用（例如憑證 ID）；前三種不用
}

// AssetTarget 資產目標。
func AssetTarget(assetID uint) ScopeTarget {
	return ScopeTarget{Kind: ScopeTargetAsset, AssetID: assetID}
}

// AssetAccountTarget 資產帳號目標。
func AssetAccountTarget(assetID, accountID uint) ScopeTarget {
	return ScopeTarget{Kind: ScopeTargetAssetAccount, AssetID: assetID, AccountID: accountID}
}

// NodeTarget 節點目標。
func NodeTarget(nodeID uint) ScopeTarget {
	return ScopeTarget{Kind: ScopeTargetNode, NodeID: nodeID}
}
