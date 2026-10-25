package authz

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 共用憑證歸屬的交易內範圍判定，實作 asset 的消費者側窄介面 CredentialOwnershipScopePort。
//
// 呼叫方先在同一交易取拓撲序列化鎖，再呼叫本檔方法；主體在交易內重解（傳入主體的指派一律忽略）。
// 判定依該建立動作自己的權限點（credential:create 或 credential:convert-scope）的一般三態集合：
//
//   - 不限（超管或任一全域來源）：未帶歸屬預設全域；全域與任一節點皆可（節點存在性由呼叫方驗）。
//   - 條件（只有節點範圍來源）：必須帶節點歸屬，節點須在有效節點集合內；範圍外、已刪除與不存在
//     回同一個節點範圍拒絕值（由判定器對節點目標判出）；要求全域回能力拒絕（單一 forbidden）。
//   - 空：能力拒絕。
var (
	errCredentialOwnershipScopeUnwired = errors.New("authz: credential ownership scope without evaluator or topology")
	errCredentialOwnershipPermUnknown  = errors.New("authz: credential ownership with unsupported permission")
	// errCredentialOwnershipInconsistent 物化集合判為範圍外，判定器對同一節點卻未判出範圍拒絕。
	errCredentialOwnershipInconsistent = errors.New("authz: credential ownership decision inconsistent with topology")
)

// CredentialOwnershipCapabilityError 交易內重解後主體不持有該權限點，或範圍化主體要求全域歸屬（能力拒絕）。
type CredentialOwnershipCapabilityError struct {
	Perm Permission
}

// Error 固定字串，不含權限點或名稱。
func (e *CredentialOwnershipCapabilityError) Error() string {
	return "authz: credential ownership without capability"
}

// CredentialOwnershipScope 共用憑證歸屬的範圍判定。零值不可用；以 NewCredentialOwnershipScope 建立。
type CredentialOwnershipScope struct {
	e *ScopeEvaluator
}

// NewCredentialOwnershipScope 以判定器（目錄與拓撲）建立。
func NewCredentialOwnershipScope(e *ScopeEvaluator) *CredentialOwnershipScope {
	return &CredentialOwnershipScope{e: e}
}

var _ asset.CredentialOwnershipScopePort = (*CredentialOwnershipScope)(nil)

func credentialOwnershipPerm(capability string) (Permission, bool) {
	switch Permission(capability) {
	case PermCredentialCreate, PermCredentialConvertScope:
		return Permission(capability), true
	}
	return "", false
}

// ownershipPrincipal ctx 內同一使用者的主體只提供伺服器端脈絡；背景工作（批次）沒有請求主體，以發起者識別重解。
func ownershipPrincipal(ctx context.Context, actorUserID uint) *Principal {
	if p := PrincipalFromContext(ctx); p != nil && p.UserID == actorUserID {
		return p
	}
	return &Principal{UserID: actorUserID}
}

// AuthorizeSharedOwnership 見檔頭規則。
func (w *CredentialOwnershipScope) AuthorizeSharedOwnership(ctx context.Context, tx *gorm.DB, actorUserID uint,
	capability string, requested *asset.CredentialOwnershipInput) (asset.CredentialOwnership, error) {

	if w == nil || w.e == nil || w.e.topo == nil {
		return asset.CredentialOwnership{}, errCredentialOwnershipScopeUnwired
	}
	perm, ok := credentialOwnershipPerm(capability)
	if !ok {
		return asset.CredentialOwnership{}, errCredentialOwnershipPermUnknown
	}
	if actorUserID == 0 {
		return asset.CredentialOwnership{}, &CredentialOwnershipCapabilityError{Perm: perm}
	}
	principal := ownershipPrincipal(ctx, actorUserID)
	p, err := w.e.resolveInTx(tx, principal)
	if err != nil {
		return asset.CredentialOwnership{}, err
	}
	s, err := w.e.materialize(tx, scopeSetOn(p, perm, sourcesAll))
	if err != nil {
		return asset.CredentialOwnership{}, err
	}
	switch s.state {
	case ScopeSetUnlimited:
		return unlimitedOwnership(requested), nil
	case ScopeSetConditional:
	default:
		return asset.CredentialOwnership{}, &CredentialOwnershipCapabilityError{Perm: perm}
	}
	if requested == nil {
		return asset.CredentialOwnership{}, asset.ErrCredentialOwnershipInvalid
	}
	if requested.Kind != model.CredentialOwnerNode || requested.NodeID == nil {
		return asset.CredentialOwnership{}, &CredentialOwnershipCapabilityError{Perm: perm}
	}
	id := *requested.NodeID
	if s.nodes[id] {
		return asset.CredentialOwnership{Kind: model.CredentialOwnerNode, NodeID: &id}, nil
	}
	_, denied, err := w.e.DecideWithDenial(tx, principal, perm, NodeTarget(id))
	if err != nil {
		return asset.CredentialOwnership{}, err
	}
	if denied != nil {
		return asset.CredentialOwnership{}, denied
	}
	return asset.CredentialOwnership{}, errCredentialOwnershipInconsistent
}

// unlimitedOwnership 不限範圍的主體：未帶即全域，帶什麼寫什麼（形狀已由呼叫方驗過）。
func unlimitedOwnership(requested *asset.CredentialOwnershipInput) asset.CredentialOwnership {
	if requested == nil || requested.Kind == model.CredentialOwnerGlobal || requested.NodeID == nil {
		return asset.CredentialOwnership{Kind: model.CredentialOwnerGlobal}
	}
	id := *requested.NodeID
	return asset.CredentialOwnership{Kind: model.CredentialOwnerNode, NodeID: &id}
}

// AuthorizeOwnershipChange 改歸的範圍判定（credential:update）：見 asset.CredentialOwnershipScopePort。
//
// 判定順序：能力（空集合即能力拒絕）→ 目的歸屬（條件範圍下要求全域為能力拒絕；範圍外、已刪除與
// 不存在的節點回同一個範圍拒絕值）→ 逐筆現行歸屬（全域或範圍外節點＝不可操作，只回布林、不回原因）。
func (w *CredentialOwnershipScope) AuthorizeOwnershipChange(ctx context.Context, tx *gorm.DB, actorUserID uint,
	capability string, target asset.CredentialOwnershipInput, current []asset.CredentialOwnership) ([]bool, error) {

	if w == nil || w.e == nil || w.e.topo == nil {
		return nil, errCredentialOwnershipScopeUnwired
	}
	if Permission(capability) != PermCredentialUpdate {
		return nil, errCredentialOwnershipPermUnknown
	}
	perm := PermCredentialUpdate
	if actorUserID == 0 {
		return nil, &CredentialOwnershipCapabilityError{Perm: perm}
	}
	principal := ownershipPrincipal(ctx, actorUserID)
	p, err := w.e.resolveInTx(tx, principal)
	if err != nil {
		return nil, err
	}
	s, err := w.e.materialize(tx, scopeSetOn(p, perm, sourcesAll))
	if err != nil {
		return nil, err
	}
	allowed := make([]bool, len(current))
	switch s.state {
	case ScopeSetUnlimited:
		for i := range allowed {
			allowed[i] = true
		}
		return allowed, nil
	case ScopeSetConditional:
	default:
		return nil, &CredentialOwnershipCapabilityError{Perm: perm}
	}
	if target.Kind != model.CredentialOwnerNode || target.NodeID == nil {
		return nil, &CredentialOwnershipCapabilityError{Perm: perm}
	}
	if id := *target.NodeID; !s.nodes[id] {
		_, denied, derr := w.e.DecideWithDenial(tx, principal, perm, NodeTarget(id))
		if derr != nil {
			return nil, derr
		}
		if denied != nil {
			return nil, denied
		}
		return nil, errCredentialOwnershipInconsistent
	}
	for i, c := range current {
		allowed[i] = c.Kind == model.CredentialOwnerNode && c.NodeID != nil && s.nodes[*c.NodeID]
	}
	return allowed, nil
}
