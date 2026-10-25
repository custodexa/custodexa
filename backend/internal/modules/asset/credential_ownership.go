package asset

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 憑證管理歸屬的寫入規則。
//
// 歸屬回答「誰能管理這筆憑證」，與共用／專用（Scope）是兩件事：共用憑證歸屬全域或一個節點，
// 專用憑證一律隨資產（依其唯一掛載的資產判定）。每個建立新憑證或改變 Scope 的交易，
// 都在同一交易內寫入歸屬欄，不以 GORM hook 補預設、不由建立者動態推導。
//
// 共用憑證的歸屬判定交給消費者側窄介面 CredentialOwnershipScopePort（組裝根注入 authz 的實作）：
// 判定在呼叫端交易內、拓撲序列化鎖之後執行，主體在交易內重解。未注入時 fail-close，
// 不退回「一律全域」——那會讓節點範圍的主體建出只有全域主體才能管理的憑證。

// CredentialOwnershipInput 請求帶的歸屬（nil＝未帶）。
type CredentialOwnershipInput struct {
	// Kind global｜node（asset 不接受由請求指定）
	Kind string `json:"kind"`
	// NodeID Kind=node 時必填
	NodeID *uint `json:"node_id,omitempty"`
}

// CredentialOwnership 判定後要寫入的歸屬。
type CredentialOwnership struct {
	Kind   string
	NodeID *uint
}

// CredentialOwnershipScopePort 共用憑證歸屬的交易內範圍判定（tx-taking 窄介面）。
//
// 呼叫端已在同一交易取得拓撲序列化鎖；實作在 tx 內重解 actorUserID 的主體（ctx 內同一使用者的主體
// 只提供伺服器端脈絡，其指派一律忽略），依 capability（credential:create 或 credential:convert-scope）
// 的指派範圍判定：
//
//   - requested 為 nil：不限範圍的主體回 global；只經節點範圍持有者回 ErrCredentialOwnershipInvalid。
//   - global：限不限範圍的主體；其餘回能力拒絕（單一 forbidden）。
//   - node：不限範圍的主體回該節點（存在性由呼叫端驗）；條件範圍下節點須在範圍內，
//     範圍外、已刪除與不存在回同一個節點範圍拒絕值。
//
// AuthorizeOwnershipChange（改歸，capability 為 credential:update）：target 為形狀已驗過的新歸屬；
// 不限範圍的主體一律可（目的節點存在性由呼叫端驗）；條件範圍下 target 須為範圍內節點
// （要求全域回能力拒絕，範圍外與不存在回同一個節點範圍拒絕值），並逐筆回報 current 是否在範圍內
// （全域歸屬或範圍外節點＝不可操作）。回傳切片與 current 等長。
//
// 能力拒絕與範圍拒絕以實作方的錯誤值回傳，交 handler 的共用出口；本介面不寫表、不推進權限版本。
type CredentialOwnershipScopePort interface {
	AuthorizeSharedOwnership(ctx context.Context, tx *gorm.DB, actorUserID uint, capability string,
		requested *CredentialOwnershipInput) (CredentialOwnership, error)
	AuthorizeOwnershipChange(ctx context.Context, tx *gorm.DB, actorUserID uint, capability string,
		target CredentialOwnershipInput, current []CredentialOwnership) ([]bool, error)
}

var (
	// ErrCredentialOwnershipInvalid 歸屬欄不合法：kind 值域外、node 缺節點、global 帶節點、
	// 對專用憑證指定歸屬，或範圍化主體未帶歸屬。
	ErrCredentialOwnershipInvalid = errors.New("憑證歸屬不合法")
	// ErrCredentialOwnershipScopeUnwired 歸屬判定未注入；整筆回滾（回 500，不放行）。
	ErrCredentialOwnershipScopeUnwired = errors.New("asset: credential ownership scope not injected")
)

// WithOwnershipScope 注入共用憑證歸屬的範圍判定（組裝根）。
func (s *CredentialService) WithOwnershipScope(p CredentialOwnershipScopePort) *CredentialService {
	s.ownership = p
	return s
}

// WithOwnershipScope 注入批次整組模式建立共用憑證時的歸屬判定（組裝根）。
func (r *ChangeSecretRunner) WithOwnershipScope(p CredentialOwnershipScopePort) *ChangeSecretRunner {
	r.ownership = p
	return r
}

// ValidateCredentialOwnershipInput 歸屬欄的形狀檢查（不查範圍、不查節點存在）；nil＝未帶，合法。
func ValidateCredentialOwnershipInput(in *CredentialOwnershipInput) error {
	if in == nil {
		return nil
	}
	switch in.Kind {
	case model.CredentialOwnerGlobal:
		if in.NodeID != nil {
			return ErrCredentialOwnershipInvalid
		}
	case model.CredentialOwnerNode:
		if in.NodeID == nil || *in.NodeID == 0 {
			return ErrCredentialOwnershipInvalid
		}
	default:
		return ErrCredentialOwnershipInvalid
	}
	return nil
}

// dedicatedOwnership 專用憑證的歸屬：隨資產。
func dedicatedOwnership() CredentialOwnership {
	return CredentialOwnership{Kind: model.CredentialOwnerAsset}
}

// resolveSharedOwnershipTx 在呼叫端交易（已取拓撲序列化鎖）內判定新共用憑證的歸屬。
// 判定器回節點歸屬時另驗節點存在（不限範圍的主體不經目標解析）；不存在回 ErrNodeNotFound。
func resolveSharedOwnershipTx(ctx context.Context, tx *gorm.DB, p CredentialOwnershipScopePort,
	actorUserID uint, capability string, requested *CredentialOwnershipInput) (CredentialOwnership, error) {

	if err := ValidateCredentialOwnershipInput(requested); err != nil {
		return CredentialOwnership{}, err
	}
	if p == nil {
		return CredentialOwnership{}, ErrCredentialOwnershipScopeUnwired
	}
	o, err := p.AuthorizeSharedOwnership(ctx, tx, actorUserID, capability, requested)
	if err != nil {
		return CredentialOwnership{}, err
	}
	switch o.Kind {
	case model.CredentialOwnerGlobal:
		if o.NodeID != nil {
			return CredentialOwnership{}, fmt.Errorf("asset: ownership scope returned global with node")
		}
	case model.CredentialOwnerNode:
		if o.NodeID == nil || *o.NodeID == 0 {
			return CredentialOwnership{}, fmt.Errorf("asset: ownership scope returned node without id")
		}
		if err := validateNodeIDsTx(tx, []uint{*o.NodeID}); err != nil {
			return CredentialOwnership{}, err
		}
	default:
		return CredentialOwnership{}, fmt.Errorf("asset: ownership scope returned kind %q", o.Kind)
	}
	return o, nil
}

// applyOwnership 把歸屬寫進尚未建立的憑證列（建立交易內，tx.Create 之前）。
func applyOwnership(cred *model.Credential, o CredentialOwnership) {
	kind := o.Kind
	cred.OwnerKind = &kind
	cred.OwnerNodeID = nil
	if o.NodeID != nil {
		id := *o.NodeID
		cred.OwnerNodeID = &id
	}
}

// ownershipColumns 既有憑證改變 Scope 或歸屬時同一筆 Updates 要帶的兩欄。
func ownershipColumns(o CredentialOwnership) map[string]any {
	var node any
	if o.NodeID != nil {
		node = *o.NodeID
	}
	return map[string]any{"owner_kind": o.Kind, "owner_node_id": node}
}

// credentialOwnershipAudit 審計 details 的歸屬投影（只帶識別，不帶節點名稱）。
type credentialOwnershipAudit struct {
	Kind   string `json:"kind"`
	NodeID *uint  `json:"node_id,omitempty"`
}

func ownershipAudit(o CredentialOwnership) *credentialOwnershipAudit {
	a := &credentialOwnershipAudit{Kind: o.Kind}
	if o.NodeID != nil {
		id := *o.NodeID
		a.NodeID = &id
	}
	return a
}

// advanceOwnershipVersionTx 建立或轉換寫入了共用憑證歸屬後，交易擁有者推進權限版本（每交易一次）。
func (s *CredentialService) advanceOwnershipVersionTx(tx *gorm.DB) error {
	return s.assets.advanceTopologyVersionTx(tx)
}

// beginOwnershipTx 共用憑證歸屬寫入交易的開頭：第一個動作取拓撲序列化鎖，其後 Begin（不取鎖）。
func (s *CredentialService) beginOwnershipTx(tx *gorm.DB) error {
	if err := s.assets.lockTopologyTx(tx); err != nil {
		return err
	}
	return s.assets.beginTopologyChangeTx(tx)
}
