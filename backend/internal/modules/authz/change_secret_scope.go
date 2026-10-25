package authz

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// ChangeSecretScope 批次改密的範圍判定：拓撲序列化鎖、不帶目標的能力檢核與資產範圍子查詢。
// 主體一律在呼叫方交易內重解，不讀請求進入時的快取。
type ChangeSecretScope struct {
	e *ScopeEvaluator
}

// NewChangeSecretScope 以判定器（目錄與拓撲）建立。
func NewChangeSecretScope(e *ScopeEvaluator) *ChangeSecretScope {
	return &ChangeSecretScope{e: e}
}

var _ asset.ChangeSecretScopePort = (*ChangeSecretScope)(nil)

var (
	errChangeSecretScopeUnwired  = errors.New("authz: change-secret scope without evaluator or topology")
	errChangeSecretScopePermUnkn = errors.New("authz: change-secret scope for unsupported permission")
)

// LockTopology 取拓撲序列化鎖（與其他拓撲寫入同一把）。
func (s *ChangeSecretScope) LockTopology(tx *gorm.DB) error { return LockScopeTopologyTx(tx) }

// CapabilityMissing 見 asset.ChangeSecretScopePort。
func (s *ChangeSecretScope) CapabilityMissing(ctx context.Context, tx *gorm.DB, actorUserID uint,
	caps []string) (string, error) {

	if s == nil || s.e == nil {
		return "", errChangeSecretScopeUnwired
	}
	return s.e.CredentialCapabilityMissing(ctx, tx, actorUserID, caps)
}

// AssetScope 見 asset.ChangeSecretScopePort；只接受帳號改密與憑證改密兩個權限點。
func (s *ChangeSecretScope) AssetScope(ctx context.Context, tx *gorm.DB, actorUserID uint,
	capability string) (asset.ChangeSecretAssetScope, error) {

	if s == nil || s.e == nil || s.e.topo == nil {
		return asset.ChangeSecretAssetScope{}, errChangeSecretScopeUnwired
	}
	perm := Permission(capability)
	if perm != PermAccountRotate && perm != PermCredentialRotate {
		return asset.ChangeSecretAssetScope{}, fmt.Errorf("%w: %q", errChangeSecretScopePermUnkn, capability)
	}
	if actorUserID == 0 {
		return asset.ChangeSecretAssetScope{}, ErrScopeNilPrincipal
	}
	set, err := s.e.ScopeSetFor(tx, ownershipPrincipal(ctx, actorUserID), perm)
	if err != nil {
		return asset.ChangeSecretAssetScope{}, err
	}
	if set.State() == ScopeSetUnlimited {
		return asset.ChangeSecretAssetScope{}, nil
	}
	q, err := s.e.ApplyScopeSet(tx, tx.Model(&model.Asset{}).Select("assets.id"), set, ScopeQueryAsset)
	if err != nil {
		return asset.ChangeSecretAssetScope{}, err
	}
	return asset.ChangeSecretAssetScope{Limited: true, AssetIDs: q}, nil
}

// ViewScope 見 asset.ChangeSecretScopePort：改密頁讀取投影的資產範圍。
//
// 與 AssetScope 同一個能力的三態集合，另加一條相容規則：主體完全不持有該能力時，
// 以頁面入口的權限點判斷——入口權限點有全系統來源者維持全量（現行行為），否則為空。
// 只經節點範圍持有該能力者收斂為其範圍內資產。
func (s *ChangeSecretScope) ViewScope(ctx context.Context, db *gorm.DB, actorUserID uint,
	capability string) (asset.ChangeSecretAssetScope, error) {

	if s == nil || s.e == nil || s.e.topo == nil {
		return asset.ChangeSecretAssetScope{}, errChangeSecretScopeUnwired
	}
	perm := Permission(capability)
	if perm != PermAccountRotate && perm != PermCredentialRotate {
		return asset.ChangeSecretAssetScope{}, fmt.Errorf("%w: %q", errChangeSecretScopePermUnkn, capability)
	}
	if actorUserID == 0 {
		return asset.ChangeSecretAssetScope{}, ErrScopeNilPrincipal
	}
	p, err := s.e.resolveInTx(db, ownershipPrincipal(ctx, actorUserID))
	if err != nil {
		return asset.ChangeSecretAssetScope{}, err
	}
	if changeSecretViewUnlimited(p, perm) {
		return asset.ChangeSecretAssetScope{}, nil
	}
	set := scopeSetOn(p, perm, sourcesAll)
	q, err := s.e.ApplyScopeSet(db, db.Model(&model.Asset{}).Select("assets.id"), set, ScopeQueryAsset)
	if err != nil {
		return asset.ChangeSecretAssetScope{}, err
	}
	return asset.ChangeSecretAssetScope{Limited: true, AssetIDs: q}, nil
}

// changeSecretViewUnlimited 讀取投影是否不限範圍：超管、該能力有全系統來源，或沒有任何含該能力的
// 角色指派而改密頁入口權限點有全系統來源（現行行為）。仍有含該能力的節點範圍指派、只是有效節點已空者
// 不屬相容全量，收斂為空集合（節點範圍指派的空集合不生效，也不回退成全域）。
func changeSecretViewUnlimited(p *Principal, perm Permission) bool {
	if scopeSetOn(p, perm, sourcesAll).State() == ScopeSetUnlimited {
		return true
	}
	return !p.Has(perm) && !p.assignsPermission(perm) &&
		scopeSetOn(p, PermChangeSecretManage, sourcesAll).State() == ScopeSetUnlimited
}

// CandidateDenial 見 asset.ChangeSecretScopePort：候選所屬資產（候選 → 帳號 → 資產）是否在檢視者的
// 帳號改密讀取範圍內。範圍外與不存在回判定器給的候選種類範圍拒絕值（由出口回「候選不存在」）；
// 完全不持有帳號改密且不屬相容全量者回 asset.ErrCandidateNotFound（同一個 404）。
func (s *ChangeSecretScope) CandidateDenial(ctx context.Context, db *gorm.DB, actorUserID, candidateID uint) error {
	if s == nil || s.e == nil || s.e.topo == nil {
		return errChangeSecretScopeUnwired
	}
	if actorUserID == 0 {
		return ErrScopeNilPrincipal
	}
	principal := ownershipPrincipal(ctx, actorUserID)
	p, err := s.e.resolveInTx(db, principal)
	if err != nil {
		return err
	}
	if changeSecretViewUnlimited(p, PermAccountRotate) {
		return nil
	}
	if !p.Has(PermAccountRotate) {
		return asset.ErrCandidateNotFound
	}
	res, denied, err := s.e.DecideWithDenial(db, principal, PermAccountRotate, ChangeSecretCandidateTarget(candidateID))
	if err != nil {
		return err
	}
	if denied != nil {
		return denied
	}
	if res.Outcome != ScopeAllow {
		return asset.ErrCandidateNotFound
	}
	return nil
}

// CredentialsVisible 見 asset.ChangeSecretScopePort：憑證歸屬（歸屬口徑，同憑證庫）是否在檢視者該能力的
// 讀取範圍內。不限範圍時回 (nil, true)；否則逐筆判定，回可見的憑證識別集合。
func (s *ChangeSecretScope) CredentialsVisible(ctx context.Context, db *gorm.DB, actorUserID uint,
	capability string, credentialIDs []uint) (map[uint]bool, bool, error) {

	if s == nil || s.e == nil || s.e.topo == nil {
		return nil, false, errChangeSecretScopeUnwired
	}
	perm := Permission(capability)
	if perm != PermAccountRotate && perm != PermCredentialRotate {
		return nil, false, fmt.Errorf("%w: %q", errChangeSecretScopePermUnkn, capability)
	}
	if actorUserID == 0 {
		return nil, false, ErrScopeNilPrincipal
	}
	p, err := s.e.resolveInTx(db, ownershipPrincipal(ctx, actorUserID))
	if err != nil {
		return nil, false, err
	}
	if changeSecretViewUnlimited(p, perm) {
		return nil, true, nil
	}
	out := map[uint]bool{}
	if !p.Has(perm) {
		return out, false, nil
	}
	for _, id := range credentialIDs {
		missing, denied, err := s.e.DecideCredentialManagement(ctx, db, actorUserID, []string{capability}, []uint{id}, nil)
		if err != nil {
			return nil, false, err
		}
		if missing == "" && denied == nil {
			out[id] = true
		}
	}
	return out, false, nil
}
