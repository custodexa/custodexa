package authz

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
)

// 堡壘機專用帳號管理的範圍判定，實作 asset 的消費者側窄介面。
//
// 讀取、設定、更換、清除與公鑰匯出都以資產為目標判定 asset:executor-manage：
// 範圍外的拒絕值由判定器對資產目標判出（對外與資產不存在同碼、同出口），
// 不持該能力回單一形狀的能力拒絕。寫入時呼叫方已在同一交易取拓撲序列化鎖，主體在交易內重解。

var _ asset.ExecutorScopePort = (*AssetWriteScope)(nil)

// errExecutorDecisionInconsistent 判定結果與拒絕值的組合不合法，不放行。
var errExecutorDecisionInconsistent = errors.New("authz: inconsistent executor manage decision")

// AuthorizeExecutorManage 對 assetID 判定 asset:executor-manage。
func (w *AssetWriteScope) AuthorizeExecutorManage(ctx context.Context, db *gorm.DB, assetID uint) error {
	if w == nil || w.e == nil || w.e.topo == nil {
		return errAssetWriteScopeUnwired
	}
	res, denied, err := w.e.DecideWithDenial(db, PrincipalFromContext(ctx), PermAssetExecutorManage, AssetTarget(assetID))
	if err != nil {
		return err
	}
	switch {
	case res.Outcome == ScopeAllow && denied == nil:
		return nil
	case res.Outcome == ScopeDenyCapability && denied == nil:
		return &AssetWriteCapabilityError{Perm: PermAssetExecutorManage}
	case res.Outcome == ScopeDenyScope && denied != nil:
		return denied
	}
	return errExecutorDecisionInconsistent
}

var _ asset.ExecutorCredentialVisibility = (*CredentialScopeReader)(nil)

// SharedCredentialVisible 共用憑證是否在主體的憑證可見集合內：與帳號列的憑證投影同一判定
// （欄位能力不成立＝不可見；非範圍化檢視者＝可見；範圍化檢視者看憑證檢視集合）。
func (r *CredentialScopeReader) SharedCredentialVisible(ctx context.Context, credentialID uint) (bool, error) {
	shape, inView, err := r.AccountCredentialProjection(ctx, []uint{credentialID})
	if err != nil {
		return false, err
	}
	switch shape {
	case AccountCredentialFull:
		return true, nil
	case AccountCredentialScoped:
		return inView[credentialID], nil
	}
	return false, nil
}
