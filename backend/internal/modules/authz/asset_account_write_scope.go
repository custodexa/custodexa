package authz

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
)

// 資產帳號寫入的交易內範圍判定，實作 asset 的消費者側窄介面。
//
// 呼叫方已在同一交易取拓撲序列化鎖；主體在交易內重解。帳號寫入一律依資產編輯能力，
// 帳號隨所屬資產判定（資產帳號解析器：帳號須屬於 URL 的資產）。建立沒有帳號，以所屬資產為目標判定，
// 判定器判出的資產拒絕值原樣回傳（資產層不成立，對外與「資產不存在」同碼、同出口）。
// 拒絕值一律由判定器判出，本檔不改寫種類或層次。
// 全域來源不解析目標：不存在的資產與帳號照現行由服務回報。

var _ asset.AccountWriteScopePort = (*AssetWriteScope)(nil)

// errAccountWriteDecisionInconsistent 判定結果與拒絕值的組合不合法，不放行。
var errAccountWriteDecisionInconsistent = errors.New("authz: inconsistent account write decision")

// AuthorizeAccountWrite 對 assetID 的帳號 accountID（建立時為 0）執行寫入的判定。
func (w *AssetWriteScope) AuthorizeAccountWrite(ctx context.Context, tx *gorm.DB, assetID, accountID uint) error {
	if w == nil || w.e == nil || w.e.topo == nil {
		return errAssetWriteScopeUnwired
	}
	target := AssetAccountTarget(assetID, accountID)
	if accountID == 0 {
		target = AssetTarget(assetID)
	}
	res, denied, err := w.e.DecideWithDenial(tx, PrincipalFromContext(ctx), PermAssetUpdate, target)
	if err != nil {
		return err
	}
	switch {
	case res.Outcome == ScopeAllow && denied == nil:
		return nil
	case res.Outcome == ScopeDenyCapability && denied == nil:
		return &AssetWriteCapabilityError{Perm: PermAssetUpdate}
	case res.Outcome == ScopeDenyScope && denied != nil:
		return denied
	}
	return errAccountWriteDecisionInconsistent
}
