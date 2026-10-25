package api

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// assetTagReference 標籤書寫歸一參照的可視集合：範圍化檢視者取與資產列表同一聯集（scopedVisibleUnion），
// 其他主體回 scoped=false（全表，現行）。主體取自 ctx。
//
// 系統呼叫者在 asset 端已直接取全表、不會呼叫到這裡；走到這裡卻沒有主體，表示使用者請求路徑漏接主體，
// 一律回錯誤（fail-close），不得退回全表——全表參照會把只在範圍外出現的寫法歸一進範圍化主體的資產。
//
// 連線可視集合由授權服務讀取、不在呼叫方交易內；只影響書寫歸一的參照，不是授權判定。
type assetTagReference struct {
	auth  AssetAuthorizationServiceInterface
	scope AssetScopeSource
}

var (
	errTagReferenceUnwired     = errors.New("api: tag reference source not wired")
	errTagReferenceNoPrincipal = errors.New("api: tag reference requires a principal on non-system calls")
)

// NewAssetTagReference 以授權服務與範圍化讀取器建立歸一參照來源（組裝根注入 AssetService）。
func NewAssetTagReference(auth AssetAuthorizationServiceInterface, scope AssetScopeSource) asset.TagReferencePort {
	return &assetTagReference{auth: auth, scope: scope}
}

// VisibleAssetIDsTx 見 asset.TagReferencePort。
func (r *assetTagReference) VisibleAssetIDsTx(ctx context.Context, _ *gorm.DB) ([]uint, bool, error) {
	if r == nil || r.auth == nil || r.scope == nil {
		return nil, false, errTagReferenceUnwired
	}
	p := authz.PrincipalFromContext(ctx)
	if p == nil {
		return nil, false, errTagReferenceNoPrincipal
	}
	v, err := r.scope.View(ctx)
	if err != nil {
		return nil, false, err
	}
	if v == nil {
		return nil, false, nil
	}
	_, _, union, err := scopedVisibleUnion(ctx, r.auth, r.scope, v, p, p.UserID)
	if err != nil {
		return nil, false, err
	}
	return union, true, nil
}
