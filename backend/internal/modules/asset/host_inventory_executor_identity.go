package asset

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 盤點的專用帳號身分：資產有未刪除的專用帳號掛載就一律用它，不看它能不能用，也不退回預設帳號；
// 沒有掛載才委派預設帳號來源。壞掉的專用帳號要讓人看見，而不是默默換成權限較小的身分、
// 產出一份看似正常卻不完整的結果。

var (
	// ErrInventoryExecutorUnavailable 專用帳號沒有可用的秘密（沒有就位版本、讀不到憑證）。
	ErrInventoryExecutorUnavailable = errors.New("inventory: executor has no usable secret")
	// ErrInventoryExecutorBusy 專用帳號所引用的憑證整組輪替中，或掛載有未驗證的候選秘密。
	ErrInventoryExecutorBusy = errors.New("inventory: executor is being rotated")
	// ErrInventoryExecutorRateLimited 目標身分的頻率上限用盡。
	ErrInventoryExecutorRateLimited = errors.New("inventory: executor sign-in rate limit reached")
)

// inventoryExecutorResolver 取專用帳號登入材料的窄介面（*AssetService 實作）。
type inventoryExecutorResolver interface {
	ResolveExecutorCredentials(ctx context.Context, assetID uint, pin ExecutorPin) (*ExecutorCredentials, error)
}

// executorAwareIdentitySource 有專用帳號掛載即為 executor 身分，否則委派預設帳號來源。
type executorAwareIdentitySource struct {
	db       *gorm.DB
	fallback inventoryIdentitySource
	resolver inventoryExecutorResolver
}

func newExecutorAwareIdentitySource(db *gorm.DB, fallback inventoryIdentitySource, resolver inventoryExecutorResolver) *executorAwareIdentitySource {
	return &executorAwareIdentitySource{db: db, fallback: fallback, resolver: resolver}
}

// readInventoryExecutorMount 讀資產的專用帳號掛載。只有確定查無列才回 found=false；
// 其他錯誤（逾時、連線中斷、交易中止）原樣回傳，呼叫端 fail-closed。
func readInventoryExecutorMount(db *gorm.DB, assetID uint) (mount model.AssetAccount, found bool, err error) {
	rows := []model.AssetAccount{}
	if err = db.Where("asset_id = ? AND purpose = ?", assetID, model.AccountPurposeExecutor).Limit(1).Find(&rows).Error; err != nil {
		return mount, false, err
	}
	if len(rows) == 0 {
		return mount, false, nil
	}
	return rows[0], true, nil
}

// executorPrecheck 不解封的前置檢查，與取密的輪替中、候選、就位版本判定共用 executorMountState。
func executorPrecheck(db *gorm.DB, mount *model.AssetAccount) error {
	switch err := executorMountState(db, mount); {
	case err == nil:
		return nil
	case errors.Is(err, ErrExecutorBusy):
		return ErrInventoryExecutorBusy
	default:
		return ErrInventoryExecutorUnavailable
	}
}

// Resolve 先看專用帳號掛載；沒有才委派預設帳號。不解封。
func (s *executorAwareIdentitySource) Resolve(tx *gorm.DB, asset *model.Asset) (inventoryIdentity, error) {
	if !inventoryPlatformSupported(asset) {
		return inventoryIdentity{}, ErrInventoryPlatformUnsupported
	}
	mount, found, err := readInventoryExecutorMount(tx, asset.ID)
	if err != nil {
		return inventoryIdentity{}, err
	}
	if !found {
		return s.fallback.Resolve(tx, asset)
	}
	if err := executorPrecheck(tx, &mount); err != nil {
		return inventoryIdentity{}, err
	}
	return inventoryIdentity{AccountID: mount.ID, Mode: model.HostAccountIdentityExecutor, Username: mount.Username}, nil
}

// Credentials 只處理預設帳號身分；executor 身分的取密要先取互斥，走 acquireExecutorCredentials。
func (s *executorAwareIdentitySource) Credentials(asset *model.Asset, id inventoryIdentity) (*AssetCredentials, error) {
	if id.Mode == model.HostAccountIdentityExecutor {
		return nil, ErrInventoryExecutorUnavailable
	}
	return s.fallback.Credentials(asset, id)
}
