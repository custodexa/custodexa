package asset

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
)

// 資產帳號寫入（建立、更新、刪除、設預設）的交易內範圍判定（消費者側窄介面）。
//
// 帳號隨所屬資產判定：URL 的資產須在主體的資產編輯能力範圍內，帳號須屬於該資產。
// 非系統呼叫者的帳號寫入交易，第一個動作取拓撲序列化鎖，再於同交易重解主體判定，
// 之後才取資產列鎖（lockAssetForAccountMutation）與任何憑證列鎖。
// 判定回傳的範圍拒絕與能力拒絕是 authz 定義的值，本模組原樣經交易回滾交回 handler。
// 系統呼叫者（WithSystemCaller）不經判定、不取序列化鎖，行為與現行相同。

// AccountWriteScopePort 帳號寫入的交易內範圍判定；accountID 為 0 表示建立（只判資產）。
type AccountWriteScopePort interface {
	AuthorizeAccountWrite(ctx context.Context, tx *gorm.DB, assetID, accountID uint) error
}

// ErrAccountWriteScopePortMissing 帳號寫入範圍判定未注入：寧可拒絕，也不在沒有判定的情況下寫入。
var ErrAccountWriteScopePortMissing = errors.New("asset: account write scope port not injected")

// WithAccountWriteScope 注入帳號寫入的範圍判定（組裝時）。
func (s *AssetAccountService) WithAccountWriteScope(p AccountWriteScopePort) *AssetAccountService {
	s.writeScope = p
	return s
}

// authorizeAccountWriteTx 帳號寫入交易的第一個動作：取拓撲序列化鎖並判定（系統呼叫者略過）。
func (s *AssetAccountService) authorizeAccountWriteTx(ctx context.Context, tx *gorm.DB, assetID, accountID uint) error {
	if isSystemCaller(ctx) {
		return nil
	}
	if s.writeScope == nil {
		return ErrAccountWriteScopePortMissing
	}
	if err := s.assets.lockTopologyTx(tx); err != nil {
		return err
	}
	return s.checkAccountWrite(ctx, tx, assetID, accountID)
}

// checkAccountWrite 帳號寫入的範圍判定本身（不取鎖）：寫入交易在取鎖後呼叫，帳號列的移除旗標
// 以同一函式在交易外求值。系統呼叫者略過；未注入回 ErrAccountWriteScopePortMissing。
func (s *AssetAccountService) checkAccountWrite(ctx context.Context, db *gorm.DB, assetID, accountID uint) error {
	if isSystemCaller(ctx) {
		return nil
	}
	if s.writeScope == nil {
		return ErrAccountWriteScopePortMissing
	}
	return s.writeScope.AuthorizeAccountWrite(ctx, db, assetID, accountID)
}

// earlyAccountScopeCheck 交易外的提早判定：範圍外與不存在先於憑證能力、欄位能力與值驗證回同一個 404
// （與資產更新的提早判定同一作法）。以交易內判定為準；這裡不取序列化鎖，只讓回應順序與「資產不存在」一致。
func (s *AssetAccountService) earlyAccountScopeCheck(ctx context.Context, assetID, accountID uint) error {
	if isSystemCaller(ctx) {
		return nil
	}
	if s.writeScope == nil {
		return ErrAccountWriteScopePortMissing
	}
	return s.writeScope.AuthorizeAccountWrite(ctx, database.DB, assetID, accountID)
}
