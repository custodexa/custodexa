package asset

import (
	"context"
	"errors"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 專用帳號身分的執行開頭：取互斥 -> 重讀釘住值 -> 解封 -> 撥號。
// 先上鎖再重讀，整組輪替就不可能在「判定通過」與「拿到鎖」之間改掉遠端秘密，
// 盤點因此不會以舊秘密多送一次失敗登入。

const (
	// inventoryExecutorLockWait 盤點等專用帳號互斥的上限，計入單次執行期限。
	inventoryExecutorLockWait = 30 * time.Second
	// executorLockPoll 等鎖迴圈的輪詢間隔。
	executorLockPoll = 50 * time.Millisecond
)

// errExecutorLockBusy 等不到專用帳號的互斥（逾時或 ctx 結束）。
var errExecutorLockBusy = errors.New("executor: account lock busy")

// waitRotationAccountLock 每 50 ms 嘗試一次既有的不等待取鎖，取得即回解鎖函式；
// ctx 結束或超過 maxWait 回 errExecutorLockBusy。等待期間不持任何資料庫交易。
func waitRotationAccountLock(ctx context.Context, accountID uint, maxWait time.Duration) (func(), error) {
	deadline := time.NewTimer(maxWait)
	defer deadline.Stop()
	tick := time.NewTicker(executorLockPoll)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, errExecutorLockBusy
		}
		if unlock, ok := tryLockRotationAccount(accountID); ok {
			return unlock, nil
		}
		select {
		case <-ctx.Done():
			return nil, errExecutorLockBusy
		case <-deadline.C:
			return nil, errExecutorLockBusy
		case <-tick.C:
		}
	}
}

// acquireExecutorCredentials 專用帳號身分的取鎖與取密。成功時回憑證與解鎖函式（連線關閉後才呼叫）；
// 失敗回結束原因碼，且此時已釋放互斥、沒有任何秘密留存。呼叫前不得持有資料庫交易。
func (s *HostAccountInventoryService) acquireExecutorCredentials(ctx context.Context, a *model.Asset, scan *model.HostAccountScan) (*AssetCredentials, func(), string) {
	aware, ok := s.identity.(*executorAwareIdentitySource)
	if !ok {
		return nil, nil, model.InventoryExecutorUnavailable
	}
	if s.beforeExecutorLock != nil {
		s.beforeExecutorLock()
	}
	wait := s.executorLockWait
	if wait <= 0 {
		wait = inventoryExecutorLockWait
	}
	unlock, err := waitRotationAccountLock(ctx, scan.IdentityAccountID, wait)
	if err != nil {
		return nil, nil, model.InventoryExecutorBusy
	}
	pin, err := readExecutorPin(s.db, a.ID)
	switch {
	case err != nil:
		unlock()
		return nil, nil, model.InventoryInterrupted
	case pin == nil || pin.AccountID != scan.IdentityAccountID:
		unlock()
		return nil, nil, model.InventoryExecutorChanged
	}
	ec, err := aware.resolver.ResolveExecutorCredentials(ctx, a.ID, *pin)
	if err != nil {
		unlock()
		switch {
		case errors.Is(err, ErrExecutorBusy):
			return nil, nil, model.InventoryExecutorBusy
		case errors.Is(err, ErrExecutorChanged):
			return nil, nil, model.InventoryExecutorChanged
		default:
			return nil, nil, model.InventoryExecutorUnavailable
		}
	}
	return &AssetCredentials{Asset: a, AccountID: ec.AccountID, Username: ec.Username, Password: ec.Password, PrivateKey: ec.PrivateKey}, unlock, ""
}
