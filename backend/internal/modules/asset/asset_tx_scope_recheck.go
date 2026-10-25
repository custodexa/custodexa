package asset

import (
	"context"

	"gorm.io/gorm"
)

// 寫入交易內的目標範圍重判。
//
// HTTP 層在登錄閘判過範圍的請求上，把「在呼叫方交易內重判同一組判定」的函式放進 context；
// 服務在交易內改動拓撲後呼叫它。函式回非 nil 時交易回滾、錯誤原樣交回 handler
// （範圍拒絕為 authz 定義的拒絕值，由 handler 交共用出口），本模組不解讀也不改寫。
// context 沒有該函式（內部呼叫、未經範圍判定的路由）時不重判，行為不變。
// 本模組不依賴 authz，函式以 gorm 交易句柄為唯一參數。

type txScopeRecheckKey struct{}

// WithTxScopeRecheck 回傳帶有交易內範圍重判函式的 context；fn 為 nil 時原樣回傳。
func WithTxScopeRecheck(ctx context.Context, fn func(tx *gorm.DB) error) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, txScopeRecheckKey{}, fn)
}

// recheckTargetScopeTx 在呼叫方交易內重判；context 沒有重判函式時回 nil。
func recheckTargetScopeTx(ctx context.Context, tx *gorm.DB) error {
	fn, _ := ctx.Value(txScopeRecheckKey{}).(func(tx *gorm.DB) error)
	if fn == nil {
		return nil
	}
	return fn(tx)
}
