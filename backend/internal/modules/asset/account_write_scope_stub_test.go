package asset

import (
	"context"

	"gorm.io/gorm"
)

// 不測帳號寫入範圍的夾具所注入的帳號寫入範圍判定替身（產品碼缺注入即拒絕，夾具須明示注入）。

// allowAllAccountWriteScope 帳號寫入範圍判定替身：全放行。
type allowAllAccountWriteScope struct{}

func (allowAllAccountWriteScope) AuthorizeAccountWrite(context.Context, *gorm.DB, uint, uint) error {
	return nil
}

// allowAllAssetWriteScope 資產寫入範圍判定替身：全放行，節點合併照送出整組取代（等同全域持有者）。
// 不測資產寫入範圍的夾具以非系統呼叫者走更新、建立時注入（產品碼缺注入即拒絕）。
type allowAllAssetWriteScope struct{}

func (allowAllAssetWriteScope) AuthorizeAssetCreate(context.Context, *gorm.DB, []uint) error {
	return nil
}

func (allowAllAssetWriteScope) AuthorizeAssetWrite(context.Context, *gorm.DB, AssetWriteOp, uint, []uint) error {
	return nil
}

func (allowAllAssetWriteScope) MergeAssetNodes(_ context.Context, _ *gorm.DB, _ uint, _, requested []uint) ([]uint, error) {
	return requested, nil
}

// AccessPolicyCoversNodes 全放行替身：每組目的節點皆在存取政策範圍內。
func (allowAllAssetWriteScope) AccessPolicyCoversNodes(_ context.Context, _ *gorm.DB, nodeSets [][]uint) ([]bool, error) {
	out := make([]bool, len(nodeSets))
	for i := range out {
		out[i] = true
	}
	return out, nil
}
