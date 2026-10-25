package main

import (
	"context"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
)

// 不測資產範圍的夾具所注入的寫入範圍判定與涵蓋快照替身（產品碼缺注入即拒絕，夾具須明示注入）。

// allowAllAssetWriteScope 寫入範圍判定替身：全放行，節點合併照現行整組取代。
type allowAllAssetWriteScope struct{}

func (allowAllAssetWriteScope) AuthorizeAssetCreate(context.Context, *gorm.DB, []uint) error {
	return nil
}

func (allowAllAssetWriteScope) AuthorizeAssetWrite(context.Context, *gorm.DB, asset.AssetWriteOp, uint, []uint) error {
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

// allowAllAccountWriteScope 帳號寫入範圍判定替身：全放行。
type allowAllAccountWriteScope struct{}

func (allowAllAccountWriteScope) AuthorizeAccountWrite(context.Context, *gorm.DB, uint, uint) error {
	return nil
}

// emptyCoverageSnapshot 涵蓋快照替身：前後皆空（審計列帶空的涵蓋差集）。
type emptyCoverageSnapshot struct{}

func (emptyCoverageSnapshot) CoverageSnapshot(*gorm.DB, []uint) (asset.CoverageSnapshot, error) {
	return asset.CoverageSnapshot{}, nil
}
