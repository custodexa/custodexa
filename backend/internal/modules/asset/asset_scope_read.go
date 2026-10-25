package asset

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 範圍化讀取投影所需的歸屬唯讀查詢。只讀資產自有的掛載表與節點表，不取鎖、不判定範圍；
// 範圍判定由授權模組以這些結果計算。

// NodeIDsOfAssets 一批資產各自的掛載節點（依節點識別碼升冪）；未掛載的資產不出現在結果中。
func NodeIDsOfAssets(db *gorm.DB, assetIDs []uint) (map[uint][]uint, error) {
	out := make(map[uint][]uint, len(assetIDs))
	if len(assetIDs) == 0 {
		return out, nil
	}
	var members []model.AssetNode
	if err := db.Where("asset_id IN ?", assetIDs).Order("asset_id, node_id").Find(&members).Error; err != nil {
		return nil, fmt.Errorf("查詢節點成員失敗: %w", err)
	}
	for _, m := range members {
		out[m.AssetID] = append(out[m.AssetID], m.NodeID)
	}
	return out, nil
}

// NodeFilterNodeIDs 節點篩選命中的節點集合：含子樹時為該節點與其未刪除後代，否則只有該節點；
// 節點不存在或已刪除時含子樹為空集合（與現行列表篩選同口徑）。
func NodeFilterNodeIDs(db *gorm.DB, nodeID uint, includeSubtree bool) (map[uint]bool, error) {
	out := map[uint]bool{}
	if !includeSubtree {
		out[nodeID] = true
		return out, nil
	}
	var ids []uint
	if err := NewScopeTopologyReader().SubtreeNodeIDs(db, []uint{nodeID}).Scan(&ids).Error; err != nil {
		return nil, fmt.Errorf("節點過濾查詢失敗: %w", err)
	}
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}
