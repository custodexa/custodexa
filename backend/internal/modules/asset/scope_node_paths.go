package asset

import (
	"fmt"

	"gorm.io/gorm"
)

// NodeNamePaths 節點由根起的名稱路徑（每層一個元素，不串接、不需拆字串）。
//
// 與 NodeCoverNodes 同一口徑：只認未刪除的節點，已刪除的祖先不被穿過——路徑從最近一個
// 已刪除祖先之下開始。已刪除或不存在的節點不出現在回傳的映射中。只回祖先與自身的名稱，
// 子節點與其他節點的名稱不讀出。查詢一次全部未刪除節點後在記憶體走訪，次數不隨節點數成長。
func (r *ScopeTopologyReader) NodeNamePaths(tx *gorm.DB, nodeIDs []uint) (map[uint][]string, error) {
	out := make(map[uint][]string, len(nodeIDs))
	if len(nodeIDs) == 0 {
		return out, nil
	}
	var rows []struct {
		ID       uint
		Name     string
		ParentID *uint
	}
	if err := fresh(tx).Raw(`SELECT id, name, parent_id FROM asset_groups WHERE deleted_at IS NULL`).
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢節點路徑失敗: %w", err)
	}
	type node struct {
		name   string
		parent *uint
	}
	live := make(map[uint]node, len(rows))
	for _, n := range rows {
		live[n.ID] = node{name: n.Name, parent: n.ParentID}
	}
	for _, id := range nodeIDs {
		if _, ok := live[id]; !ok {
			continue
		}
		var rev []string
		cur := &id
		// 逾深度上限即停（環防禦，與節點深度判定同口徑）
		for depth := 0; cur != nil && depth <= maxNodeDepth; depth++ {
			n, ok := live[*cur]
			if !ok {
				break
			}
			rev = append(rev, n.name)
			cur = n.parent
		}
		path := make([]string, len(rev))
		for i, name := range rev {
			path[len(rev)-1-i] = name
		}
		out[id] = path
	}
	return out, nil
}
