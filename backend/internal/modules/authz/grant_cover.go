package authz

import (
	"sync"

	"gorm.io/gorm"
)

// 授權變更分類的節點涵蓋讀取。範圍項以涵蓋比較（節點自身加未刪除祖先），拓撲由組裝時注入；
// 未注入時每個節點的涵蓋集合只含自己，祖先與子孫關係看不到，結果偏向多報（不漏報）。

// GrantNodeCoverReader 節點自身加未刪除祖先的唯讀查詢；已刪除的節點 exists 為 false。
// 範圍判定器的拓撲介面（ScopeTopology）的同名方法即滿足本介面。
type GrantNodeCoverReader interface {
	NodeCoverNodes(tx *gorm.DB, nodeID uint) (nodeIDs []uint, exists bool, err error)
}

var grantCover struct {
	mu sync.RWMutex
	r  GrantNodeCoverReader
}

// SetGrantNodeCoverReader 注入分類器的節點涵蓋讀取；傳 nil 即移除。
func SetGrantNodeCoverReader(r GrantNodeCoverReader) {
	grantCover.mu.Lock()
	grantCover.r = r
	grantCover.mu.Unlock()
}

func currentGrantCoverReader() GrantNodeCoverReader {
	grantCover.mu.RLock()
	defer grantCover.mu.RUnlock()
	return grantCover.r
}

// grantCoverOf 各節點的涵蓋集合；沒有讀取器、或讀取到節點已不存在時只含節點自身。
func grantCoverOf(tx *gorm.DB, nodes []uint) (map[uint][]uint, error) {
	out := make(map[uint][]uint, len(nodes))
	r := currentGrantCoverReader()
	for _, n := range nodes {
		if r == nil {
			out[n] = []uint{n}
			continue
		}
		cover, exists, err := r.NodeCoverNodes(tx, n)
		if err != nil {
			return nil, err
		}
		if !exists || len(cover) == 0 {
			cover = []uint{n}
		}
		out[n] = cover
	}
	return out, nil
}
