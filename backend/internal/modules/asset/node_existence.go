package asset

import (
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/kernel"
)

// NodeExistenceReader 接受呼叫方交易的節點存在讀取（供節點範圍指派寫入在取得拓撲序列化鎖後檢查節點）。
//
// 只讀呼叫方交易、不取鎖、不留存結果；與節點刪除的互斥由呼叫方先取拓撲序列化鎖保證。
// 已刪除與不存在是同一結果，回應不帶名稱。讀取錯誤原樣回傳，呼叫方不得當成存在或不存在。
type NodeExistenceReader struct{}

// NewNodeExistenceReader 建立無狀態的讀取器。
func NewNodeExistenceReader() *NodeExistenceReader { return &NodeExistenceReader{} }

// LiveNodesTx 回每個輸入識別碼是否為未刪除節點（每個輸入一個鍵）。
func (r *NodeExistenceReader) LiveNodesTx(tx *gorm.DB, ids []uint) (map[uint]bool, error) {
	out := make(map[uint]bool, len(ids))
	for _, id := range ids {
		out[id] = false
	}
	uniq := kernel.DedupeUint(ids)
	if len(uniq) == 0 {
		return out, nil
	}
	var live []uint
	if err := fresh(tx).Raw(`SELECT id FROM asset_groups WHERE id IN ? AND deleted_at IS NULL`, uniq).Scan(&live).Error; err != nil {
		return nil, err
	}
	for _, id := range live {
		out[id] = true
	}
	return out, nil
}
