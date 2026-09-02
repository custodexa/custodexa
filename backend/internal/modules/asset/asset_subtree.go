package asset

import (
	"gorm.io/gorm"
)

// 節點子樹的共用查詢。
//
// 同一段遞迴 SQL 原本只存在於節點樹的計數路徑；報告的節點範圍需要同一組
// 「子樹內的資產」，抄一份即意味著兩處對「子樹」的定義可以各自漂移，
// 而漂移的後果是報告的母體與畫面上看到的節點內容不一致。

// subtreeNodeIDsSQL 子樹節點識別碼（含根自身）的遞迴子查詢；單一參數為根節點 id。
const subtreeNodeIDsSQL = `WITH RECURSIVE sub(id) AS (
					SELECT id FROM asset_groups WHERE id = ? AND deleted_at IS NULL
					UNION
					SELECT g.id FROM asset_groups g JOIN sub ON g.parent_id = sub.id
					WHERE g.deleted_at IS NULL
				) SELECT id FROM sub`

// descendantAssetIDs 節點子樹內掛載的資產識別碼（已刪除資產除外）。
//
// 多掛載去重由 DISTINCT 保證：同一台資產掛在父節點與子節點下只算一次，
// 否則它的帳號會在報告裡出現兩列，總數與合規率跟著失真。
func descendantAssetIDs(db *gorm.DB, nodeID uint) ([]uint, error) {
	var ids []uint
	err := db.Raw(`SELECT DISTINCT an.asset_id FROM asset_nodes an
			JOIN assets a ON a.id = an.asset_id AND a.deleted_at IS NULL
			WHERE an.node_id IN (`+subtreeNodeIDsSQL+`)`, nodeID).Scan(&ids).Error
	if err != nil {
		return nil, err
	}
	return ids, nil
}
