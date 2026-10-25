package asset

import (
	"fmt"
	"sort"

	"gorm.io/gorm"
)

// AssignmentNode 指派角色畫面用的節點摘要：只有結構與台數，不含任何資產內容。
type AssignmentNode struct {
	ID       uint
	Name     string
	ParentID *uint
	// Depth 根層為 1，沿未刪除的祖先逐層累加。
	Depth int
	// Path 與 NodePathMap 同形（以 " / " 串接的名稱路徑）。
	Path string
	// SubtreeAssetCount 節點子樹內未刪除資產的去重台數；
	// 子樹定義與 subtreeNodeIDsSQL 相同（含自身、只走未刪除節點）。
	SubtreeAssetCount int
}

// AssignmentNodes 回全部未刪除節點的扁平清單與各自的子樹去重台數。
//
// 查詢次數固定（節點、節點路徑、資產掛載各一次），不隨節點數成長：
// 子樹台數在記憶體內由掛載列彙整，不逐節點呼叫 descendantAssetIDs，也不呼叫 Tree。
// 同一台資產掛在父節點與其子孫下時，父節點只計一次。
func AssignmentNodes(db *gorm.DB) ([]AssignmentNode, error) {
	var rows []assignmentNodeRow
	if err := db.Raw(`SELECT id, name, parent_id FROM asset_groups WHERE deleted_at IS NULL ORDER BY id`).
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢節點失敗: %w", err)
	}
	if len(rows) == 0 {
		return []AssignmentNode{}, nil
	}
	paths, err := NodePathMap(db)
	if err != nil {
		return nil, err
	}

	type memberRow struct {
		NodeID  uint
		AssetID uint
	}
	var members []memberRow
	if err := db.Raw(`SELECT an.node_id AS node_id, an.asset_id AS asset_id FROM asset_nodes an
			JOIN assets a ON a.id = an.asset_id AND a.deleted_at IS NULL`).Scan(&members).Error; err != nil {
		return nil, fmt.Errorf("查詢節點掛載失敗: %w", err)
	}

	live := make(map[uint]*assignmentNodeRow, len(rows))
	children := make(map[uint][]uint, len(rows))
	for i := range rows {
		live[rows[i].ID] = &rows[i]
	}
	for i := range rows {
		if p := rows[i].ParentID; p != nil && live[*p] != nil {
			children[*p] = append(children[*p], rows[i].ID)
		}
	}
	direct := make(map[uint][]uint, len(rows))
	for _, m := range members {
		if live[m.NodeID] != nil {
			direct[m.NodeID] = append(direct[m.NodeID], m.AssetID)
		}
	}

	out := make([]AssignmentNode, 0, len(rows))
	for i := range rows {
		n := &rows[i]
		out = append(out, AssignmentNode{
			ID:                n.ID,
			Name:              n.Name,
			ParentID:          n.ParentID,
			Depth:             assignmentNodeDepth(live, n.ID),
			Path:              paths[n.ID],
			SubtreeAssetCount: subtreeDistinctCount(n.ID, children, direct),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

type assignmentNodeRow struct {
	ID       uint
	Name     string
	ParentID *uint
}

// assignmentNodeDepth 沿未刪除祖先數層數；逾上限即停（環防禦，與 nodeDepthTx 同口徑）。
func assignmentNodeDepth(live map[uint]*assignmentNodeRow, id uint) int {
	depth := 0
	cur := &id
	for cur != nil {
		n := live[*cur]
		if n == nil {
			break
		}
		depth++
		if depth > maxNodeDepth {
			return depth
		}
		cur = n.ParentID
	}
	return depth
}

// subtreeDistinctCount 節點子樹（含自身）內掛載資產的去重台數。
func subtreeDistinctCount(root uint, children, direct map[uint][]uint) int {
	seenNodes := map[uint]bool{}
	assets := map[uint]struct{}{}
	stack := []uint{root}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seenNodes[id] {
			continue
		}
		seenNodes[id] = true
		for _, a := range direct[id] {
			assets[a] = struct{}{}
		}
		stack = append(stack, children[id]...)
	}
	return len(assets)
}

// AssignmentNodes 服務方法：指派角色畫面用的節點清單（組裝根經窄介面注入 API 層）。
func (s *AssetGroupService) AssignmentNodes() ([]AssignmentNode, error) {
	return AssignmentNodes(s.db)
}
