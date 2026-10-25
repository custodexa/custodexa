package asset

import (
	"fmt"
	"strings"
)

// 節點改名、改描述與搬移的審計 details。既有鍵的寫法（asset_node_rename、asset_node_move）與先前逐字相同，
// 新鍵只附加在後，不改動既有鍵值。

// nodeUpdateDetails 改名與改描述同一筆：只改名帶 asset_node_rename、只改描述帶 asset_node_describe、
// 兩者都改兩鍵並存；都沒改回空字串（不留痕）。
func nodeUpdateDetails(oldName, newName, oldDesc, newDesc string) string {
	var parts []string
	if oldName != newName {
		parts = append(parts, fmt.Sprintf(`"asset_node_rename":{"old":%q,"new":%q}`, oldName, newName))
	}
	if oldDesc != newDesc {
		parts = append(parts, fmt.Sprintf(`"asset_node_describe":{"old":%q,"new":%q}`, oldDesc, newDesc))
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// nodeMoveDetails 搬移審計：既有 asset_node_move 鍵，加上 topology_coverage（一律附上）與
// cross_assignment（只在經節點範圍指派授權的搬移出現）。
func nodeMoveDetails(name string, oldParent, newParent *uint, scope NodeMoveScope, cov TopologyCoverage) (string, error) {
	covJSON, err := MarshalTopologyCoverage(cov)
	if err != nil {
		return "", fmt.Errorf("涵蓋差異序列化失敗: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `{"asset_node_move":{"name":%q,"old_parent_id":%v,"new_parent_id":%v}`,
		name, ptrOrNull(oldParent), ptrOrNull(newParent))
	if scope.ViaNodeScope {
		fmt.Fprintf(&b, `,"cross_assignment":%t`, scope.CrossAssignment)
	}
	b.WriteString(`,"topology_coverage":`)
	b.WriteString(covJSON)
	b.WriteString("}")
	return b.String(), nil
}
