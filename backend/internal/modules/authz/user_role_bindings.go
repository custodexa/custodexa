package authz

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 使用者直接指派（user_roles）的讀取面。寫入面隨使用者服務在 identity，經本包的交易內函式進出。

// UserRoleBinding 使用者的一筆直接角色指派（讀取面）。
type UserRoleBinding struct {
	RoleID     uint    `json:"role_id"`
	RoleName   string  `json:"role_name"`
	BuiltinKey *string `json:"builtin_key"`
	// Source 這一列的來源：manual（管理者指派）、mapped（外部群組映射）、both。
	Source string `json:"source"`
	// ScopeKind 內部欄，不出現在 JSON；有 node_ids 欄即節點範圍，沒有即全域。
	ScopeKind string `json:"-"`
	// NodeIDs 只在節點範圍列出現（照實回傳，含已刪除節點的編號）；全域列沒有此鍵。
	// 以指標表示：節點範圍而無節點的異常資料仍輸出空陣列，不被讀成全域。
	NodeIDs *[]uint `json:"node_ids,omitempty" gorm:"-"`
}

// UserRoleBindings 使用者目前的直接角色指派（含角色名與內建範本識別，依角色編號排序）。
// 不含經群組取得的角色。
func UserRoleBindings(tx *gorm.DB, userID uint) ([]UserRoleBinding, error) {
	var rows []UserRoleBinding
	if err := tx.Raw(`SELECT u.role_id AS role_id, r.name AS role_name, r.builtin_key AS builtin_key,
 u.source AS source, u.scope_kind AS scope_kind
 FROM user_roles u JOIN roles r ON r.id = u.role_id AND r.deleted_at IS NULL
 WHERE u.user_id = ? ORDER BY u.role_id`, userID).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取使用者角色指派失敗: %w", err)
	}
	hasNodes := false
	for i := range rows {
		hasNodes = hasNodes || rows[i].ScopeKind == model.ScopeKindNodes
	}
	if !hasNodes {
		return rows, nil
	}
	nodes, err := SubjectBindingNodes(tx, model.BindingSubjectUser, userID)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].ScopeKind == model.ScopeKindNodes {
			ids := nodes[rows[i].RoleID]
			if ids == nil {
				ids = []uint{}
			}
			rows[i].NodeIDs = &ids
		}
	}
	return rows, nil
}
