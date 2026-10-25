package authz

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// Resolver 伺服器端主體解析器。
//
// 每個請求由資料庫解析主體的有效指派與能力，**不快取**：直接指派＋群組指派＋（範圍為節點時）
// 節點涵蓋，約兩到三次索引查詢。解析失敗（資料庫錯誤）回傳 error，呼叫端一律拒絕該請求，
// 不以 JWT 角色兜底。
type Resolver struct {
	db *gorm.DB
}

// NewResolver 建立解析器。
func NewResolver(db *gorm.DB) *Resolver { return &Resolver{db: db} }

type assignmentRow struct {
	RoleID     uint
	RoleName   string
	BuiltinKey *string
	ScopeKind  string
	RoleSource string
	GroupID    uint
	DefVersion int64
}

// ResolveUserOn 在給定連線（可為交易句柄）上解析主體，不保存句柄：寫入路徑的交易內重驗用。
func ResolveUserOn(db *gorm.DB, userID uint, facts TokenFacts) (*Principal, error) {
	return resolveUserWith(db, ProductCatalogue(), userID, facts)
}

// ResolveUser 解析使用者的主體。已刪除的角色與已刪除的使用者群組不產生指派。
func (r *Resolver) ResolveUser(userID uint, facts TokenFacts) (*Principal, error) {
	return resolveUserWith(r.db, ProductCatalogue(), userID, facts)
}

func resolveUserWith(db *gorm.DB, cat Catalogue, userID uint, facts TokenFacts) (*Principal, error) {
	var direct []assignmentRow
	if err := db.Raw(`SELECT roles.id AS role_id, roles.name AS role_name, roles.builtin_key AS builtin_key, roles.definition_version AS def_version,
 user_roles.scope_kind AS scope_kind, user_roles.source AS role_source
 FROM user_roles JOIN roles ON roles.id = user_roles.role_id AND roles.deleted_at IS NULL
 WHERE user_roles.user_id = ? ORDER BY roles.id`, userID).Scan(&direct).Error; err != nil {
		return nil, fmt.Errorf("解析直接角色指派失敗: %w", err)
	}
	var viaGroup []assignmentRow
	if err := db.Raw(`SELECT roles.id AS role_id, roles.name AS role_name, roles.builtin_key AS builtin_key, roles.definition_version AS def_version,
 user_group_roles.scope_kind AS scope_kind, user_group_roles.user_group_id AS group_id
 FROM user_group_members
 JOIN user_groups ON user_groups.id = user_group_members.user_group_id AND user_groups.deleted_at IS NULL
 JOIN user_group_roles ON user_group_roles.user_group_id = user_group_members.user_group_id
 JOIN roles ON roles.id = user_group_roles.role_id AND roles.deleted_at IS NULL
 WHERE user_group_members.user_id = ? ORDER BY user_group_roles.user_group_id, roles.id`, userID).Scan(&viaGroup).Error; err != nil {
		return nil, fmt.Errorf("解析群組角色指派失敗: %w", err)
	}

	custom, err := customPermissionsOf(db, cat, direct, viaGroup)
	if err != nil {
		return nil, err
	}
	assignments := make([]Assignment, 0, len(direct)+len(viaGroup))
	for _, d := range direct {
		a := assignmentFromRow(d, ViaDirect, custom)
		if a.Scope == model.ScopeKindNodes {
			ids, err := liveNodesOf(db, model.BindingSubjectUser, userID, d.RoleID)
			if err != nil {
				return nil, err
			}
			a.LiveNodeIDs = ids
		}
		assignments = append(assignments, a)
	}
	for _, g := range viaGroup {
		a := assignmentFromRow(g, ViaGroup, custom)
		if a.Scope == model.ScopeKindNodes {
			ids, err := liveNodesOf(db, model.BindingSubjectUserGroup, g.GroupID, g.RoleID)
			if err != nil {
				return nil, err
			}
			a.LiveNodeIDs = ids
		}
		assignments = append(assignments, a)
	}
	return NewPrincipalOn(cat, userID, facts, assignments), nil
}

// assignmentFromRow 一列指派（直接或經群組）映射為 Assignment；正式解析與指派集合入口共用。
// 直接指派的列沒有群組 ID、經群組的列沒有來源，兩者各自保持零值。範圍節點由呼叫方另填。
func assignmentFromRow(r assignmentRow, via string, custom map[uint][]Permission) Assignment {
	a := Assignment{RoleID: r.RoleID, RoleName: r.RoleName, Via: via, GroupID: r.GroupID, Scope: r.ScopeKind, RoleSource: r.RoleSource}
	if r.BuiltinKey != nil {
		a.BuiltinKey = *r.BuiltinKey
	} else if r.DefVersion >= 1 {
		a.Custom, a.Permissions = true, custom[r.RoleID]
	}
	return a
}

// liveNodesOf 指派涵蓋且尚未刪除的節點：先讀綁定節點，再經 filterLiveNodes 過濾。
func liveNodesOf(db *gorm.DB, subjectKind string, subjectID, roleID uint) ([]uint, error) {
	var ids []uint
	if err := db.Raw(`SELECT role_binding_nodes.node_id FROM role_binding_nodes
 WHERE role_binding_nodes.subject_kind = ? AND role_binding_nodes.subject_id = ? AND role_binding_nodes.role_id = ?
 ORDER BY role_binding_nodes.node_id`, subjectKind, subjectID, roleID).Scan(&ids).Error; err != nil {
		return nil, fmt.Errorf("解析指派節點範圍失敗: %w", err)
	}
	return filterLiveNodes(db, ids)
}

// filterLiveNodes 給定節點中尚未刪除者（節點是軟刪除，以 asset_groups.deleted_at 判定；
// 不存在的節點 ID 一併濾掉），依節點 ID 排序、去重。正式解析與指派集合入口共用同一判準。
func filterLiveNodes(db *gorm.DB, nodeIDs []uint) ([]uint, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}
	var ids []uint
	if err := db.Raw(`SELECT asset_groups.id FROM asset_groups
 WHERE asset_groups.id IN ? AND asset_groups.deleted_at IS NULL ORDER BY asset_groups.id`, nodeIDs).Scan(&ids).Error; err != nil {
		return nil, fmt.Errorf("解析指派節點範圍失敗: %w", err)
	}
	return ids, nil
}

// customPermissions 一次讀出本次出現的自訂角色（無內建識別、定義版本 >= 1）的權限集合。
// 目錄外的鍵（資料遭直改）不授權：載入時略過，由備份核對／重放負責指出。
func customPermissionsOf(db *gorm.DB, cat Catalogue, lists ...[]assignmentRow) (map[uint][]Permission, error) {
	ids := map[uint]bool{}
	for _, l := range lists {
		for _, a := range l {
			if a.BuiltinKey == nil && a.DefVersion >= 1 {
				ids[a.RoleID] = true
			}
		}
	}
	out := map[uint][]Permission{}
	if len(ids) == 0 {
		return out, nil
	}
	idList := make([]uint, 0, len(ids))
	for id := range ids {
		idList = append(idList, id)
	}
	var rows []struct {
		RoleID        uint
		PermissionKey string
	}
	if err := db.Raw(`SELECT role_id, permission_key FROM role_permissions WHERE role_id IN ? ORDER BY role_id, permission_key`, idList).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("解析自訂角色權限集合失敗: %w", err)
	}
	for _, row := range rows {
		if _, ok := cat.Lookup(Permission(row.PermissionKey)); ok {
			out[row.RoleID] = append(out[row.RoleID], Permission(row.PermissionKey))
		}
	}
	return out, nil
}
