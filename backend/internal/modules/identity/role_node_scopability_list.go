package identity

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// RoleNodeScopabilityEntry 一個角色以節點範圍指派時的判定結果。
type RoleNodeScopabilityEntry struct {
	RoleID uint
	Class  authz.NodeScopability
	// Reason 只在 Class 為 no_effect 時有值。
	Reason authz.NodeScopeNoEffectReason
}

// RoleNodeScopabilityReader 讀出全部未刪除角色的節點限定判定（唯讀，不快取）。
// 判定交給 authz.ClassifyRoleNodeScopability，與寫入關卡使用同一個函式，這裡只負責批次讀入角色與權限集合。
type RoleNodeScopabilityReader struct {
	db *gorm.DB
}

// NewRoleNodeScopabilityReader 建立讀取器。
func NewRoleNodeScopabilityReader(db *gorm.DB) *RoleNodeScopabilityReader {
	return &RoleNodeScopabilityReader{db: db}
}

// List 依角色編號遞增回傳每個未刪除角色的判定；固定兩次查詢，不隨角色數成長。
func (r *RoleNodeScopabilityReader) List() ([]RoleNodeScopabilityEntry, error) {
	var roles []model.Role
	if err := r.db.Order("id").Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("讀取角色失敗: %w", err)
	}
	var customIDs []uint
	for _, role := range roles {
		if role.BuiltinKey == nil && role.DefinitionVersion >= 1 {
			customIDs = append(customIDs, role.ID)
		}
	}
	perms := make(map[uint][]authz.Permission, len(customIDs))
	if len(customIDs) > 0 {
		var rows []struct {
			RoleID        uint
			PermissionKey string
		}
		if err := r.db.Table("role_permissions").Select("role_id, permission_key").
			Where("role_id IN ?", customIDs).Scan(&rows).Error; err != nil {
			return nil, fmt.Errorf("讀取自訂角色權限集合失敗: %w", err)
		}
		for _, row := range rows {
			perms[row.RoleID] = append(perms[row.RoleID], authz.Permission(row.PermissionKey))
		}
	}
	out := make([]RoleNodeScopabilityEntry, 0, len(roles))
	for _, role := range roles {
		class, reason := authz.ClassifyRoleNodeScopability(role, perms[role.ID])
		out = append(out, RoleNodeScopabilityEntry{RoleID: role.ID, Class: class, Reason: reason})
	}
	return out, nil
}
