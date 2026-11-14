package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// APITokenAuditRole 稽核詳情所附 token 的一個授權角色。
type APITokenAuditRole struct {
	RoleID uint   `json:"role_id"`
	Name   string `json:"name"`
}

// APITokenAuditRef 稽核詳情所附的 token 資訊：授權角色與到期取自 token 列（建立後不變），
// 名稱由呼叫端取稽核列的快照。token 列不存在時 Found 為假，其餘欄位為零值。
type APITokenAuditRef struct {
	Found        bool
	GrantedRoles []APITokenAuditRole
	ExpiresAt    *time.Time
	OwnerDeleted bool
}

// AuditRef 讀取稽核詳情所需的 token 資訊。所屬帳號已刪除（軟刪或列已不存在）時 OwnerDeleted 為真。
// 不回傳雜湊或任何可用於認證的值。
func (s *APITokenService) AuditRef(tokenID uint) (APITokenAuditRef, error) {
	var tok model.APIToken
	if err := s.db.Select("id", "user_id", "expires_at").First(&tok, tokenID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return APITokenAuditRef{}, nil
		}
		return APITokenAuditRef{}, fmt.Errorf("讀取 API token 失敗: %w", err)
	}
	var rows []struct {
		RoleID  uint
		Name    string
		Deleted bool
	}
	if err := s.db.Table("api_token_roles").
		Select("api_token_roles.role_id AS role_id, COALESCE(roles.name, '') AS name, roles.deleted_at IS NOT NULL AS deleted").
		Joins("LEFT JOIN roles ON roles.id = api_token_roles.role_id").
		Where("api_token_roles.api_token_id = ?", tokenID).
		Order("api_token_roles.role_id").Scan(&rows).Error; err != nil {
		return APITokenAuditRef{}, fmt.Errorf("讀取 API token 授權角色失敗: %w", err)
	}
	roles := make([]APITokenAuditRole, 0, len(rows))
	for _, r := range rows {
		roles = append(roles, APITokenAuditRole{RoleID: r.RoleID, Name: grantedRoleName(r.RoleID, r.Name, r.Deleted)})
	}
	var alive int64
	if err := s.db.Model(&model.User{}).Where("id = ?", tok.UserID).Count(&alive).Error; err != nil {
		return APITokenAuditRef{}, fmt.Errorf("讀取所屬帳號失敗: %w", err)
	}
	return APITokenAuditRef{Found: true, GrantedRoles: roles, ExpiresAt: tok.ExpiresAt, OwnerDeleted: alive == 0}, nil
}
