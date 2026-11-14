package api

import (
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// apiTokenAuditRefReader 稽核詳情所附 token 資訊的讀取面（*identity.APITokenService 實作）。
type apiTokenAuditRefReader interface {
	AuditRef(tokenID uint) (identity.APITokenAuditRef, error)
}

// WithAPITokenRefs 注入稽核詳情所附 token 資訊的讀取面。
func (h *AuditLogHandler) WithAPITokenRefs(r apiTokenAuditRefReader) *AuditLogHandler {
	h.apiTokens = r
	return h
}

// apiTokenAuditDTO 稽核詳情的 token 物件：名稱取稽核列的快照，授權角色與到期取 token 列。
type apiTokenAuditDTO struct {
	ID           uint                         `json:"id"`
	Name         string                       `json:"name"`
	GrantedRoles []identity.APITokenAuditRole `json:"granted_roles"`
	ExpiresAt    *time.Time                   `json:"expires_at"`
	OwnerDeleted bool                         `json:"owner_deleted"`
}

// auditLogDetailResponse 稽核詳情：列本身加上經由的 token（非 token 請求的列不出現 api_token 鍵）。
type auditLogDetailResponse struct {
	audit.AuditLogView
	APIToken *apiTokenAuditDTO `json:"api_token,omitempty"`
}

func (h *AuditLogHandler) apiTokenRefOf(l *model.AuditLog) (*apiTokenAuditDTO, error) {
	if l == nil || l.APITokenID == nil || l.APITokenName == nil || h.apiTokens == nil {
		return nil, nil
	}
	ref, err := h.apiTokens.AuditRef(*l.APITokenID)
	if err != nil {
		return nil, err
	}
	dto := &apiTokenAuditDTO{ID: *l.APITokenID, Name: *l.APITokenName, GrantedRoles: []identity.APITokenAuditRole{}}
	if !ref.Found {
		// token 列已不存在：無從得知授權角色與到期，所屬帳號視同已刪除
		dto.OwnerDeleted = true
		return dto, nil
	}
	if ref.GrantedRoles != nil {
		dto.GrantedRoles = ref.GrantedRoles
	}
	dto.ExpiresAt, dto.OwnerDeleted = ref.ExpiresAt, ref.OwnerDeleted
	return dto, nil
}
