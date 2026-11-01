package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// RolePreviewFunc 由角色的內建識別、定義版本與已儲存的權限鍵求出預覽集合。
// 組裝端注入 DefaultRolePreviewFunc；它不得讀寫任何資料表、不得簽發憑證。
type RolePreviewFunc func(builtinKey string, definitionVersion int64, permissions []string) (*authz.RolePreview, error)

// DefaultRolePreviewFunc 正式的預覽計算：與目前使用者回應走同一套主體解析與能力投影（純函式）。
func DefaultRolePreviewFunc() RolePreviewFunc {
	return func(builtinKey string, definitionVersion int64, permissions []string) (*authz.RolePreview, error) {
		return authz.PreviewRole(builtinKey, definitionVersion, permissions), nil
	}
}

// SetRolePreviewer 注入預覽計算（組裝端呼叫）。未注入時預覽端點一律回內部錯誤，
// 不以空集合冒充「這個角色什麼都沒有」。
func (h *RoleDefinitionHandler) SetRolePreviewer(f RolePreviewFunc) { h.previewer = f }

type rolePreviewRole struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// rolePreviewResponse 預覽回應。permissions 與 /auth/me 的 permissions 同形；
// 不含範圍摘要，也不含任何節點、資產、使用者或憑證資料。
type rolePreviewResponse struct {
	Role        rolePreviewRole           `json:"role"`
	Previewable bool                      `json:"previewable"`
	Reason      string                    `json:"reason,omitempty"`
	Permissions []string                  `json:"permissions"`
	EntryStates []authz.PreviewEntryState `json:"entry_states"`
}

// PreviewCapabilities 角色預覽的權限集合與頁面狀態。唯讀：不寫任何資料、不推進權限版本、
// 不產生事件或審計列、不簽發 token 或票證。必要能力（角色檢視）由路由登錄表先裁決。
func (h *RoleDefinitionHandler) PreviewCapabilities(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "role"})
		return
	}
	if h.previewer == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleQuery, errors.New("role preview projection not wired"))
		return
	}
	def, err := h.reader.Get(c.Request.Context(), uint(id))
	if err != nil {
		if errors.Is(err, identity.ErrRoleDefinitionNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeRoleNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleQuery, err)
		return
	}
	builtin := ""
	if def.BuiltinKey != nil {
		builtin = *def.BuiltinKey
	}
	pv, err := h.previewer(builtin, def.DefinitionVersion, def.Permissions)
	if err == nil && pv == nil {
		err = errors.New("role preview projection returned nothing")
	}
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleQuery, err)
		return
	}
	out := rolePreviewResponse{
		Role:        rolePreviewRole{ID: def.ID, Name: def.Name},
		Previewable: pv.Previewable, Reason: pv.Reason,
		Permissions: pv.Permissions, EntryStates: pv.EntryStates,
	}
	if out.Permissions == nil {
		out.Permissions = []string{}
	}
	if out.EntryStates == nil {
		out.EntryStates = []authz.PreviewEntryState{}
	}
	c.JSON(http.StatusOK, out)
}
