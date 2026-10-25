package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/authz"
)

// userRoleBindingReader 使用者直接角色指派的讀取（由 identity.UserService 實作）。
type userRoleBindingReader interface {
	RoleBindings(userID uint) ([]authz.UserRoleBinding, error)
}

// ListRoleBindings 讀取使用者目前的直接角色指派；節點範圍列另帶 node_ids，全域列沒有此鍵。
func (h *UserHandler) ListRoleBindings(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}
	reader, ok := h.userService.(userRoleBindingReader)
	if !ok {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserQuery, errors.New("使用者角色指派讀取未接線"))
		return
	}
	rows, err := reader.RoleBindings(uint(id))
	if err != nil {
		respondIdentityError(c, err, apierror.CodeInternalUserQuery)
		return
	}
	if rows == nil {
		rows = []authz.UserRoleBinding{}
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "total": len(rows)})
}
