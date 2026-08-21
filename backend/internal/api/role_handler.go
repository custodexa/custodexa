package api

import (
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
)

// RoleLister 角色清單能力（消費者側窄介面，SD-2 收斂）。
// handler 不再自持 `*gorm.DB`：角色主檔屬 identity 域，由 `identity.UserService` 實作。
type RoleLister interface {
	ListRoles() ([]model.Role, int64, error)
}

// RoleHandler 角色 API handler
type RoleHandler struct {
	roles RoleLister
}

// NewRoleHandler 創建角色 handler
func NewRoleHandler(roles RoleLister) *RoleHandler {
	return &RoleHandler{
		roles: roles,
	}
}

// List 獲取角色列表
func (h *RoleHandler) List(c *gin.Context) {
	roles, total, err := h.roles.ListRoles()

	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleQuery, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  roles,
		"total": total,
	})
}

// RegisterRoutes 註冊角色相關路由
func (h *RoleHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	roles := r.Group("/roles")
	roles.Use(middleware.AuthMiddleware(authService))
	roles.Use(middleware.RequireRole("admin"))
	{
		roles.GET("", h.List)
	}
}
