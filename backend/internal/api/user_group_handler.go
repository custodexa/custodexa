package api

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
)

// UserGroupServiceInterface 使用者群組服務接口（用於測試注入）
type UserGroupServiceInterface interface {
	List() ([]model.UserGroup, error)
	Create(req *identity.UserGroupRequest) (*model.UserGroup, error)
	Update(id uint, req *identity.UserGroupRequest) (*model.UserGroup, error)
	Delete(id uint, actorID uint, actorName, clientIP string) (int64, error)
	ReplaceMembers(id uint, userIDs []uint) (*model.UserGroup, error)
	AuthorizationCount(id uint) (int64, error)
}

// UserGroupHandler 使用者群組 API（user-group-authorization，admin only）
type UserGroupHandler struct {
	groups UserGroupServiceInterface
}

// NewUserGroupHandler 建立 handler
func NewUserGroupHandler(groups UserGroupServiceInterface) *UserGroupHandler {
	return &UserGroupHandler{groups: groups}
}

func respondUserGroupError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	switch {
	case errors.Is(err, identity.ErrUserGroupNameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeUserGroupNameExists, nil)
	case errors.Is(err, identity.ErrUserGroupNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeUserGroupNotFound, nil)
	case errors.Is(err, identity.ErrUserGroupMemberNotFound):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeUserGroupMemberNotFound, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}

func parseUserGroupID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user_group"})
		return 0, false
	}
	return uint(id), true
}

// List 群組列表（含成員）
func (h *UserGroupHandler) List(c *gin.Context) {
	groups, err := h.groups.List()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserGroupQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": groups, "total": len(groups)})
}

// Create 建立群組
func (h *UserGroupHandler) Create(c *gin.Context) {
	var req identity.UserGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	group, err := h.groups.Create(&req)
	if err != nil {
		respondUserGroupError(c, apierror.CodeInternalUserGroupCreate, err)
		return
	}
	c.JSON(http.StatusCreated, group)
}

// Update 更新群組
func (h *UserGroupHandler) Update(c *gin.Context) {
	id, ok := parseUserGroupID(c)
	if !ok {
		return
	}
	var req identity.UserGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	group, err := h.groups.Update(id, &req)
	if err != nil {
		respondUserGroupError(c, apierror.CodeInternalUserGroupUpdate, err)
		return
	}
	c.JSON(http.StatusOK, group)
}

// AuthorizationCount 群組授權筆數（刪除確認 UI「將連動撤銷 N 筆授權」）
func (h *UserGroupHandler) AuthorizationCount(c *gin.Context) {
	id, ok := parseUserGroupID(c)
	if !ok {
		return
	}
	count, err := h.groups.AuthorizationCount(id)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserGroupAuthCount, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"authorization_count": count})
}

// Delete 刪除群組：連動撤銷授權＋審計留痕（user-group-authorization D5）
func (h *UserGroupHandler) Delete(c *gin.Context) {
	id, ok := parseUserGroupID(c)
	if !ok {
		return
	}
	actorID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	actorName, _ := middleware.GetCurrentUsername(c)

	revoked, err := h.groups.Delete(id, actorID, actorName, sourceip.Of(c))
	if err != nil {
		respondUserGroupError(c, apierror.CodeInternalUserGroupDelete, err)
		return
	}
	// message 欄已移除（D9：成功回應不攜帶 UI 文案，前端自有 $t 文案）；
	// revoked_authorizations 為機器數值，保留
	c.JSON(http.StatusOK, gin.H{
		"revoked_authorizations": revoked,
	})
}

// ReplaceMembers 全量替換成員（穿梭框語義）
func (h *UserGroupHandler) ReplaceMembers(c *gin.Context) {
	id, ok := parseUserGroupID(c)
	if !ok {
		return
	}
	var req struct {
		UserIDs []uint `json:"user_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	group, err := h.groups.ReplaceMembers(id, req.UserIDs)
	if err != nil {
		respondUserGroupError(c, apierror.CodeInternalUserGroupMembersUpdate, err)
		return
	}
	c.JSON(http.StatusOK, group)
}

// RegisterRoutes 註冊路由：群組是授權主體的管理面，全部 admin only
func (h *UserGroupHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	groups := r.Group("/user-groups")
	groups.Use(middleware.AuthMiddleware(authService), middleware.RequireRole("admin"))
	{
		groups.GET("", h.List)
		groups.POST("", h.Create)
		groups.PUT("/:id", h.Update)
		groups.DELETE("/:id", h.Delete)
		groups.PUT("/:id/members", h.ReplaceMembers)
		groups.GET("/:id/authorization-count", h.AuthorizationCount)
	}
}
