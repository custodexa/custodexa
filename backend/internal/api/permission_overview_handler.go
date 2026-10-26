package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// PermissionOverviewReader 單一使用者權限一覽的唯讀來源（authz.PermissionOverviewService 實作）。
type PermissionOverviewReader interface {
	Overview(ctx context.Context, subjectUserID uint) (*authz.PermissionOverview, error)
	ProbeAsset(ctx context.Context, subjectUserID, assetID uint) (*authz.OverviewAssetProbe, error)
}

// PermissionOverviewHandler 使用者權限一覽：兩條唯讀路由，只有一種放行條件（路由登錄的使用者檢視能力），
// 不接受任何改變裁決的查詢參數。
type PermissionOverviewHandler struct {
	reader PermissionOverviewReader
}

// NewPermissionOverviewHandler 建立 handler；reader 缺席時兩條路由回內部錯誤，不回空集合。
func NewPermissionOverviewHandler(r PermissionOverviewReader) *PermissionOverviewHandler {
	return &PermissionOverviewHandler{reader: r}
}

func overviewIDParam(c *gin.Context, name, resource string) (uint, bool) {
	id, err := strconv.ParseUint(c.Param(name), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": resource})
		return 0, false
	}
	return uint(id), true
}

// Get GET /users/:id/permission-overview
func (h *PermissionOverviewHandler) Get(c *gin.Context) {
	id, ok := overviewIDParam(c, "id", "user")
	if !ok {
		return
	}
	if h == nil || h.reader == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPermissionOverview, authz.ErrPermissionOverviewUnwired)
		return
	}
	res, err := h.reader.Overview(operatorContext(c), id)
	if err != nil {
		if errors.Is(err, authz.ErrEffectiveSubjectNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPermissionOverview, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// GetAsset GET /users/:id/permission-overview/assets/:asset_id
func (h *PermissionOverviewHandler) GetAsset(c *gin.Context) {
	id, ok := overviewIDParam(c, "id", "user")
	if !ok {
		return
	}
	assetID, ok := overviewIDParam(c, "asset_id", "asset")
	if !ok {
		return
	}
	if h == nil || h.reader == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPermissionOverview, authz.ErrPermissionOverviewUnwired)
		return
	}
	res, err := h.reader.ProbeAsset(operatorContext(c), id, assetID)
	if err != nil {
		switch {
		case errors.Is(err, authz.ErrEffectiveSubjectNotFound):
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotFound, nil)
		case errors.Is(err, authz.ErrEffectiveAssetNotFound):
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
		default:
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPermissionOverview, err)
		}
		return
	}
	c.JSON(http.StatusOK, res)
}

// RegisterRoutes 註冊兩條唯讀路由；權限由路由登錄裁決（使用者檢視能力，全系統範圍）。
func (h *PermissionOverviewHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/users/:id/permission-overview")
	g.Use(middleware.AuthMiddleware(authService), middleware.EnforceRegistry())
	g.GET("", h.Get)
	g.GET("/assets/:asset_id", h.GetAsset)
}
