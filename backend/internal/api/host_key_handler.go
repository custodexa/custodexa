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
	"gorm.io/gorm"
)

// HostKeyServiceInterface host key 服務接口（用於測試注入）
type HostKeyServiceInterface interface {
	Get(assetID uint) (*model.AssetHostKey, error)
	Reset(assetID uint) (bool, error)
}

// HostKeyHandler 資產 host key 管理 API（host-key-verification）
type HostKeyHandler struct {
	hostKeys HostKeyServiceInterface
	authz    middleware.AssetPermissionChecker
}

// NewHostKeyHandler 建立 host key handler。authz 用於逐資產可視性守門
// （asset-access-scoping：host-key 揭露資產指紋與存在性，須與 /assets/:id 同級授權）
func NewHostKeyHandler(hostKeys HostKeyServiceInterface, authz middleware.AssetPermissionChecker) *HostKeyHandler {
	return &HostKeyHandler{hostKeys: hostKeys, authz: authz}
}

// Get 檢視資產的 host key 指紋
func (h *HostKeyHandler) Get(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}
	rec, err := h.hostKeys.Get(uint(id))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeHostKeyNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalHostKeyQuery, err)
		return
	}
	c.JSON(http.StatusOK, rec)
}

// Reset 重置資產 host key（admin；主機重灌場景）
func (h *HostKeyHandler) Reset(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}
	existed, err := h.hostKeys.Reset(uint(id))
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalHostKeyReset, err)
		return
	}
	if !existed {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeHostKeyNoRecordToReset, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

// RegisterRoutes 註冊路由：檢視需對該資產有可視授權（非 admin/auditor 逐資產守門），
// 重置 admin only。逐資產守門無條件生效（權限旗標已退場）。
func (h *HostKeyHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/assets/:id/host-key")
	g.Use(middleware.AuthMiddleware(authService))
	{
		g.GET("", middleware.RequireAssetVisible(h.authz), h.Get)
		g.DELETE("", middleware.RequireRole("admin"), h.Reset)
	}
}
