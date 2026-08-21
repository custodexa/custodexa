package api

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
)

// TransmissionInventoryHandler 通道加密清冊 API（transmission-security-policy 4.1/4.2，
// admin 限定；清冊揭露全通道安全態勢屬敏感資源，讀取與匯出均入審計）
type TransmissionInventoryHandler struct {
	inventory    *policy.TransmissionInventoryService
	auditService *audit.AuditLogService
}

// NewTransmissionInventoryHandler 建立清冊 handler（auditService 可為 nil，表示停用審計）
func NewTransmissionInventoryHandler(inventory *policy.TransmissionInventoryService, auditService *audit.AuditLogService) *TransmissionInventoryHandler {
	return &TransmissionInventoryHandler{inventory: inventory, auditService: auditService}
}

// audit 清冊讀取/匯出審計（匯出＝讀取聚合，比照 audit-export 用 read＋resource 區分）
func (h *TransmissionInventoryHandler) audit(c *gin.Context, event string) {
	if h.auditService == nil {
		return
	}
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	details, _ := json.Marshal(gin.H{"event": event})
	h.auditService.Log(&audit.AuditLogEntry{
		UserID: userID, Username: username,
		Action: model.ActionRead, Resource: model.ResourceTransmission,
		Status: model.StatusSuccess, Method: c.Request.Method,
		Path: c.Request.URL.Path, ClientIP: sourceip.Of(c),
		StatusCode: http.StatusOK, Details: string(details),
	})
}

// Get 取得通道加密清冊
func (h *TransmissionInventoryHandler) Get(c *gin.Context) {
	inv, err := h.inventory.Build()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTransmissionInventoryBuild, err)
		return
	}
	h.audit(c, "inventory_read")
	c.JSON(http.StatusOK, gin.H{"data": inv})
}

// Export 匯出清冊快照（JSON＋時間戳＋產生者＝稽核 inventory）
func (h *TransmissionInventoryHandler) Export(c *gin.Context) {
	inv, err := h.inventory.Build()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTransmissionInventoryBuild, err)
		return
	}
	username, _ := middleware.GetCurrentUsername(c)
	inv.GeneratedBy = username
	h.audit(c, "inventory_export")

	filename := "transmission-inventory-" + inv.GeneratedAt.Format("20060102-150405") + ".json"
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.JSON(http.StatusOK, inv)
}

// RegisterRoutes 註冊清冊路由（admin 限定）
func (h *TransmissionInventoryHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	group := r.Group("/transmission-inventory")
	group.Use(middleware.AuthMiddleware(authService))
	group.Use(middleware.RequireRole("admin"))
	{
		group.GET("", h.Get)
		group.POST("/export", h.Export)
	}
}
