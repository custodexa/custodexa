package api

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
)

// CommandAlertServiceInterface 告警查詢服務接口（用於測試注入）
type CommandAlertServiceInterface interface {
	List(filter *audit.CommandAlertFilter) (*audit.CommandAlertListResponse, error)
	Review(alertID, reviewerID uint, disposition, note string) error
}

// CommandAlertHandler 告警查詢 API handler（command-alerts D4，audit:view）
type CommandAlertHandler struct {
	alertService CommandAlertServiceInterface
	// auditService 審閱處置的顯式審計；nil 表示停用
	auditService *audit.AuditLogService
}

// NewCommandAlertHandler 創建告警查詢 handler
func NewCommandAlertHandler(alertService CommandAlertServiceInterface) *CommandAlertHandler {
	return &CommandAlertHandler{alertService: alertService}
}

// SetAuditService 注入審計服務（審閱處置事件留痕）
func (h *CommandAlertHandler) SetAuditService(auditService *audit.AuditLogService) {
	h.auditService = auditService
}

// List 告警列表查詢
func (h *CommandAlertHandler) List(c *gin.Context) {
	filter := &audit.CommandAlertFilter{
		Page:     1,
		PageSize: 20,
	}

	// severity 在 handler 層先驗證：非法值直接 400 比靜默回空集合更可診斷
	if severity := c.Query("severity"); severity != "" {
		if !model.ValidAlertSeverity(severity) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAlertSeverity, nil)
			return
		}
		filter.Severity = severity
	}

	if userIDStr := c.Query("user_id"); userIDStr != "" {
		if userID, err := strconv.ParseUint(userIDStr, 10, 32); err == nil {
			uid := uint(userID)
			filter.UserID = &uid
		}
	}
	if assetIDStr := c.Query("asset_id"); assetIDStr != "" {
		if assetID, err := strconv.ParseUint(assetIDStr, 10, 32); err == nil {
			aid := uint(assetID)
			filter.AssetID = &aid
		}
	}

	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filter.StartTime = &startTime
		}
	}
	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if endTime, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filter.EndTime = &endTime
		}
	}

	// 未審閱篩選（audit-workflows D3）：供每日審閱走查（10.4.1）
	if c.Query("unreviewed") == "true" {
		filter.Unreviewed = true
	}

	if page, err := strconv.Atoi(c.Query("page")); err == nil && page > 0 {
		filter.Page = page
	}
	if pageSize, err := strconv.Atoi(c.Query("page_size")); err == nil && pageSize > 0 {
		filter.PageSize = pageSize
	}

	result, err := h.alertService.List(filter)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalCommandAlertQuery, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// Review 審閱處置一筆告警（audit-workflows D3，PCI 10.4.1）
func (h *CommandAlertHandler) Review(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidCommandAlertID, nil)
		return
	}

	var req struct {
		Disposition string `json:"disposition" binding:"required"`
		Note        string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidReviewRequest, nil)
		return
	}

	reviewerID, _ := middleware.GetCurrentUserID(c)
	if err := h.alertService.Review(uint(id), reviewerID, req.Disposition, req.Note); err != nil {
		switch err {
		case audit.ErrAlertNotFound:
			apierror.Respond(c, http.StatusNotFound, apierror.CodeCommandAlertNotFound, nil)
		case audit.ErrInvalidDisposition:
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidDisposition, nil)
		default:
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAlertReview, err)
		}
		return
	}

	// 審閱處置屬稽核動作，顯式留痕（誰在何時將哪筆告警處置為何）
	if h.auditService != nil {
		reviewerName, _ := middleware.GetCurrentUsername(c)
		alertID := uint(id)
		h.auditService.Log(&audit.AuditLogEntry{
			UserID:     reviewerID,
			Username:   reviewerName,
			Action:     model.ActionUpdate,
			Resource:   model.ResourceCommandAlert,
			ResourceID: &alertID,
			Status:     model.StatusSuccess,
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			ClientIP:   sourceip.Of(c),
			StatusCode: http.StatusOK,
			ErrorMsg:   "alert_disposition_" + req.Disposition,
		})
	}

	// 成功訊息不落 payload（design D9）：前端以自有 $t 文案顯示
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// RegisterRoutes 註冊告警查詢路由：
// 與審計日誌/跨會話指令搜尋同掛 audit:view（design D4），無條件強制
func (h *CommandAlertHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	alerts := r.Group("/command-alerts")
	alerts.Use(middleware.AuthMiddleware(authService))

	alerts.GET("", middleware.RequirePermission(middleware.PermAuditView), h.List)
	// 審閱處置屬告警管理，掛 alert:manage（auditor/admin 有；user 無）
	alerts.POST("/:id/review", middleware.RequirePermission(middleware.PermAlertManage), h.Review)
}
