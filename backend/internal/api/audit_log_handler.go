package api

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
)

// AuditLogHandler 審計日誌 API Handler
type AuditLogHandler struct {
	auditService *audit.AuditLogService
}

// NewAuditLogHandler 創建審計日誌 Handler
func NewAuditLogHandler(auditService *audit.AuditLogService) *AuditLogHandler {
	return &AuditLogHandler{
		auditService: auditService,
	}
}

// RegisterRoutes 註冊審計日誌路由
func (h *AuditLogHandler) RegisterRoutes(
	router *gin.RouterGroup,
	authService *identity.AuthService,
) {
	auditLogs := router.Group("/audit-logs")
	auditLogs.Use(middleware.AuthMiddleware(authService))

	auditLogs.GET("", middleware.RequirePermission(middleware.PermAuditView), h.List)
	auditLogs.GET("/:id", middleware.RequirePermission(middleware.PermAuditView), h.Get)
	auditLogs.GET("/resource/:resource/:id", middleware.RequirePermission(middleware.PermAuditView), h.GetByResourceID)
}

// List 查詢審計日誌列表
func (h *AuditLogHandler) List(c *gin.Context) {
	filter := &audit.AuditLogFilter{}

	// 解析查詢參數
	if userID := c.Query("user_id"); userID != "" {
		if id, err := strconv.ParseUint(userID, 10, 32); err == nil {
			uid := uint(id)
			filter.UserID = &uid
		}
	}

	if action := c.Query("action"); action != "" {
		act := model.AuditAction(action)
		filter.Action = &act
	}

	if resource := c.Query("resource"); resource != "" {
		res := model.AuditResource(resource)
		filter.Resource = &res
	}

	if status := c.Query("status"); status != "" {
		stat := model.AuditStatus(status)
		filter.Status = &stat
	}

	if clientIP := c.Query("client_ip"); clientIP != "" {
		filter.ClientIP = &clientIP
	}

	if startTime := c.Query("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			filter.StartTime = &t
		}
	}

	if endTime := c.Query("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			filter.EndTime = &t
		}
	}

	// 分頁參數
	if page := c.Query("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil {
			filter.Page = p
		}
	}

	if pageSize := c.Query("page_size"); pageSize != "" {
		if ps, err := strconv.Atoi(pageSize); err == nil {
			filter.PageSize = ps
		}
	}

	// 排序參數
	filter.SortBy = c.DefaultQuery("sort_by", "created_at")
	filter.SortOrder = c.DefaultQuery("sort_order", "desc")

	// 查詢審計日誌
	result, err := h.auditService.List(filter)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuditLogQuery, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get 獲取單條審計日誌
func (h *AuditLogHandler) Get(c *gin.Context) {
	idParam := c.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "audit_log"})
		return
	}

	auditLog, err := h.auditService.Get(uint(id))
	if err != nil {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAuditLogNotFound, nil)
		return
	}

	c.JSON(http.StatusOK, auditLog)
}

// GetByResourceID 查詢特定資源的審計歷史
func (h *AuditLogHandler) GetByResourceID(c *gin.Context) {
	resourceType := c.Param("resource")
	idParam := c.Param("id")

	// 驗證資源類型。白名單的既有規則：**各型的 :id SHALL 一致地指向該型自身的
	// 實體 id**，否則樞紐回的是形式合法、語義虛假的結果集。
	//
	// `recording` 已於 audit-resource-classification-closure 批 1 移出：
	// 該分類的 resource_id 自此是**連線 id**（`/sessions/:id/recording*`）或 nil
	//（`/recordings/stats`），沒有一種是「錄影列 id」——留在白名單即違反
	// 上述規則。移除代價為零：訂正前 `/recordings/*` 的 resource_id 恆為 nil，
	// 該入口至今**永遠是空集**。錄影調閱改由連線樞紐以子資源展開涵蓋
	//（model.AuditHubSubResources），與 clipboard_event 的處置一致
	var resource model.AuditResource
	switch resourceType {
	case "asset":
		resource = model.ResourceAsset
	case "session":
		resource = model.ResourceSession
	case "user":
		resource = model.ResourceUser
	default:
		apierror.Write(c, http.StatusBadRequest, apierror.ErrorResponse{
			Code: apierror.CodeAuditResourceTypeInvalid,
			Meta: gin.H{"valid_types": []string{"asset", "session", "user"}},
		})
		return
	}

	// 解析資源 ID（resourceType 已經上方 switch 白名單驗證過，可安全作為 enum param）
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": resourceType})
		return
	}

	// 查詢審計歷史。樞紐涵蓋 id 空間相同的子資源（model.AuditHubSubResources）：
	// 查一場連線時，「誰取走了這場連線的剪貼簿內容／錄影本體／指令原文」屬於
	// 同一次調查的答案，不應因取證動作被獨立分類而從連線樞紐消失。
	//
	// 展開留在 handler 而非下沉服務層：service 的 GetByResourceID 是「單一分類 ×
	// 單一 id」的原語，「一次調查涵蓋哪些分類」是樞紐端點的語義，兩者不該混。
	logs, err := h.auditService.GetByResourceID(resource, uint(id))
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuditLogResourceHistoryQuery, err)
		return
	}
	for _, sub := range model.AuditHubSubResources[resource] {
		subLogs, err := h.auditService.GetByResourceID(sub, uint(id))
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuditLogResourceHistoryQuery, err)
			return
		}
		logs = append(logs, subLogs...)
	}
	// 合併後重排：各分類各自已依時間倒序，合併會破壞單一時間軸
	sort.SliceStable(logs, func(i, j int) bool {
		return logs[i].CreatedAt.After(logs[j].CreatedAt)
	})

	c.JSON(http.StatusOK, gin.H{
		"resource":    resourceType,
		"resource_id": id,
		"total":       len(logs),
		"logs":        logs,
	})
}
