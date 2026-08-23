package api

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
)

// AuditFailureHandler 審計機制失效事件查詢 API
type AuditFailureHandler struct {
	failureService *audit.AuditFailureService
}

// NewAuditFailureHandler 建立失效事件 handler
func NewAuditFailureHandler(failureService *audit.AuditFailureService) *AuditFailureHandler {
	return &AuditFailureHandler{failureService: failureService}
}

// failureEventItem 失效事件回應形狀：
// 內嵌 model 保留既有欄位，另以物件形態曝露 cause_params——DB 存的是 JSON
// 字串，直送會讓前端拿到「JSON 裡的 JSON」還得二次 parse。
// cause_code 為權威表述（前端查譯），cause 散文續留作既有讀取點的 fallback
type failureEventItem struct {
	model.AuditFailureEvent
	CauseParams map[string]string `json:"cause_params"`
}

// toFailureEventItems 解碼 cause_params；解不開（含空字串）即空物件，
// 不因單列壞資料讓整份列表失敗——失效事件本身常誕生於系統異常之際
func toFailureEventItems(rows []model.AuditFailureEvent) []failureEventItem {
	items := make([]failureEventItem, 0, len(rows))
	for _, row := range rows {
		params := map[string]string{}
		if row.CauseParams != "" {
			if err := json.Unmarshal([]byte(row.CauseParams), &params); err != nil {
				params = map[string]string{}
			}
		}
		items = append(items, failureEventItem{AuditFailureEvent: row, CauseParams: params})
	}
	return items
}

// List 失效事件列表（起訖時間+原因碼與參數，PCI 10.7.3 處置記錄）
func (h *AuditFailureHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	rows, total, err := h.failureService.List(page, pageSize)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuditFailureQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"items": toFailureEventItems(rows), "total": total}})
}

// RegisterRoutes 註冊失效事件路由（audit:view）
func (h *AuditFailureHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	failures := r.Group("/audit-failures")
	failures.Use(middleware.AuthMiddleware(authService))
	failures.GET("", middleware.RequirePermission(middleware.PermAuditView), h.List)
}
