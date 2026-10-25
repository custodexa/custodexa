package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// AuditFailureHandler 審計機制失效事件查詢 API
type AuditFailureHandler struct {
	failureService *audit.AuditFailureService
	// permAccept 超管確認權限狀態「無來源變動」；nil＝端點回內部錯誤，不靜默成功
	permAccept permissionStateAcceptor
}

// permissionStateAcceptor 確認服務的窄介面（實作為 *audit.PermissionAcceptService）。
type permissionStateAcceptor interface {
	Accept(ctx context.Context, who audit.PermissionAcceptActor, reason string) (*audit.PermissionAcceptResult, error)
}

// SetPermissionAccept 注入確認服務（組裝根呼叫）。
func (h *AuditFailureHandler) SetPermissionAccept(s permissionStateAcceptor) { h.permAccept = s }

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

// acceptPermissionStateRequest 確認請求本文：只有原因。
type acceptPermissionStateRequest struct {
	Reason string `json:"reason"`
}

// AcceptPermissionState 超管確認權限狀態的「無來源變動」並以目前狀態為新基準。
// 成功回 200 與摘要（事件序號、差集計數與具型別 ID）；沒有可確認的差異回 409。
func (h *AuditFailureHandler) AcceptPermissionState(c *gin.Context) {
	var req acceptPermissionStateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationPermissionStateAcceptReason, nil)
		return
	}
	if h.permAccept == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPermissionStateAccept, errors.New("accept service unavailable"))
		return
	}
	who := audit.PermissionAcceptActor{
		Actor:   gatewayapi.Actor{UserID: c.GetUint("userID"), Username: c.GetString("username")},
		Request: gatewayapi.RequestMeta{Method: c.Request.Method, Path: c.Request.URL.Path, ClientIP: sourceip.Of(c), RequestID: c.GetString("request_id"), StatusCode: http.StatusOK},
	}
	res, err := h.permAccept.Accept(c.Request.Context(), who, req.Reason)
	if err != nil {
		var notAcceptable *audit.PermissionNotAcceptableError
		switch {
		case errors.Is(err, audit.ErrPermissionAcceptReason):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationPermissionStateAcceptReason, nil)
		case errors.As(err, &notAcceptable):
			apierror.Respond(c, http.StatusConflict, apierror.CodeConflictPermissionStateNotAcceptable, nil)
		default:
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPermissionStateAccept, err)
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": res})
}

// RequirePermissionAcceptSuperAdmin 匯出供路由測試掛同一道守衛（正式路由仍掛未匯出的同名守衛，路由表不變）。
func RequirePermissionAcceptSuperAdmin(c *gin.Context) { requirePermissionAcceptSuperAdmin(c) }

// requirePermissionAcceptSuperAdmin 確認端點的保留資格守衛：登錄項為 BaseAuthenticated，
// 超管身分屬保留能力（不是權限點），由此判定；非超管回能力拒絕單一形狀（依據為保留條件），服務不被呼叫。
func requirePermissionAcceptSuperAdmin(c *gin.Context) {
	if p := middleware.PrincipalFrom(c); p == nil || !p.IsSuperAdmin() {
		middleware.WriteCapabilityDenial(c, middleware.ReservedCapabilityDenial(authz.ReservedSuperAdmin))
		return
	}
	c.Next()
}

// RegisterRoutes 註冊失效事件路由（登錄執行）；確認端點為超管保留能力（admin only）
func (h *AuditFailureHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	failures := r.Group("/audit-failures")
	failures.Use(middleware.AuthMiddleware(authService))
	failures.GET("", middleware.EnforceRegistry(), h.List)
	failures.POST("/permission-state/accept", middleware.EnforceRegistry(), requirePermissionAcceptSuperAdmin, h.AcceptPermissionState)
}
