package api

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
)

// AlertRuleServiceInterface 告警規則服務接口（用於測試注入）
type AlertRuleServiceInterface interface {
	List() ([]model.AlertRule, error)
	Create(req *audit.AlertRuleRequest) (*model.AlertRule, error)
	Update(id uint, req *audit.AlertRuleRequest) (*model.AlertRule, error)
	Delete(id uint) error
}

// AlertRuleHandler 告警規則 API handler（command-alerts D4，admin only）
type AlertRuleHandler struct {
	ruleService AlertRuleServiceInterface
}

// NewAlertRuleHandler 創建告警規則 handler
func NewAlertRuleHandler(ruleService AlertRuleServiceInterface) *AlertRuleHandler {
	return &AlertRuleHandler{ruleService: ruleService}
}

// respondRuleError 將 service 錯誤映射為 HTTP 狀態：
// 輸入問題（regex 無效/severity 非法）回 400 並附機器碼，名稱撞既有規則回 409
// （與 CONFLICT_ASSET_NAME 等唯一性衝突同形），找不到回 404，其餘 500。
// 名稱衝突由 service 從資料庫回傳的唯一鍵違反轉譯而來（非先查後寫），
// 到這裡已是哨兵錯誤，驅動訊息中的表名/索引名/SQL 不隨回應外流。
// service 層以 %w 包裝底層細節（如 regex 編譯器原文）：碼化後這些細節不再入
// client 回應（僅碼＋固定 zh fallback），泛化訊息，避免內部實作細節外洩
func respondRuleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, audit.ErrInvalidPattern):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAlertPattern, nil)
	case errors.Is(err, audit.ErrInvalidSeverity):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAlertSeverity, nil)
	case errors.Is(err, audit.ErrInvalidAction):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAlertAction, nil)
	case errors.Is(err, audit.ErrInvalidProtocols):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAlertProtocols, nil)
	case errors.Is(err, audit.ErrAlertRuleNameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAlertRuleNameExists, nil)
	case errors.Is(err, audit.ErrAlertRuleNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAlertRuleNotFound, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAlertRuleOp, err)
	}
}

// List 列出所有告警規則
func (h *AlertRuleHandler) List(c *gin.Context) {
	rules, err := h.ruleService.List()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAlertRuleQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":  rules,
		"total": len(rules),
	})
}

// Create 建立告警規則
func (h *AlertRuleHandler) Create(c *gin.Context) {
	var req audit.AlertRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	rule, err := h.ruleService.Create(&req)
	if err != nil {
		respondRuleError(c, err)
		return
	}
	c.JSON(http.StatusCreated, rule)
}

// Update 更新告警規則
func (h *AlertRuleHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAlertRuleID, nil)
		return
	}

	var req audit.AlertRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	rule, err := h.ruleService.Update(uint(id), &req)
	if err != nil {
		respondRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Delete 刪除告警規則
func (h *AlertRuleHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAlertRuleID, nil)
		return
	}

	if err := h.ruleService.Delete(uint(id)); err != nil {
		respondRuleError(c, err)
		return
	}
	// 成功訊息不落 payload（design D9）：前端以自有 $t 文案顯示
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// RegisterRoutes 註冊告警規則路由：
// 規則 CUD 影響全系統告警行為，整組 admin only（與 user 管理同模式，design D4）
func (h *AlertRuleHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	rules := r.Group("/alert-rules")
	rules.Use(middleware.AuthMiddleware(authService))
	rules.Use(middleware.RequireRole("admin"))
	{
		rules.GET("", h.List)
		rules.POST("", h.Create)
		rules.PUT("/:id", h.Update)
		rules.DELETE("/:id", h.Delete)
	}
}
