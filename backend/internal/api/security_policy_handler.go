package api

import (
	"errors"
	"fmt"
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

// SecurityPolicyHandler 安全政策 API handler（admin 限定）
type SecurityPolicyHandler struct {
	policyService *policy.SecurityPolicyService
	auditService  *audit.AuditLogService
}

// NewSecurityPolicyHandler 建立安全政策 handler（auditService 可為 nil，表示停用審計）
func NewSecurityPolicyHandler(policyService *policy.SecurityPolicyService, auditService *audit.AuditLogService) *SecurityPolicyHandler {
	return &SecurityPolicyHandler{
		policyService: policyService,
		auditService:  auditService,
	}
}

// List 取得全部安全政策（含兩基準的建議值 metadata 與各自的符合性）
func (h *SecurityPolicyHandler) List(c *gin.Context) {
	views := h.policyService.List()
	deviation := 0
	epaymentDeviation := 0
	for _, v := range views {
		if v.Compliant != nil && !*v.Compliant {
			deviation++
		}
		if v.EPaymentCompliant != nil && !*v.EPaymentCompliant {
			epaymentDeviation++
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"data": views,
		// deviation_count 語義不變＝PCI 偏離數（既有前端與 fixture 依賴此意義）；
		// 電支偏離數以新欄位承載，兩者 SHALL NOT 合計（security-backlog-settlement D6）
		"deviation_count":          deviation,
		"epayment_deviation_count": epaymentDeviation,
	})
}

// UpdateRequest 批次更新請求：僅送有變更的鍵
type securityPolicyUpdateRequest struct {
	Policies map[string]string `json:"policies" binding:"required"`
}

// Update 批次更新安全政策（逐鍵驗證與審計，PCI 10.2.2：變更留痕含舊值→新值）
func (h *SecurityPolicyHandler) Update(c *gin.Context) {
	var req securityPolicyUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	if len(req.Policies) == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePolicyUpdateEmpty, nil)
		return
	}

	username, _ := middleware.GetCurrentUsername(c)
	userID, _ := middleware.GetCurrentUserID(c)

	// 單一交易內批次更新（POL-3：驗證與落庫皆在服務層，中途失敗全回滾不半套生效）
	changes, err := h.policyService.UpdateBatch(req.Policies, username)
	if err != nil {
		// 批次一次送多鍵，故錯誤必須指名是哪一鍵，否則 admin 無從得知該改哪一項
		var unknownKey *policy.PolicyUnknownKeyError
		if errors.As(err, &unknownKey) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodePolicyUnknownKey,
				map[string]any{"key": unknownKey.Key})
			return
		}
		// 跨鍵約束（audit-checkpoint-chain D9）：先於 InvalidValue 判定——
		// 兩者的修法不同（改關係 vs 改值域），共用碼會誤導 admin
		var crossKey *policy.PolicyRetentionCrossKeyError
		if errors.As(err, &crossKey) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodePolicyRetentionCrossKey,
				map[string]any{"key": crossKey.Key})
			return
		}
		var invalidValue *policy.PolicyInvalidValueError
		if errors.As(err, &invalidValue) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodePolicyInvalidValue,
				map[string]any{"key": invalidValue.Key})
			return
		}
		// 裸 sentinel 保底（僅保住狀態碼，訊息缺鍵名）
		if errors.Is(err, policy.ErrPolicyUnknownKey) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodePolicyUnknownKey, nil)
			return
		}
		if errors.Is(err, policy.ErrPolicyInvalidValue) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodePolicyInvalidValue, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPolicyWrite, err)
		return
	}

	// 交易提交後才審計，且僅審計真正有變動者（舊≠新，old→new，PCI 10.2.2）
	for _, ch := range changes {
		h.auditPolicyChange(c, userID, username, ch.Key, ch.OldValue, ch.NewValue)
	}

	h.List(c)
}

// auditPolicyChange 政策變更審計（10.2.2：who/what/when/old→new）
func (h *SecurityPolicyHandler) auditPolicyChange(c *gin.Context, userID uint, username, key, oldValue, newValue string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     model.ActionUpdate,
		Resource:   model.ResourceSecurityPolicy,
		Status:     model.StatusSuccess,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		ClientIP:   sourceip.Of(c),
		StatusCode: http.StatusOK,
		ErrorMsg:   fmt.Sprintf("policy=%s old=%s new=%s", key, oldValue, newValue),
	})
}

// RegisterRoutes 註冊安全政策路由（admin 限定）
func (h *SecurityPolicyHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	policies := r.Group("/security-policies")
	policies.Use(middleware.AuthMiddleware(authService))
	policies.Use(middleware.RequireRole("admin"))
	{
		policies.GET("", h.List)
		policies.PUT("", h.Update)
	}
}
