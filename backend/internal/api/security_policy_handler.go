package api

import (
	"encoding/json"
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
		// 電支偏離數以新欄位承載，兩者 SHALL NOT 合計
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

	// 單一交易內批次更新（驗證與落庫皆在服務層，中途失敗全回滾不半套生效）
	changes, err := h.policyService.UpdateBatch(req.Policies, username)
	if err != nil {
		// 批次一次送多鍵，故錯誤必須指名是哪一鍵，否則 admin 無從得知該改哪一項
		var unknownKey *policy.PolicyUnknownKeyError
		if errors.As(err, &unknownKey) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodePolicyUnknownKey,
				map[string]any{"key": unknownKey.Key})
			return
		}
		// 跨鍵約束（audit-checkpoint-chain）：先於 InvalidValue 判定——
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

// LoginBanner 登入前告示的公開讀取端點（未認證可達）。
//
// 只回告示的兩個欄位，不回任何其他政策鍵、值、建議值、符合性或修改者——這條
// 路由沒有認證中介層，回應內容即等同對匿名者公開。
//
// 未設定的判準只看內文：標題單獨有值不成其為告示，回應與完全未設定一致，
// 前端因此不需要處理「有標題沒內文」這種半設定狀態。
//
// 不寫審計列、不寫資料庫：讀的是政策快取，一次頁面載入不該在稽核軌跡上留下
// 一列「有人打開了登入頁」。
func (h *SecurityPolicyHandler) LoginBanner(c *gin.Context) {
	// 不快取：告示改完之後下一個開登入頁的人就該看到新的
	c.Header("Cache-Control", "no-store")

	// 兩鍵各讀一次。管理員儲存的那一瞬間，可能一鍵讀到更新前、另一鍵讀到更新後，
	// 於政策快取效期內收斂——顯示型告示接受這個邊界（規格明載）
	body := h.policyService.Get(policy.PolicyLoginBannerBody)
	if body == "" {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled": true,
		"title":   h.policyService.Get(policy.PolicyLoginBannerTitle),
		"body":    body,
	})
}

// policyChangeAuditFields 依政策鍵的型別決定審計列要怎麼記變更。
//
// 文字型的值可以有換行且長達數千字元，塞進單行訊息欄會讓那一欄不可讀、也讓
// CSV 匯出多出換行；故文字鍵把舊值與新值全文放進變更詳情欄（既有的
// changes[] 形狀，前端逐欄展開），訊息欄只留鍵名。非文字鍵維持既有的單行格式。
//
// 抽成純函式：審計列的形狀是稽核證據的一部分，必須能被直接斷言，
// 不必為了驗它而拉起整個審計服務。
func policyChangeAuditFields(key, oldValue, newValue string) (details, errorMsg string) {
	def := policy.FindPolicyDef(key)
	if def == nil || def.Type != policy.PolicyTypeText {
		return "", fmt.Sprintf("policy=%s old=%s new=%s", key, oldValue, newValue)
	}
	payload := struct {
		Changes []policyChangeDetail `json:"changes"`
	}{Changes: []policyChangeDetail{{Field: key, Old: oldValue, New: newValue}}}
	encoded, err := json.Marshal(payload)
	if err != nil {
		// 編碼不可能失敗（全是字串欄）。真的失敗時寧可少一份詳情也不能少一列審計，
		// 故退回鍵名訊息而非丟棄整列
		return "", fmt.Sprintf("policy=%s", key)
	}
	return string(encoded), fmt.Sprintf("policy=%s", key)
}

// policyChangeDetail 變更詳情的單筆形狀（沿既有 changes[] 慣例）
type policyChangeDetail struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// auditPolicyChange 政策變更審計（10.2.2：who/what/when/old→new）
func (h *SecurityPolicyHandler) auditPolicyChange(c *gin.Context, userID uint, username, key, oldValue, newValue string) {
	if h.auditService == nil {
		return
	}
	details, errorMsg := policyChangeAuditFields(key, oldValue, newValue)
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
		ErrorMsg:   errorMsg,
		Details:    details,
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

	// 登入前告示：公開端點（未認證可達），與登入方法清單同一層
	r.GET("/auth/banner", h.LoginBanner)
}
