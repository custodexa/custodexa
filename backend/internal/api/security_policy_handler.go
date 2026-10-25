package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"net/http"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// SecurityPolicyHandler 安全政策 API handler（admin 限定）
type SecurityPolicyHandler struct {
	policyService *policy.SecurityPolicyService
	auditService  *audit.AuditLogService
	// auditTx 政策變更審計的交易內落地面：審計與政策寫入同成敗（PCI 10.2.2）
	auditTx port.TxSink
	// compliance 判定契約：列表的逐鍵判定、草稿回饋與套用預覽三處共用同一次建構
	compliance *policy.ComplianceService
	// groups 政策組讀取面：頁首的生效組列要組名，判定結果只帶代號
	groups *policy.PolicyGroupRepository
}

// NewSecurityPolicyHandler 建立安全政策 handler（auditService 可為 nil，表示停用審計）
func NewSecurityPolicyHandler(policyService *policy.SecurityPolicyService,
	auditService *audit.AuditLogService, compliance *policy.ComplianceService,
	groups *policy.PolicyGroupRepository) *SecurityPolicyHandler {
	return &SecurityPolicyHandler{
		policyService: policyService,
		auditService:  auditService,
		auditTx:       audit.NewTxSink(),
		compliance:    compliance,
		groups:        groups,
	}
}

// SetAuditTxSink 替換政策變更審計的交易內落地面（組裝根注入啟動自檢過的同一個；
// 測試注入會失敗的落地面以驗證回滾）。設為 nil 時政策寫入一律失敗，不會無審計放行。
func (h *SecurityPolicyHandler) SetAuditTxSink(sink port.TxSink) { h.auditTx = sink }

// securityPolicyItem 政策項視圖加上它對各生效政策組的判定。
//
// 判定隨列表一起回，理由是設定頁的每一個分區都要立刻算得出偏離數；分兩支端點
// 讀會讓值與判定來自兩個時點，而那正是「同一個畫面上兩個數字對不起來」的成因。
type securityPolicyItem struct {
	policy.PolicyView
	// Verdicts 該鍵對各生效組的判定（未對照時為一列 unmapped）
	Verdicts []policy.Verdict `json:"verdicts"`
}

// List 取得全部安全政策（含現值、對各生效組的判定，與過渡期的兩基準欄位）
func (h *SecurityPolicyHandler) List(c *gin.Context) {
	// **現值只讀一次，判定由這一份建構**：列表與判定各讀一次的話，其間的一次
	// 寫入會讓同一列顯示新值配舊值算出的結果，而畫面上看不出那是兩個時點。
	// 讀取失敗也不退回出廠預設——那會讓一份看起來正常的「全部符合」蓋住
	// 「現值根本沒讀到」這件事
	views, err := h.policyService.ListWithError()
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalComplianceSnapshot)
		return
	}
	snapshot, err := h.compliance.SnapshotWithValues(views, "", nil, nil)
	if err != nil {
		// **不退回「零偏離」**：判定讀不到時把列表照常回出去，畫面會顯示全部符合，
		// 那是安全控制的呈現在失效方向上說謊
		respondPolicyGroupError(c, err, apierror.CodeInternalComplianceSnapshot)
		return
	}
	groups, err := h.groups.ListGroups()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalPolicyGroupRead, err)
		return
	}
	enabled := make([]model.PolicyGroup, 0, len(groups))
	for _, g := range groups {
		if g.Enabled {
			enabled = append(enabled, g)
		}
	}

	items := make([]securityPolicyItem, 0, len(views))
	for _, v := range views {
		verdicts := snapshot.VerdictsForKey(v.Key)
		if verdicts == nil {
			verdicts = []policy.Verdict{}
		}
		items = append(items, securityPolicyItem{PolicyView: v, Verdicts: verdicts})
	}
	c.JSON(http.StatusOK, gin.H{
		"data": items,
		// groups 為生效組清單，供各承載頁的頁首列出「現在對照的是哪幾組」
		"groups": enabled,
	})
}

// policyDefView 單一設定鍵的定義與現值（政策組條文表單選鍵後取用）。
//
// 表單要問的是四件事：這個鍵是什麼型別、要求可以用哪幾種比較方式、合法值域到
// 哪裡、以及現在是多少（據以即時說出「儲存後這一條會顯示為偏離」）。
type policyDefView struct {
	policy.PolicyDef
	// Value 目前生效值（無政策列時為出廠預設）
	Value string `json:"value"`
	// Comparators 這個型別允許的比較方式；空集合＝不可作為條文要求的對象
	Comparators []string   `json:"comparators"`
	UpdatedBy   string     `json:"updated_by,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// comparatorsForType 依鍵型別列出可選的比較方式。
//
// 整數型才有方向（至少／至多）；開關與枚舉之間沒有強弱序，只能要求明確值。
// 三者都可以是「有要求但不定值」——條文說的是「足夠強度」這類語境式要求時，
// 系統不替它發明一個門檻。自由文字型沒有可比較的要求值，回空集合。
func comparatorsForType(policyType string) []string {
	switch policyType {
	case policy.PolicyTypeInt:
		return []string{
			model.PolicyControlComparatorMin,
			model.PolicyControlComparatorMax,
			model.PolicyControlComparatorReview,
		}
	case policy.PolicyTypeBool, policy.PolicyTypeEnum:
		return []string{
			model.PolicyControlComparatorEquals,
			model.PolicyControlComparatorReview,
		}
	default:
		return []string{}
	}
}

// Def 單一設定鍵的定義與現值。
func (h *SecurityPolicyHandler) Def(c *gin.Context) {
	key := c.Param("key")
	def := policy.FindPolicyDef(key)
	if def == nil {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeValidationPolicyGroupUnknownKey, nil)
		return
	}
	view := policyDefView{PolicyDef: *def, Comparators: comparatorsForType(def.Type)}
	for _, item := range h.policyService.List() {
		if item.Key != key {
			continue
		}
		view.Value = item.Value
		view.UpdatedBy = item.UpdatedBy
		view.UpdatedAt = item.UpdatedAt
	}
	c.JSON(http.StatusOK, gin.H{"data": view})
}

// securityPolicyDraftRequest 尚未儲存的表單值。
//
// 草稿由後端重算判定而不是前端自己算：前端算一份會與伺服器的判定漂移，
// 而兩者的分歧不會有任何一處報錯。
type securityPolicyDraftRequest struct {
	Draft map[string]string `json:"draft"`
	// TempControls 尚未儲存的條文要求，只影響本次回應。
	//
	// 條文編輯器據此問「這一條存下去會判成什麼」——那個答案必須由判定契約給，
	// 編輯器自己算一份會與伺服器漂移，而分歧不會有任何一處報錯
	TempControls []policy.TempControl `json:"temp_controls"`
}

// CompliancePreview 以草稿值與尚未儲存的要求重算一份判定（唯讀，不寫入任何東西）。
func (h *SecurityPolicyHandler) CompliancePreview(c *gin.Context) {
	var req securityPolicyDraftRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	snapshot, err := h.compliance.SnapshotWithTemp(c.Query("group"), req.Draft, req.TempControls)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalComplianceSnapshot)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": snapshot})
}

// securityPolicyApplyRequest 套用預覽的請求。
//
// scope 是本頁的鍵集合：套用一律限本頁，介面也明示本頁——一個按鈕改掉四個頁面
// 的設定，管理者按下去之前看不出影響範圍。
type securityPolicyApplyRequest struct {
	Scope     []string          `json:"scope"`
	Mode      string            `json:"mode"`
	GroupCode string            `json:"group_code"`
	Draft     map[string]string `json:"draft"`
}

// ApplyPreview 套用政策建議值的預覽（只算不寫）。
//
// 確認套用只把 changes 填進表單，仍走既有的批次儲存流程與審計——預覽端點自己
// 落庫會讓一次「看看會變成什麼」變成一次沒有經過確認的變更。
func (h *SecurityPolicyHandler) ApplyPreview(c *gin.Context) {
	var req securityPolicyApplyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	preview, err := h.compliance.PreviewApply(req.Scope, req.Mode, req.GroupCode, req.Draft)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalComplianceSnapshot)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": preview})
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

	// 單一交易內批次更新（驗證與落庫皆在服務層，中途失敗全回滾不半套生效）。
	// 只審計真正有變動者（舊≠新，old→new，PCI 10.2.2），且審計與政策寫入同一交易：
	// 審計寫不進去，政策值就不變
	// 高危鍵的變更另在同一交易內、審計之後建立系統告警，審計 details 與告警共用關聯識別
	actor := policy.PolicyActor{ID: userID, Name: username, ClientIP: sourceip.Of(c)}
	_, err := h.policyService.UpdateBatchAudited(req.Policies, actor,
		func(tx *gorm.DB, ch policy.PolicyChange) error {
			return h.auditPolicyChange(tx, c, userID, username, ch)
		})
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
		if errors.Is(err, policy.ErrHighRiskAlertRaise) {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSystemAlertRaise, err)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPolicyWrite, err)
		return
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
		return "", model.PolicyChangeAuditMessage(key, oldValue, newValue)
	}
	return policyTextChangeDetails(key, oldValue, newValue)
}

// policyChangeAuditFieldsWithCorrelation 同 policyChangeAuditFields；本鍵的變更觸發高危設定
// 告警時（correlationID 非空），details 另帶 correlation_id 供從告警回查本列；原始存量值
// 不合法時另帶 effective_old_value。非文字鍵原本沒有 details，此時只放這兩欄。
func policyChangeAuditFieldsWithCorrelation(key, oldValue, newValue, correlationID, effectiveOld string) (details, errorMsg string) {
	details, errorMsg = policyChangeAuditFields(key, oldValue, newValue)
	if correlationID == "" && effectiveOld == "" {
		return details, errorMsg
	}
	payload := map[string]any{}
	if details != "" {
		if err := json.Unmarshal([]byte(details), &payload); err != nil {
			payload = map[string]any{}
		}
	}
	if correlationID != "" {
		payload["correlation_id"] = correlationID
	}
	// 原始存量值不合法時，另記讀取路徑實際生效的舊值（告警的前值以它為準）
	if effectiveOld != "" {
		payload["effective_old_value"] = effectiveOld
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return details, errorMsg
	}
	return string(encoded), errorMsg
}

// policyTextChangeDetails 文字鍵的變更詳情（舊值與新值全文放進 changes[]）。
func policyTextChangeDetails(key, oldValue, newValue string) (details, errorMsg string) {
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

// auditPolicyChange 政策變更審計（10.2.2：who/what/when/old→new）。
// 在政策寫入的交易內同步落地；回 error 即整批政策寫入回滾。
func (h *SecurityPolicyHandler) auditPolicyChange(tx *gorm.DB, c *gin.Context, userID uint, username string, ch policy.PolicyChange) error {
	details, errorMsg := policyChangeAuditFieldsWithCorrelation(ch.Key, ch.OldValue, ch.NewValue, ch.CorrelationID, ch.EffectiveOldValue)
	return port.WriteInTx(h.auditTx, tx, port.AuditEvent{
		Actor:    gatewayapi.Actor{UserID: userID, Username: username},
		Action:   string(model.ActionUpdate),
		Resource: string(model.ResourceSecurityPolicy),
		Status:   string(model.StatusSuccess),
		Request: gatewayapi.RequestMeta{
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			ClientIP:   sourceip.Of(c),
			StatusCode: http.StatusOK,
		},
		ErrorMsg: errorMsg,
		Details:  details,
	})
}

// RegisterRoutes 註冊安全政策路由（admin 限定）
func (h *SecurityPolicyHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	policies := r.Group("/security-policies")
	policies.Use(middleware.AuthMiddleware(authService))
	policies.Use(middleware.EnforceRegistry())
	{
		policies.GET("", h.List)
		policies.PUT("", h.Update)
		// 條文表單選鍵後取型別、比較方式候選、值域與現值
		policies.GET("/defs/:key", h.Def)
		// 草稿回饋與套用預覽：兩者都唯讀，寫入仍走上面的批次更新
		policies.POST("/compliance/preview", h.CompliancePreview)
		policies.POST("/apply-preview", h.ApplyPreview)
	}

	// 登入前告示：公開端點（未認證可達），與登入方法清單同一層
	r.GET("/auth/banner", h.LoginBanner)
}
