package api

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/sourceip"
)

// LDAP 目錄設定 API（ldap-settings-migration 3.1，admin-only）。
//
// **singleton 資源**：`/api/v1/ldap-directory` 無集合式建立端點、無 `:id`——
// 「至多一條 live 設定」由資源形狀＋DB 層守衛（CHECK＋partial unique index）
// 表達，不靠服務層計數。PUT 為 upsert（無列即建、有列即改），DELETE 為軟刪。
//
// 本 handler 是**薄轉接層**：驗證、密碼語義、存檔閘、審計、限流全在服務層，
// 這裡只做三件事——(1) 綁定請求並自 JWT 填 actor（不接受請求端指定操作者）、
// (2) 把服務層的哨兵／型別錯誤映射為機器碼與 HTTP 狀態、(3) 回傳 DTO。
//
// # 連線測試的兩種「失敗」不可混為一談
//
// `TestConnection` 的回傳語義是契約的一部分：
//
//   - `err != nil`＝測試**未執行**（欄位驗證、傳輸閘、限流、既存設定不可讀）
//     → 對應 400／429／500，走 apierror 信封。
//   - `err == nil`＝階梯已跑完（**含失敗**）→ 一律 **HTTP 200**，失敗資訊在
//     body 的 `stages[]`／`failed_stage`／`code`／`diagnostic_id`。
//
// 把「bind 失敗」回成 4xx 會使前端無從呈現「撥號成功但 bind 失敗」這種**部分
// 成功**的階梯結果——而分階段定位正是這個端點存在的理由。
type LDAPDirectoryHandler struct {
	directories *identity.LDAPDirectoryService
}

// NewLDAPDirectoryHandler 建立 LDAP 目錄設定 handler
func NewLDAPDirectoryHandler(directories *identity.LDAPDirectoryService) *LDAPDirectoryHandler {
	return &LDAPDirectoryHandler{directories: directories}
}

// RegisterRoutes 註冊 LDAP 目錄設定路由（admin 限定，比照 OIDC provider 的權限掛法）
func (h *LDAPDirectoryHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	dir := r.Group("/ldap-directory")
	dir.Use(middleware.AuthMiddleware(authService))
	dir.Use(middleware.RequireRole("admin"))
	{
		dir.GET("", h.Get)
		dir.PUT("", h.Update)
		dir.DELETE("", h.Delete)
		dir.POST("/test", h.Test)
	}
}

// currentLDAPActor 由已認證脈絡取操作者。
//
// **不自請求 body 取**：actor 是審計的主體，讓請求端指定等於讓被劫持的 session
// 自選署名
func currentLDAPActor(c *gin.Context) identity.LDAPDirectoryActor {
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	return identity.LDAPDirectoryActor{ID: userID, Name: username, IP: sourceip.Of(c)}
}

// Get 讀取現行設定。未設定回 `{"configured": false}` 而非 404——
// 「還沒設定」是 singleton 資源的正常狀態，不是找不到資源
func (h *LDAPDirectoryHandler) Get(c *gin.Context) {
	view, err := h.directories.Get(c.Request.Context())
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalLDAPDirectoryQuery, err)
		return
	}
	c.JSON(http.StatusOK, view)
}

// Update upsert 設定（PUT 語義：無列建、有列改）。
//
// 回應與 GET 同形狀且**恆不含 bind 密碼**，僅以 has_bind_password 表達有無
func (h *LDAPDirectoryHandler) Update(c *gin.Context) {
	var req identity.LDAPDirectoryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	req.Actor = currentLDAPActor(c)

	view, err := h.directories.Upsert(c.Request.Context(), req)
	if err != nil {
		respondLDAPDirectoryError(c, err, apierror.CodeInternalLDAPDirectorySave)
		return
	}
	c.JSON(http.StatusOK, view)
}

// Delete 軟刪設定（同一事務抹除密文）；無列時回 404
func (h *LDAPDirectoryHandler) Delete(c *gin.Context) {
	if err := h.directories.Delete(c.Request.Context(), currentLDAPActor(c)); err != nil {
		respondLDAPDirectoryError(c, err, apierror.CodeInternalLDAPDirectoryDelete)
		return
	}
	c.Status(http.StatusNoContent)
}

// Test 以表單當下值執行分階段連線測試（先測後存）。
//
// 階梯已執行即 200（含失敗）——見型別註解對兩種失敗的區分
func (h *LDAPDirectoryHandler) Test(c *gin.Context) {
	var req identity.LDAPDirectoryTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	req.Actor = currentLDAPActor(c)

	result, err := h.directories.TestConnection(c.Request.Context(), req)
	if err != nil {
		respondLDAPDirectoryError(c, err, apierror.CodeInternalLDAPDirectoryTest)
		return
	}
	c.JSON(http.StatusOK, result)
}

// ── 錯誤映射 ────────────────────────────────────────────────────────────

// ldapURLReasonCodes 服務層 URL 拒因 → 機器碼（逐因對應，見 codes_ldap_directory.go）
var ldapURLReasonCodes = map[string]apierror.ErrCode{
	identity.LDAPURLReasonEmpty:     apierror.CodeValidationLDAPURLEmpty,
	identity.LDAPURLReasonTooLong:   apierror.CodeValidationLDAPURLTooLong,
	identity.LDAPURLReasonMalformed: apierror.CodeValidationLDAPURLMalformed,
	identity.LDAPURLReasonScheme:    apierror.CodeValidationLDAPURLScheme,
	identity.LDAPURLReasonUserinfo:  apierror.CodeValidationLDAPURLUserinfo,
	identity.LDAPURLReasonPath:      apierror.CodeValidationLDAPURLPath,
	identity.LDAPURLReasonQuery:     apierror.CodeValidationLDAPURLQuery,
	identity.LDAPURLReasonFragment:  apierror.CodeValidationLDAPURLFragment,
	identity.LDAPURLReasonHost:      apierror.CodeValidationLDAPURLHost,
	identity.LDAPURLReasonPort:      apierror.CodeValidationLDAPURLPort,
}

// ldapFilterReasonCodes 服務層 user_filter 拒因 → 機器碼
var ldapFilterReasonCodes = map[string]apierror.ErrCode{
	identity.LDAPFilterReasonEmpty:               apierror.CodeValidationLDAPFilterEmpty,
	identity.LDAPFilterReasonTooLong:             apierror.CodeValidationLDAPFilterTooLong,
	identity.LDAPFilterReasonPlaceholderMissing:  apierror.CodeValidationLDAPFilterPlaceholderMissing,
	identity.LDAPFilterReasonPlaceholderMultiple: apierror.CodeValidationLDAPFilterPlaceholderMultiple,
	identity.LDAPFilterReasonFormatVerb:          apierror.CodeValidationLDAPFilterFormatVerb,
	identity.LDAPFilterReasonParenUnbalanced:     apierror.CodeValidationLDAPFilterParenUnbalanced,
	identity.LDAPFilterReasonSyntax:              apierror.CodeValidationLDAPFilterSyntax,
	identity.LDAPFilterReasonPlaceholderScope:    apierror.CodeValidationLDAPFilterPlaceholderScope,
	identity.LDAPFilterReasonPlaceholderPosition: apierror.CodeValidationLDAPFilterPlaceholderPosition,
}

// ldapFieldReasonCodes 欄位拒因 → 機器碼（欄位名經 Meta 傳遞，非文案）
var ldapFieldReasonCodes = map[string]apierror.ErrCode{
	identity.LDAPFieldReasonRequired: apierror.CodeValidationLDAPFieldRequired,
	identity.LDAPFieldReasonTooLong:  apierror.CodeValidationLDAPFieldTooLong,
	identity.LDAPFieldReasonFormat:   apierror.CodeValidationLDAPFieldFormat,
}

// respondLDAPDirectoryError 服務層錯誤的統一 HTTP 出口。
//
// fallback 為「無法歸類時的 500 碼」，由呼叫端依動作（存檔／刪除／測試）給定
// ——泛化訊息對外、原始 cause 只落伺服端 log。
//
// **判定順序有意義**：型別錯誤（URL／filter／欄位）必須先於哨兵比對，因為
// LDAPFieldError.Unwrap 會歸入 ErrLDAPSettingsIncomplete／ErrLDAPFieldInvalid，
// 先比哨兵會把「哪個欄位、什麼原因」的解析度整片吃掉
func respondLDAPDirectoryError(c *gin.Context, err error, fallback apierror.ErrCode) {
	// 存檔閘：沿既有三通道共用出口（400＋VALIDATION_TRANSMISSION_*＋risks Meta），
	// 不新造形狀——syslog／通知通道已用同一套且被測試釘死
	var gateErr *policy.TransmissionGateError
	if errors.As(err, &gateErr) {
		respondTransmissionGate(c, gateErr)
		return
	}

	var urlErr *identity.LDAPURLError
	if errors.As(err, &urlErr) {
		respondLDAPReason(c, ldapURLReasonCodes, urlErr.Reason, nil, apierror.CodeValidationLDAPURLMalformed)
		return
	}

	var filterErr *identity.LDAPFilterError
	if errors.As(err, &filterErr) {
		respondLDAPReason(c, ldapFilterReasonCodes, filterErr.Reason, nil, apierror.CodeValidationLDAPFilterSyntax)
		return
	}

	var fieldErr *identity.LDAPFieldError
	if errors.As(err, &fieldErr) {
		// field 是 wire 欄名（機器值），供前端高亮定位；非使用者可見文案
		respondLDAPReason(c, ldapFieldReasonCodes, fieldErr.Reason,
			map[string]any{"field": fieldErr.Field}, apierror.CodeValidationLDAPFieldFormat)
		return
	}

	switch {
	case errors.Is(err, identity.ErrLDAPBindPasswordConflict):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationLDAPBindPasswordConflict, nil)
	case errors.Is(err, identity.ErrLDAPBindPasswordRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationLDAPBindPasswordRequired, nil)
	case errors.Is(err, identity.ErrLDAPDirectoryNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeNotFoundLDAPDirectory, nil)
	// 取鎖忙碌與唯一鍵衝突皆為**可重試**語義：回 409 而非 500，前端可據以提示
	// 「請稍後重試」而不是把它當系統故障
	case errors.Is(err, identity.ErrLDAPDirectoryBusy):
		apierror.Respond(c, http.StatusConflict, apierror.CodeConflictLDAPDirectoryBusy, nil)
	case errors.Is(err, identity.ErrLDAPDirectoryConflict):
		apierror.Respond(c, http.StatusConflict, apierror.CodeConflictLDAPDirectoryConcurrent, nil)
	case errors.Is(err, identity.ErrLDAPTestRateLimited):
		apierror.Respond(c, http.StatusTooManyRequests, apierror.CodeRuleLDAPTestRateLimited, nil)
	case errors.Is(err, identity.ErrLDAPTestStoredSettingsUnavailable):
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalLDAPStoredSettingsUnavailable, err)
	// 以下三者皆 5xx，但維運行動不同（部署疏漏／金鑰事故／組裝缺陷），
	// 故不落入 default 泛碼——同一個泛碼會使三種成因在維運端不可區分
	case errors.Is(err, identity.ErrLDAPTransmissionGateUnavailable):
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalLDAPTransmissionGateUnavailable, err)
	case errors.Is(err, identity.ErrLDAPBindPasswordDecrypt),
		errors.Is(err, identity.ErrLDAPBindPasswordEncrypt):
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalLDAPBindPasswordCrypto, err)
	case errors.Is(err, identity.ErrLDAPDirectoryServiceUnavailable):
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalLDAPDirectoryServiceUnavailable, err)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, fallback, err)
	}
}

// respondLDAPReason 依靜態拒因碼回 400。
//
// 查無對應時退回同族的泛碼而非 500：拒絕的判定本身是正確的（輸入確實不合法），
// 只是 HTTP 層的對照表落後於服務層新增的拒因——把它變成 500 會讓一個合法的
// 400 拒絕看起來像系統故障。對照表的完整性由 TestLDAPReasonCodeTablesExhaustive
// 靜態守衛（新增拒因未登記即紅），本分支是執行期的最後防線
func respondLDAPReason(c *gin.Context, table map[string]apierror.ErrCode,
	reason string, meta map[string]any, fallback apierror.ErrCode) {
	code, ok := table[reason]
	if !ok {
		code = fallback
	}
	apierror.Write(c, http.StatusBadRequest, apierror.ErrorResponse{Code: code, Meta: meta})
}
