package api

import (
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
)

// MFASetup 產生 TOTP secret 與 otpauth URL
func (h *AuthHandler) MFASetup(c *gin.Context) {
	userID, username, ok := currentUser(c)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	resp, err := h.authService.GenerateMFASetup(userID)
	if err != nil {
		h.auditAuthEvent(c, userID, username, model.ActionUpdate, model.StatusFailure, http.StatusInternalServerError, err.Error())
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalMFASetup, err)
		return
	}

	h.auditAuthEvent(c, userID, username, model.ActionUpdate, model.StatusSuccess, http.StatusOK, "")
	c.JSON(http.StatusOK, resp)
}

// MFAEnable 驗證 TOTP 碼後啟用 MFA
func (h *AuthHandler) MFAEnable(c *gin.Context) {
	userID, username, ok := currentUser(c)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}

	if err := h.authService.EnableMFA(userID, req.Code); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, identity.ErrMFAInvalidCode) || errors.Is(err, identity.ErrMFASetupRequired) ||
			errors.Is(err, identity.ErrMFAReplay) {
			status = http.StatusBadRequest
		}
		// 啟用失敗（含錯碼/重放）必須留審計軌跡，便於偵測暴力嘗試
		h.auditAuthEvent(c, userID, username, model.ActionUpdate, model.StatusFailure, status, err.Error())
		respondMFAError(c, status, err, apierror.CodeInternalMFAEnable)
		return
	}

	h.auditAuthEvent(c, userID, username, model.ActionUpdate, model.StatusSuccess, http.StatusOK, "")
	c.JSON(http.StatusOK, gin.H{})
}

// extractBearer 取出 Authorization: Bearer <token>（enrollment 端點自帶 scoped token）
func extractBearer(c *gin.Context) string {
	parts := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" && parts[1] != "" {
		return parts[1]
	}
	return ""
}

// MFAEnrollSetup 強制註冊：以 enrollment token 產生 TOTP 設定（公開端點，自帶 scoped token）
func (h *AuthHandler) MFAEnrollSetup(c *gin.Context) {
	token := extractBearer(c)
	if token == "" {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeMFAEnrollTokenMissing, nil)
		return
	}
	resp, err := h.authService.EnrollmentSetup(token)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, identity.ErrMFAPendingTokenInvalid):
			status = http.StatusUnauthorized
		case errors.Is(err, identity.ErrMFAAlreadyEnrolled):
			// 已註冊者持 enrollment token 重放（MFA-1）：409 明示、記審計偵測改綁企圖
			status = http.StatusConflict
			h.auditAuthEvent(c, 0, "", model.ActionUpdate, model.StatusFailure, status, err.Error())
		}
		respondMFAError(c, status, err, apierror.CodeInternalMFASetup)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// MFAEnrollConfirm 強制註冊：以 enrollment token + TOTP 碼完成綁定並直接換發正式會話（D12）
func (h *AuthHandler) MFAEnrollConfirm(c *gin.Context) {
	token := extractBearer(c)
	if token == "" {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeMFAEnrollTokenMissing, nil)
		return
	}
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}

	resp, err := h.authService.CompleteEnrollment(token, req.Code)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, identity.ErrMFAInvalidCode), errors.Is(err, identity.ErrMFAReplay),
			errors.Is(err, identity.ErrMFASetupRequired):
			status = http.StatusBadRequest
		case errors.Is(err, identity.ErrMFAPendingTokenInvalid), errors.Is(err, identity.ErrUserInactive):
			status = http.StatusUnauthorized
		case errors.Is(err, identity.ErrMFAAlreadyEnrolled):
			status = http.StatusConflict // 已註冊者不得改綁（MFA-1）
		case errors.Is(err, identity.ErrAccountLocked):
			status = http.StatusLocked // 綁定碼暴力達門檻（MFA-2 共用鎖定計數）
		}
		// 公開端點無 auth context，失敗直記審計（偵測暴力綁定）
		h.auditAuthEvent(c, 0, "", model.ActionUpdate, model.StatusFailure, status, err.Error())
		respondMFAError(c, status, err, apierror.CodeInternalMFAEnroll)
		return
	}

	// 綁定後可能仍須強制改密（改密 gate 排在 MFA 之後）
	if resp.PasswordChangeRequired {
		h.auditMFALoginSuccess(c, resp.PendingUserID, resp.PendingUsername,
			"mfa_enrolled_password_change_required", resp)
		c.JSON(http.StatusOK, resp)
		return
	}
	h.auditMFALoginSuccess(c, resp.User.ID, resp.User.Username, "mfa_enrolled", resp)
	// 發放端點 3／6：強制註冊完成直接換發正式會話（D12）
	h.refreshCookies.SetFromLogin(c, resp)
	c.JSON(http.StatusOK, resp)
}

// MFADisable 用戶自行停用 MFA（需重新驗證密碼）
func (h *AuthHandler) MFADisable(c *gin.Context) {
	userID, username, ok := currentUser(c)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}

	if err := h.authService.DisableMFA(userID, req.Password); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, identity.ErrInvalidCredentials) {
			status = http.StatusUnauthorized
		}
		h.auditAuthEvent(c, userID, username, model.ActionUpdate, model.StatusFailure, status, err.Error())
		respondMFAError(c, status, err, apierror.CodeInternalMFADisable)
		return
	}

	h.auditAuthEvent(c, userID, username, model.ActionUpdate, model.StatusSuccess, http.StatusOK, "")
	c.JSON(http.StatusOK, gin.H{})
}

// MFAVerify 第二階段登入：pending token + TOTP 碼換正式 JWT（公開端點）
func (h *AuthHandler) MFAVerify(c *gin.Context) {
	var req identity.MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}

	resp, err := h.authService.VerifyMFALogin(&req)
	if err != nil {
		// 公開端點：僅 sentinel 可回原文，內部錯誤泛化
		status := http.StatusInternalServerError
		if errors.Is(err, identity.ErrMFAInvalidCode) || errors.Is(err, identity.ErrMFAReplay) ||
			errors.Is(err, identity.ErrMFAPendingTokenInvalid) ||
			errors.Is(err, identity.ErrMFANotEnabled) || errors.Is(err, identity.ErrUserInactive) {
			status = http.StatusUnauthorized
		}
		// TOTP 失敗與密碼失敗共用鎖定計數（D2），達門檻回 423 明示鎖定
		if errors.Is(err, identity.ErrAccountLocked) {
			status = http.StatusLocked
		}
		// 公開端點無認證 context，audit middleware 會跳過，失敗必須直記
		h.auditAuthEvent(c, 0, "", model.ActionLogin, model.StatusFailure, status, err.Error())
		respondMFAError(c, status, err, apierror.CodeInternalMFAVerify)
		return
	}

	// MFA 通過但須先改密（D4：改密 gate 排在 MFA 之後防繞過）
	if resp.PasswordChangeRequired {
		h.auditMFALoginSuccess(c, resp.PendingUserID, resp.PendingUsername, "password_change_required", resp)
		c.JSON(http.StatusOK, resp)
		return
	}

	// 認證方式與 provider 於 MFA 完成路徑一併保留（oidc-auth spec「登入 gate chain
	// 匯流」）：正式會話的成功列由此寫出
	h.auditMFALoginSuccess(c, resp.User.ID, resp.User.Username, "", resp)
	// 發放端點 2／6：MFA 第二階段完成，正式會話由此發出
	h.refreshCookies.SetFromLogin(c, resp)
	c.JSON(http.StatusOK, resp)
}

// AdminDisableMFA 管理員救援：停用指定用戶的 MFA
func (h *AuthHandler) AdminDisableMFA(c *gin.Context) {
	adminID, adminName, ok := currentUser(c)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	targetID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}

	if err := h.authService.AdminDisableMFA(uint(targetID)); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, identity.ErrUserNotFound) {
			status = http.StatusNotFound
		}
		h.auditAuthEventWithResource(c, adminID, adminName, model.ActionUpdate, model.StatusFailure, status, err.Error(), uint(targetID))
		respondMFAError(c, status, err, apierror.CodeInternalMFAAdminDisable)
		return
	}

	// 救援操作記入 admin 身分 + 目標用戶 ID，防濫用追責（design.md Risks）
	h.auditAuthEventWithResource(c, adminID, adminName, model.ActionUpdate, model.StatusSuccess, http.StatusOK, "", uint(targetID))
	c.JSON(http.StatusOK, gin.H{})
}

// respondMFAError 統一 MFA 失敗回應：5xx 記 cause 後回泛化 internalCode（不洩漏）；
// 4xx 依 sentinel 映射為對應機器碼（狀態由呼叫端各自的守衛決定，不在此處改動）。
func respondMFAError(c *gin.Context, status int, err error, internalCode apierror.ErrCode) {
	if status >= http.StatusInternalServerError {
		apierror.RespondInternal(c, status, internalCode, err)
		return
	}
	apierror.Respond(c, status, mfaSentinelCode(err), nil)
}

// mfaSentinelCode 把 MFA／認證 sentinel 對映到機器碼。僅在 status < 500 時被呼叫，
// 此時 err 必為呼叫端守衛過的 sentinel 之一；default 僅為防禦性保底。
func mfaSentinelCode(err error) apierror.ErrCode {
	switch {
	case errors.Is(err, identity.ErrMFAInvalidCode):
		return apierror.CodeMFAInvalidCode
	case errors.Is(err, identity.ErrMFAReplay):
		return apierror.CodeMFAReplay
	case errors.Is(err, identity.ErrMFASetupRequired):
		return apierror.CodeMFASetupRequired
	case errors.Is(err, identity.ErrMFAPendingTokenInvalid):
		return apierror.CodeMFAPendingTokenInvalid
	case errors.Is(err, identity.ErrMFANotEnabled):
		return apierror.CodeMFANotEnabled
	case errors.Is(err, identity.ErrMFAAlreadyEnrolled):
		return apierror.CodeMFAAlreadyEnrolled
	case errors.Is(err, identity.ErrUserInactive):
		return apierror.CodeUserInactive
	case errors.Is(err, identity.ErrInvalidCredentials):
		return apierror.CodeInvalidCredentials
	case errors.Is(err, identity.ErrAccountLocked):
		return apierror.CodeAccountLocked
	case errors.Is(err, identity.ErrUserNotFound):
		return apierror.CodeUserNotFound
	default:
		return apierror.CodeInternalMFAVerify
	}
}

// currentUser 從 context 取得目前用戶 ID 與名稱
func currentUser(c *gin.Context) (uint, string, bool) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		return 0, "", false
	}
	username, _ := middleware.GetCurrentUsername(c)
	return userID, username, true
}

// auditAuthEvent 直記 auth 資源審計事件（與 auditLogin 同模式）
func (h *AuthHandler) auditAuthEvent(c *gin.Context, userID uint, username string, action model.AuditAction, status model.AuditStatus, statusCode int, errMsg string) {
	h.auditAuthEventWithResource(c, userID, username, action, status, statusCode, errMsg, 0)
}

// auditAuthEventWithResource 直記審計事件並關聯目標資源 ID（管理員救援用）
func (h *AuthHandler) auditAuthEventWithResource(c *gin.Context, userID uint, username string, action model.AuditAction, status model.AuditStatus, statusCode int, errMsg string, resourceID uint) {
	h.auditAuthEventFull(c, userID, username, action, status, statusCode, errMsg, resourceID, "")
}

// auditAuthEventFull 本檔審計列的**單一寫入點**（其餘皆為薄包覆）。
//
// 一個字面量而非多份：分家後「某條路徑少填了 provider／來源位址」不會讓任何
// 測試轉紅——那正是 2.9 被打出的缺陷形態（MFA 完成路徑只標認證方式、未標 provider）
func (h *AuthHandler) auditAuthEventFull(c *gin.Context, userID uint, username string, action model.AuditAction, status model.AuditStatus, statusCode int, errMsg string, resourceID uint, details string) {
	if h.auditService == nil {
		return
	}
	entry := &audit.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     action,
		Resource:   model.ResourceAuth,
		Status:     status,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		ClientIP:   h.auditSourceIP(c),
		StatusCode: statusCode,
		ErrorMsg:   errMsg,
		Details:    details,
	}
	if resourceID != 0 {
		entry.ResourceID = &resourceID
	}
	h.auditService.Log(entry)
}

// auditMFALoginSuccess 記 MFA 完成路徑的登入成功列，**認證方式與 provider 一併保留**。
//
// spec `oidc-auth`「登入 gate chain 匯流」：登入審計 SHALL 標註認證方式與 provider，
// 且 SHALL 於 MFA 完成路徑一併保留。這條路徑寫出的是 SSO＋MFA 使用者**唯一的**
// 正式會話成功列——只附註 `source=oidc` 而不帶 provider，稽核就答不出「他是經哪個
// 身分來源進來的」，而多 provider 部署下那正是第一個要問的問題。
//
// Details 形態與 OIDC 直登成功列一致（`oidc_handler.go` 的 auditOIDCLogin：
// `{provider_id, provider_name, auth_method}`），使兩條路徑在同一個審計視圖上可比對；
// 本地密碼登入（AuthSource 空）不附 Details，維持既有輸出零變化
func (h *AuthHandler) auditMFALoginSuccess(c *gin.Context, userID uint, username, note string, resp *identity.LoginResponse) {
	h.auditAuthEventFull(c, userID, username, model.ActionLogin, model.StatusSuccess, http.StatusOK,
		annotateAuthSource(note, resp.AuthSource), 0, authProviderDetails(resp))
}

// authProviderDetails 建構 provider 標註的 Details JSON；非外部認證回空字串（不寫 Details）
func authProviderDetails(resp *identity.LoginResponse) string {
	if resp == nil || resp.AuthSource == "" {
		return ""
	}
	b, err := json.Marshal(map[string]any{
		"provider_id":   resp.AuthProviderID,
		"provider_name": resp.AuthProviderName,
		"auth_method":   resp.AuthSource,
	})
	if err != nil {
		// map[string]any 內全為可序列化型別，不可達；標註失敗不得中斷登入
		return ""
	}
	return string(b)
}
