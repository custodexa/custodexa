package api

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
)

// UserServiceInterface 用戶服務接口（用於測試注入）
type UserServiceInterface interface {
	List(req *identity.ListUsersRequest) (*identity.UserListResponse, error)
	GetByID(id uint) (*model.User, error)
	Create(req *identity.CreateUserRequest) (*model.User, error)
	Update(id uint, req *identity.UpdateUserRequest) (*model.User, map[string]string, error)
	Delete(id uint) error
	AssignRoles(userID uint, roleNames []string) error
	AddRole(userID uint, roleName string) error
	UpdateStatus(userID uint, active bool) error
	ChangePassword(userID uint, newPassword string) error
	Unlock(userID uint) error
	SetInactivityExempt(userID uint, exempt bool) error
	// CountLocalAdmins 本地 admin 計數（管理端條件式警示）
	CountLocalAdmins() (int64, error)
	// 外部身分管理四操作
	ListExternalIdentities(userID uint) ([]identity.ExternalIdentityDTO, error)
	BindExternalIdentity(userID, providerID uint, subject string,
		actor identity.IdentityAdminActor) (*identity.ExternalIdentityDTO, error)
	UnbindExternalIdentity(userID, identityID uint, actor identity.IdentityAdminActor) error
	UnbindExternalIdentityAndDisable(userID, identityID uint, actor identity.IdentityAdminActor) error
	ConvertToExternalOnly(userID uint, actor identity.IdentityAdminActor) error
}

// UserHandler 用戶 API handler
type UserHandler struct {
	userService UserServiceInterface
	// auditService 解鎖等安全事件的顯式審計；nil 表示停用
	auditService *audit.AuditLogService
	// sourcePolicy 允許來源網段的現讀面（G1 強制點）。管理者對他人認證因子的
	// 三個端點依**操作者本人**的清單判定。**nil 即 fail-close**
	sourcePolicy sourcePolicyReader
}

// NewUserHandler 創建用戶 handler
func NewUserHandler(userService UserServiceInterface) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// SetAuditService 注入審計服務（解鎖事件顯式留痕）
func (h *UserHandler) SetAuditService(auditService *audit.AuditLogService) {
	h.auditService = auditService
}

// List 列出用戶
func (h *UserHandler) List(c *gin.Context) {
	// 解析查詢參數
	req := &identity.ListUsersRequest{
		Search:   c.Query("search"),
		Page:     1,
		PageSize: 20,
	}

	// 解析頁碼
	if page, err := strconv.Atoi(c.Query("page")); err == nil && page > 0 {
		req.Page = page
	}

	// 解析每頁大小
	if pageSize, err := strconv.Atoi(c.Query("page_size")); err == nil && pageSize > 0 {
		req.PageSize = pageSize
	}

	// 解析 active 狀態
	if activeStr := c.Query("active"); activeStr != "" {
		if active, err := strconv.ParseBool(activeStr); err == nil {
			req.Active = &active
		}
	}

	// 供應來源篩選。**值域封閉**：
	// 未知值靜默忽略會使前端拼錯參數時「篩選看似沒生效」，比直接不接受更難查
	if origin := c.Query("provisioning_origin"); origin != "" {
		switch origin {
		case model.AuthSourceLocal, model.AuthSourceLDAP, model.AuthSourceOIDC:
			req.ProvisioningOrigin = origin
		default:
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationUserOriginFilter, nil)
			return
		}
	}

	// 依 provider 實例篩選
	if pid, err := strconv.ParseUint(c.Query("auth_provider_id"), 10, 32); err == nil && pid > 0 {
		req.AuthProviderID = uint(pid)
	}

	// 調用服務
	resp, err := h.userService.List(req)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserQuery, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  resp.Data,
		"total": resp.Total,
	})
}

// Create 創建用戶
func (h *UserHandler) Create(c *gin.Context) {
	var req identity.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	// 調用服務創建用戶
	user, err := h.userService.Create(&req)
	if err != nil {
		if errors.Is(err, identity.ErrUsernameExists) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeUsernameExists, nil)
			return
		}
		if errors.Is(err, identity.ErrRoleNotFound) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeRoleNotFound, nil)
			return
		}
		if code, ok := sourcePolicyValidationCode(err); ok {
			apierror.Respond(c, http.StatusBadRequest, code, nil)
			return
		}
		// 密碼政策違規（長度/組成）回可讀訊息（code+params 由 service 綁定）
		var violation *policy.PasswordPolicyViolation
		if errors.As(err, &violation) {
			apierror.Respond(c, http.StatusBadRequest, violation.Code, violation.Params)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserCreate, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"data": user,
	})
}

// Get 獲取用戶詳情
func (h *UserHandler) Get(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}

	// 調用服務
	user, err := h.userService.GetByID(uint(id))
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserQuery, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": user,
	})
}

// Update 更新用戶
func (h *UserHandler) Update(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}

	// 解析請求
	var req identity.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	// 調用服務
	user, diff, err := h.userService.Update(uint(id), &req)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
			return
		}
		if errors.Is(err, identity.ErrEmailConflict) {
			// email 撞其他 live 帳號回 409（非通用 500）
			apierror.Respond(c, http.StatusConflict, apierror.CodeEmailConflict, nil)
			return
		}
		if errors.Is(err, identity.ErrInvalidEmail) {
			// 正規化後仍非合法 email 格式（binding 放寬後由 service 把關）→ 400
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
		if code, ok := sourcePolicyValidationCode(err); ok {
			apierror.Respond(c, http.StatusBadRequest, code, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserUpdate, err)
		return
	}

	// 欄位級 before/after 變更注入審計 details：審計 middleware 會與查詢摘要合併，
	// 讓「改了什麼」可稽核。full_name 不再被脫敏（MaskSensitiveFields 白名單已納入）
	if len(diff) > 0 {
		c.Set("audit_details", diff)
	}

	c.JSON(http.StatusOK, gin.H{
		"data": user,
	})
}

// Delete 刪除用戶
func (h *UserHandler) Delete(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}

	// 調用服務
	err = h.userService.Delete(uint(id))
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
			return
		}
		// 「最後一個**本地** admin」不變式（2.7）：errors.As 取精確碼。
		// 必須在 ErrLastAdmin 的 errors.Is 之前——LastLocalAdminError 刻意滿足
		// errors.Is(err, ErrLastAdmin)（相容保證），先判 Is 會把它壓成舊碼，
		// 管理者只會看到「不能刪除最後一個管理員」而不知真正的原因是解封能力
		var lastLocalAdmin *identity.LastLocalAdminError
		if errors.As(err, &lastLocalAdmin) {
			apierror.Respond(c, http.StatusBadRequest, lastLocalAdmin.Code, nil)
			return
		}
		if errors.Is(err, identity.ErrLastAdmin) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeLastAdminDelete, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserDelete, err)
		return
	}

	// message 欄已移除（成功回應不攜帶 UI 文案，前端自有 $t 文案）
	c.JSON(http.StatusOK, gin.H{})
}

// AssignRoles 分配角色
func (h *UserHandler) AssignRoles(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}

	// 解析請求
	var req struct {
		Roles []string `json:"roles" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	// 調用服務
	err = h.userService.AssignRoles(uint(id), req.Roles)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
			return
		}
		if errors.Is(err, identity.ErrRoleNotFound) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeRoleNotFound, nil)
			return
		}
		// 移除 admin 角色觸發「最後一個本地 admin」不變式時，這是規則拒絕而非
		// 伺服器故障（2.7：AssignRoles 是該不變式的四條路徑之一）
		var lastLocalAdmin *identity.LastLocalAdminError
		if errors.As(err, &lastLocalAdmin) {
			apierror.Respond(c, http.StatusBadRequest, lastLocalAdmin.Code, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleAssign, err)
		return
	}

	// message 欄已移除（成功回應不攜帶 UI 文案，前端自有 $t 文案）
	c.JSON(http.StatusOK, gin.H{})
}

// AddRole 冪等追加單一角色（一站式代配用）
func (h *UserHandler) AddRole(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}
	roleName := c.Param("role")
	if err := h.userService.AddRole(uint(id), roleName); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
			return
		}
		if errors.Is(err, identity.ErrRoleNotFound) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeRoleNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleAdd, err)
		return
	}
	// message 欄已移除（成功回應不攜帶 UI 文案，前端自有 $t 文案）
	c.JSON(http.StatusOK, gin.H{})
}

// UpdateStatus 更新用戶狀態
func (h *UserHandler) UpdateStatus(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}

	// 解析請求
	var req struct {
		Active *bool `json:"active" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	// 檢查 active 是否為 nil
	if req.Active == nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeActiveRequired, nil)
		return
	}

	// 調用服務
	err = h.userService.UpdateStatus(uint(id), *req.Active)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
			return
		}
		// 同 Delete：精確碼優先於相容用的 ErrLastAdmin（2.7）
		var lastLocalAdmin *identity.LastLocalAdminError
		if errors.As(err, &lastLocalAdmin) {
			apierror.Respond(c, http.StatusBadRequest, lastLocalAdmin.Code, nil)
			return
		}
		if errors.Is(err, identity.ErrLastAdmin) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeLastAdminDisable, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalStatusUpdate, err)
		return
	}

	// message 欄已移除（成功回應不攜帶 UI 文案，前端自有 $t 文案）
	c.JSON(http.StatusOK, gin.H{})
}

// ChangePassword 修改密碼
func (h *UserHandler) ChangePassword(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}

	// 來源限定（盤點表 #18）：管理者對他人的密碼寫入，依**操作者本人**的清單判定。
	// 留痕交 AuditLogMiddleware（本路由掛了中介層），helper 只把判定依據併進
	// 那一列的 details——另寫一列會讓「被擋幾次」翻倍
	if !h.requireSourceAllowed(c, currentActorID(c), nil) {
		return
	}

	// 解析請求。長度等規則由 service 層政策 validator 統一判定（單一事實源），
	// binding 不再帶 min 長度
	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodePasswordFieldMissing, nil)
		return
	}

	// 調用服務
	err = h.userService.ChangePassword(uint(id), req.Password)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
			return
		}
		// 政策違規（長度/組成/歷史重用）回可讀訊息（code+params 由 service 綁定）
		var violation *policy.PasswordPolicyViolation
		if errors.As(err, &violation) {
			apierror.Respond(c, http.StatusBadRequest, violation.Code, violation.Params)
			return
		}
		// LDAP 用戶屬請求語義錯誤而非伺服器故障，回 400 並附明確原因
		if errors.Is(err, identity.ErrLDAPUserPassword) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeLDAPUserPassword, nil)
			return
		}
		if errors.Is(err, identity.ErrExternalUserPassword) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeExternalUserPassword, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChangePassword, err)
		return
	}

	// message 欄已移除（成功回應不攜帶 UI 文案，前端自有 $t 文案）
	c.JSON(http.StatusOK, gin.H{})
}

// Unlock 管理員手動解鎖帳號（8.3.4：清零失敗計數與鎖定時間）
func (h *UserHandler) Unlock(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}

	// 來源限定（盤點表 #19）：解鎖他人是認證狀態寫入，依操作者本人的清單判定
	if !h.requireSourceAllowed(c, currentActorID(c), nil) {
		return
	}

	if err := h.userService.Unlock(uint(id)); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUnlock, err)
		return
	}

	// 解鎖屬安全事件，顯式留痕（action=unlock；middleware 只會記通用 CRUD 動作）
	if h.auditService != nil {
		adminID, _ := middleware.GetCurrentUserID(c)
		adminName, _ := middleware.GetCurrentUsername(c)
		targetID := uint(id)
		h.auditService.Log(&audit.AuditLogEntry{
			UserID:     adminID,
			Username:   adminName,
			Action:     model.ActionUnlock,
			Resource:   model.ResourceUser,
			ResourceID: &targetID,
			Status:     model.StatusSuccess,
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			ClientIP:   sourceip.Of(c),
			StatusCode: http.StatusOK,
		})
	}

	// message 欄已移除（成功回應不攜帶 UI 文案，前端自有 $t 文案）
	c.JSON(http.StatusOK, gin.H{})
}

// SetInactivityExempt 設定閒置停用豁免（PCI 8.2.6）
func (h *UserHandler) SetInactivityExempt(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}

	var req struct {
		Exempt *bool `json:"exempt" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Exempt == nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeExemptRequired, nil)
		return
	}

	if err := h.userService.SetInactivityExempt(uint(id), *req.Exempt); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalInactivityExempt, err)
		return
	}

	// 豁免旗標變更屬合規例外文件化，顯式留痕
	if h.auditService != nil {
		adminID, _ := middleware.GetCurrentUserID(c)
		adminName, _ := middleware.GetCurrentUsername(c)
		targetID := uint(id)
		h.auditService.Log(&audit.AuditLogEntry{
			UserID:     adminID,
			Username:   adminName,
			Action:     model.ActionUpdate,
			Resource:   model.ResourceUser,
			ResourceID: &targetID,
			Status:     model.StatusSuccess,
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			ClientIP:   sourceip.Of(c),
			StatusCode: http.StatusOK,
			ErrorMsg:   inactivityExemptAuditMsg(*req.Exempt),
		})
	}

	// message 欄已移除（成功回應不攜帶 UI 文案，前端自有 $t 文案）
	c.JSON(http.StatusOK, gin.H{})
}

// inactivityExemptAuditMsg 豁免變更的審計註記（沿用 ErrorMsg 慣例欄位記狀態）
func inactivityExemptAuditMsg(exempt bool) string {
	if exempt {
		return "inactivity_exempt_granted"
	}
	return "inactivity_exempt_revoked"
}

// --- 外部身分管理---
//
// 四個操作的共同性質：admin only（路由群組已掛 RequireRole）、全部留痕於審計、
// 失敗零副作用（service 端以交易與鎖保證）。**解綁類操作一律使該使用者的既有存取
// 全數失效**（使用者級粒度的刻意取捨，見 spec）——前端確認文案須明示。

// identityActor 自認證脈絡取管理者身分（審計歸屬）。
// service 不接觸 gin context，故由 handler 在此收口
func identityActor(c *gin.Context) identity.IdentityAdminActor {
	adminID, _ := middleware.GetCurrentUserID(c)
	adminName, _ := middleware.GetCurrentUsername(c)
	return identity.IdentityAdminActor{
		UserID:   adminID,
		Username: adminName,
		ClientIP: sourceip.Of(c),
	}
}

// parseUserAndIdentityID 解析路徑上的使用者與外部身分 ID
func parseUserAndIdentityID(c *gin.Context) (uint, uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return 0, 0, false
	}
	identityID, err := strconv.ParseUint(c.Param("identityId"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationExternalIdentityID, nil)
		return 0, 0, false
	}
	return uint(id), uint(identityID), true
}

// respondIdentityError 四操作共用的錯誤映射。
//
// 規則拒絕（登入途徑歸零、最後本地 admin）一律 4xx＋精確機器碼：這些是合法的
// 業務裁決，落到 RespondInternal 會變成 500，管理者只會看到「伺服器錯誤」
func respondIdentityError(c *gin.Context, err error, internalCode apierror.ErrCode) {
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
	case errors.Is(err, identity.ErrExternalIdentityNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeNotFoundExternalIdentity, nil)
	case errors.Is(err, identity.ErrOIDCProviderNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeNotFoundOIDCProvider, nil)
	case errors.Is(err, identity.ErrExternalIdentitySubjectInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationExternalIdentitySubject, nil)
	case errors.Is(err, identity.ErrExternalIdentityExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeConflictExternalIdentityExists, nil)
	case errors.Is(err, identity.ErrUserAlreadyExternal):
		apierror.Respond(c, http.StatusConflict, apierror.CodeConflictUserAlreadyExternal, nil)
	case errors.Is(err, identity.ErrExternalIdentityRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeExternalIdentityRequired, nil)
	default:
		var lastPath *identity.LastLoginPathError
		if errors.As(err, &lastPath) {
			apierror.Respond(c, http.StatusBadRequest, lastPath.Code, nil)
			return
		}
		// 最後本地 admin 不變式：errors.As 取精確碼（RULE_USER_LAST_LOCAL_ADMIN）。
		// 必須在 ErrLastAdmin 的 errors.Is 之前判定——前者刻意滿足後者的比對
		var lastLocalAdmin *identity.LastLocalAdminError
		if errors.As(err, &lastLocalAdmin) {
			apierror.Respond(c, http.StatusBadRequest, lastLocalAdmin.Code, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}

// ListExternalIdentities 列出帳號已綁定的外部身分
func (h *UserHandler) ListExternalIdentities(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}
	items, err := h.userService.ListExternalIdentities(uint(id))
	if err != nil {
		respondIdentityError(c, err, apierror.CodeInternalExternalIdentityQuery)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": items, "total": len(items)})
}

// BindExternalIdentity (a) 綁定外部身分。
// issuer／client_id 取自 provider 列，請求只提供 provider_id 與 subject
func (h *UserHandler) BindExternalIdentity(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}
	var req struct {
		ProviderID uint   `json:"provider_id" binding:"required"`
		Subject    string `json:"subject" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	dto, err := h.userService.BindExternalIdentity(uint(id), req.ProviderID, req.Subject, identityActor(c))
	if err != nil {
		respondIdentityError(c, err, apierror.CodeInternalExternalIdentityBind)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": dto})
}

// UnbindExternalIdentity (b) 解綁；成功即使該使用者全部既有存取失效
func (h *UserHandler) UnbindExternalIdentity(c *gin.Context) {
	userID, identityID, ok := parseUserAndIdentityID(c)
	if !ok {
		return
	}
	if err := h.userService.UnbindExternalIdentity(userID, identityID, identityActor(c)); err != nil {
		respondIdentityError(c, err, apierror.CodeInternalExternalIdentityUnbind)
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

// UnbindExternalIdentityAndDisable (c) 原子「解綁＋停用帳號」
func (h *UserHandler) UnbindExternalIdentityAndDisable(c *gin.Context) {
	userID, identityID, ok := parseUserAndIdentityID(c)
	if !ok {
		return
	}
	if err := h.userService.UnbindExternalIdentityAndDisable(userID, identityID, identityActor(c)); err != nil {
		respondIdentityError(c, err, apierror.CodeInternalExternalIdentityUnbind)
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

// ConvertToExternalOnly (d) 改為僅外部登入（清密碼雜湊＋推進憑證世代）
func (h *UserHandler) ConvertToExternalOnly(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "user"})
		return
	}
	if err := h.userService.ConvertToExternalOnly(uint(id), identityActor(c)); err != nil {
		respondIdentityError(c, err, apierror.CodeInternalUserExternalOnly)
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

// GetLocalAdminCount 現存本地 admin 數（唯讀，admin only）。
//
// 管理端「已無本地管理員 → 解封能力已失」警示的資料來源：
// 計數直接來自 identity.CountLocalAdmins，與不變式拒絕四條路徑時的判定同一定義。
// 不入快取、每次現查——低頻管理頁讀取，一致性優先於延遲；讀取失敗時前端 fail-safe
// 退回通用警語，故此處不需要專屬錯誤碼（沿用既有查詢碼）
func (h *UserHandler) GetLocalAdminCount(c *gin.Context) {
	count, err := h.userService.CountLocalAdmins()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"count": count})
}

// RegisterRoutes 註冊用戶相關路由
func (h *UserHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	users := r.Group("/users")
	users.Use(middleware.AuthMiddleware(authService))
	users.Use(middleware.RequireRole("admin"))
	{
		users.GET("", h.List)
		users.POST("", h.Create)
		// 靜態路徑須與 /:id 共存（gin 1.9 支援同層 static/param 兄弟節點）；
		// 命名帶連字號避免與任何數字 ID 形式衝突
		users.GET("/local-admin-count", h.GetLocalAdminCount)
		// 允許來源網段的判定端點：純判定、不寫狀態。掛在靜態段而非 /:id 之下
		// ——建立表單尚無 id，且判定與特定使用者無關
		users.POST("/source-policy/check", h.SourcePolicyCheck)
		users.GET("/:id", h.Get)
		users.PUT("/:id", h.Update)
		users.DELETE("/:id", h.Delete)
		users.PUT("/:id/roles", h.AssignRoles)
		users.POST("/:id/roles/:role", h.AddRole)
		users.PUT("/:id/status", h.UpdateStatus)
		users.PUT("/:id/password", h.ChangePassword)
		users.POST("/:id/unlock", h.Unlock)
		users.PUT("/:id/inactivity-exempt", h.SetInactivityExempt)
		// 外部身分管理。
		// 「解綁＋停用」與「改為僅外部登入」是狀態轉換而非資源刪除，故用 POST
		// 動作端點（同既有的 /unlock 慣例），不塞進 DELETE 的查詢參數——
		// 後者會讓「順手多帶一個參數就停用帳號」變成可能
		users.GET("/:id/external-identities", h.ListExternalIdentities)
		users.POST("/:id/external-identities", h.BindExternalIdentity)
		users.DELETE("/:id/external-identities/:identityId", h.UnbindExternalIdentity)
		users.POST("/:id/external-identities/:identityId/unbind-and-disable", h.UnbindExternalIdentityAndDisable)
		users.POST("/:id/external-only", h.ConvertToExternalOnly)
	}
}
