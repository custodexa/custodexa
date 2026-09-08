package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/sourceip"
)

// 身分來源 API（admin-only）：目錄與提供者的合併列表，以及以來源為軸的映射規則 CRUD。
//
// # 路徑參數為什麼不叫 `:id`
//
// 審計中介層以 `c.Param("id")` 填 `resource_id`。這裡的 `:sourceId` 指的是目錄或
// 提供者的列識別，`:ruleId` 指的是規則列——兩者都不是本路由分類（auth）自身的
// 實體識別，叫 `:id` 會在稽核列上長出一個指向別種資源的假錨點。
//
// # 為什麼規則一律以（來源型別，來源識別）定址
//
// 一條規則屬於某一個來源。以規則識別直接定址的旁路會讓一次筆誤改到另一個來源
// 的規則，而症狀是「我明明沒動那個目錄」。多一段路徑換掉整類錯誤。
type IdentitySourceHandler struct {
	sources *identity.IdentitySourceService
}

// NewIdentitySourceHandler 建立身分來源 handler
func NewIdentitySourceHandler(sources *identity.IdentitySourceService) *IdentitySourceHandler {
	return &IdentitySourceHandler{sources: sources}
}

// RegisterRoutes 註冊路由（admin 限定，掛法照目錄設定 handler）
func (h *IdentitySourceHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/identity-sources")
	g.Use(middleware.AuthMiddleware(authService))
	g.Use(middleware.RequireRole("admin"))
	{
		g.GET("", h.List)
		g.GET("/:type/:sourceId/mappings", h.ListMappings)
		g.POST("/:type/:sourceId/mappings", h.CreateMapping)
		g.PUT("/:type/:sourceId/mappings/:ruleId", h.UpdateMapping)
		g.DELETE("/:type/:sourceId/mappings/:ruleId", h.DeleteMapping)
	}
}

// currentMappingActor 由已認證脈絡取操作者（不自請求 body 取，理由同目錄設定）
func currentMappingActor(c *gin.Context) identity.GroupRoleMappingActor {
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	return identity.GroupRoleMappingActor{ID: userID, Name: username, IP: sourceip.Of(c)}
}

// List 合併列表（目錄至多一列，其餘為提供者）
func (h *IdentitySourceHandler) List(c *gin.Context) {
	rows, err := h.sources.ListSources()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalOIDCProviderList, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// mappingScope 解析來源型別與識別（兩者任一不合法即 400）
func mappingScope(c *gin.Context) (kind string, sourceID uint, ok bool) {
	kind, err := identity.MappingSourceKind(c.Param("type"))
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID,
			map[string]any{"resource": "identity_source"})
		return "", 0, false
	}
	id, perr := strconv.ParseUint(c.Param("sourceId"), 10, 32)
	if perr != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID,
			map[string]any{"resource": "identity_source"})
		return "", 0, false
	}
	return kind, uint(id), true
}

func mappingRuleID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("ruleId"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID,
			map[string]any{"resource": "identity_source"})
		return 0, false
	}
	return uint(id), true
}

// ListMappings 某來源的規則清單
func (h *IdentitySourceHandler) ListMappings(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	rows, err := h.sources.ListMappings(kind, sourceID)
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// CreateMapping 建立規則（命中風險情形且未確認即 422）
func (h *IdentitySourceHandler) CreateMapping(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	var req identity.GroupRoleMappingInput
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	req.Actor = currentMappingActor(c)

	view, err := h.sources.CreateMapping(kind, sourceID, req)
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": view})
}

// UpdateMapping 更新規則
func (h *IdentitySourceHandler) UpdateMapping(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	ruleID, ok := mappingRuleID(c)
	if !ok {
		return
	}
	var req identity.GroupRoleMappingInput
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	req.Actor = currentMappingActor(c)

	view, err := h.sources.UpdateMapping(kind, sourceID, ruleID, req)
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": view})
}

// DeleteMapping 刪除規則
func (h *IdentitySourceHandler) DeleteMapping(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	ruleID, ok := mappingRuleID(c)
	if !ok {
		return
	}
	if err := h.sources.DeleteMapping(kind, sourceID, ruleID, currentMappingActor(c)); err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// respondMappingError 映射規則服務層錯誤的統一 HTTP 出口。
//
// **需要確認**先於其他哨兵比對：它是型別錯誤（帶命中的警告碼），
// 先比哨兵會把警告清單整片吃掉，而那份清單正是介面要顯示給操作者確認的內容。
func respondMappingError(c *gin.Context, kind string, err error) {
	var ackErr *identity.MappingAckRequiredError
	if errors.As(err, &ackErr) {
		warnings := make([]map[string]string, 0, len(ackErr.Warnings))
		for _, w := range ackErr.Warnings {
			warnings = append(warnings, map[string]string{"code": w})
		}
		apierror.Write(c, http.StatusUnprocessableEntity, apierror.ErrorResponse{
			Code: apierror.CodeMappingAckRequired,
			Meta: map[string]any{"warnings": warnings},
		})
		return
	}
	switch {
	case errors.Is(err, identity.ErrMappingSourceNotFound):
		// 來源不存在的碼依型別分：介面要能分辨「目錄還沒設定」與「這個提供者不在了」
		code := apierror.CodeNotFoundOIDCProvider
		if kind == model.RoleMappingChannelKindDirectory {
			code = apierror.CodeNotFoundLDAPDirectory
		}
		apierror.Respond(c, http.StatusNotFound, code, nil)
	case errors.Is(err, identity.ErrMappingRuleNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeMappingRuleNotFound, nil)
	case errors.Is(err, identity.ErrMappingRoleUnknown):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationMappingRoleUnknown, nil)
	case errors.Is(err, identity.ErrMappingMatchValueDN):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationMappingMatchValueDN, nil)
	case errors.Is(err, identity.ErrMappingMatchValueEmpty),
		errors.Is(err, identity.ErrMappingSourceKind):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalLDAPDirectorySave, err)
	}
}
