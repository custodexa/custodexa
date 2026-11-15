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
	g.Use(middleware.EnforceRegistry())
	{
		g.GET("", h.List)
		g.GET("/:type/:sourceId/mappings", h.ListMappings)
		g.POST("/:type/:sourceId/mappings", h.CreateMapping)
		g.PUT("/:type/:sourceId/mappings/:ruleId", h.UpdateMapping)
		g.DELETE("/:type/:sourceId/mappings/:ruleId", h.DeleteMapping)
		g.GET("/:type/:sourceId/role-mappings", h.ListMappings)
		g.GET("/:type/:sourceId/role-mappings/:ruleId", h.GetMapping)
		g.POST("/:type/:sourceId/role-mappings", h.CreateMapping)
		g.PUT("/:type/:sourceId/role-mappings/:ruleId", h.UpdateMapping)
		g.DELETE("/:type/:sourceId/role-mappings/:ruleId", h.DeleteMapping)
		g.GET("/:type/:sourceId/user-group-mappings", h.ListUserGroupMappings)
		g.GET("/:type/:sourceId/user-group-mappings/:ruleId", h.GetUserGroupMapping)
		g.GET("/:type/:sourceId/user-group-usage/:userGroupId", h.UserGroupMappingUsage)
		g.POST("/:type/:sourceId/user-group-mappings", h.CreateUserGroupMapping)
		g.PUT("/:type/:sourceId/user-group-mappings/:ruleId", h.UpdateUserGroupMapping)
		g.DELETE("/:type/:sourceId/user-group-mappings/:ruleId", h.DeleteUserGroupMapping)
		g.GET("/:type/:sourceId/external-groups", h.ListExternalGroups)
		g.PUT("/:type/:sourceId/external-groups/:externalGroupId", h.UpdateExternalGroupNote)
	}
}

// lookupParam 讀一個精確查找參數：沒帶回 (nil, true)；帶一次回其值（含空字串，由 service 判空）；
// 同名參數重複出現回 (nil, false)。重複時不取其中一個：取哪一個都會讓結果隨參數順序改變。
func lookupParam(c *gin.Context, name string) (*string, bool) {
	vals, present := c.GetQueryArray(name)
	if !present {
		return nil, true
	}
	if len(vals) != 1 {
		return nil, false
	}
	return &vals[0], true
}

// ListUserGroupMappings 某來源的使用者群組規則；可依群組值（match_value）與目標群組
// （user_group_id）精確查找，取交集，不帶即全部
func (h *IdentitySourceHandler) ListUserGroupMappings(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	matchValue, okMatch := lookupParam(c, "match_value")
	raw, okGroup := lookupParam(c, "user_group_id")
	if !okMatch || !okGroup {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	lookup := identity.UserGroupMappingLookup{MatchValue: matchValue}
	if raw != nil {
		id, err := strconv.ParseUint(*raw, 10, 32)
		if err != nil || id == 0 {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
		gid := uint(id)
		lookup.UserGroupID = &gid
	}
	rows, err := h.sources.LookupUserGroupMappings(kind, sourceID, lookup)
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// GetUserGroupMapping 依識別讀單條使用者群組規則，內容與列表中的那一列相同
func (h *IdentitySourceHandler) GetUserGroupMapping(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	ruleID, ok := mappingRuleID(c)
	if !ok {
		return
	}
	view, err := h.sources.GetUserGroupMapping(kind, sourceID, ruleID)
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": view})
}

func (h *IdentitySourceHandler) UserGroupMappingUsage(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(c.Param("userGroupId"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, nil)
		return
	}
	usage, err := h.sources.UserGroupMappingUsage(kind, sourceID, uint(id))
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": usage})
}

func (h *IdentitySourceHandler) CreateUserGroupMapping(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	var req identity.UserGroupMappingInput
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	req.Actor = currentMappingActor(c)
	row, err := h.sources.CreateUserGroupMapping(kind, sourceID, req)
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	view, err := h.sources.UserGroupMappingView(kind, sourceID, row.ID)
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": view})
}

func (h *IdentitySourceHandler) UpdateUserGroupMapping(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	ruleID, ok := mappingRuleID(c)
	if !ok {
		return
	}
	var req identity.UserGroupMappingInput
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	req.Actor = currentMappingActor(c)
	row, err := h.sources.UpdateUserGroupMapping(kind, sourceID, ruleID, req)
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	view, err := h.sources.UserGroupMappingView(kind, sourceID, row.ID)
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": view})
}

func (h *IdentitySourceHandler) DeleteUserGroupMapping(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	ruleID, ok := mappingRuleID(c)
	if !ok {
		return
	}
	if err := h.sources.DeleteUserGroupMapping(kind, sourceID, ruleID, currentMappingActor(c)); err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *IdentitySourceHandler) ListExternalGroups(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	rows, err := h.sources.ListExternalGroups(kind, sourceID)
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

func (h *IdentitySourceHandler) UpdateExternalGroupNote(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(c.Param("externalGroupId"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, nil)
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	if err := h.sources.UpdateExternalGroupNote(kind, sourceID, uint(id), req.Note, currentMappingActor(c)); err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"id": uint(id), "note": req.Note}})
}

// currentMappingActor 由已認證脈絡取操作者（不自請求 body 取，理由同目錄設定）
func currentMappingActor(c *gin.Context) identity.GroupRoleMappingActor {
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	return identity.GroupRoleMappingActor{ID: userID, Name: username, IP: sourceip.Of(c),
		Principal: middleware.PrincipalFrom(c), APIToken: middleware.APITokenRefOf(c)}
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
	matchValue, okMatch := lookupParam(c, "match_value")
	role, okRole := lookupParam(c, "role")
	if !okMatch || !okRole {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	rows, err := h.sources.LookupMappings(kind, sourceID, identity.RoleMappingLookup{MatchValue: matchValue, Role: role})
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// GetMapping 依識別讀單條角色規則，內容與列表中的那一列相同
func (h *IdentitySourceHandler) GetMapping(c *gin.Context) {
	kind, sourceID, ok := mappingScope(c)
	if !ok {
		return
	}
	ruleID, ok := mappingRuleID(c)
	if !ok {
		return
	}
	view, err := h.sources.GetMapping(kind, sourceID, ruleID)
	if err != nil {
		respondMappingError(c, kind, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": view})
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
	// 指派關卡與映射守衛的拒絕：原樣轉成機器碼，不帶角色或權限名
	if respondPrincipalError(c, err) {
		return
	}
	var ackErr *identity.MappingAckRequiredError
	if errors.As(err, &ackErr) {
		warnings := make([]map[string]string, 0, len(ackErr.Warnings))
		for _, w := range ackErr.Warnings {
			warnings = append(warnings, map[string]string{"code": w})
		}
		apierror.Write(c, http.StatusUnprocessableEntity, apierror.ErrorResponse{
			Code: apierror.CodeMappingAckRequired,
			Meta: map[string]any{"meta": map[string]any{"warnings": warnings}},
		})
		return
	}
	var usageErr *identity.UserGroupMappingUsageAckError
	if errors.As(err, &usageErr) {
		apierror.Write(c, http.StatusConflict, apierror.ErrorResponse{Code: apierror.CodeMappingUsageAckRequired, Meta: map[string]any{"meta": map[string]any{"usage": usageErr.UserGroupMappingUsage}}})
		return
	}
	switch {
	case errors.Is(err, identity.ErrExternalGroupNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeExternalGroupNotFound, nil)
	case errors.Is(err, identity.ErrExternalGroupNoteTooLong):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeExternalGroupNoteTooLong, nil)
	case errors.Is(err, identity.ErrUserGroupNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeUserGroupNotFound, nil)
	case errors.Is(err, identity.ErrMappingSourceNotFound):
		// 來源不存在的碼依型別分：介面要能分辨「目錄還沒設定」與「這個提供者不在了」
		code := apierror.CodeNotFoundOIDCProvider
		if kind == model.RoleMappingChannelKindDirectory {
			code = apierror.CodeNotFoundLDAPDirectory
		}
		apierror.Respond(c, http.StatusNotFound, code, nil)
	case errors.Is(err, identity.ErrMappingRuleNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeMappingRuleNotFound, nil)
	case errors.Is(err, identity.ErrMappingRuleExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeMappingRuleExists, nil)
	// 目錄型來源的規則寫入與目錄設定共用同一把互斥，取不到時不排隊。
	// 這是可重試的情形，與目錄設定自己的寫入回同一個碼，不當成系統故障
	case errors.Is(err, identity.ErrLDAPDirectoryBusy):
		apierror.Respond(c, http.StatusConflict, apierror.CodeConflictLDAPDirectoryBusy, nil)
	case errors.Is(err, identity.ErrMappingLookupParam):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
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
