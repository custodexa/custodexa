package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// RoleDefinitionReader 角色定義的唯讀服務（由 identity.RoleDefinitionReader 實作）。
type RoleDefinitionReader interface {
	List(ctx context.Context, operatorID uint) (*identity.RoleDefinitionList, error)
	Get(ctx context.Context, roleID uint) (*identity.RoleDefinitionDetail, error)
	DraftSummary(keys []string) (*identity.RoleDraftSummary, error)
}

// RoleDefinitionHandler 角色定義 API。讀取權限由路由登錄表裁決（角色檢視能力），
// 讀取不改任何資料、不推進版本；寫入方法（見 role_definition_write_handler.go）只轉呼叫
// 角色定義服務，是否為超級管理者由服務在交易內裁決。
type RoleDefinitionHandler struct {
	reader RoleDefinitionReader
	writer RoleDefinitionWriter
}

// NewRoleDefinitionHandler 建立 handler。writer 為 nil 時寫入方法一律以內部錯誤拒絕（fail-close）。
func NewRoleDefinitionHandler(r RoleDefinitionReader, w RoleDefinitionWriter) *RoleDefinitionHandler {
	return &RoleDefinitionHandler{reader: r, writer: w}
}

// List 角色列表：每列含摘要與唯讀判定，頂層帶 can_define。
func (h *RoleDefinitionHandler) List(c *gin.Context) {
	operatorID, _ := middleware.GetCurrentUserID(c)
	out, err := h.reader.List(c.Request.Context(), operatorID)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleQuery, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

type entryStateView struct {
	Name string   `json:"name"`
	Keys []string `json:"keys"`
}

type entryDetailView struct {
	ID       string `json:"id"`
	Key      string `json:"key"`
	Scopable bool   `json:"scopable"`
}

type entryDescriptorView struct {
	ID        string            `json:"id"`
	Group     string            `json:"group"`
	States    []entryStateView  `json:"states"`
	WriteKeys []string          `json:"write_keys"`
	Details   []entryDetailView `json:"details"`
	Scopable  bool              `json:"scopable"`
}

type capabilityDescriptorView struct {
	ID            string `json:"id"`
	Key           string `json:"key"`
	TrustHint     bool   `json:"trust_hint"`
	RequiresEntry bool   `json:"requires_entry"`
	Scopable      bool   `json:"scopable"`
}

func permKeys(ks []authz.Permission) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = string(k)
	}
	return out
}

// Descriptors 編輯描述：入口與各態集合、獨立能力、固定入口，皆由 authz 的描述表原樣產生。
func (h *RoleDefinitionHandler) Descriptors(c *gin.Context) {
	entries := authz.EntryDescriptors()
	ev := make([]entryDescriptorView, len(entries))
	for i, e := range entries {
		v := entryDescriptorView{ID: e.ID, Group: string(e.Group),
			States: make([]entryStateView, len(e.States)), Details: make([]entryDetailView, len(e.Details)),
			WriteKeys: permKeys(authz.EntryWriteKeys(e)), Scopable: authz.EntryNodeScopable(e)}
		for j, s := range e.States {
			v.States[j] = entryStateView{Name: s.Name, Keys: permKeys(s.Keys)}
		}
		for j, d := range e.Details {
			v.Details[j] = entryDetailView{ID: d.ID, Key: string(d.Key), Scopable: authz.PermissionScopeEnforced(d.Key)}
		}
		ev[i] = v
	}
	caps := authz.CapabilityDescriptors()
	cv := make([]capabilityDescriptorView, len(caps))
	for i, cp := range caps {
		cv[i] = capabilityDescriptorView{ID: cp.ID, Key: string(cp.Key), TrustHint: cp.TrustHint, RequiresEntry: cp.RequiresEntry,
			Scopable: authz.PermissionScopeEnforced(cp.Key)}
	}
	c.JSON(http.StatusOK, gin.H{"entries": ev, "capabilities": cv, "fixed_entries": authz.FixedEntries()})
}

// Get 單筆角色。
func (h *RoleDefinitionHandler) Get(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "role"})
		return
	}
	out, err := h.reader.Get(c.Request.Context(), uint(id))
	if err != nil {
		if errors.Is(err, identity.ErrRoleDefinitionNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeRoleNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleQuery, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

type roleDraftSummaryBody struct {
	Permissions []string `json:"permissions"`
}

// DraftSummary 以草稿權限集合產生摘要與缺依賴，不寫入。
// 本文以嚴格解碼處理：頂層出現 permissions 以外的鍵一律 400。
func (h *RoleDefinitionHandler) DraftSummary(c *gin.Context) {
	var body roleDraftSummaryBody
	if !decodeStrictBody(c, &body) {
		return
	}
	out, err := h.reader.DraftSummary(body.Permissions)
	if err != nil {
		if authz.IsInvalidRolePermission(err) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeRolePermissionInvalid, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleQuery, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// RegisterRoutes 註冊四條讀取與四條寫入路由。讀取權限由路由登錄表裁決；寫入以登入身分放行，
// 是否為超級管理者由服務在交易內裁決。
func (h *RoleDefinitionHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/role-definitions")
	g.Use(middleware.AuthMiddleware(authService), middleware.EnforceRegistry())
	g.GET("", h.List)
	g.GET("/descriptors", h.Descriptors)
	g.GET("/:id", h.Get)
	g.POST("/summary", h.DraftSummary)
	g.POST("", h.Create)
	g.POST("/:id/copy", h.Copy)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
}
