package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// 個人 API token 的端點：本人的清單、建立與撤銷，管理者對某個帳號的清單、撤銷單把與撤銷全部，
// 以及以 API token 認證的自我查驗。回應永不含明文與雜湊；明文只出現在建立回應一次（不快取）。

// apiTokenService 端點所需的服務面（測試可替換）。
type apiTokenService interface {
	ListForUser(userID uint) ([]identity.APITokenView, error)
	Eligibility(userID uint) (*identity.APITokenEligibility, error)
	RestoreSummaryOf(tokens []identity.APITokenView) identity.APITokenRestoreSummary
	Create(op identity.Operator, in identity.CreateAPITokenInput) (*identity.CreatedAPIToken, error)
	RevokeOwn(op identity.Operator, tokenID uint, note string) error
	ListForAdmin(op identity.Operator, ownerID uint) (*identity.APITokenAdminList, error)
	RevokeForUser(op identity.Operator, ownerID, tokenID uint, note string) error
	RevokeAllForUser(op identity.Operator, ownerID uint, note string) (int, error)
}

var _ apiTokenService = (*identity.APITokenService)(nil)

// APITokenHandler 個人 API token 端點。
type APITokenHandler struct {
	tokens apiTokenService
	// nodeNames 節點識別到呈現名稱（節點路徑）；nil 或讀取失敗時名稱留空
	nodeNames func() (map[uint]string, error)
}

// NewAPITokenHandler 建立端點。nodeNames 供範圍內節點的呈現名稱（可為 nil）。
func NewAPITokenHandler(tokens apiTokenService, nodeNames func() (map[uint]string, error)) *APITokenHandler {
	return &APITokenHandler{tokens: tokens, nodeNames: nodeNames}
}

// RegisterRoutes 註冊端點。管理 token 本身的端點只接受人類工作階段（以 API token 呼叫由全域閘門以路由範圍拒絕）；
// 自我查驗端點只接受以 API token 認證的請求。
func (h *APITokenHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	my := r.Group("/my/api-tokens", middleware.AuthMiddleware(authService), middleware.EnforceRegistry())
	my.GET("", h.ListMine)
	my.POST("", h.CreateMine)
	my.DELETE("/:id", h.RevokeMine)

	users := r.Group("/users/:id/api-tokens", middleware.AuthMiddleware(authService), middleware.EnforceRegistry())
	users.GET("", h.ListForUser)
	users.DELETE("/:tokenId", h.RevokeForUser)
	users.POST("/revoke-all", h.RevokeAllForUser)

	verify := r.Group("/api-tokens/verify", middleware.AuthMiddleware(authService), middleware.EnforceRegistry())
	verify.GET("", h.Verify)
}

// apiTokenNodeRef 範圍內的一個節點。
type apiTokenNodeRef struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// apiTokenScopeDTO 角色目前的範圍：{"kind":"global"} 或 {"kind":"nodes","nodes":[...]}。
type apiTokenScopeDTO struct {
	Kind  string            `json:"kind"`
	Nodes []apiTokenNodeRef `json:"nodes,omitempty"`
}

// apiTokenRoleDTO 一個角色與其目前是否有效、範圍（不生效時為 null）。
type apiTokenRoleDTO struct {
	identity.APITokenRoleRef
	Effective bool              `json:"effective"`
	Scope     *apiTokenScopeDTO `json:"scope"`
}

// apiTokenViewDTO 一把 token 的呈現物件。
type apiTokenViewDTO struct {
	ID           uint                       `json:"id"`
	UserID       uint                       `json:"user_id"`
	Name         string                     `json:"name"`
	Status       identity.APITokenStatus    `json:"status"`
	GrantedRoles []apiTokenRoleDTO          `json:"granted_roles"`
	Privileged   bool                       `json:"privileged"`
	CreatedAt    time.Time                  `json:"created_at"`
	ExpiresAt    *time.Time                 `json:"expires_at"`
	LastUsedAt   *time.Time                 `json:"last_used_at"`
	LastUsedIP   string                     `json:"last_used_ip"`
	RevokedAt    *time.Time                 `json:"revoked_at"`
	RevokedBy    *identity.APITokenActorRef `json:"revoked_by"`
	RevokeNote   string                     `json:"revoke_note"`
}

// apiTokenCreatedDTO 建立回應：呈現物件加一次性明文。
type apiTokenCreatedDTO struct {
	apiTokenViewDTO
	Token string `json:"token"`
}

type apiTokenShaper struct{ names map[uint]string }

func (h *APITokenHandler) shaper() apiTokenShaper {
	s := apiTokenShaper{names: map[uint]string{}}
	if h.nodeNames != nil {
		if m, err := h.nodeNames(); err == nil && m != nil {
			s.names = m
		}
	}
	return s
}

func (s apiTokenShaper) role(r identity.APITokenRoleView) apiTokenRoleDTO {
	out := apiTokenRoleDTO{APITokenRoleRef: r.APITokenRoleRef, Effective: r.Effective}
	if r.Scope != nil {
		scope := &apiTokenScopeDTO{Kind: r.Scope.Kind}
		if r.Scope.Kind == model.ScopeKindNodes {
			scope.Nodes = make([]apiTokenNodeRef, 0, len(r.Scope.NodeIDs))
			for _, id := range r.Scope.NodeIDs {
				scope.Nodes = append(scope.Nodes, apiTokenNodeRef{ID: id, Name: s.names[id]})
			}
		}
		out.Scope = scope
	}
	return out
}

func (s apiTokenShaper) roles(in []identity.APITokenRoleView) []apiTokenRoleDTO {
	out := make([]apiTokenRoleDTO, 0, len(in))
	for _, r := range in {
		out = append(out, s.role(r))
	}
	return out
}

func (s apiTokenShaper) view(v identity.APITokenView) apiTokenViewDTO {
	return apiTokenViewDTO{ID: v.ID, UserID: v.UserID, Name: v.Name, Status: v.Status, GrantedRoles: s.roles(v.GrantedRoles),
		Privileged: v.Privileged, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, LastUsedAt: v.LastUsedAt,
		LastUsedIP: v.LastUsedIP, RevokedAt: v.RevokedAt, RevokedBy: v.RevokedBy, RevokeNote: v.RevokeNote}
}

func (s apiTokenShaper) views(in []identity.APITokenView) []apiTokenViewDTO {
	out := make([]apiTokenViewDTO, 0, len(in))
	for _, v := range in {
		out = append(out, s.view(v))
	}
	return out
}

// splitAllowedCIDRs 帳號的允許來源網段（原樣字串，逗號或換行分隔）轉為陣列；空字串為空陣列。
func splitAllowedCIDRs(raw string) []string {
	out := []string{}
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == ',' || raw[i] == '\n' || raw[i] == '\r' {
			part := raw[start:i]
			for len(part) > 0 && (part[0] == ' ' || part[0] == '\t') {
				part = part[1:]
			}
			for len(part) > 0 && (part[len(part)-1] == ' ' || part[len(part)-1] == '\t') {
				part = part[:len(part)-1]
			}
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

// ListMine GET /my/api-tokens：本人的清單、建立資格與可勾選的角色、還原造成的失效。
func (h *APITokenHandler) ListMine(c *gin.Context) {
	userID, ok := middleware.GetCurrentUserID(c)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeTokenMissing, nil)
		return
	}
	tokens, err := h.tokens.ListForUser(userID)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserQuery, err)
		return
	}
	elig, err := h.tokens.Eligibility(userID)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserQuery, err)
		return
	}
	s := h.shaper()
	restore := h.tokens.RestoreSummaryOf(tokens)
	nonGrantable := elig.NonGrantableRoles
	if nonGrantable == nil {
		nonGrantable = []identity.APITokenRoleRef{}
	}
	c.JSON(http.StatusOK, gin.H{
		"data": s.views(tokens),
		"eligibility": gin.H{
			"can_create": elig.CanCreate, "reason": elig.Reason,
			"grantable_roles": s.roles(elig.GrantableRoles), "non_grantable_roles": nonGrantable,
			"allowed_cidrs": splitAllowedCIDRs(elig.AllowedCIDRs),
		},
		"restore": gin.H{"invalidated_count": restore.InvalidatedCount, "restored_at": restore.RestoredAt},
	})
}

// createAPITokenRequest 建立請求；expires_at 與 never_expires=true 恰擇一。
type createAPITokenRequest struct {
	Name         string     `json:"name"`
	RoleIDs      []uint     `json:"role_ids"`
	ExpiresAt    *time.Time `json:"expires_at"`
	NeverExpires bool       `json:"never_expires"`
}

// CreateMine POST /my/api-tokens：為本人建立，回一次性明文（201，不快取）。
func (h *APITokenHandler) CreateMine(c *gin.Context) {
	var req createAPITokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	created, err := h.tokens.Create(operatorFromRequest(c), identity.CreateAPITokenInput{
		Name: req.Name, RoleIDs: req.RoleIDs, ExpiresAt: req.ExpiresAt, NeverExpires: req.NeverExpires})
	if err != nil {
		respondAPITokenError(c, err)
		return
	}
	c.Set("audit_resource", model.ResourceAPIToken)
	c.Set("audit_resource_id", created.View.ID)
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusCreated, apiTokenCreatedDTO{apiTokenViewDTO: h.shaper().view(created.View), Token: created.Token})
}

// apiTokenRevokeRequest 撤銷的選填原因。
type apiTokenRevokeRequest struct {
	Note string `json:"note"`
}

func parsePositiveUintParam(c *gin.Context, name string) (uint, bool) {
	v, err := strconv.ParseUint(c.Param(name), 10, 32)
	if err != nil || v == 0 {
		return 0, false
	}
	return uint(v), true
}

// RevokeMine DELETE /my/api-tokens/:id：本人撤銷自己的一把（不是自己的或不存在同為 404）。
func (h *APITokenHandler) RevokeMine(c *gin.Context) {
	tokenID, ok := parsePositiveUintParam(c, "id")
	if !ok {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAPITokenNotFound, nil)
		return
	}
	var req apiTokenRevokeRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
	}
	note := req.Note
	c.Set("audit_resource", model.ResourceAPIToken)
	if err := h.tokens.RevokeOwn(operatorFromRequest(c), tokenID, note); err != nil {
		respondAPITokenError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// adminTarget 管理者端點路徑上的帳號；不合法的識別與帳號不存在同為 404（與使用者詳情相同）。
func adminTarget(c *gin.Context) (uint, bool) {
	id, ok := parsePositiveUintParam(c, "id")
	if !ok {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
		return 0, false
	}
	return id, true
}

// ListForUser GET /users/:id/api-tokens：管理者查看某個帳號的 token（需帳號管理能力，由路由判定）。
func (h *APITokenHandler) ListForUser(c *gin.Context) {
	ownerID, ok := adminTarget(c)
	if !ok {
		return
	}
	c.Set("audit_resource", model.ResourceUser)
	list, err := h.tokens.ListForAdmin(operatorFromRequest(c), ownerID)
	if err != nil {
		respondAPITokenError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": h.shaper().views(list.Tokens), "can_revoke": list.CanRevoke,
		"protected": list.Protected, "account_active": list.AccountActive})
}

// RevokeForUser DELETE /users/:id/api-tokens/:tokenId：管理者撤銷某個帳號的一把。
func (h *APITokenHandler) RevokeForUser(c *gin.Context) {
	ownerID, ok := adminTarget(c)
	if !ok {
		return
	}
	tokenID, ok := parsePositiveUintParam(c, "tokenId")
	if !ok {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAPITokenNotFound, nil)
		return
	}
	var req apiTokenRevokeRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
	}
	note := req.Note
	c.Set("audit_resource", model.ResourceAPIToken)
	c.Set("audit_resource_id", tokenID)
	if err := h.tokens.RevokeForUser(operatorFromRequest(c), ownerID, tokenID, note); err != nil {
		markProtectedAccountRefusal(c, err, "api_token_revoke")
		respondAPITokenError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// RevokeAllForUser POST /users/:id/api-tokens/revoke-all：管理者一次撤銷某個帳號全部尚可使用的 token。
func (h *APITokenHandler) RevokeAllForUser(c *gin.Context) {
	ownerID, ok := adminTarget(c)
	if !ok {
		return
	}
	var req apiTokenRevokeRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
	}
	note := req.Note
	c.Set("audit_resource", model.ResourceUser)
	revoked, err := h.tokens.RevokeAllForUser(operatorFromRequest(c), ownerID, note)
	if err != nil {
		markProtectedAccountRefusal(c, err, "api_token_revoke_all")
		respondAPITokenError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": revoked})
}

// Verify GET /api-tokens/verify：以 API token 認證的請求查驗自己的授權；其他認證方式回 403。
func (h *APITokenHandler) Verify(c *gin.Context) {
	ref := middleware.APITokenRefOf(c)
	userID, ok := middleware.GetCurrentUserID(c)
	if ref.ID == 0 || !ok {
		apierror.Respond(c, http.StatusForbidden, apierror.CodePermissionDenied, nil)
		return
	}
	username, _ := middleware.GetCurrentUsername(c)
	tokens, err := h.tokens.ListForUser(userID)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserQuery, err)
		return
	}
	var self *identity.APITokenView
	for i := range tokens {
		if tokens[i].ID == ref.ID {
			self = &tokens[i]
			break
		}
	}
	if self == nil {
		apierror.Respond(c, http.StatusForbidden, apierror.CodePermissionDenied, nil)
		return
	}
	s := h.shaper()
	granted := s.roles(self.GrantedRoles)
	effective := make([]apiTokenRoleDTO, 0, len(granted))
	for _, r := range granted {
		if r.Effective {
			effective = append(effective, r)
		}
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"valid":           true,
		"token":           gin.H{"id": self.ID, "name": self.Name, "expires_at": self.ExpiresAt},
		"user":            gin.H{"id": userID, "username": username},
		"granted_roles":   granted,
		"effective_roles": effective,
	})
}

// respondAPITokenError token 端點的錯誤出口。
func respondAPITokenError(c *gin.Context, err error) {
	var te *identity.APITokenError
	switch {
	case errors.As(err, &te):
		apierror.Respond(c, te.Status, te.Code, nil)
	case errors.Is(err, identity.ErrAPITokenNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAPITokenNotFound, nil)
	case errors.Is(err, identity.ErrUserNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeUserNotExist, nil)
	case respondPrincipalError(c, err):
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserQuery, err)
	}
}
