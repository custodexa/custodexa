package api

import (
	"context"
	"errors"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/sourceip"
)

// AssetGroupServiceInterface 資產節點樹服務接口（用於測試注入）
type AssetGroupServiceInterface interface {
	ListWithAssets() ([]asset.GroupWithAssets, error)
	Tree(parentID *uint, vis *asset.TreeVisibility) ([]asset.TreeNode, error)
	Create(req *asset.AssetGroupRequest, actorID uint, actorName, clientIP string) (*model.AssetGroup, error)
	Update(id uint, req *asset.AssetGroupRequest, actorID uint, actorName, clientIP string) (*model.AssetGroup, error)
	Move(id uint, newParentID *uint, actorID uint, actorName, clientIP string) (*model.AssetGroup, error)
	Delete(id uint, actorID uint, actorName, clientIP string) (int64, error)
}

// AssetNodeVisibilityResolver 非特權角色的樹收斂範圍解析（asset-node-tree D6）：
// 可視資產集＋其節點祖先鏈——節點過濾與計數同受收斂，不洩漏無關子樹
type AssetNodeVisibilityResolver interface {
	VisibleTreeScope(ctx context.Context, userID uint) (*asset.TreeVisibility, error)
}

// AssetGroupHandler 資產節點樹 API（asset-node-tree，寫入 admin only）
type AssetGroupHandler struct {
	groupService AssetGroupServiceInterface
	authz        AssetAuthorizationServiceInterface
	visibility   AssetNodeVisibilityResolver
}

// NewAssetGroupHandler 建立 handler。authz 用於一般 user 的節點列表資產收斂、
// visibility 用於樹端點的可視節點鏈收斂（asset-access-scoping／asset-node-tree D6）
func NewAssetGroupHandler(groupService AssetGroupServiceInterface, authz AssetAuthorizationServiceInterface, visibility AssetNodeVisibilityResolver) *AssetGroupHandler {
	return &AssetGroupHandler{groupService: groupService, authz: authz, visibility: visibility}
}

// respondGroupError 節點樹寫入端點的統一錯誤出口（backend-i18n-unification A2）：
// 已知 sentinel 依 errors.Is 映射到機器碼（狀態碼與遷移前逐一相同），未知一律
// RespondInternal。internalCode 為該端點的 INTERNAL_ASSET_NODE_<VERB> 碼。
func respondGroupError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	switch {
	case errors.Is(err, asset.ErrGroupNameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAssetNodeNameExists, nil)
	case errors.Is(err, asset.ErrGroupNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNodeNotFound, nil)
	case errors.Is(err, asset.ErrNodeDepthExceeded):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeNodeDepthExceeded, nil)
	case errors.Is(err, asset.ErrNodeCycle):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeNodeCycle, nil)
	case errors.Is(err, asset.ErrNodeNotEmpty):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeNodeNotEmpty, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}

// scopedContext 帶 role 的 ctx（沿既有 CheckPermission 慣例）
func scopedContext(c *gin.Context) context.Context {
	ctx := c.Request.Context()
	if role, ok := c.Get("role"); ok {
		ctx = context.WithValue(ctx, "role", role) //nolint:staticcheck // 沿用既有慣例
	}
	return ctx
}

// List 節點平面列表（登入即可——授權精靈/工作區分節需要）。非 admin/auditor
// 收斂：每節點僅回該 user 授權的直掛資產，並僅保留「有授權資產的節點＋其祖先鏈」
// （祖先空殼保留以維持樹形連貫；asset-access-scoping 語義隨樹升級）
func (h *AssetGroupHandler) List(c *gin.Context) {
	groups, err := h.groupService.ListWithAssets()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetNodeQuery, err)
		return
	}

	if !isPrivilegedRole(c) {
		userID, exists := middleware.GetCurrentUserID(c)
		if !exists {
			apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
			return
		}
		authorized, err := h.authz.GetAuthorizedAssets(scopedContext(c), userID, model.PermissionView)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizedAssetQuery, err)
			return
		}
		allowed := make(map[uint]bool, len(authorized))
		for _, a := range authorized {
			allowed[a.ID] = true
		}

		parentOf := make(map[uint]*uint, len(groups))
		for _, g := range groups {
			parentOf[g.ID] = g.ParentID
		}
		keep := make(map[uint]bool)
		for i := range groups {
			kept := make([]model.Asset, 0, len(groups[i].Assets))
			for _, a := range groups[i].Assets {
				if allowed[a.ID] {
					kept = append(kept, a)
				}
			}
			groups[i].Assets = kept
			if len(kept) > 0 {
				// 節點自身＋祖先鏈全保留（樹形連貫；深度上限防環）
				cur := &groups[i].ID
				for depth := 0; cur != nil && depth <= 10; depth++ {
					keep[*cur] = true
					cur = parentOf[*cur]
				}
			}
		}
		filtered := make([]asset.GroupWithAssets, 0, len(groups))
		for _, g := range groups {
			if keep[g.ID] {
				filtered = append(filtered, g)
			}
		}
		groups = filtered
	}

	c.JSON(http.StatusOK, gin.H{"data": groups, "total": len(groups)})
}

// Tree 樹導覽端點（asset-node-tree D5：惰性載入，parent_id 空＝根層）。
// 非 admin/auditor 依可視節點鏈收斂（D6）
func (h *AssetGroupHandler) Tree(c *gin.Context) {
	var parentID *uint
	if raw := c.Query("parent_id"); raw != "" {
		id64, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidNodeID, nil)
			return
		}
		id := uint(id64)
		parentID = &id
	}

	var visible *asset.TreeVisibility
	if !isPrivilegedRole(c) {
		userID, exists := middleware.GetCurrentUserID(c)
		if !exists {
			apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
			return
		}
		v, err := h.visibility.VisibleTreeScope(scopedContext(c), userID)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetNodeVisibility, err)
			return
		}
		visible = v
	}

	nodes, err := h.groupService.Tree(parentID, visible)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetNodeTreeQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": nodes})
}

// Create 建立節點（含 parent_id；深度/同層同名由 service 驗證）
func (h *AssetGroupHandler) Create(c *gin.Context) {
	var req asset.AssetGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	actorID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	actorName, _ := middleware.GetCurrentUsername(c)
	group, err := h.groupService.Create(&req, actorID, actorName, sourceip.Of(c))
	if err != nil {
		respondGroupError(c, apierror.CodeInternalAssetNodeCreate, err)
		return
	}
	c.JSON(http.StatusCreated, group)
}

// Update 更新節點名稱/描述（位置不動，搬移走 Move）
func (h *AssetGroupHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidNodeID, nil)
		return
	}
	var req asset.AssetGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	actorID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	actorName, _ := middleware.GetCurrentUsername(c)
	group, err := h.groupService.Update(uint(id), &req, actorID, actorName, sourceip.Of(c))
	if err != nil {
		respondGroupError(c, apierror.CodeInternalAssetNodeUpdate, err)
		return
	}
	c.JSON(http.StatusOK, group)
}

// moveRequest 搬移請求：parent_id null＝搬到根層
type moveRequest struct {
	ParentID *uint `json:"parent_id"`
}

// Move 搬移節點（asset-node-tree D4：環路檢查＋深度重驗＋同層同名）
func (h *AssetGroupHandler) Move(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidNodeID, nil)
		return
	}
	var req moveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	actorID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	actorName, _ := middleware.GetCurrentUsername(c)
	group, err := h.groupService.Move(uint(id), req.ParentID, actorID, actorName, sourceip.Of(c))
	if err != nil {
		respondGroupError(c, apierror.CodeInternalAssetNodeMove, err)
		return
	}
	c.JSON(http.StatusOK, group)
}

// Delete 刪除節點（僅空節點；掛該節點的授權與審核範圍連動撤銷）
func (h *AssetGroupHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidNodeID, nil)
		return
	}
	actorID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	actorName, _ := middleware.GetCurrentUsername(c)

	revoked, err := h.groupService.Delete(uint(id), actorID, actorName, sourceip.Of(c))
	if err != nil {
		respondGroupError(c, apierror.CodeInternalAssetNodeDelete, err)
		return
	}
	// 成功回應不攜帶 UI 文案（D9）：前端以 $t('nodeTree.deleted') 自有文案提示；
	// revoked_authorizations 是機器欄（連動撤銷筆數），保留
	c.JSON(http.StatusOK, gin.H{
		"revoked_authorizations": revoked,
	})
}

// RegisterRoutes 註冊路由：讀取登入即可，寫入 admin only
func (h *AssetGroupHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	groups := r.Group("/asset-groups")
	groups.Use(middleware.AuthMiddleware(authService))
	{
		groups.GET("", h.List)
		groups.GET("/tree", h.Tree)
		groups.POST("", middleware.RequireRole("admin"), h.Create)
		groups.PUT("/:id", middleware.RequireRole("admin"), h.Update)
		groups.PUT("/:id/move", middleware.RequireRole("admin"), h.Move)
		groups.DELETE("/:id", middleware.RequireRole("admin"), h.Delete)
	}
}
