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
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/sourceip"
)

// AssetGroupServiceInterface 資產節點樹服務接口（用於測試注入）
type AssetGroupServiceInterface interface {
	ListWithAssets() ([]asset.GroupWithAssets, error)
	Tree(parentID *uint, vis *asset.TreeVisibility) ([]asset.TreeNode, error)
	Create(ctx context.Context, req *asset.AssetGroupRequest, actorID uint, actorName, clientIP string) (*model.AssetGroup, error)
	Update(ctx context.Context, id uint, req *asset.AssetGroupRequest, actorID uint, actorName, clientIP string) (*model.AssetGroup, error)
	Move(ctx context.Context, id uint, newParentID *uint, actorID uint, actorName, clientIP string) (*model.AssetGroup, error)
	Delete(ctx context.Context, id uint, actorID uint, actorName, clientIP string) (int64, error)
}

// AssetNodeVisibilityResolver 非特權角色的樹收斂範圍解析：
// 可視資產集＋其節點祖先鏈——節點過濾與計數同受收斂，不洩漏無關子樹
type AssetNodeVisibilityResolver interface {
	VisibleTreeScope(ctx context.Context, userID uint) (*asset.TreeVisibility, error)
}

// NodeTreeScopeResolver 節點樹與平面列表的範圍化讀取（authz 實作）：範圍化檢視者的管理可視與列級旗標，
// 以及用途參數的節點投影。非範圍化檢視者兩者皆回 nil，handler 走現行路徑、回應不變。
type NodeTreeScopeResolver interface {
	TreeView(ctx context.Context) (*authz.NodeTreeView, error)
	PurposeProjection(ctx context.Context, perm authz.Permission) (*authz.NodeProjection, error)
}

// AssetGroupHandler 資產節點樹 API（寫入 admin only）
type AssetGroupHandler struct {
	groupService AssetGroupServiceInterface
	authz        AssetAuthorizationServiceInterface
	visibility   AssetNodeVisibilityResolver
	treeScope    NodeTreeScopeResolver
}

// SetNodeTreeScope 注入範圍化讀取。未注入時範圍化檢視者只見連線可視（不擴大資料）、不帶旗標。
func (h *AssetGroupHandler) SetNodeTreeScope(r NodeTreeScopeResolver) { h.treeScope = r }

// nodePurposePerms 平面節點列表用途參數的白名單與對應權限點。
var nodePurposePerms = map[string]authz.Permission{
	"asset_create":             authz.PermAssetCreate,
	"asset_update":             authz.PermAssetUpdate,
	"credential_create":        authz.PermCredentialCreate,
	"credential_update":        authz.PermCredentialUpdate,
	"credential_convert_scope": authz.PermCredentialConvertScope,
}

// parseNodePurpose 解析用途參數：未帶回 present=false；帶了但不在白名單（含空值、重複給值）回 ok=false。
func parseNodePurpose(c *gin.Context) (perm authz.Permission, present, ok bool) {
	vals, present := c.Request.URL.Query()["purpose"]
	if !present {
		return "", false, true
	}
	if len(vals) != 1 {
		return "", true, false
	}
	perm, ok = nodePurposePerms[vals[0]]
	return perm, true, ok
}

// unionIDs 兩個集合的聯集（新建，不改傳入值）。
func unionIDs(sets ...map[uint]bool) map[uint]bool {
	out := map[uint]bool{}
	for _, s := range sets {
		for id, v := range s {
			if v {
				out[id] = true
			}
		}
	}
	return out
}

// NewAssetGroupHandler 建立 handler。authz 用於一般 user 的節點列表資產收斂、
// visibility 用於樹端點的可視節點鏈收斂
func NewAssetGroupHandler(groupService AssetGroupServiceInterface, authz AssetAuthorizationServiceInterface, visibility AssetNodeVisibilityResolver) *AssetGroupHandler {
	return &AssetGroupHandler{groupService: groupService, authz: authz, visibility: visibility}
}

// respondGroupError 節點樹寫入端點的統一錯誤出口：
// 已知 sentinel 依 errors.Is 映射到機器碼（狀態碼與遷移前逐一相同），未知一律
// RespondInternal。internalCode 為該端點的 INTERNAL_ASSET_NODE_<VERB> 碼。
func respondGroupError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	if respondNodeScopeError(c, err) {
		return
	}
	switch {
	case errors.Is(err, asset.ErrGroupNameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAssetNodeNameExists, nil)
	case errors.Is(err, asset.ErrGroupNotFound):
		// 真不存在：經種類對照寫出，與範圍拒絕同形但不留範圍拒絕標記
		middleware.RespondTargetNotFound(c, authz.ScopeTargetNode, authz.ScopeLayerNode)
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

// scopedContext 帶主體的 ctx（CheckPermission 的保留身分短路由主體判定）
func scopedContext(c *gin.Context) context.Context {
	return authz.ContextWithPrincipal(c.Request.Context(), middleware.PrincipalFrom(c))
}

// List 節點平面列表（登入即可——授權精靈/工作區分節需要）。非 admin/auditor
// 收斂：每節點僅回該 user 可視的直掛資產，並僅保留「有可視資產的節點＋其祖先鏈」
// （祖先空殼保留以維持樹形連貫）。範圍化檢視者另聯集管理可視的節點與資產並附列級旗標；
// 帶用途參數且範圍化判定成立者另附 selectable／selectable_all。
func (h *AssetGroupHandler) List(c *gin.Context) {
	purposePerm, hasPurpose, ok := parseNodePurpose(c)
	if !ok {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	groups, err := h.groupService.ListWithAssets()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetNodeQuery, err)
		return
	}

	if isPrivilegedRole(c) {
		c.JSON(http.StatusOK, gin.H{"data": groups, "total": len(groups)})
		return
	}
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
	connAllowed := make(map[uint]bool, len(authorized))
	for _, a := range authorized {
		connAllowed[a.ID] = true
	}
	var view *authz.NodeTreeView
	var proj *authz.NodeProjection
	if h.treeScope != nil {
		if view, err = h.treeScope.TreeView(scopedContext(c)); err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizedAssetQuery, err)
			return
		}
		if hasPurpose {
			if proj, err = h.treeScope.PurposeProjection(scopedContext(c), purposePerm); err != nil {
				apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizedAssetQuery, err)
				return
			}
		}
	}
	allowed := connAllowed
	if view != nil {
		allowed = unionIDs(connAllowed, view.ManageAssets)
	}

	parentOf := make(map[uint]*uint, len(groups))
	for _, g := range groups {
		parentOf[g.ID] = g.ParentID
	}
	keep := make(map[uint]bool)
	keepChain := func(id uint) {
		// 節點自身＋祖先鏈全保留（樹形連貫；深度上限防環）
		cur := &id
		for depth := 0; cur != nil && depth <= 10; depth++ {
			keep[*cur] = true
			cur = parentOf[*cur]
		}
	}
	connDirect := make(map[uint]bool)
	for i := range groups {
		kept := make([]model.Asset, 0, len(groups[i].Assets))
		for _, a := range groups[i].Assets {
			if connAllowed[a.ID] {
				connDirect[groups[i].ID] = true
			}
			if allowed[a.ID] {
				kept = append(kept, a)
			}
		}
		groups[i].Assets = kept
		// 節點可視只來自連線可視的直掛資產與下方的管理可視節點；管理可視資產的其他掛載
		// 不使節點可視（與樹端點同一組節點）。非範圍化檢視者 allowed 即連線可視，行為不變。
		if connDirect[groups[i].ID] {
			keepChain(groups[i].ID)
		}
	}
	if view != nil {
		for id := range unionIDs(view.ManageNodes, view.ManageLocators) {
			keepChain(id)
		}
	}
	if proj != nil && proj.State == authz.ScopeSetConditional {
		// 範圍內但原不可視的節點與其祖先一併列出（資產仍只含原可視者）
		for id := range unionIDs(proj.Selectable, proj.Locators) {
			keepChain(id)
		}
	}
	filtered := make([]asset.GroupWithAssets, 0, len(groups))
	for _, g := range groups {
		if keep[g.ID] {
			filtered = append(filtered, g)
		}
	}
	if view != nil {
		ids := make([]uint, 0, len(filtered))
		for _, g := range filtered {
			ids = append(ids, g.ID)
		}
		flags, err := view.Flags(ids)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetNodeQuery, err)
			return
		}
		for i := range filtered {
			f := flags[filtered[i].ID].WithLocator(connDirect[filtered[i].ID])
			filtered[i].NodeRowFlags = &f
		}
	}
	resp := gin.H{"data": filtered, "total": len(filtered)}
	if proj != nil {
		all := proj.State == authz.ScopeSetUnlimited
		for i := range filtered {
			sel := all || proj.Selectable[filtered[i].ID]
			filtered[i].Selectable = &sel
		}
		resp["selectable_all"] = all
	}
	c.JSON(http.StatusOK, resp)
}

// Tree 樹導覽端點（惰性載入，parent_id 空＝根層）。
// 非 admin/auditor 依可視節點鏈收斂
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
	var view *authz.NodeTreeView
	if visible != nil && h.treeScope != nil {
		var err error
		if view, err = h.treeScope.TreeView(scopedContext(c)); err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetNodeVisibility, err)
			return
		}
	}
	if view != nil {
		// 範圍化檢視者：連線可視與管理可視聯集，祖先鏈作定位；計數只計聯集後的可視資產
		visible = &asset.TreeVisibility{
			NodeIDs:  unionIDs(visible.NodeIDs, view.ManageNodes, view.ManageLocators),
			AssetIDs: unionIDs(visible.AssetIDs, view.ManageAssets),
			Scoped:   &asset.NodeTreeScope{ConnAssetIDs: visible.AssetIDs, Flags: view.Flags},
		}
	}

	nodes, err := h.groupService.Tree(parentID, visible)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetNodeTreeQuery, err)
		return
	}
	resp := gin.H{"data": nodes}
	if view != nil && parentID == nil {
		resp["can_create_root"] = view.CanCreateRoot
	}
	c.JSON(http.StatusOK, resp)
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
	group, err := h.groupService.Create(scopedContext(c), &req, actorID, actorName, sourceip.Of(c))
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
	group, err := h.groupService.Update(scopedContext(c), uint(id), &req, actorID, actorName, sourceip.Of(c))
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

// Move 搬移節點（環路檢查＋深度重驗＋同層同名）
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
	group, err := h.groupService.Move(scopedContext(c), uint(id), req.ParentID, actorID, actorName, sourceip.Of(c))
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

	revoked, err := h.groupService.Delete(scopedContext(c), uint(id), actorID, actorName, sourceip.Of(c))
	if err != nil {
		respondGroupError(c, apierror.CodeInternalAssetNodeDelete, err)
		return
	}
	// 成功回應不攜帶 UI 文案：前端以 $t('nodeTree.deleted') 自有文案提示；
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
		groups.GET("", middleware.EnforceRegistry(), h.List)
		groups.GET("/tree", middleware.EnforceRegistry(), h.Tree)
		groups.POST("", middleware.EnforceRegistry(), h.Create)
		groups.PUT("/:id", middleware.EnforceRegistry(), h.Update)
		groups.PUT("/:id/move", middleware.EnforceRegistry(), h.Move)
		groups.DELETE("/:id", middleware.EnforceRegistry(), h.Delete)
	}
}
