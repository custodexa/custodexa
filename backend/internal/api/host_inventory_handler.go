package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/sourceip"
)

// HostInventoryServiceInterface 主機帳號盤點服務（測試可注入）。
type HostInventoryServiceInterface interface {
	Initiate(assetID uint, actor asset.InventoryActor) (*model.HostAccountScan, error)
	GetAssetInventory(assetID uint, q asset.InventoryFindingQuery) (*asset.AssetInventoryView, error)
	ListGlobalFindings(q asset.InventoryGlobalQuery) (*asset.InventoryGlobalView, error)
	IgnoreFinding(assetID, findingID uint, reason string, actor asset.InventoryActor) (*model.HostAccountFinding, error)
	ReopenFinding(assetID, findingID uint, actor asset.InventoryActor) (*model.HostAccountFinding, error)
}

// HostInventoryHandler 主機帳號盤點端點。能力由路由登錄閘把關（發起、忽略、重新開啟為盤點權限點，
// 兩條讀取為資產檢視權限點）。三條寫入的範圍判定在登錄閘；兩條讀取的可視範圍與資產詳情、資產列表
// 同一組判定：單資產讀取掛與資產詳情相同的逐資產可視守門（連線可視或管理可視），全域清單投影到
// 資產列表的可見集合（檢視捷徑主體為全部，其他主體為連線可視與管理可視的聯集）。
// 全域資產檢視（含零指派套用的一般使用者範本）不構成管理可視，所以不會因此看到範圍外資產的盤點。
type HostInventoryHandler struct {
	svc       HostInventoryServiceInterface
	auth      AssetAuthorizationServiceInterface
	scope     AssetScopeSource
	scopeGate *middleware.ScopeGate
}

// NewHostInventoryHandler 建立 handler。auth 為連線可視的判定來源，scope 為管理可視的判定來源；
// auth 為 nil 時全域清單對非檢視捷徑主體回空（不放行），scope 為 nil 時只計連線可視（不擴大資料）。
func NewHostInventoryHandler(svc HostInventoryServiceInterface, auth AssetAuthorizationServiceInterface, scope AssetScopeSource, scopeGate ...*middleware.ScopeGate) *HostInventoryHandler {
	h := &HostInventoryHandler{svc: svc, auth: auth, scope: scope}
	if len(scopeGate) > 0 {
		h.scopeGate = scopeGate[0]
	}
	return h
}

func inventoryActor(c *gin.Context) asset.InventoryActor {
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	return asset.InventoryActor{UserID: userID, Username: username, ClientIP: sourceip.Of(c), APIToken: middleware.APITokenRefOf(c)}
}

func inventoryAssetID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return 0, false
	}
	return uint(id), true
}

func inventoryFindingID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("findingId"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidFindingID, nil)
		return 0, false
	}
	return uint(id), true
}

// respondInventoryError 把服務的 sentinel 一對一映射成出口碼；其餘一律 500，碼由呼叫端依讀寫給定。
func respondInventoryError(c *gin.Context, err error, internal apierror.ErrCode) {
	switch {
	case errors.Is(err, asset.ErrInventoryPlatformUnsupported):
		apierror.Respond(c, http.StatusUnprocessableEntity, apierror.CodeInventoryPlatformUnsupported, nil)
	case errors.Is(err, asset.ErrInventoryNoAccount):
		apierror.Respond(c, http.StatusUnprocessableEntity, apierror.CodeInventoryNoAccount, nil)
	case errors.Is(err, asset.ErrInventoryNoSecret):
		apierror.Respond(c, http.StatusUnprocessableEntity, apierror.CodeInventoryNoSecret, nil)
	case errors.Is(err, asset.ErrInventoryExecutorUnavailable):
		apierror.Respond(c, http.StatusUnprocessableEntity, apierror.CodeInventoryExecutorUnavailable, nil)
	case errors.Is(err, asset.ErrInventoryExecutorBusy):
		apierror.Respond(c, http.StatusConflict, apierror.CodeInventoryExecutorBusy, nil)
	case errors.Is(err, asset.ErrInventoryExecutorRateLimited):
		apierror.Respond(c, http.StatusTooManyRequests, apierror.CodeInventoryExecutorRateLimited, nil)
	case errors.Is(err, asset.ErrInventoryScanRunning):
		apierror.Respond(c, http.StatusConflict, apierror.CodeInventoryScanRunning, nil)
	case errors.Is(err, asset.ErrInventoryIgnoreReason):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInventoryIgnoreReason, nil)
	case errors.Is(err, asset.ErrInventoryFindingNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeInventoryFindingNotFound, nil)
	case errors.Is(err, asset.ErrInventoryAssetNotFound):
		middleware.RespondTargetNotFound(c, authz.ScopeTargetAsset, authz.ScopeLayerAsset)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internal, err)
	}
}

// Initiate POST /assets/:id/account-inventory/scans — 發起一次盤點，202 回掃描列。
func (h *HostInventoryHandler) Initiate(c *gin.Context) {
	id, ok := inventoryAssetID(c)
	if !ok {
		return
	}
	scan, err := h.svc.Initiate(id, inventoryActor(c))
	if err != nil {
		respondInventoryError(c, err, apierror.CodeInternalInventoryUpdate)
		return
	}
	c.JSON(http.StatusAccepted, scan)
}

func queryBool(c *gin.Context, key string) (*bool, bool) {
	raw, present := c.GetQuery(key)
	if !present || raw == "" {
		return nil, true
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return nil, false
	}
	return &v, true
}

func queryPage(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.Query("page"))
	size, _ := strconv.Atoi(c.Query("page_size"))
	return page, size
}

// Get GET /assets/:id/account-inventory — 最近一次盤點與結果。
func (h *HostInventoryHandler) Get(c *gin.Context) {
	id, ok := inventoryAssetID(c)
	if !ok {
		return
	}
	var q asset.InventoryFindingQuery
	for key, dst := range map[string]**bool{"privileged": &q.Privileged, "managed": &q.Managed, "present": &q.Present} {
		v, ok := queryBool(c, key)
		if !ok {
			return
		}
		*dst = v
	}
	actionable, ok := queryBool(c, "actionable")
	if !ok {
		return
	}
	q.Actionable = actionable != nil && *actionable
	q.Status = c.Query("status")
	if q.Status != "" && q.Status != model.HostAccountFindingOpen && q.Status != model.HostAccountFindingIgnored {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	q.Page, q.PageSize = queryPage(c)
	view, err := h.svc.GetAssetInventory(id, q)
	if err != nil {
		respondInventoryError(c, err, apierror.CodeInternalInventoryQuery)
		return
	}
	c.JSON(http.StatusOK, view)
}

// visibleAssetIDs 全域清單的資產範圍，與資產列表的可見集合同源：檢視捷徑主體回 nil（不限）；
// 範圍化檢視者為連線可視與管理可視的聯集；其他主體只有連線可視。結果恆非 nil 時空切片即無資產。
func (h *HostInventoryHandler) visibleAssetIDs(c *gin.Context) ([]uint, error) {
	p := middleware.PrincipalFrom(c)
	if p.ViewShortcut() {
		return nil, nil
	}
	userID, ok := middleware.GetCurrentUserID(c)
	if !ok || h.auth == nil {
		return []uint{}, nil
	}
	// 範圍讀取器與授權服務自脈絡取主體重解，須把登錄閘解出的主體帶進請求脈絡
	ctx := authz.ContextWithPrincipal(c.Request.Context(), p)
	if h.scope != nil {
		v, err := h.scope.View(ctx)
		if err != nil {
			return nil, err
		}
		if v != nil {
			_, _, union, err := scopedVisibleUnion(ctx, h.auth, h.scope, v, p, userID)
			if err != nil {
				return nil, err
			}
			return union, nil
		}
	}
	conn, err := authorizedAssetsOf(ctx, h.auth, p, userID)
	if err != nil {
		return nil, err
	}
	ids := make([]uint, 0, len(conn))
	seen := make(map[uint]bool, len(conn))
	for _, d := range conn {
		if !seen[d.ID] {
			seen[d.ID] = true
			ids = append(ids, d.ID)
		}
	}
	return ids, nil
}

// ListGlobal GET /account-inventory/findings — 全域清單（未納管的特權帳號），投影到資產列表的可見集合。
func (h *HostInventoryHandler) ListGlobal(c *gin.Context) {
	q := asset.InventoryGlobalQuery{}
	q.Page, q.PageSize = queryPage(c)
	ids, err := h.visibleAssetIDs(c)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalInventoryQuery, err)
		return
	}
	q.AllowedAssetIDs = ids
	view, err := h.svc.ListGlobalFindings(q)
	if err != nil {
		respondInventoryError(c, err, apierror.CodeInternalInventoryQuery)
		return
	}
	c.JSON(http.StatusOK, view)
}

type inventoryIgnoreRequest struct {
	Reason string `json:"reason"`
}

func findingBody(f *model.HostAccountFinding) gin.H {
	return gin.H{"id": f.ID, "asset_id": f.AssetID, "username": f.Username, "status": f.Status}
}

// Ignore POST /assets/:id/account-inventory/findings/:findingId/ignore
func (h *HostInventoryHandler) Ignore(c *gin.Context) {
	id, ok := inventoryAssetID(c)
	if !ok {
		return
	}
	fid, ok := inventoryFindingID(c)
	if !ok {
		return
	}
	var req inventoryIgnoreRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	f, err := h.svc.IgnoreFinding(id, fid, req.Reason, inventoryActor(c))
	if err != nil {
		respondInventoryError(c, err, apierror.CodeInternalInventoryUpdate)
		return
	}
	c.JSON(http.StatusOK, findingBody(f))
}

// Reopen POST /assets/:id/account-inventory/findings/:findingId/reopen
func (h *HostInventoryHandler) Reopen(c *gin.Context) {
	id, ok := inventoryAssetID(c)
	if !ok {
		return
	}
	fid, ok := inventoryFindingID(c)
	if !ok {
		return
	}
	f, err := h.svc.ReopenFinding(id, fid, inventoryActor(c))
	if err != nil {
		respondInventoryError(c, err, apierror.CodeInternalInventoryUpdate)
		return
	}
	c.JSON(http.StatusOK, findingBody(f))
}

// RegisterRoutes 註冊五條路由（認證之後交 MountRoutes）。
func (h *HostInventoryHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("")
	g.Use(middleware.AuthMiddleware(authService))
	h.MountRoutes(g)
}

// MountRoutes 在已認證的路由群組上掛五條路由；每條都掛路由登錄閘。單資產讀取另掛與資產詳情
// 相同的逐資產可視守門（連線可視或管理可視，皆否與不存在同形），寫入的範圍由登錄閘以盤點權限點判定。
func (h *HostInventoryHandler) MountRoutes(g gin.IRoutes) {
	gate := middleware.EnforceRegistry(h.scopeGate)
	var mgmt middleware.AssetManagementVisibility
	if h.scope != nil {
		mgmt = h.scope
	}
	visible := middleware.RequireAssetVisibleOrManaged(h.auth, mgmt)
	g.POST("/assets/:id/account-inventory/scans", gate, h.Initiate)
	g.GET("/assets/:id/account-inventory", gate, visible, h.Get)
	g.POST("/assets/:id/account-inventory/findings/:findingId/ignore", gate, h.Ignore)
	g.POST("/assets/:id/account-inventory/findings/:findingId/reopen", gate, h.Reopen)
	g.GET("/account-inventory/findings", gate, h.ListGlobal)
}
