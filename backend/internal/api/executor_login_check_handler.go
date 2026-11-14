package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/sourceip"
)

// ExecutorLoginCheckServiceInterface 測試登入服務（用於測試注入）。
type ExecutorLoginCheckServiceInterface interface {
	Run(ctx context.Context, assetID uint, actor asset.InventoryActor) (*asset.ExecutorLoginCheckResult, error)
	State(assetID uint) (*asset.ExecutorLoginCheckState, error)
}

// ExecutorLoginCheckHandler 堡壘機專用帳號的測試登入：POST 發起一次，GET 讀最近一次結果。
//
// 範圍判定由路由登錄閘（asset:executor-manage 對該資產）完成，範圍外與不存在同形。
// 429 與其他錯誤都不附 Retry-After 與任何數值。
type ExecutorLoginCheckHandler struct {
	svc       ExecutorLoginCheckServiceInterface
	scopeGate *middleware.ScopeGate
}

// NewExecutorLoginCheckHandler 建立 handler。
func NewExecutorLoginCheckHandler(svc ExecutorLoginCheckServiceInterface, scopeGate ...*middleware.ScopeGate) *ExecutorLoginCheckHandler {
	return &ExecutorLoginCheckHandler{svc: svc, scopeGate: firstScopeGate(scopeGate)}
}

func respondExecutorCheckError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, asset.ErrExecutorCheckAssetNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetExecutorNotFound, nil)
	case errors.Is(err, asset.ErrAssetExecutorNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetExecutorNotFound, nil)
	case errors.Is(err, asset.ErrExecutorStateChanged):
		apierror.Respond(c, http.StatusConflict, apierror.CodeExecutorStateChanged, nil)
	case errors.Is(err, asset.ErrExecutorCheckBusy):
		apierror.Respond(c, http.StatusConflict, apierror.CodeExecutorCheckBusy, nil)
	case errors.Is(err, asset.ErrExecutorCheckPlatformUnsupported):
		apierror.Respond(c, http.StatusUnprocessableEntity, apierror.CodeExecutorCheckPlatformUnsupported, nil)
	case errors.Is(err, asset.ErrExecutorCheckRateLimited):
		apierror.Respond(c, http.StatusTooManyRequests, apierror.CodeExecutorCheckRateLimited, nil)
	default:
		apierror.Respond(c, http.StatusInternalServerError, apierror.CodeInternalExecutorCheck, nil)
	}
}

func executorCheckAssetID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return 0, false
	}
	return uint(id), true
}

// Run POST /assets/:id/executor/login-check — 發起一次測試登入，同步等結果。
func (h *ExecutorLoginCheckHandler) Run(c *gin.Context) {
	assetID, ok := executorCheckAssetID(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	res, err := h.svc.Run(c.Request.Context(), assetID, asset.InventoryActor{UserID: userID, Username: username, ClientIP: sourceip.Of(c), APIToken: middleware.APITokenRefOf(c)})
	if err != nil {
		respondExecutorCheckError(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// Get GET /assets/:id/executor/login-check — 最近一次結果（掛載或憑證已變更時為過期）。
func (h *ExecutorLoginCheckHandler) Get(c *gin.Context) {
	assetID, ok := executorCheckAssetID(c)
	if !ok {
		return
	}
	st, err := h.svc.State(assetID)
	if err != nil {
		respondExecutorCheckError(c, err)
		return
	}
	c.JSON(http.StatusOK, st)
}

// RegisterRoutes 註冊兩條路由；都掛路由登錄閘（能力加範圍判定）。
func (h *ExecutorLoginCheckHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/assets/:id/executor/login-check")
	g.Use(middleware.AuthMiddleware(authService))
	gate := middleware.EnforceRegistry(h.scopeGate)
	g.POST("", gate, h.Run)
	g.GET("", gate, h.Get)
}
