package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// AssetExecutorServiceInterface 堡壘機專用帳號服務（用於測試注入）。
type AssetExecutorServiceInterface interface {
	Get(ctx context.Context, assetID uint) (*asset.AssetExecutorDTO, error)
	Set(ctx context.Context, assetID uint, req *asset.SetExecutorRequest) (*asset.AssetExecutorDTO, error)
	Clear(ctx context.Context, assetID uint, expectedAccountID *uint) error
	ExportPublicKey(ctx context.Context, assetID uint) (string, error)
}

// AssetExecutorHandler 堡壘機專用帳號 API：讀取、設定／更換、清除、公鑰匯出。
//
// 範圍判定在服務層（asset:executor-manage 對該資產），範圍外與不存在同形；回應不含任何秘密與公鑰本體，
// 公鑰只經匯出端點以 text/plain 附件取得。
type AssetExecutorHandler struct {
	svc       AssetExecutorServiceInterface
	scopeGate *middleware.ScopeGate
	mgmt      middleware.AssetManagementVisibility
	// accountRows 帳號列投影器（執行身分回應的 credential 欄）；未注入時範圍化主體不得取得該欄
	accountRows *accountRowProjector
}

// NewAssetExecutorHandler 建立 handler。
func NewAssetExecutorHandler(svc AssetExecutorServiceInterface, scopeGate ...*middleware.ScopeGate) *AssetExecutorHandler {
	return &AssetExecutorHandler{svc: svc, scopeGate: firstScopeGate(scopeGate)}
}

// SetAssetManagementVisibility 注入資產管理可視判定（組裝時，須早於 RegisterRoutes）。
func (h *AssetExecutorHandler) SetAssetManagementVisibility(m middleware.AssetManagementVisibility) {
	h.mgmt = m
}

// respondExecutorError 專用帳號端點的統一錯誤出口。
func respondExecutorError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	if respondTxScopeError(c, err) || respondAssetWriteScopeError(c, err) {
		return
	}
	var hostCount *asset.ExecutorSharedHostCountError
	if errors.As(err, &hostCount) {
		apierror.Respond(c, http.StatusConflict, apierror.CodeExecutorSharedHostCount, map[string]any{"count": hostCount.Count})
		return
	}
	switch {
	case errors.Is(err, asset.ErrAssetNotFound):
		middleware.RespondTargetNotFound(c, authz.ScopeTargetAsset, authz.ScopeLayerAsset)
	case errors.Is(err, asset.ErrExecutorSourceInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeExecutorSourceInvalid, nil)
	case errors.Is(err, asset.ErrExecutorProtocolUnsupported):
		apierror.Respond(c, http.StatusUnprocessableEntity, apierror.CodeExecutorProtocolUnsupported, nil)
	case errors.Is(err, asset.ErrExecutorSecretTypeUnsupported):
		apierror.Respond(c, http.StatusUnprocessableEntity, apierror.CodeExecutorSecretTypeUnsupported, nil)
	case errors.Is(err, asset.ErrExecutorStateChanged):
		apierror.Respond(c, http.StatusConflict, apierror.CodeExecutorStateChanged, nil)
	case errors.Is(err, asset.ErrExecutorConvertCandidatePending):
		apierror.Respond(c, http.StatusConflict, apierror.CodeExecutorConvertCandidatePending, nil)
	case errors.Is(err, asset.ErrAssetExecutorNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetExecutorNotFound, nil)
	case errors.Is(err, asset.ErrAssetExecutorPublicKeyNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetExecutorPublicKeyNotFound, nil)
	case errors.Is(err, asset.ErrCredentialOutOfSync):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialOutOfSync, nil)
	default:
		respondAccountError(c, internalCode, err)
	}
}

func executorAssetID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return 0, false
	}
	return uint(id), true
}

// Get 讀取專用帳號（未設定時 configured=false）。
func (h *AssetExecutorHandler) Get(c *gin.Context) {
	assetID, ok := executorAssetID(c)
	if !ok {
		return
	}
	dto, err := h.svc.Get(accountContext(c), assetID)
	if err != nil {
		respondExecutorError(c, apierror.CodeInternalAssetExecutorRead, err)
		return
	}
	out, err := h.projectExecutor(c, dto)
	if err != nil {
		respondExecutorError(c, apierror.CodeInternalAssetExecutorRead, err)
		return
	}
	respondScoped(c, http.StatusOK, out)
}

// Set 設定或更換（四種來源；expected_account_id 必帶）。
func (h *AssetExecutorHandler) Set(c *gin.Context) {
	assetID, ok := executorAssetID(c)
	if !ok {
		return
	}
	var req asset.SetExecutorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeExecutorSourceInvalid, nil)
		return
	}
	dto, err := h.svc.Set(accountContext(c), assetID, &req)
	if err != nil {
		respondExecutorError(c, apierror.CodeInternalAssetExecutorWrite, err)
		return
	}
	out, err := h.projectExecutor(c, dto)
	if err != nil {
		respondExecutorError(c, apierror.CodeInternalAssetExecutorWrite, err)
		return
	}
	respondScoped(c, http.StatusOK, out)
}

// Clear 清除專用帳號；expected_account_id（選填查詢參數）為畫面載入時的專用帳號識別，與 PUT 同語義：
// 缺漏＝不比對；0＝認定目前沒有（已有專用帳號時回 409）；其餘與當下不符回 409。
func (h *AssetExecutorHandler) Clear(c *gin.Context) {
	assetID, ok := executorAssetID(c)
	if !ok {
		return
	}
	var expected *uint
	if raw, present := c.GetQuery("expected_account_id"); present {
		v, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeExecutorSourceInvalid, nil)
			return
		}
		id := uint(v)
		expected = &id
	}
	if err := h.svc.Clear(accountContext(c), assetID, expected); err != nil {
		respondExecutorError(c, apierror.CodeInternalAssetExecutorWrite, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ExportPublicKey 以 text/plain 附件回 authorized_keys 單行；每次取得都留審計。
func (h *AssetExecutorHandler) ExportPublicKey(c *gin.Context) {
	assetID, ok := executorAssetID(c)
	if !ok {
		return
	}
	line, err := h.svc.ExportPublicKey(accountContext(c), assetID)
	if err != nil {
		respondExecutorError(c, apierror.CodeInternalAssetExecutorRead, err)
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fmt.Sprintf("asset-%d-executor.pub", assetID)))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(line+"\n"))
}

// RegisterRoutes 註冊專用帳號路由：登錄閘 → 逐資產可視守門 → 服務層範圍判定。
func (h *AssetExecutorHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService, authzSvc AssetAuthorizationServiceInterface) {
	g := r.Group("/assets/:id/executor")
	g.Use(middleware.AuthMiddleware(authService))
	visible := middleware.RequireAssetVisible(authzSvc)
	if h.mgmt != nil {
		visible = middleware.RequireAssetVisibleOrManaged(authzSvc, h.mgmt)
	}
	g.GET("", middleware.EnforceRegistry(h.scopeGate), visible, h.Get)
	g.PUT("", middleware.EnforceRegistry(h.scopeGate), visible, h.Set)
	g.DELETE("", middleware.EnforceRegistry(h.scopeGate), visible, h.Clear)
	g.GET("/public-key", middleware.EnforceRegistry(h.scopeGate), visible, h.ExportPublicKey)
}
