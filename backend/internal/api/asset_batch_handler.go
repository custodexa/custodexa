package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 資產批次操作（搬移、加標籤、刪除）的 HTTP 入口。
//
// 路由閘只判能力（沒有任何含該權限點的有效指派即單一 forbidden，不看 asset_ids）；逐列範圍、
// 目的節點與刪除歸屬規則由服務在批次交易內判定。錯誤依型別寫出，本檔不解讀範圍拒絕的內容。

// AssetBatchMoveRequest 批次搬移本文。
type AssetBatchMoveRequest struct {
	AssetIDs     []uint `json:"asset_ids"`
	TargetNodeID uint   `json:"target_node_id"`
}

// AssetBatchTagsRequest 批次加標籤本文。
type AssetBatchTagsRequest struct {
	AssetIDs []uint   `json:"asset_ids"`
	Tags     []string `json:"tags"`
}

// AssetBatchDeleteRequest 批次刪除本文。
type AssetBatchDeleteRequest struct {
	AssetIDs []uint `json:"asset_ids"`
}

// registerBatchRoutes 掛三條批次路由（assets 群組已掛認證）。路由閘只判能力，逐列範圍由服務在批次交易內判定。
// 獨立成不內聯的函式：中介層閉包在此函式內編號，不改動 RegisterRoutes 內既有路由的閉包編號。
//
//go:noinline
func (h *AssetHandler) registerBatchRoutes(assets *gin.RouterGroup) {
	assets.POST("/batch/move", middleware.EnforceRegistry(h.scopeGate), h.BatchMove)
	assets.POST("/batch/tags", middleware.EnforceRegistry(h.scopeGate), h.BatchAddTags)
	assets.POST("/batch/delete", middleware.EnforceRegistry(h.scopeGate), h.BatchDelete)
}

// BatchMove POST /api/v1/assets/batch/move
func (h *AssetHandler) BatchMove(c *gin.Context) {
	var req AssetBatchMoveRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(asset.DedupeBatchIDs(req.AssetIDs)) == 0 || req.TargetNodeID == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	res, err := h.assetService.BatchMove(assetWriteContext(c, operatorRequestContext(c)), req.AssetIDs, req.TargetNodeID)
	if err != nil {
		respondAssetBatchError(c, apierror.CodeInternalAssetUpdate, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": res})
}

// BatchAddTags POST /api/v1/assets/batch/tags
func (h *AssetHandler) BatchAddTags(c *gin.Context) {
	var req AssetBatchTagsRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(asset.DedupeBatchIDs(req.AssetIDs)) == 0 || len(req.Tags) == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	res, err := h.assetService.BatchAddTags(assetWriteContext(c, operatorRequestContext(c)), req.AssetIDs, req.Tags)
	if err != nil {
		respondAssetBatchError(c, apierror.CodeInternalAssetUpdate, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": res})
}

// BatchDelete POST /api/v1/assets/batch/delete
func (h *AssetHandler) BatchDelete(c *gin.Context) {
	var req AssetBatchDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(asset.DedupeBatchIDs(req.AssetIDs)) == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	res, err := h.assetService.BatchDelete(assetWriteContext(c, operatorRequestContext(c)), req.AssetIDs)
	if err != nil {
		respondAssetBatchError(c, apierror.CodeInternalAssetDelete, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": res})
}

// respondAssetBatchError 批次專屬的兩個錯誤先寫出，其餘（能力拒絕、目的節點、標籤驗證等）沿單筆的資產錯誤出口。
func respondAssetBatchError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	var unavailable *asset.BatchItemsUnavailableError
	if errors.As(err, &unavailable) {
		middleware.RespondBatchUnavailable(c, unavailable.Count)
		return
	}
	var blocked *asset.BatchOutOfScopeNodesError
	if errors.As(err, &blocked) {
		// 受阻台數由批次服務計數；不經揭露登錄（單位是台數，不是範圍外歸屬數）
		apierror.Respond(c, http.StatusConflict, apierror.CodeAssetBatchHasOutOfScopeNodes, map[string]any{"count": blocked.Count})
		return
	}
	if errors.Is(err, asset.ErrBatchEmpty) || errors.Is(err, asset.ErrBatchTagsEmpty) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	respondAssetError(c, internalCode, err)
}
