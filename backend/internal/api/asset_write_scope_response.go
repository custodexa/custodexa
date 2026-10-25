package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 資產寫入（建立、更新、停用、刪除）的範圍判定錯誤寫出與成功回應的範圍化遮蔽。
// 範圍拒絕由 respondTxScopeError 交共用出口；本檔處理能力拒絕與兩個業務規則碼。

// respondAssetWriteScopeError 寫出資產寫入的能力拒絕與歸屬規則錯誤；回傳 true 表示已寫出。
func respondAssetWriteScopeError(c *gin.Context, err error) bool {
	var capDenied *authz.AssetWriteCapabilityError
	if errors.As(err, &capDenied) {
		middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(capDenied.Perm))
		return true
	}
	var outOfScope *asset.AssetOutOfScopeNodesError
	if errors.As(err, &outOfScope) {
		apierror.Respond(c, http.StatusConflict, apierror.CodeAssetHasOutOfScopeNodes, map[string]any{
			"count": disclosure.Count(disclosure.OutOfScopeNodeCount, outOfScope.Count),
		})
		return true
	}
	if errors.Is(err, asset.ErrAssetNodeRequired) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAssetNodeRequired, nil)
		return true
	}
	return false
}

// assetWriteContext 寫入服務的 ctx：帶主體（交易內重解範圍判定用）。
func assetWriteContext(c *gin.Context, ctx context.Context) context.Context {
	return authz.ContextWithPrincipal(ctx, middleware.PrincipalFrom(c))
}

// writeScopedAssetResponse 建立與更新的成功回應：範圍化檢視者與詳情同遮蔽（範圍外歸屬不出），其餘主體回原形狀。
// 寫入不經逐資產守門，故連線可視另判；管理與連線皆不可視的資產（寫入權來自全域指派）也只回計數。
func (h *AssetHandler) writeScopedAssetResponse(c *gin.Context, status int, row *model.Asset) {
	if h.assetScope != nil {
		scoped, served, err := h.scopedDetail(c, row, false)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
			return
		}
		if served {
			c.JSON(status, scoped)
			return
		}
	}
	c.JSON(status, row)
}
