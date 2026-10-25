package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 共用憑證管理歸屬的錯誤寫出（建立、範圍轉換、改歸）。
//
// 批次改歸任一筆不可操作（無權、範圍外、不存在或為專用）走批次唯一出口，只回筆數。
//
// 範圍拒絕（節點範圍外、已刪除、不存在）由服務在交易內取得判定器給出的拒絕值，交共用出口，
// 回應與節點不存在同形；範圍化主體要求全域、或交易內重解後不再持有能力，回單一 forbidden。
// 不限範圍的主體指定不存在的節點，回同一個節點不存在碼（沒有範圍拒絕標記）。

// respondCredentialOwnershipError 回傳 true 表示已寫出。
func respondCredentialOwnershipError(c *gin.Context, err error) bool {
	if respondTxScopeError(c, err) {
		return true
	}
	var capDenied *authz.CredentialOwnershipCapabilityError
	if errors.As(err, &capDenied) {
		middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(capDenied.Perm))
		return true
	}
	var batch *asset.CredentialBatchUnavailableError
	if errors.As(err, &batch) {
		middleware.RespondBatchUnavailable(c, batch.Count)
		return true
	}
	switch {
	case errors.Is(err, asset.ErrCredentialReassignEmpty):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return true
	case errors.Is(err, asset.ErrCredentialOwnershipInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialOwnershipInvalid, nil)
		return true
	case errors.Is(err, asset.ErrNodeNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNodeNotFound, nil)
		return true
	}
	return false
}
