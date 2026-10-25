package api

import (
	"errors"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
)

// respondTxScopeError 服務在寫入交易內重判出的拒絕交共用出口；回 true 表示已寫出。
// 範圍拒絕的種類與層取自服務回傳的拒絕值（由判定器給出），這裡不自組回應。
func respondTxScopeError(c *gin.Context, err error) bool {
	var denied *authz.ErrScopeDenied
	if errors.As(err, &denied) {
		middleware.RespondScopeDenied(c, denied)
		return true
	}
	var capDenied *middleware.TxCapabilityDenied
	if errors.As(err, &capDenied) {
		return middleware.RespondAuthzDecision(c, capDenied.Result, nil, capDenied.Basis)
	}
	return false
}
