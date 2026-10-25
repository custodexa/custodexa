package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/authz"
)

// scopedListTags 非檢視捷徑主體的標籤字典。
//
// 範圍化檢視者（持節點範圍的資產或資產帳號指派）只看其可視資產（與同一主體不帶篩選的資產列表同一聯集）
// 上出現過的標籤，使用數只計這些資產；其他主體（含只經全域指派持有資產檢視能力的自訂角色與一般使用者）
// 維持現行拒絕。範圍化檢視者的身分不授予能力：沒有資產檢視生效來源者已被路由閘擋下，走不到這裡。
func (h *AssetHandler) scopedListTags(c *gin.Context) {
	v, err := h.assetScopeView(c)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTagListQuery, err)
		return
	}
	if v == nil {
		middleware.WriteCapabilityDenial(c, middleware.ReservedCapabilityDenial(authz.ReservedSuperAdminOrAuditor))
		return
	}
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	_, _, union, err := scopedVisibleUnion(c.Request.Context(), h.authorizationService, h.assetScope, v,
		middleware.PrincipalFrom(c), userID)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTagListQuery, err)
		return
	}
	tags, err := h.assetService.ListTagsForAssetIDs(union)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTagListQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tags})
}
