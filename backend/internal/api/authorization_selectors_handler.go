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
	"github.com/custodexa/backend/internal/modules/authz"
)

// AuthorizationSelectorsSource 授權畫面的有限選擇器來源（authz.AuthorizationSelectors 實作）。
type AuthorizationSelectorsSource interface {
	SubjectOptions(ctx context.Context, q authz.SubjectOptionsQuery) (*authz.SubjectOptionsPage, error)
	TargetOptions(ctx context.Context, q authz.TargetOptionsQuery) (*authz.TargetOptionsPage, error)
}

var errSelectorsMissing = errors.New("authorization handler: selectors not wired")

// respondSelectorError 選擇器的失敗出口：沒有生效指派為能力拒絕，其餘為內部錯誤。
func respondSelectorError(c *gin.Context, err error) {
	if errors.Is(err, authz.ErrSelectorCapabilityMissing) {
		middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(authz.PermAuthorizationManage))
		return
	}
	apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizationQuery, err)
}

func selectorPaging(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	return page, size
}

// SubjectOptions GET /authorizations/subject-options：主體目錄（使用者或群組），欄位固定。
func (h *AuthorizationHandler) SubjectOptions(c *gin.Context) {
	kind := c.Query("kind")
	if kind != authz.SubjectKindUser && kind != authz.SubjectKindUserGroup {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidQueryParam, map[string]any{"field": "kind"})
		return
	}
	if h.selectors == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizationQuery, errSelectorsMissing)
		return
	}
	page, size := selectorPaging(c)
	res, err := h.selectors.SubjectOptions(operatorContext(c), authz.SubjectOptionsQuery{
		Kind: kind, Search: c.Query("search"), Page: page, PageSize: size,
	})
	if err != nil {
		respondSelectorError(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// TargetOptions GET /authorizations/target-options：客體候選（資產、節點、標籤），依授權規則管理範圍投影。
func (h *AuthorizationHandler) TargetOptions(c *gin.Context) {
	kind := c.Query("kind")
	if kind != authz.TargetKindAsset && kind != authz.TargetKindNode && kind != authz.TargetKindTag {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidQueryParam, map[string]any{"field": "kind"})
		return
	}
	query := authz.TargetOptionsQuery{Kind: kind, Search: c.Query("search")}
	if raw := c.Query("node_id"); raw != "" {
		v, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidQueryParam, map[string]any{"field": "node_id"})
			return
		}
		id := uint(v)
		query.NodeID = &id
	}
	if raws := c.QueryArray("tags"); len(raws) > 0 {
		joined := ""
		for i, r := range raws {
			if i > 0 {
				joined += ","
			}
			joined += r
		}
		tags, err := asset.ParseTagsQuery(joined)
		if err != nil {
			code, ok := tagValidationCode(err)
			if !ok {
				code = apierror.CodeBadParams
			}
			apierror.Respond(c, http.StatusBadRequest, code, nil)
			return
		}
		query.Tags = tags
	}
	if h.selectors == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizationQuery, errSelectorsMissing)
		return
	}
	query.Page, query.PageSize = selectorPaging(c)
	res, err := h.selectors.TargetOptions(operatorContext(c), query)
	if err != nil {
		respondSelectorError(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}
