package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 單台存取政策覆寫清單（唯讀）：GET /api/v1/assets/access-policy-overrides。
// 登錄閘只判存取政策權限點的能力；範圍投影由資產服務以該權限點的集合在分頁前套用。
// 範圍化檢視者的每列另帶範圍外歸屬計數（最小揭露例外），其餘主體的列不帶這個鍵。

// accessPolicyOverrideLister 覆寫清單的服務面（*asset.AssetService 實作）。不併入 AssetServiceInterface：
// 只有本端點使用，替身不必為它補方法；未實作即視為投影未接上（fail-close）。
type accessPolicyOverrideLister interface {
	ListAccessPolicyOverrides(ctx context.Context, q asset.AccessPolicyOverrideQuery) (*asset.AccessPolicyOverridePage, error)
}

type accessPolicyOverrideRowDTO struct {
	ID           uint     `json:"id"`
	Name         string   `json:"name"`
	Protocol     string   `json:"protocol"`
	AccessPolicy *string  `json:"access_policy"`
	NodeIDs      []uint   `json:"node_ids"`
	NodePaths    []string `json:"node_paths"`
	*disclosure.NodeCountField
}

type accessPolicyOverrideMetaDTO struct {
	GlobalDefault string `json:"global_default"`
	Scoped        bool   `json:"scoped"`
}

type accessPolicyOverrideListDTO struct {
	Data     []accessPolicyOverrideRowDTO `json:"data"`
	Total    int64                        `json:"total"`
	Page     int                          `json:"page"`
	PageSize int                          `json:"page_size"`
	Meta     accessPolicyOverrideMetaDTO  `json:"meta"`
}

// ListAccessPolicyOverrides 覆寫清單：overridden（預設 true）、search、page、page_size。
func (h *AssetHandler) ListAccessPolicyOverrides(c *gin.Context) {
	q := asset.AccessPolicyOverrideQuery{Overridden: true, Search: c.Query("search")}
	if raw, ok := c.GetQuery("overridden"); ok {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
		q.Overridden = v
	}
	for name, dst := range map[string]*int{"page": &q.Page, "page_size": &q.PageSize} {
		raw, ok := c.GetQuery(name)
		if !ok {
			continue
		}
		v, err := strconv.Atoi(raw)
		if err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
		*dst = v
	}
	ctx := authz.ContextWithPrincipal(c.Request.Context(), middleware.PrincipalFrom(c))
	lister, ok := h.assetService.(accessPolicyOverrideLister)
	if !ok {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, asset.ErrAccessPolicyOverrideScopeMissing)
		return
	}
	page, err := lister.ListAccessPolicyOverrides(ctx, q)
	if err != nil {
		respondAssetError(c, apierror.CodeInternalAssetQuery, err)
		return
	}
	out := accessPolicyOverrideListDTO{Data: make([]accessPolicyOverrideRowDTO, 0, len(page.Rows)),
		Total: page.Total, Page: page.Page, PageSize: page.PageSize,
		Meta: accessPolicyOverrideMetaDTO{GlobalDefault: page.GlobalDefault, Scoped: page.Scoped}}
	for _, r := range page.Rows {
		out.Data = append(out.Data, overrideRowDTO(r, page.Scoped))
	}
	c.JSON(http.StatusOK, out)
}

// overrideRowDTO 覆寫清單的一列；scoped 時附範圍外歸屬計數。
func overrideRowDTO(r asset.AccessPolicyOverrideRow, scoped bool) accessPolicyOverrideRowDTO {
	row := accessPolicyOverrideRowDTO{ID: r.ID, Name: r.Name, Protocol: string(r.Protocol),
		AccessPolicy: r.AccessPolicy, NodeIDs: r.NodeIDs, NodePaths: r.NodePaths}
	if scoped {
		row.NodeCountField = &disclosure.NodeCountField{
			OutOfScopeNodeCount: disclosure.NodeCountValue{Value: disclosure.Count(disclosure.OutOfScopeNodeCount, r.OutOfScopeNodes)}}
	}
	return row
}

// accessPolicyOverrideRowSource 單台的覆寫清單列（*asset.AssetService 實作）；只含存取政策的更新回應使用。
type accessPolicyOverrideRowSource interface {
	AccessPolicyOverrideRowOf(ctx context.Context, id uint) (*asset.AccessPolicyOverrideRow, bool, error)
}

// writeAccessPolicyUpdateResponse 只含存取政策的更新成功後：經節點範圍持有存取政策權限點、且該權限點的範圍
// 有限縮的主體，回與覆寫清單同形的一列（歸屬依該權限點遮蔽，附範圍外計數），不回資產模型。
// 回 false 表示主體不受該權限點限縮，呼叫方照原形狀回應。服務未實作單台列時寧可回內部錯誤，不回未遮蔽的模型。
func (h *AssetHandler) writeAccessPolicyUpdateResponse(c *gin.Context, id uint) bool {
	p := middleware.PrincipalFrom(c)
	if !authz.HoldsViaNodeScope(p, authz.PermAccessPolicyManage) {
		return false
	}
	src, ok := h.assetService.(accessPolicyOverrideRowSource)
	if !ok {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, asset.ErrAccessPolicyOverrideScopeMissing)
		return true
	}
	row, scoped, err := src.AccessPolicyOverrideRowOf(authz.ContextWithPrincipal(c.Request.Context(), p), id)
	if err != nil {
		respondAssetError(c, apierror.CodeInternalAssetQuery, err)
		return true
	}
	if !scoped {
		return false
	}
	c.JSON(http.StatusOK, overrideRowDTO(*row, true))
	return true
}
