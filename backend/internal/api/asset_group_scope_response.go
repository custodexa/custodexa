package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 節點寫入的範圍拒絕、限超級管理者與引用阻擋的寫出。授權層（404、403）先於業務規則，
// 由服務的判定順序保證；本檔只把服務交回的錯誤值交給對應的共用出口。

// nodeReferenceDTO 超級管理者檢視的引用清單一列（群組另附成員數，只作提示）。
type nodeReferenceDTO struct {
	SubjectKind string `json:"subject_kind"`
	SubjectID   uint   `json:"subject_id"`
	SubjectName string `json:"subject_name"`
	RoleID      uint   `json:"role_id"`
	RoleName    string `json:"role_name"`
	MemberCount *int   `json:"member_count,omitempty"`
}

// respondNodeScopeError 寫出節點範圍類錯誤；回傳 true 表示已寫出。
func respondNodeScopeError(c *gin.Context, err error) bool {
	var denied *authz.ErrScopeDenied
	if errors.As(err, &denied) {
		middleware.RespondScopeDenied(c, denied)
		return true
	}
	var referenced *asset.NodeScopeReferencedError
	if errors.As(err, &referenced) {
		respondNodeScopeReferenced(c, referenced)
		return true
	}
	switch {
	case errors.Is(err, authz.ErrNodeWriteSuperAdminOnly):
		middleware.WriteCapabilityDenial(c, middleware.ReservedCapabilityDenial(authz.ReservedSuperAdmin))
		return true
	case errors.Is(err, authz.ErrNodeWriteRootLevelGlobalOnly), errors.Is(err, authz.ErrNodeWriteNoCapability):
		middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(authz.PermAssetGroupManage))
		return true
	}
	return false
}

// respondNodeScopeReferenced 409：所有人只看到節點路徑與引用筆數；超級管理者另附引用清單。
func respondNodeScopeReferenced(c *gin.Context, e *asset.NodeScopeReferencedError) {
	resp := apierror.ErrorResponse{
		Code: apierror.CodeNodeScopeReferenced,
		Params: map[string]any{
			"path":  e.Path,
			"count": disclosure.Count(disclosure.NodeDeleteScopeReferenced, e.References.Count),
		},
	}
	if p := middleware.PrincipalFrom(c); p != nil && p.IsSuperAdmin() {
		refs := make([]nodeReferenceDTO, 0, len(e.References.Items))
		for _, r := range e.References.Items {
			refs = append(refs, nodeReferenceDTO{
				SubjectKind: r.SubjectKind, SubjectID: r.SubjectID, SubjectName: r.SubjectName,
				RoleID: r.RoleID, RoleName: r.RoleName, MemberCount: r.MemberCount,
			})
		}
		resp.Meta = map[string]any{"references": refs}
	}
	apierror.Write(c, http.StatusConflict, resp)
}
