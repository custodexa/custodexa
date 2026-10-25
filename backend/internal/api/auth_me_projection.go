package api

import (
	"errors"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 目前使用者回應的能力投影。
//
// GET／PATCH /auth/me 的成功回應在原 UserInfo 之上**只新增** permissions 與 scope_summary。
// 專用 DTO 內嵌 UserInfo 而不擴充 UserInfo 本體：登入、MFA、續期、改密共用同一型別，
// 擴充本體會讓那些回應跟著多欄位，超出核准的差異範圍（approved-diffs.json 的目前使用者回應項）。

// currentUserResponse 內嵌指標使 UserInfo 的欄位仍平鋪在頂層，序列化後舊欄位的
// 名稱、型別、omitempty 語義與原回應逐字相同。
type currentUserResponse struct {
	*identity.UserInfo
	Permissions  []string                  `json:"permissions"`
	ScopeSummary []authz.ScopeSummaryEntry `json:"scope_summary"`
}

// resolveProjectionPrincipal 取本請求的主體。
//
// 優先用 AuthMiddleware 已解析並放入請求脈絡的主體（經認證中介層的請求都走此路徑，不重複查詢）；
// 尚未接線時才在此以 Resolver 逐請求解析，**不快取、不讀 JWT 角色**。解析失敗回 error，
// 呼叫端一律拒絕，不以舊角色推估值兜底。
func resolveProjectionPrincipal(c *gin.Context, userID uint) (*authz.Principal, error) {
	if p := middleware.PrincipalFrom(c); p != nil {
		return p, nil
	}
	kind, ok := middleware.GetPrincipalKind(c)
	if !ok {
		kind = model.KindHuman
	}
	return authz.NewResolver(database.DB).ResolveUser(userID, authz.TokenFacts{SubjectKind: kind})
}

// scopeNodePathReader 節點名稱路徑的拓撲唯讀介面（asset 的拓撲讀取器實作）：只回未刪除的節點。
type scopeNodePathReader interface {
	NodeNamePaths(tx *gorm.DB, nodeIDs []uint) (map[uint][]string, error)
}

// errScopeNodePathsUnwired 主體有節點範圍條目但未注入路徑來源：回解析失敗，不以全域條目兜底。
var errScopeNodePathsUnwired = errors.New("api: current user scope summary without node path reader")

// SetScopeNodePathReader 注入目前使用者範圍摘要的節點路徑來源（組裝端呼叫）。
func (h *AuthHandler) SetScopeNodePathReader(r scopeNodePathReader) { h.scopeNodePaths = r }

// currentUserNodePaths 本主體摘要節點條目所需的名稱路徑。只持全域指派者不查詢、不需注入；
// 需要而未注入或查詢失敗回 error，呼叫端沿用解析失敗的回應。
func (h *AuthHandler) currentUserNodePaths(p *authz.Principal) (map[uint][]string, error) {
	ids := authz.ScopeSummaryNodeIDs(p)
	if len(ids) == 0 {
		return nil, nil
	}
	if h.scopeNodePaths == nil {
		return nil, errScopeNodePathsUnwired
	}
	return h.scopeNodePaths.NodeNamePaths(database.DB, ids)
}

// buildCurrentUserResponse 以同一次組裝的 UserInfo 資格值、principal 與節點路徑產生回應。
func buildCurrentUserResponse(info *identity.UserInfo, p *authz.Principal, paths map[uint][]string) *currentUserResponse {
	proj := authz.ProjectCapabilitiesWithNodePaths(p, authz.ProjectionInputs{
		IsApprover:         info.IsApprover,
		OwnsAgents:         info.OwnsAgents,
		CanSelfCreateAgent: info.CanSelfCreateAgent,
	}, paths)
	return &currentUserResponse{UserInfo: info, Permissions: proj.Permissions, ScopeSummary: proj.ScopeSummary}
}
