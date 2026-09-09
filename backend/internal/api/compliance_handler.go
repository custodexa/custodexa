package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 合規對照的唯讀端點。
//
// **這一組沒有任何寫入**：對照的內容改在政策組管理端，設定值改在安全政策端。
// 對照頁要回答的是「現在這一刻，設定對每一個生效政策組符不符」，把寫入放進來
// 會讓同一份對照有兩個入口，而「這條要求是誰改的」就分裂成兩套記錄。
//
// 回應一次帶齊判定、逐組摘要、政策組本體與條文卡片：那四樣是同一個畫面的四個
// 區塊，分成四支端點會讓它們在不同時點各讀一次——而判定是有時點的，
// 兩個時點之間管理者改了一個值，畫面上的摘要與逐條結果就對不起來。

// ComplianceHandler 合規判定結果的讀取端（admin 與 auditor）。
type ComplianceHandler struct {
	compliance *policy.ComplianceService
	groups     *policy.PolicyGroupRepository
}

// NewComplianceHandler 建立合規對照 handler。
func NewComplianceHandler(compliance *policy.ComplianceService,
	groups *policy.PolicyGroupRepository) *ComplianceHandler {
	return &ComplianceHandler{compliance: compliance, groups: groups}
}

// Snapshot 一份判定結果。
//
// query 參數 `group` 指定單一政策組；省略＝全部生效組。指定不存在的組回 404
// 而不是一份「每個鍵都未對照」的結果——後者與組代號打錯字在畫面上分不出來。
func (h *ComplianceHandler) Snapshot(c *gin.Context) {
	groupFilter := c.Query("group")
	snapshot, err := h.compliance.Snapshot(groupFilter, nil)
	if err != nil {
		respondPolicyGroupError(c, err, apierror.CodeInternalComplianceSnapshot)
		return
	}
	payload, err := h.decorate(snapshot, groupFilter)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError,
			apierror.CodeInternalPolicyGroupRead, err)
		return
	}
	c.JSON(http.StatusOK, payload)
}

// decorate 把判定結果補上畫面需要的政策組本體、逐組摘要與條文卡片。
func (h *ComplianceHandler) decorate(snapshot policy.ComplianceSnapshot,
	groupFilter string) (gin.H, error) {

	groups, err := h.groups.ListGroups()
	if err != nil {
		return nil, err
	}
	clauses, err := h.groups.ListClauses(groupFilter)
	if err != nil {
		return nil, err
	}
	controls, err := h.groups.ListControls(groupFilter)
	if err != nil {
		return nil, err
	}
	annotations, err := h.groups.ListAnnotations(groupFilter)
	if err != nil {
		return nil, err
	}

	inScope := make([]model.PolicyGroup, 0, len(groups))
	summaries := make([]policy.GroupSummary, 0, len(groups))
	for _, g := range groups {
		if groupFilter != "" && g.Code != groupFilter {
			continue
		}
		inScope = append(inScope, g)
		if g.Enabled {
			summaries = append(summaries, snapshot.GroupSummary(g.Code))
		}
	}
	return gin.H{
		"data":      snapshot,
		"groups":    inScope,
		"summaries": summaries,
		"clauses":   buildClauseViews(clauses, controls, annotations),
	}, nil
}

// RegisterRoutes 註冊合規對照路由（admin 與 auditor，唯讀）。
func (h *ComplianceHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	compliance := r.Group("/compliance")
	compliance.Use(middleware.AuthMiddleware(authService))
	compliance.Use(middleware.RequireAnyRole(model.RoleAdmin, model.RoleAuditor))
	{
		compliance.GET("/snapshot", h.Snapshot)
	}
}
