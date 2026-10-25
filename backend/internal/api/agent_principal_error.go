package api

import (
	"errors"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// noteAssignmentDenyReason 共用指派關卡拒絕時，把被拒規則的原因碼併進本次請求的審計 details
// （鍵 deny_reason）。只寫原因碼，不寫角色、權限或任何請求值；不是關卡拒絕時不動。
func noteAssignmentDenyReason(c *gin.Context, err error) {
	reason := identity.AssignmentDenyReason(err)
	if reason == "" {
		return
	}
	merged := map[string]string{}
	if v, ok := c.Get("audit_details"); ok {
		if prev, ok := v.(map[string]string); ok {
			for k, val := range prev {
				merged[k] = val
			}
		}
	}
	merged["deny_reason"] = reason
	c.Set("audit_details", merged)
}

// noteAgentRoleUpdateRejection 角色修改因 agent 持有者被拒時，把受影響 agent 數與受限權限點
// （逗號分隔、升冪）併進本次請求的審計 details（鍵 agent_count、restricted_permissions），
// 與 deny_reason 同一列；不放進回應。不是這種拒絕時不動。
func noteAgentRoleUpdateRejection(c *gin.Context, err error) {
	count, restricted, ok := identity.AgentRoleUpdateRejectionFacts(err)
	if !ok {
		return
	}
	merged := map[string]string{}
	if v, ok := c.Get("audit_details"); ok {
		if prev, ok := v.(map[string]string); ok {
			for k, val := range prev {
				merged[k] = val
			}
		}
	}
	merged["agent_count"] = strconv.Itoa(count)
	merged["restricted_permissions"] = strings.Join(restricted, ",")
	c.Set("audit_details", merged)
}

// respondPrincipalError 主體與指派關卡錯誤的統一出口；關卡拒絕的原因碼同時記入審計。
//
// 操作者缺指派角色能力（含無操作者主體）屬能力拒絕，以哨兵判定後經能力拒絕的單一寫出函式寫出，
// 依據為 all_of=[role:assign]。其餘同碼的規則拒絕（agent 不得持有的角色、限人類帳號的操作）
// 照原樣寫出，不留能力拒絕依據。
func respondPrincipalError(c *gin.Context, err error) bool {
	noteAssignmentDenyReason(c, err)
	if errors.Is(err, identity.ErrRoleAssignmentForbidden) {
		middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(authz.PermRoleAssign))
		return true
	}
	var principal *identity.PrincipalError
	if !errors.As(err, &principal) {
		return false
	}
	response := apierror.ErrorResponse{Code: principal.Code}
	if len(principal.AgentIDs) > 0 {
		response.Meta = map[string]any{"agent_ids": principal.AgentIDs}
	}
	apierror.Write(c, principal.Status, response)
	return true
}

func principalErrorStatus(err error, fallback int) int {
	var principal *identity.PrincipalError
	if errors.As(err, &principal) {
		return principal.Status
	}
	return fallback
}
