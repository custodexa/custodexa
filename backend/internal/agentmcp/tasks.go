package agentmcp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gorm.io/gorm"
)

func (h *Handler) visible(ctx context.Context, o sessionOwner, id uint) *mcp.CallToolResult {
	ok, err := h.requests.RequestItemVisible(o.User, nil, id)
	if err != nil {
		return codeResult("INTERNAL_ACCESS_REQUEST")
	}
	if !ok {
		if err := h.ssh.AuthorizationService.RecordDeniedAgentProbe(ctx, o.User, o.Token, id, "mcp"); err != nil {
			return codeResult("INTERNAL_ACCESS_REQUEST")
		}
		return codeResult("NOTFOUND_ASSET")
	}
	return nil
}
func (h *Handler) activeTask(user, asset uint, accounts []string) (uint, error) {
	var tasks []model.AccessRequest
	if err := h.ssh.DB.Where("closed_at IS NULL AND (executor_user_id=? OR (executor_user_id IS NULL AND requester_id=?))", user, user).Order("id DESC").Find(&tasks).Error; err != nil {
		return 0, err
	}
	for _, t := range tasks {
		valid := len(accounts) > 0
		for _, a := range accounts {
			if _, err := h.ssh.AuthorizationService.MatchRequestItem(t.ID, user, asset, a, h.now()); err != nil {
				valid = false
				break
			}
		}
		if valid {
			return t.ID, nil
		}
	}
	return 0, nil
}
func (h *Handler) listAssets(ctx context.Context, c *gin.Context, o sessionOwner) *mcp.CallToolResult {
	rows, err := h.ssh.AuthorizationService.GetAuthorizedAssets(ctx, o.User, model.PermissionView)
	if err != nil {
		return codeResult("INTERNAL_ACCESS_REQUEST")
	}
	result := []map[string]any{}
	ids := []uint{}
	for _, a := range rows {
		scope, err := h.ssh.AuthorizationService.EffectiveViewAccountScope(ctx, o.User, a.ID)
		if err != nil {
			return codeResult("INTERNAL_ACCESS_REQUEST")
		}
		var accounts []model.AssetAccount
		if h.ssh.DB.Where("asset_id=?", a.ID).Find(&accounts).Error != nil {
			return codeResult("INTERNAL_ACCESS_REQUEST")
		}
		list := []map[string]any{}
		connectable := false
		for _, account := range accounts {
			if !scope.Allows(account.Username) {
				continue
			}
			task, err := h.activeTask(o.User, a.ID, []string{account.Username})
			if err != nil {
				return codeResult("INTERNAL_ACCESS_REQUEST")
			}
			can := a.Active && task != 0
			if can {
				auth := middleware.GetAuthContext(c)
				_, out := h.ssh.IssueConnectGrant(c, gatewayapi.ConnectSubject{UserID: o.User, AuthMethod: auth.EffectiveMethod(), ProviderID: auth.ProviderID, AuthEpoch: auth.AuthEpoch, CredEpoch: auth.CredEpoch, ClientIP: sourceip.Of(c)}, &sshproxy.ConnectTokenRequest{AssetID: a.ID, AccountID: account.ID, AccessRequestID: task})
				can = out == nil
			}
			connectable = connectable || can
			list = append(list, map[string]any{"account_id": account.ID, "username": account.Username, "connectable": can, "request_id": task})
		}
		result = append(result, map[string]any{"asset_id": a.ID, "name": a.Name, "protocol": a.Protocol, "accounts": list, "connectable": connectable})
		ids = append(ids, a.ID)
	}
	if err := h.ssh.AuthorizationService.RecordAgentVisibilityExposures(ctx, o.User, ids); err != nil {
		return codeResult("INTERNAL_ACCESS_REQUEST")
	}
	return jsonResult(map[string]any{"assets": result})
}
func (h *Handler) requestAccess(ctx context.Context, o sessionOwner, raw json.RawMessage) *mcp.CallToolResult {
	var in struct {
		Items []struct {
			AssetID  uint      `json:"asset_id"`
			Accounts *[]string `json:"accounts"`
		} `json:"items"`
		Reason   string `json:"reason"`
		Duration int    `json:"duration_minutes"`
	}
	if json.Unmarshal(raw, &in) != nil {
		return codeResult("VALIDATION_BAD_REQUEST")
	}
	items := []authz.ItemInput{}
	same := uint(0)
	all := len(in.Items) > 0
	for _, i := range in.Items {
		if denied := h.visible(ctx, o, i.AssetID); denied != nil {
			return denied
		}
		items = append(items, authz.ItemInput{AssetID: i.AssetID, Accounts: i.Accounts})
		if i.Accounts == nil || len(*i.Accounts) == 0 {
			all = false
			continue
		}
		id, err := h.activeTask(o.User, i.AssetID, *i.Accounts)
		if err != nil {
			return codeResult("INTERNAL_ACCESS_REQUEST")
		}
		if id == 0 || same != 0 && same != id {
			all = false
		}
		same = id
	}
	if all {
		return jsonResult(map[string]any{"status": "already_connectable", "request_id": same})
	}
	var user model.User
	if h.ssh.DB.First(&user, o.User).Error != nil {
		return codeResult("AUTH_AGENT_TOKEN_INVALID")
	}
	task, err := h.requests.Submit(o.User, user.Username, model.RoleUser, authz.SubmitAccessRequestInput{Items: items, Reason: in.Reason, DurationMinutes: in.Duration})
	if err != nil {
		return requestError(err)
	}
	return jsonResult(map[string]any{"request_id": task.ID, "status": task.Status})
}
func requestError(err error) *mcp.CallToolResult {
	var duration *authz.DurationExceedsPolicyError
	if errors.As(err, &duration) {
		r := jsonResult(map[string]any{"code": string(apierror.CodeAccessRequestDurationExceeds), "params": map[string]any{"minutes": duration.MaxMinutes}})
		r.IsError = true
		return r
	}
	switch {
	case errors.Is(err, authz.ErrRequestItemsShape), errors.Is(err, gorm.ErrInvalidValue):
		return codeResult(string(apierror.CodeBadParams))
	case errors.Is(err, authz.ErrAccessRequestNotFound):
		return codeResult(string(apierror.CodeAccessRequestNotFound))
	case errors.Is(err, authz.ErrStartInPast):
		return codeResult(string(apierror.CodeAccessRequestStartInPast))
	case errors.Is(err, authz.ErrAccountScopeInvalid):
		return codeResult(string(apierror.CodeAccountScopeInvalid))
	case errors.Is(err, authz.ErrRequesterExempt):
		return codeResult(string(apierror.CodeRequesterExempt))
	case errors.Is(err, authz.ErrPolicyOpenNoRequest):
		return codeResult(string(apierror.CodeAccessRequestPolicyOpen))
	case errors.Is(err, authz.ErrAgentAccountsRequired):
		return codeResult("VALIDATION_AGENT_ACCOUNTS_REQUIRED")
	case errors.Is(err, authz.ErrAgentRequestRate):
		return codeResult("RULE_AGENT_REQUEST_RATE")
	case errors.Is(err, authz.ErrAccountNotOnAsset):
		return codeResult("VALIDATION_ACCOUNT_NOT_ON_ASSET")
	case errors.Is(err, authz.ErrDuplicatePendingRequest):
		return codeResult("CONFLICT_ACCESS_REQUEST_DUPLICATE_PENDING")
	default:
		return codeResult(string(apierror.CodeInternalAccessRequestCreate))
	}
}
func (h *Handler) checkRequest(ctx context.Context, o sessionOwner, raw json.RawMessage) *mcp.CallToolResult {
	var in arguments
	if json.Unmarshal(raw, &in) != nil {
		return codeResult("VALIDATION_BAD_REQUEST")
	}
	r, err := h.requests.AgentTask(o.User, in.RequestID)
	if err != nil {
		return codeResult("NOTFOUND_ACCESS_REQUEST")
	}
	versions, err := h.reports.Versions(ctx, r.ID, o.User, model.RoleUser)
	if err != nil {
		return codeResult("INTERNAL_ACCESS_REQUEST_MINE_QUERY")
	}
	return jsonResult(map[string]any{"request_id": r.ID, "created_at": r.CreatedAt, "status": r.Status, "approvals_received": r.ApprovalsReceived, "approvals_required": taskApprovalsRequired(r), "expires_at": r.PendingExpiresAt, "closed_at": r.ClosedAt, "missing_report_at_close": versions.MissingAtClose})
}
func (h *Handler) closeTask(ctx context.Context, o sessionOwner, task *model.AccessRequest, raw json.RawMessage) *mcp.CallToolResult {
	var in struct {
		Report string `json:"report"`
	}
	if json.Unmarshal(raw, &in) != nil {
		return codeResult("VALIDATION_BAD_REQUEST")
	}
	body, count, err := redactValue(in.Report, "")
	if err != nil {
		return codeResult("INTERNAL_OUTPUT_REDACTION")
	}
	report, err := h.reports.SubmitAndClose(ctx, task.ID, gatewayapi.Actor{UserID: o.User}, body.(string), authz.CloseAgentTask)
	if err != nil {
		switch {
		case errors.Is(err, audit.ErrAgentReportWindow):
			return codeResult("CONFLICT_ACCESS_REQUEST_STATE")
		case errors.Is(err, audit.ErrAgentReportForbidden):
			return codeResult("AUTH_AGENT_FORBIDDEN_ROUTE")
		default:
			return codeResult("VALIDATION_BAD_PARAMS")
		}
	}
	if _, err := h.ssh.SessionService.TerminateByAccessRequest(task.ID, model.EndReasonRevoked); err != nil {
		return codeResult("INTERNAL_SESSION_TERMINATE")
	}
	return jsonResult(map[string]any{"status": "closed", "request_id": task.ID, "version": report.Version, "report": report.Body, "masked_count": count})
}

// taskApprovalsRequired 以各項目決定當下的政策快照為準：自動核准的項目為 0，
// 需人核的項目取其快照值；沒有任何項目快照時才退回單層級的全域下限。
// 任務詳情端點同樣以快照為準，兩處對同一張單回同一個數字。
func taskApprovalsRequired(r *model.AccessRequest) int {
	found, required := false, 0
	for _, item := range r.Items {
		var snap struct {
			RequiredApprovals *int `json:"required_approvals"`
		}
		if json.Unmarshal([]byte(item.PolicySnapshot), &snap) != nil || snap.RequiredApprovals == nil {
			continue
		}
		found = true
		if *snap.RequiredApprovals > required {
			required = *snap.RequiredApprovals
		}
	}
	if !found {
		return r.ApprovalsRequired
	}
	return required
}
