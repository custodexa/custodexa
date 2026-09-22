package api

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/model"
)

// Embed the legacy response so existing fields and omission rules remain intact.
type accessRequestDTO struct {
	*model.AccessRequest
	Items []accessRequestItemDTO `json:"items"`
}
type accessRequestItemDTO struct {
	model.AccessRequestItem
	PolicySnapshot    map[string]any                `json:"policy_snapshot"`
	Approvals         []model.AccessRequestApproval `json:"approvals,omitempty"`
	ApprovalsReceived int                           `json:"approvals_received"`
	ApprovalsRequired int                           `json:"approvals_required"`
}

func accessRequestResponse(req *model.AccessRequest) *accessRequestDTO {
	if req == nil {
		return nil
	}
	out := &accessRequestDTO{AccessRequest: req, Items: make([]accessRequestItemDTO, 0, len(req.Items))}
	for _, item := range req.Items {
		i := accessRequestItemDTO{AccessRequestItem: item, PolicySnapshot: map[string]any{}, ApprovalsRequired: req.ApprovalsRequired}
		_ = json.Unmarshal([]byte(item.PolicySnapshot), &i.PolicySnapshot)
		if i.PolicySnapshot == nil {
			i.PolicySnapshot = map[string]any{}
		}
		if n, ok := i.PolicySnapshot["required_approvals"].(float64); ok {
			i.ApprovalsRequired = int(n)
		}
		for _, vote := range req.Approvals {
			if (vote.ItemID != nil && *vote.ItemID == item.ID) || (vote.ItemID == nil && len(req.Items) == 1) {
				i.Approvals = append(i.Approvals, vote)
			}
		}
		i.ApprovalsReceived = len(i.Approvals)
		out.Items = append(out.Items, i)
	}
	return out
}
func accessRequestResponses(reqs []*model.AccessRequest) []*accessRequestDTO {
	if reqs == nil {
		return nil
	}
	out := make([]*accessRequestDTO, len(reqs))
	for i, req := range reqs {
		out[i] = accessRequestResponse(req)
	}
	return out
}
