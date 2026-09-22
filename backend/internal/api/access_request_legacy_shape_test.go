package api

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// This explicit pre-items field/value contract is independent of the response DTO.
func TestAccessRequestLegacyShape(t *testing.T) {
	at := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	id, duration := uint(7), 30
	row := &model.AccessRequest{ID: 9, CreatedAt: at, UpdatedAt: at, RequesterID: 5, AssetID: 3,
		Reason: "maintenance", RequestedDurationMinutes: 60, RequestedDateStart: &at,
		Accounts: model.AccountScope{"app"}, Status: model.AccessRequestApproved, ApproverID: &id,
		DecidedAt: &at, DecisionNote: "approved", ApprovedDurationMinutes: &duration, ApprovedDateStart: &at,
		AutoApproved: false, AuthorizationID: &id, PendingExpiresAt: at, Kind: "normal", ReviewStatus: "reviewed",
		ReviewedBy: &id, ReviewedAt: &at, ReviewDisposition: "confirmed", ReviewNote: "review", RevokedAt: &at,
		RevokedBy: &id, RevokeNote: "revoke", Requester: model.User{ID: 5}, Asset: &model.Asset{ID: 3},
		Approver: &model.User{ID: 7}, Authorization: &model.AssetAuthorization{ID: 7},
		Approvals: []model.AccessRequestApproval{{ID: 1, RequestID: 9, ApproverID: 7}}, ApprovalsReceived: 1, ApprovalsRequired: 1,
		Items: []model.AccessRequestItem{{ID: 10, RequestID: 9, AssetID: 3, Accounts: model.AccountScope{"app"}, PolicySnapshot: `{"segment":"approval","required_approvals":1}`}},
	}
	expected := map[string]any{
		"id": float64(9), "created_at": "2026-09-21T00:00:00Z", "updated_at": "2026-09-21T00:00:00Z",
		"requester_id": float64(5), "asset_id": float64(3), "reason": "maintenance", "requested_duration_minutes": float64(60),
		"requested_date_start": "2026-09-21T00:00:00Z", "accounts": []any{"app"}, "status": "approved",
		"approver_id": float64(7), "decided_at": "2026-09-21T00:00:00Z", "decision_note": "approved",
		"approved_duration_minutes": float64(30), "approved_date_start": "2026-09-21T00:00:00Z", "auto_approved": false,
		"authorization_id": float64(7), "pending_expires_at": "2026-09-21T00:00:00Z", "kind": "normal", "review_status": "reviewed",
		"reviewed_by": float64(7), "reviewed_at": "2026-09-21T00:00:00Z", "review_disposition": "confirmed", "review_note": "review",
		"revoked_at": "2026-09-21T00:00:00Z", "revoked_by": float64(7), "revoke_note": "revoke",
		"approvals_received": float64(1), "approvals_required": float64(1),
	}
	for _, endpoint := range []string{"create", "mine", "pending", "history"} {
		t.Run(endpoint, func(t *testing.T) {
			svc := new(MockAccessRequestService)
			r, _ := newAccessRequestRouter(svc, nil, 5, "user", nil)
			method, path := "GET", "/access-requests/"+endpoint
			var payload any
			switch endpoint {
			case "create":
				method, path = "POST", "/access-requests"
				payload = map[string]any{"asset_id": 3, "accounts": []string{"app"}, "reason": "maintenance", "duration_minutes": 60, "date_start": at}
				svc.On("Submit", uint(5), "tester", "user", mock.MatchedBy(func(in authz.SubmitAccessRequestInput) bool {
					return in.AssetID == 3 && in.Items == nil && in.ExecutorUserID == nil && in.Accounts != nil && len(*in.Accounts) == 1 && (*in.Accounts)[0] == "app" && in.Reason == "maintenance" && in.DurationMinutes == 60 && in.DateStart.Equal(at)
				})).Return(row, nil)
			case "mine":
				svc.On("ListMine", uint(5)).Return([]*model.AccessRequest{row}, nil)
			case "pending":
				svc.On("ListPending", uint(5), false, mock.Anything).Return([]*model.AccessRequest{row}, nil)
			case "history":
				svc.On("ListHistory", uint(5), false, 1, 20).Return([]*model.AccessRequest{row}, int64(1), nil)
			}
			w := doJSON(r, method, path, payload)
			if endpoint == "create" {
				require.Equal(t, 201, w.Code)
			} else {
				require.Equal(t, 200, w.Code)
			}
			var got map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			if endpoint != "create" {
				require.Equal(t, float64(1), got["total"])
				if endpoint == "history" {
					require.Equal(t, float64(1), got["page"])
					require.Equal(t, float64(20), got["page_size"])
				}
				got = got["data"].([]any)[0].(map[string]any)
			}
			for key, value := range expected {
				require.Contains(t, got, key)
				require.Equal(t, value, got[key], key)
			}
			for key, wantID := range map[string]float64{"requester": 5, "asset": 3, "approver": 7, "authorization": 7} {
				require.Equal(t, wantID, got[key].(map[string]any)["id"], key)
			}
			require.Equal(t, float64(1), got["approvals"].([]any)[0].(map[string]any)["id"])
			item := got["items"].([]any)[0].(map[string]any)
			require.Equal(t, "approval", item["policy_snapshot"].(map[string]any)["segment"])
			require.Equal(t, float64(1), item["approvals_received"])
			require.NotContains(t, got, "deleted_at")
			require.NotContains(t, got, "review_overdue_notified_at")
			svc.AssertExpectations(t)
		})
	}
}

func TestAccessRequestItemsCreateBinding(t *testing.T) {
	svc := new(MockAccessRequestService)
	svc.On("Submit", uint(5), "tester", "user", mock.MatchedBy(func(in authz.SubmitAccessRequestInput) bool {
		return in.AssetID == 0 && in.ExecutorUserID != nil && *in.ExecutorUserID == 8 && len(in.Items) == 2 && in.Items[0].AssetID == 3 && in.Items[1].AssetID == 4 && (*in.Items[1].Accounts)[0] == "app"
	})).Return(&model.AccessRequest{ID: 9}, nil)
	r, _ := newAccessRequestRouter(svc, nil, 5, "user", nil)
	w := doJSON(r, "POST", "/access-requests", map[string]any{"items": []any{map[string]any{"asset_id": 3, "accounts": []string{"app"}}, map[string]any{"asset_id": 4, "accounts": []string{"app"}}}, "executor_user_id": 8, "reason": "work", "duration_minutes": 60})
	require.Equal(t, 201, w.Code, w.Body.String())
	svc.AssertExpectations(t)
}

type itemActionMock struct {
	*MockAccessRequestService
	item, request uint
	action        string
}

func (m *itemActionMock) RejectItem(actor uint, admin bool, request, item uint, note string) (*model.AccessRequest, error) {
	m.item, m.request, m.action = item, request, "reject"
	return &model.AccessRequest{ID: request}, nil
}
func (m *itemActionMock) RevokeItem(actor uint, admin bool, username string, request, item uint, note string) (*model.AccessRequest, error) {
	m.item, m.request, m.action = item, request, "revoke"
	return &model.AccessRequest{ID: request}, nil
}
func TestAccessRequestItemActionBinding(t *testing.T) {
	for _, action := range []string{"reject", "revoke"} {
		t.Run(action, func(t *testing.T) {
			svc := &itemActionMock{MockAccessRequestService: new(MockAccessRequestService)}
			r, h := newAccessRequestRouter(svc.MockAccessRequestService, nil, 5, "user", nil)
			h.requests = svc
			w := doJSON(r, "POST", "/access-requests/9/"+action, map[string]any{"item_id": 42, "note": "decision"})
			require.Equal(t, 200, w.Code, w.Body.String())
			require.Equal(t, uint(42), svc.item)
			require.Equal(t, uint(9), svc.request)
			require.Equal(t, action, svc.action)
		})
	}
}
