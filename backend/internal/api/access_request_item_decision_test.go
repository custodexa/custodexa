package api

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/stretchr/testify/mock"
)

func TestApproveItemHTTP(t *testing.T) {
	svc := new(MockAccessRequestService)
	svc.On("Approve", uint(5), false, uint(9), mock.MatchedBy(func(in authz.DecideInput) bool {
		return in.ItemID == 12 && in.Accounts != nil && len(*in.Accounts) == 1 && (*in.Accounts)[0] == "app" && in.DurationMinutes != nil && *in.DurationMinutes == 15
	})).Return(&model.AccessRequest{ID: 9}, nil)
	router, _ := newAccessRequestRouter(svc, nil, 5, "user", nil)
	w := doJSON(router, "POST", "/access-requests/9/approve", map[string]any{"item_id": 12, "accounts": []string{"app"}, "duration_minutes": 15})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	svc.AssertExpectations(t)
}
func TestApproveItemHTTPUpscopeIs400(t *testing.T) {
	svc := new(MockAccessRequestService)
	svc.On("Approve", uint(5), false, uint(9), mock.Anything).Return(nil, authz.ErrDecisionIncrease)
	router, _ := newAccessRequestRouter(svc, nil, 5, "user", nil)
	w := doJSON(router, "POST", "/access-requests/9/approve", map[string]any{"item_id": 12, "accounts": []string{"@ALL"}})
	if w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
	svc.AssertExpectations(t)
}
