package api

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/stretchr/testify/mock"
)

func TestAccessRequestItemErrorResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"shape", authz.ErrRequestItemsShape, 400, "VALIDATION_BAD_PARAMS"},
		{"account", authz.ErrAccountNotOnAsset, 400, "VALIDATION_ACCOUNT_NOT_ON_ASSET"},
		{"scope", authz.ErrAgentAccountsRequired, 400, "VALIDATION_AGENT_ACCOUNTS_REQUIRED"},
		{"executor", authz.ErrExecutorNotAgent, 400, "VALIDATION_EXECUTOR_NOT_AGENT"},
		{"quota", &authz.AgentRequestRateError{Count: 30, Limit: 30, Dimension: "hour"}, 429, "RULE_AGENT_REQUEST_RATE"},
		{"duplicate", &authz.DuplicatePendingItemError{RequestID: 41, ItemID: 72}, 409, "CONFLICT_ACCESS_REQUEST_DUPLICATE_PENDING"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := new(MockAccessRequestService)
			svc.On("Submit", uint(5), "tester", "user", mock.Anything).Return(nil, fmt.Errorf("submit: %w", tc.err))
			r, _ := newAccessRequestRouter(svc, nil, 5, "user", nil)
			w := doJSON(r, "POST", "/access-requests", map[string]any{"asset_id": 3, "reason": "maintenance", "duration_minutes": 60})
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.status || body["code"] != tc.code {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if tc.name == "duplicate" && (body["request_id"] != float64(41) || body["item_id"] != float64(72)) {
				t.Fatal("missing conflicting identifiers", body)
			}
			svc.AssertExpectations(t)
		})
	}
}
