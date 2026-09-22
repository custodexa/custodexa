package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/stretchr/testify/require"
)

func TestAccountSourceIndex(t *testing.T) {
	s, _, db, agent := setupItemRequestEnv(t)
	good, bad := []string{"app"}, []string{"not-on-asset"}
	_, err := s.Submit(agent, "task-agent", model.RoleUser, SubmitAccessRequestInput{Reason: "fixture", DurationMinutes: 30, Items: []ItemInput{{AssetID: 1, Accounts: &good}, {AssetID: 2, Accounts: &bad}}})
	var detail *AccountNotOnAssetError
	require.True(t, errors.As(err, &detail))
	require.Equal(t, 1, detail.ItemIndex)
	require.EqualValues(t, 2, detail.AssetID)
	require.ErrorIs(t, err, ErrAccountNotOnAsset)
	var count int64
	require.NoError(t, db.Model(&model.AccessRequest{}).Count(&count).Error)
	require.Zero(t, count)
}
func TestQuotaSource(t *testing.T) {
	s, p, db, agent := setupItemRequestEnv(t)
	_, err := p.Update(policy.PolicyAgentRequestRatePerHour, "1", "test")
	require.NoError(t, err)
	_, err = s.Submit(agent, "task-agent", model.RoleUser, itemInput(1))
	require.NoError(t, err)
	_, err = s.Submit(agent, "task-agent", model.RoleUser, itemInput(2))
	var detail *AgentRequestRateError
	require.True(t, errors.As(err, &detail))
	require.EqualValues(t, 1, detail.Count)
	require.Equal(t, 1, detail.Limit)
	require.Equal(t, "hour", detail.Dimension)
	var count int64
	require.NoError(t, db.Model(&model.AccessRequest{}).Count(&count).Error)
	require.EqualValues(t, 1, count)
}
func TestBoundsUseDecisionValues(t *testing.T) {
	s, _, req, _ := twoPendingItems(t)
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	req.RequestedDateStart = &future
	require.NoError(t, s.attachReadFields([]*model.AccessRequest{req}, now))
	require.NotNil(t, req.Items[0].DecisionBounds)
	b := req.Items[0].DecisionBounds
	duration, start, accounts, err := decisionValues(req, &req.Items[0], DecideInput{}, now)
	require.NoError(t, err)
	require.Equal(t, duration, b.MaxDuration)
	require.Equal(t, start, b.EarliestStart)
	require.Equal(t, accounts, b.Accounts)
	bigger := duration + 1
	_, _, _, err = decisionValues(req, &req.Items[0], DecideInput{DurationMinutes: &bigger}, now)
	require.ErrorIs(t, err, ErrDecisionIncrease)
}
