package authz

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAccessRequestItemViews(t *testing.T) {
	s, db, req, agent := twoPendingItems(t)
	// Only the second asset is assigned to this reviewer.
	require.NoError(t, db.Where("approver_id=?", 2).Delete(&model.ApproverScope{}).Error)
	actor, assetID := uint(2), uint(2)
	require.NoError(t, db.Create(&model.ApproverScope{ApproverID: &actor, AssetID: &assetID, GrantedBy: 3}).Error)
	mine, err := s.ListMine(agent)
	require.NoError(t, err)
	require.Len(t, mine, 1)
	require.Len(t, mine[0].Items, 2)
	pending, err := s.ListPending(2, false, time.Now())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Len(t, pending[0].Items, 2)
	count, err := s.PendingCount(2, false, time.Now())
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	_, err = s.Approve(2, true, req.ID, DecideInput{})
	require.NoError(t, err)
	history, total, err := s.ListHistory(2, false, 1, 20)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, history[0].Items, 2)
	tickets, err := s.MyActiveTickets(agent, time.Now())
	require.NoError(t, err)
	require.Len(t, tickets, 2)
	for _, ticket := range tickets {
		require.NotNil(t, ticket.RequestID)
		require.Equal(t, req.ID, *ticket.RequestID)
	}
}
