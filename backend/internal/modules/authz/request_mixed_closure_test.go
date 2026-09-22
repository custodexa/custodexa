package authz

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestRequestClosedAfterRevokeThenNaturalExpiry(t *testing.T) {
	s, _, r, _ := twoPendingItems(t)
	r, err := s.Approve(2, true, r.ID, DecideInput{})
	require.NoError(t, err)
	terminator := &itemTerminations{}
	s.SetSessionService(terminator)
	r, err = s.RevokeItem(2, true, "reviewer", r.ID, r.Items[0].ID, "first done")
	require.NoError(t, err)
	require.Equal(t, model.AccessRequestItemRevoked, r.Items[0].Status)
	require.Equal(t, model.AccessRequestApproved, r.Items[1].Status)
	require.Nil(t, r.ClosedAt)
	require.Empty(t, terminator.requests)
	end := r.Items[1].ApprovedDateStart.Add(time.Duration(*r.Items[1].ApprovedDurationMinutes) * time.Minute)
	_, err = s.ExpireOverdue(end.Add(-time.Second))
	require.NoError(t, err)
	r, err = s.reload(r.ID)
	require.NoError(t, err)
	require.Nil(t, r.ClosedAt)
	// Use the expiry sweep's explicit time, without rewriting item windows.
	at := end.Add(time.Second)
	_, err = s.ExpireOverdue(at)
	require.NoError(t, err)
	r, err = s.reload(r.ID)
	require.NoError(t, err)
	require.NotNil(t, r.ClosedAt)
	require.True(t, r.ClosedAt.Equal(at), "closed_at must be the second terminal transition time")
	require.Equal(t, []uint{r.ID}, terminator.requests)
	_, err = s.ExpireOverdue(at.Add(time.Minute))
	require.NoError(t, err)
	r, err = s.reload(r.ID)
	require.NoError(t, err)
	require.True(t, r.ClosedAt.Equal(at))
}
