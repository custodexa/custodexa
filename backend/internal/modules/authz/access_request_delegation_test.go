package authz

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
)

func TestSubmitDelegatedRequestOwnerIndependent(t *testing.T) {
	s, _, db, agent := setupItemRequestEnv(t)
	requester, owner := uint(1), uint(4)
	require.NoError(t, db.Model(&model.User{}).Where("id=?", agent).Update("owner_user_id", owner).Error)
	in := itemInput(1)
	in.ExecutorUserID = &agent
	req, err := s.Submit(requester, "human", model.RoleUser, in)
	require.NoError(t, err)
	req, err = s.Approve(2, false, req.ID, DecideInput{})
	require.NoError(t, err)
	var saved model.AccessRequest
	require.NoError(t, db.First(&saved, req.ID).Error)
	// Contract §8.5: the request's requester is the persisted on_behalf_of source.
	require.Equal(t, requester, saved.RequesterID, "on_behalf_of must be the requester, not the agent owner")
	var grant model.AssetAuthorization
	require.NoError(t, db.First(&grant, *req.Items[0].AuthorizationID).Error)
	require.Equal(t, &agent, grant.UserID, "delegated authorization belongs to the agent, not its owner")
}
