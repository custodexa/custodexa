package api

import (
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUserOwnerProjection(t *testing.T) {
	e := newAgentReadEnv(t)
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", e.owner.ID).Updates(map[string]any{"email": "private-owner@example.test", "full_name": "private-owner-full-name"}).Error)
	other := model.User{Username: "second-agent", Kind: model.KindAgent, OwnerUserID: &e.other.ID, Password: "!", Active: true}
	require.NoError(t, e.db.Create(&other).Error)
	w := e.get("/users?kind=agent", e.jwt[model.RoleAdmin])
	require.Equal(t, 200, w.Code, w.Body.String())
	rows := agentReadJSON(t, w)["data"].([]any)
	require.Len(t, rows, 2)
	names := map[string]any{}
	for _, raw := range rows {
		row := raw.(map[string]any)
		names[row["username"].(string)] = row["owner_username"]
		require.NotContains(t, row, "owner")
	}
	require.Equal(t, e.owner.Username, names[e.agent.Username])
	require.Equal(t, e.other.Username, names[other.Username])
	require.NotContains(t, w.Body.String(), "private-owner")
	require.False(t, e.db.Migrator().HasColumn(&model.User{}, "owner_username"))
}

func TestMyAgentOwnerProjection(t *testing.T) {
	e := newAgentReadEnv(t)
	_, err := e.policies.Update(policy.PolicyAgentSelfCreateEnabled, "true", "test")
	require.NoError(t, err)
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", e.owner.ID).Update("full_name", "private-owner-full-name").Error)
	w := e.get(fmt.Sprintf("/my/agents?owner_user_id=%d", e.other.ID), e.jwt[model.RoleUser])
	require.Equal(t, 200, w.Code, w.Body.String())
	rows := agentReadJSON(t, w)["data"].([]any)
	require.Len(t, rows, 1)
	row := rows[0].(map[string]any)
	require.EqualValues(t, e.owner.ID, row["owner_user_id"])
	require.Equal(t, e.owner.Username, row["owner_username"])
	require.NotContains(t, row, "owner")
	require.NotContains(t, w.Body.String(), "private-owner")
	require.Empty(t, agentReadJSON(t, e.get(fmt.Sprintf("/my/agents?owner_user_id=%d", e.owner.ID), e.jwt["other"]))["data"])
}
