package api

import (
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSessionOwnerProjection(t *testing.T) {
	e := newAgentReadEnv(t)
	kind := model.KindAgent
	// Agent is currently owned by e.owner; the recorded session belonged to e.other.
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", e.other.ID).Updates(map[string]any{"full_name": "private-snapshot-owner", "email": "private-snapshot@example.test"}).Error)
	for i := 0; i < 2; i++ {
		require.NoError(t, e.db.Create(&model.Session{SessionID: fmt.Sprintf("polish2-%d", i), UserID: e.agent.ID, ActorKind: &kind, OwnerUserID: &e.other.ID, StartTime: time.Now(), Status: model.SessionStatusClosed, Protocol: model.ProtocolSSH}).Error)
	}
	for _, token := range []string{e.jwt[model.RoleAdmin], e.jwt[model.RoleAuditor]} {
		w := e.get("/sessions?actor_kind=agent&page_size=1", token)
		require.Equal(t, 200, w.Code, w.Body.String())
		body := agentReadJSON(t, w)
		require.EqualValues(t, 2, body["total"])
		rows := body["data"].([]any)
		require.Len(t, rows, 1)
		row := rows[0].(map[string]any)
		require.EqualValues(t, e.other.ID, row["owner_user_id"])
		require.Equal(t, e.other.Username, row["owner_username"])
		require.NotContains(t, row, "owner")
		require.NotContains(t, w.Body.String(), "private-snapshot")
	}
	require.Equal(t, 401, e.get("/sessions", "").Code)
	require.Equal(t, 403, e.get("/sessions", e.token).Code)
	require.Equal(t, 403, e.get("/sessions", e.jwt["other"]).Code)
	require.False(t, e.db.Migrator().HasColumn(&model.Session{}, "owner_username"))
	require.NoError(t, e.db.Delete(&e.other).Error)
	rows := agentReadJSON(t, e.get("/sessions?actor_kind=agent", e.jwt[model.RoleAdmin]))["data"].([]any)
	require.NotContains(t, rows[0].(map[string]any), "owner_username")
	require.EqualValues(t, e.other.ID, rows[0].(map[string]any)["owner_user_id"])
}
