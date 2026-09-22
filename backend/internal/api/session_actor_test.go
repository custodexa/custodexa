package api

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/model"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionActorDetails(t *testing.T) {
	id := uint(9)
	kind := model.KindAgent
	at := time.Now().UTC().Truncate(time.Microsecond)
	svc := &MockSessionService{}
	svc.On("GetByID", uint(1)).Return(&model.Session{ID: 1, ActorKind: &kind, AgentTokenID: &id, AccessRequestID: &id, OwnerUserID: &id, OnBehalfOfUserID: &id, RevokedDuringSessionAt: &at}, nil).Once()
	r := gin.New()
	r.GET("/sessions/:id", NewSessionHandler(svc).Get)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/1", nil))
	var row map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil || w.Code != 200 {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	for k, v := range map[string]any{"actor_kind": "agent", "agent_token_id": float64(9), "access_request_id": float64(9), "owner_user_id": float64(9), "on_behalf_of_user_id": float64(9), "revoked_during_session_at": at.Format(time.RFC3339Nano)} {
		if row[k] != v {
			t.Fatal(k, row[k], v)
		}
	}
	svc.AssertExpectations(t)
}
