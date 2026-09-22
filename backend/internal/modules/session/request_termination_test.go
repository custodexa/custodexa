package session

import (
	"reflect"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

func TestRequestSessionTermination(t *testing.T) {
	db := setupSessionTerminalStateDB(t)
	s := NewSessionService(nil)
	a, b, request, other := uint(1), uint(2), uint(41), uint(42)
	rows := []model.Session{
		{SessionID: "task-1", UserID: 1, AssetID: &a, AccessRequestID: &request, Status: model.SessionStatusActive, StartTime: time.Now()},
		{SessionID: "task-2", UserID: 1, AssetID: &b, AccessRequestID: &request, Status: model.SessionStatusActive, StartTime: time.Now()},
		{SessionID: "other", UserID: 1, AssetID: &b, AccessRequestID: &other, Status: model.SessionStatusActive, StartTime: time.Now()},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	ids, err := s.TerminateByUserAssetWithIDs(1, a, model.EndReasonRevoked)
	if err != nil || !reflect.DeepEqual(ids, []uint{rows[0].ID}) {
		t.Fatal(ids, err)
	}
	ids, err = s.TerminateByAccessRequest(request, model.EndReasonRevoked)
	if err != nil || !reflect.DeepEqual(ids, []uint{rows[1].ID}) {
		t.Fatal(ids, err)
	}
	if !s.IsActive(rows[2].ID) || s.IsActive(rows[1].ID) || s.IsActive(rows[0].ID) {
		t.Fatal("termination escaped selected request")
	}
	ids, err = s.TerminateByAccessRequest(request, model.EndReasonRevoked)
	if err != nil || len(ids) != 0 {
		t.Fatal("replayed termination reported IDs", ids, err)
	}
}
