package session

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"testing"
	"time"
)

func TestTerminateByAgentToken(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	first, other := uint(1), uint(2)
	rows := []model.Session{{UserID: 1, AgentTokenID: &first, Status: model.SessionStatusActive, StartTime: time.Now()}, {UserID: 1, AgentTokenID: &first, Status: model.SessionStatusActive, StartTime: time.Now()}, {UserID: 1, AgentTokenID: &first, Status: model.SessionStatusActive, StartTime: time.Now()}, {UserID: 1, AgentTokenID: &other, Status: model.SessionStatusActive, StartTime: time.Now()}, {UserID: 1, Status: model.SessionStatusActive, StartTime: time.Now()}}
	for i := range rows {
		rows[i].SessionID = fmt.Sprintf("agent-session-%d", i)
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	registry := &MockConnectionRegistry{closeFunc: func(id uint) error {
		if id == rows[0].ID {
			return errors.New("injected close failure")
		}
		return nil
	}}
	svc := NewSessionService(registry)
	got, err := svc.TerminateByAgentToken(first, model.EndReasonAdminTerminate)
	if err != nil || len(got.TerminatedIDs) != 2 || len(got.FailedIDs) != 1 || got.FailedIDs[0] != rows[0].ID {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	for i, row := range rows {
		var after model.Session
		if err := db.First(&after, row.ID).Error; err != nil {
			t.Fatal(err)
		}
		want := model.SessionStatusDisconnected
		if i >= 3 {
			want = model.SessionStatusActive
		}
		if after.Status != want {
			t.Fatalf("session %d: %s", row.ID, after.Status)
		}
	}
	again, err := svc.TerminateByAgentToken(first, model.EndReasonAdminTerminate)
	if err != nil || len(again.TerminatedIDs) != 0 || registry.callCount != 3 {
		t.Fatalf("CAS duplicate: %+v %v calls=%d", again, err, registry.callCount)
	}
}

func TestTerminateByAgentTokenLate(t *testing.T) {
	db := setupOffsiteSessionDB(t)
	tokenID := uint(7)
	row := model.Session{UserID: 1, SessionID: "late-agent-session", AgentTokenID: &tokenID, Status: model.SessionStatusActive, StartTime: time.Now()}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	svc := NewSessionService(&MockConnectionRegistry{closeFunc: func(uint) error { time.Sleep(3100 * time.Millisecond); return nil }})
	result, err := svc.TerminateByAgentToken(tokenID, model.EndReasonAdminTerminate)
	if err != nil || len(result.TerminatedIDs) != 1 || result.Late[row.ID] <= 3*time.Second {
		t.Fatalf("slow close not measured: %+v %v", result, err)
	}
}
