package audit

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
	"testing"
)

func TestPrincipalStateEventsIndependent(t *testing.T) {
	svc, db := setupFailureDB(t)
	if err := db.Create(&model.SecurityPolicy{Key: policy.PolicyFailureAlertEnabled, Value: "true"}).Error; err != nil {
		t.Fatal(err)
	}
	notified := 0
	svc.notify = func(event notifycat.Event, params map[string]string) {
		if event == notifycat.EventAuditFailure {
			notified++
			if params["cause_code"] != model.CausePrincipalStateMismatch || params["table"] != "" {
				t.Fatal("wrong notification projection", params)
			}
		}
	}
	params := map[string]string{"since_seq": "1", "actual_hash": "digest", "extra": "7"}
	for i := 0; i < 2; i++ {
		for _, table := range []string{StateTablePrincipals, StateTableAgentTokens} {
			if err := svc.ReportStateMismatch(table, params); err != nil {
				t.Fatal(err)
			}
		}
	}
	var n int64
	db.Model(&model.AuditFailureEvent{}).Where("ended_at IS NULL").Count(&n)
	if n != 2 || notified != 2 {
		t.Fatalf("not independent: open=%d notify=%d", n, notified)
	}
	if err := svc.ResolveStateMismatch(StateTablePrincipals); err != nil {
		t.Fatal(err)
	}
	row, err := svc.LatestByStateTable(StateTableAgentTokens)
	if err != nil || row == nil || row.EndedAt != nil {
		t.Fatal("resolved other projection", err)
	}
	row, err = svc.LatestByStateTable(StateTablePrincipals)
	if err != nil || row == nil || row.EndedAt == nil {
		t.Fatal("own event not resolved", err)
	}
}
