package audit

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"testing"
)

func TestAlertMatcherSubject(t *testing.T) {
	m := NewAlertMatcher(nil, nil)
	rules := []model.AlertRule{}
	for i, kind := range []string{"all", "human", "agent"} {
		rules = append(rules, model.AlertRule{ID: uint(i + 1), SubjectKind: kind, Pattern: "danger", Protocols: "ssh", Action: "block", Enabled: true, Direction: model.DirectionInput}, model.AlertRule{ID: uint(i + 11), SubjectKind: kind, Pattern: "secret", Protocols: "ssh", Enabled: true, Direction: model.DirectionOutput})
	}
	m.setRules(rules)
	for _, kind := range []string{"human", "agent", gatewayapi.PrincipalKindUnknown, "unrecognized"} {
		want := 1
		if kind == "human" || kind == "agent" {
			want = 2
		}
		got := m.ForSubject(kind).Match("danger", "ssh")
		if len(got) != want {
			t.Fatal(kind, got)
		}
		for _, rule := range got {
			if rule.SubjectKind != "all" && rule.SubjectKind != kind {
				t.Fatal(kind, rule)
			}
		}
		if out := m.OutputRules("ssh", kind); len(out) != want {
			t.Fatal(kind, out)
		}
		if got := m.ForSubject(kind).Match("danger", "mysql"); len(got) != 0 {
			t.Fatal("protocol leaked", got)
		}
	}
	// Unknown provenance must still enforce all rules, including after a reload.
	if _, hit := m.ForSubject(gatewayapi.PrincipalKindUnknown).MatchBlock("danger", "ssh"); !hit {
		t.Fatal("unknown skipped all rules")
	}
	agent := m.ForSubject(model.KindAgent)
	m.setRules([]model.AlertRule{{ID: 44, SubjectKind: "agent", Pattern: "ssh", Action: "block", Enabled: true}})
	if r, hit := agent.MatchBlock("ssh host", "ssh"); !hit || r.ID != 44 {
		t.Fatal("stale bound cache", r, hit)
	}
	if _, hit := m.ForSubject(model.KindHuman).MatchBlock("ssh host", "ssh"); hit {
		t.Fatal("human hit agent rule")
	}
}

func TestAlertMatcherSubjectStoredAlerts(t *testing.T) {
	sink := &recordingAlertSink{}
	m := NewAlertMatcher(nil, sink)
	m.setRules([]model.AlertRule{{ID: 1, SubjectKind: "agent", Pattern: "danger", Enabled: true}, {ID: 2, SubjectKind: "all", Pattern: "danger", Enabled: true}})
	row := []model.SessionCommand{{SessionID: 1, Command: "danger"}}
	m.ForSubject("human").MatchAndStore(row, "ssh")
	if len(sink.alerts) != 1 || *sink.alerts[0].RuleID != 2 {
		t.Fatal(sink.alerts)
	}
	sink.alerts = nil
	m.ForSubject("agent").MatchAndStore(row, "ssh")
	if len(sink.alerts) != 2 {
		t.Fatal(sink.alerts)
	}
}
