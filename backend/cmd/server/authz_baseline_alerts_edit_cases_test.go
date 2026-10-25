package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuthzBaselineAlertsEdit pins the two alerts entries (AD-12, AD-13):
// together they approve exactly one character-set fix in the alert cause
// text and exactly one extra permission-state alert row, and nothing else
// in the alerts field.
func TestAuthzBaselineAlertsEdit(t *testing.T) {
	real, err := loadApprovedDiffs(filepath.Join(authzBaselineDir, "approved-diffs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []approvedEntry
	for _, e := range real.Entries {
		if e.ID == "AD-12" || e.ID == "AD-13" {
			if e.Status != "active" || e.Expect == nil {
				t.Fatalf("%s must be active and carry an expectation", e.ID)
			}
			entries = append(entries, e)
		}
	}
	if len(entries) != 2 {
		t.Fatalf("AD-12 and AD-13 must both be listed, got %d", len(entries))
	}
	ad := approvedDiffs{Entries: entries}
	const id = "R/S01/GET /api/v1/audit-checkpoints/verify"
	principals := func(cause string) map[string]any {
		return map[string]any{"@table": "audit_failure_events", "cause": cause, "cause_code": "principal_state_mismatch",
			"cause_params": `json:{"since_seq":"1","table":"user_principals"}`, "mechanism": "principal_state_integrity", "id": 1.0}
	}
	var declared map[string]any
	for _, e := range entries {
		if ed, err := parseAlertsEdit(e.Expect); err == nil && ed.Added != nil {
			declared = ed.Added.Row
		}
	}
	if declared == nil {
		t.Fatal("AD-13 must declare its added row")
	}
	// permState is the declared row as the normalizer writes it.
	permState := func() map[string]any {
		m := deepCopyJSON(declared).(map[string]any)
		b, _ := json.Marshal(m["cause_params"])
		m["cause_params"] = "json:" + string(b)
		m["id"] = 2.0
		return m
	}
	rec := func(alerts ...map[string]any) map[string]map[string]any {
		arr := make([]any, len(alerts))
		for i, a := range alerts {
			arr[i] = a
		}
		return map[string]map[string]any{id: {"id": id, "status": 200.0, "alerts": arr}}
	}
	old := rec(principals("有變更未經应用程式留痕"))
	run := func(newRecs map[string]map[string]any) compareResult { return compareRecords(old, newRecs, ad) }

	if r := run(rec(principals("有變更未經應用程式留痕"), permState())); r.failed() {
		t.Fatalf("control: the fix plus one permission-state row must be approved: %s", r.summary(5))
	}
	cases := map[string]map[string]map[string]any{
		"another kind of alert added": rec(principals("有變更未經應用程式留痕"), permState(),
			map[string]any{"@table": "audit_failure_events", "cause": "y", "mechanism": "audit_chain_integrity", "id": 3.0}),
		"added row of another table": rec(principals("有變更未經應用程式留痕"),
			map[string]any{"@table": "audit_failure_events", "cause": "x", "cause_code": "principal_state_mismatch",
				"cause_params": `json:{"table":"asset_authorizations"}`, "mechanism": "principal_state_integrity", "id": 2.0}),
		"two permission-state rows": rec(principals("有變更未經應用程式留痕"), permState(), permState()),
		"added row one more column": rec(principals("有變更未經應用程式留痕"), func() map[string]any {
			m := permState()
			m["note"] = "x"
			return m
		}()),
		"added row other cause params": rec(principals("有變更未經應用程式留痕"), func() map[string]any {
			m := permState()
			m["cause_params"] = strings.Replace(m["cause_params"].(string), `"extra":"11,12"`, `"extra":"11,12,13"`, 1)
			return m
		}()),
		"text changed to another word": rec(principals("有變更未經其他程式留痕"), permState()),
		"text fix without added row":   rec(principals("有變更未經應用程式留痕")),
		"added row without text fix":   rec(principals("有變更未經应用程式留痕"), permState()),
		"alerts emptied":               rec(),
		"other column changed": rec(func() map[string]any {
			m := principals("有變更未經應用程式留痕")
			m["cause_code"] = "other"
			return m
		}(), permState()),
	}
	for name, n := range cases {
		if r := run(n); !r.failed() {
			t.Errorf("%s must not be approved", name)
		}
	}
	// Entry shape: the alerts edit may not be widened to other fields or expectations.
	bad := entries[0]
	bad.Selector.Fields = []string{"alerts", "status"}
	if (approvedDiffs{Entries: []approvedEntry{bad}}).validate() == nil {
		t.Error("an alerts_edit entry selecting more than the alerts field must be rejected")
	}
	bad = entries[0]
	bad.Expect = map[string]any{"alerts_edit": entries[0].Expect["alerts_edit"], "status": 200.0}
	if (approvedDiffs{Entries: []approvedEntry{bad}}).validate() == nil {
		t.Error("an alerts_edit entry with other expectations must be rejected")
	}
}
