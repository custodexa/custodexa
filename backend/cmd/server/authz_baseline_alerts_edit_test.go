package main

import (
	"fmt"
	"strings"
)

// alertsEditKey is an opt-in expectation for the alerts field. An entry
// that declares it approves only the listed edits to the alerts rows of a
// record, never the whole field. Entries that match the same record are
// judged together: the edits of all of them, applied to the golden rows,
// must reproduce the fresh rows exactly. Anything left over (another
// added row, any other changed text) leaves the difference unapproved.
//
// Supported edits (one per entry):
//
//	"cause_text_fix": {"from": "...", "to": "..."}
//	    replaces the text in the "cause" column of the golden rows; it must
//	    change at least one row.
//	"added_rows": {"count": N, "row": {"@table": "...", "col": value, ...}}
//	    exactly N fresh rows that are absent from the golden rows and equal
//	    the declared row as a whole: every column except the id (see
//	    declaredRowEquals; cause_params may be declared as an object).
const alertsEditKey = "alerts_edit"

type alertsEdit struct {
	Fix   *alertsTextFix
	Added *alertsAddedRows
}

type alertsTextFix struct{ From, To string }

type alertsAddedRows struct {
	Count int
	Row   map[string]any
}

func parseAlertsEdit(expect map[string]any) (alertsEdit, error) {
	var out alertsEdit
	raw, ok := expect[alertsEditKey].(map[string]any)
	if !ok || len(raw) != 1 {
		return out, fmt.Errorf("%s must hold exactly one edit", alertsEditKey)
	}
	if len(expect) != 1 {
		return out, fmt.Errorf("an entry with %s must not carry other expectations", alertsEditKey)
	}
	if f, ok := raw["cause_text_fix"].(map[string]any); ok {
		from, _ := f["from"].(string)
		to, _ := f["to"].(string)
		if from == "" || to == "" || from == to || len(f) != 2 {
			return out, fmt.Errorf("cause_text_fix needs distinct non-empty from and to")
		}
		out.Fix = &alertsTextFix{from, to}
		return out, nil
	}
	if a, ok := raw["added_rows"].(map[string]any); ok {
		cnt, _ := a["count"].(float64)
		row, _ := a["row"].(map[string]any)
		if cnt < 1 || len(a) != 2 {
			return out, fmt.Errorf("added_rows needs count >= 1 and the whole row in \"row\"")
		}
		if err := validateDeclaredRow(row); err != nil {
			return out, fmt.Errorf("added_rows: %w", err)
		}
		if _, ok := row["@table"].(string); !ok {
			return out, fmt.Errorf("added_rows: the declared row must name its @table")
		}
		out.Added = &alertsAddedRows{Count: int(cnt), Row: row}
		return out, nil
	}
	return out, fmt.Errorf("unknown %s edit", alertsEditKey)
}

// validateAlertsEdit is called from approvedDiffs.validate.
func validateAlertsEdit(e approvedEntry) error {
	if _, ok := e.Expect[alertsEditKey]; !ok {
		return nil
	}
	if _, err := parseAlertsEdit(e.Expect); err != nil {
		return fmt.Errorf("%s: %w", e.ID, err)
	}
	if len(e.Selector.Fields) != 1 || e.Selector.Fields[0] != "alerts" {
		return fmt.Errorf("%s: an %s entry must select the alerts field only", e.ID, alertsEditKey)
	}
	return nil
}

func alertRows(v any) ([]map[string]any, bool) {
	if v == nil {
		return nil, true
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]map[string]any, 0, len(arr))
	for _, x := range arr {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, false
		}
		out = append(out, m)
	}
	return out, true
}

// alertsEditHolds reports whether the alerts edits declared by the active
// entries that match the record explain the difference exactly.
func alertsEditHolds(entries []approvedEntry, id string, old, new map[string]any) bool {
	_, subject, _ := scenarioParts(id)
	oldRows, ok1 := alertRows(old["alerts"])
	newRows, ok2 := alertRows(new["alerts"])
	if !ok1 || !ok2 {
		return false
	}
	var edits []alertsEdit
	for _, e := range entries {
		if e.Status != "active" || e.Expect == nil || e.Expect[alertsEditKey] == nil {
			continue
		}
		if !e.Selector.matches(id, old, []string{"alerts"}) {
			continue
		}
		ed, err := parseAlertsEdit(e.Expect)
		if err != nil {
			return false
		}
		edits = append(edits, ed)
	}
	// Apply the text fixes to copies of the golden rows.
	expected := make([]map[string]any, len(oldRows))
	for i, r := range oldRows {
		c := map[string]any{}
		for k, v := range r {
			c[k] = v
		}
		expected[i] = c
	}
	for _, ed := range edits {
		if ed.Fix == nil {
			continue
		}
		changed := false
		for _, r := range expected {
			if s, ok := r["cause"].(string); ok && strings.Contains(s, ed.Fix.From) {
				r["cause"] = strings.ReplaceAll(s, ed.Fix.From, ed.Fix.To)
				changed = true
			}
		}
		if !changed {
			return false
		}
	}
	// Take the declared added rows out of the fresh rows.
	rest := append([]map[string]any(nil), newRows...)
	for _, ed := range edits {
		if ed.Added == nil {
			continue
		}
		removed := 0
		var kept []map[string]any
		for _, r := range rest {
			if removed < ed.Added.Count && declaredRowEquals(r, ed.Added.Row, subject) && !containsRow(expected, r) {
				removed++
				continue
			}
			kept = append(kept, r)
		}
		if removed != ed.Added.Count {
			return false
		}
		rest = kept
	}
	if len(rest) != len(expected) {
		return false
	}
	for i := range rest {
		if canon(rest[i]) != canon(expected[i]) {
			return false
		}
	}
	return true
}

func containsRow(rows []map[string]any, r map[string]any) bool {
	for _, x := range rows {
		if canon(x) == canon(r) {
			return true
		}
	}
	return false
}
