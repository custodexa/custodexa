package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
)

// TestAuthzBaselineApprovedDiffs guards the comparator and the approved
// difference list against swallowing differences: an unlisted difference,
// a difference only covered by a pending entry, an active entry that matches
// nothing, a selector that does not bound the scenario set, and an expected
// value that does not hold must all fail; a difference only in masked fields
// must compare equal, and a difference in an unmasked field must not.
func TestAuthzBaselineApprovedDiffs(t *testing.T) {
	real, err := loadApprovedDiffs(filepath.Join(authzBaselineDir, "approved-diffs.json"))
	if err != nil {
		t.Fatalf("approved-diffs.json does not load: %v", err)
	}
	if len(real.Entries) < 10 {
		t.Fatalf("approved-diffs.json lists %d entries; AD-1..AD-10 expected", len(real.Entries))
	}

	rec := func(id string, status int, body any) map[string]any {
		return map[string]any{"id": id, "status": float64(status), "body": body}
	}
	old := map[string]map[string]any{
		"R/S02/GET /api/v1/assets": rec("R/S02/GET /api/v1/assets", 403, nil),
		"R/S03/GET /api/v1/assets": rec("R/S03/GET /api/v1/assets", 200, map[string]any{"total": 1.0}),
	}
	changed := func(id string, status int, body any) map[string]map[string]any {
		n := map[string]map[string]any{}
		for k, v := range old {
			n[k] = v
		}
		n[id] = rec(id, status, body)
		return n
	}
	entry := func(id, status string, sel approvedSelector, expect map[string]any) approvedEntry {
		return approvedEntry{ID: id, Status: status, Selector: sel, Expect: expect, Reason: "synthetic"}
	}
	s02Status := approvedSelector{Group: "R", Subjects: []string{"S02"}, Keys: []string{"GET /api/v1/assets"}, Fields: []string{"status", "body"}}

	t.Run("unlisted_difference_fails", func(t *testing.T) {
		res := compareRecords(old, changed("R/S02/GET /api/v1/assets", 200, map[string]any{"total": 1.0}), approvedDiffs{})
		if !res.failed() || res.Diffs[0].Verdict != "unapproved" {
			t.Fatalf("403->200 without an entry must fail as unapproved: %+v", res)
		}
	})
	t.Run("pending_only_fails", func(t *testing.T) {
		ad := approvedDiffs{Entries: []approvedEntry{entry("AD-X", "pending", s02Status, nil)}}
		res := compareRecords(old, changed("R/S02/GET /api/v1/assets", 200, nil), ad)
		if !res.failed() || res.Diffs[0].Verdict != "pending-only" {
			t.Fatalf("a difference covered only by a pending entry must fail: %+v", res)
		}
	})
	t.Run("active_entry_without_hit_fails", func(t *testing.T) {
		ad := approvedDiffs{Entries: []approvedEntry{entry("AD-X", "active", s02Status, nil)}}
		res := compareRecords(old, old, ad)
		if !res.failed() || len(res.StaleActive) != 1 || res.StaleActive[0] != "AD-X" {
			t.Fatalf("an active entry that matches nothing must fail: %+v", res)
		}
		// Positive control: the same entry with a matching difference passes.
		res = compareRecords(old, changed("R/S02/GET /api/v1/assets", 200, nil), ad)
		if res.failed() {
			t.Fatalf("active entry with a matching difference must pass: %s", res.summary(5))
		}
	})
	t.Run("unbounded_selector_rejected", func(t *testing.T) {
		for name, sel := range map[string]approvedSelector{
			"group_only": {Group: "R", Fields: []string{"status"}},
			"wildcard":   {Group: "R", Subjects: []string{"*"}, Fields: []string{"status"}},
			"no_fields":  {Scenarios: []string{"T/T02"}},
		} {
			ad := approvedDiffs{Entries: []approvedEntry{entry("AD-X", "active", sel, nil)}}
			if err := ad.validate(); err == nil {
				t.Errorf("%s: selector must be rejected", name)
			}
		}
	})
	t.Run("selector_targets_must_exist", func(t *testing.T) {
		// A selector pointing at nothing is never in scope, so it could
		// neither approve nor go stale; loading must reject it instead.
		for name, sel := range map[string]approvedSelector{
			"unknown_group":     {Group: "B", Subjects: []string{"S01"}, Fields: []string{"status"}},
			"unknown_subject":   {Group: "R", Subjects: []string{"s02"}, Fields: []string{"status"}},
			"unknown_scenario":  {Scenarios: []string{"T/T99"}, Fields: []string{"status"}},
			"unknown_route":     {Scenarios: []string{"R/S02/GET /api/v1/no-such-route"}, Fields: []string{"status"}},
			"entry_ids":         {Scenarios: []string{"E/S01 /my-connections"}, Fields: []string{"menu_visible"}},
			"group_e_scenarios": {Group: "E", Subjects: []string{"S01"}, Scenarios: []string{"T/T02"}, Fields: []string{"menu_visible"}},
		} {
			ad := approvedDiffs{Entries: []approvedEntry{entry("AD-X", "pending", sel, nil)}}
			if err := ad.validate(); err == nil {
				t.Errorf("%s: selector naming a missing target must be rejected", name)
			}
		}
		// Positive control: existing targets of every kind load.
		for name, sel := range map[string]approvedSelector{
			"flow_scenario": {Scenarios: []string{"T/T02", "B1/S01/expired-connect"}, Fields: []string{"status"}},
			"route":         {Scenarios: []string{"R/S02/GET /api/v1/assets"}, Fields: []string{"status"}},
			"flow_group":    {Group: "B4", Subjects: []string{"S01"}, Fields: []string{"status"}},
			"entry_group":   {Group: "E", Keys: []string{"/my-connections"}, Fields: []string{"menu_visible"}},
		} {
			ad := approvedDiffs{Entries: []approvedEntry{entry("AD-X", "pending", sel, nil)}}
			if err := ad.validate(); err != nil {
				t.Errorf("%s: existing targets must load: %v", name, err)
			}
		}
	})
	t.Run("expect_mismatch_fails", func(t *testing.T) {
		ad := approvedDiffs{Entries: []approvedEntry{entry("AD-X", "active", s02Status, map[string]any{"status": 201.0})}}
		res := compareRecords(old, changed("R/S02/GET /api/v1/assets", 200, nil), ad)
		if !res.failed() || res.Diffs[0].Verdict != "expect-mismatch" {
			t.Fatalf("a new value outside the entry's expectation must fail: %+v", res)
		}
		// additive body: new keys allowed, existing keys must keep values.
		add := approvedSelector{Group: "R", Subjects: []string{"S03"}, Keys: []string{"GET /api/v1/assets"}, Fields: []string{"body"}}
		ad = approvedDiffs{Entries: []approvedEntry{entry("AD-Y", "active", add, map[string]any{"body": "additive"})}}
		if res := compareRecords(old, changed("R/S03/GET /api/v1/assets", 200, map[string]any{"total": 1.0, "extra": true}), ad); res.failed() {
			t.Fatalf("additive body must pass: %s", res.summary(5))
		}
		if res := compareRecords(old, changed("R/S03/GET /api/v1/assets", 200, map[string]any{"total": 2.0, "extra": true}), ad); !res.failed() {
			t.Fatal("changing an existing key under an additive expectation must fail")
		}
	})
	// Current-user response entry: the listed additive expectation must be
	// exact. Two new top-level keys and nothing else, on a 200 that stays a
	// 200; a third key, a missing key, a changed old key, a changed status, or
	// the same additions on an error answer all fail.
	t.Run("ad9_adds_exactly_two_keys", func(t *testing.T) {
		var ad9 approvedEntry
		for _, e := range real.Entries {
			if e.ID == "AD-9" {
				ad9 = e
			}
		}
		if ad9.ID == "" || ad9.Status != "active" {
			t.Fatalf("AD-9 must be listed and active for the capability projection phase: %+v", ad9)
		}
		ad := approvedDiffs{Entries: []approvedEntry{ad9}}
		id := "R/S03/GET /api/v1/auth/me"
		base := map[string]any{"id": 7.0, "username": "u", "roles": []any{"user"}}
		with := func(extra map[string]any) map[string]any {
			out := map[string]any{}
			for k, v := range base {
				out[k] = v
			}
			for k, v := range extra {
				out[k] = v
			}
			return out
		}
		pair := map[string]any{"permissions": []any{"asset:view"}, "scope_summary": []any{}}
		oldRecs := map[string]map[string]any{id: rec(id, 200, base)}
		pass := func(name string, oldR, newR map[string]map[string]any) {
			if res := compareRecords(oldR, newR, ad); res.failed() {
				t.Errorf("%s must pass: %s", name, res.summary(5))
			}
		}
		fail := func(name string, oldR, newR map[string]map[string]any) {
			if res := compareRecords(oldR, newR, ad); !res.failed() {
				t.Errorf("%s must fail", name)
			}
		}
		pass("exact pair", oldRecs, map[string]map[string]any{id: rec(id, 200, with(pair))})
		third := with(pair)
		third["extra"] = true
		fail("third key", oldRecs, map[string]map[string]any{id: rec(id, 200, third)})
		fail("only permissions", oldRecs, map[string]map[string]any{id: rec(id, 200, with(map[string]any{"permissions": []any{}}))})
		changed := with(pair)
		changed["username"] = "other"
		fail("changed old key", oldRecs, map[string]map[string]any{id: rec(id, 200, changed)})
		removed := with(pair)
		delete(removed, "roles")
		fail("removed old key", oldRecs, map[string]map[string]any{id: rec(id, 200, removed)})
		fail("status change", oldRecs, map[string]map[string]any{id: rec(id, 500, with(pair))})
		errOld := map[string]map[string]any{id: rec(id, 401, map[string]any{"code": "AUTH_TOKEN_INVALID"})}
		fail("same additions on an error answer", errOld, map[string]map[string]any{id: rec(id, 401, map[string]any{"code": "AUTH_TOKEN_INVALID", "permissions": []any{}, "scope_summary": []any{}})})
		other := "R/S03/GET /api/v1/assets"
		fail("other route", map[string]map[string]any{other: rec(other, 200, base)}, map[string]map[string]any{other: rec(other, 200, with(pair))})
	})
	t.Run("masked_only_difference_equal", func(t *testing.T) {
		a := normalizeRaw(t, `{"id":7,"created_at":"2026-10-15T10:00:00Z","token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln","request_id":"0f8fad5b-d9cb-469f-a165-70867728950e","details":"{\"at\":\"2026-10-15 10:00:00\"}"}`)
		b := normalizeRaw(t, `{"id":7,"created_at":"2026-10-16T11:30:00.123Z","token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIyIn0.b3RoZXI","request_id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","details":"{\"at\":\"2026-10-16 01:02:03\"}"}`)
		if canon(a) != canon(b) {
			t.Fatalf("records differing only in masked fields must compare equal:\n%s\n%s", canon(a), canon(b))
		}
	})
	t.Run("unmasked_difference_detected", func(t *testing.T) {
		for _, pair := range [][2]string{
			{`{"id":7,"total":3}`, `{"id":7,"total":4}`},
			{`{"id":7,"role":"admin"}`, `{"id":7,"role":"user"}`},
			{`{"id":7,"state":"pending"}`, `{"id":7,"state":"approved"}`},
			{`{"id":7,"details":"{\"action\":\"create\"}"}`, `{"id":7,"details":"{\"action\":\"delete\"}"}`},
			{`{"id":7,"username":"baseline-s02"}`, `{"id":7,"username":"baseline-s03"}`},
		} {
			if canon(normalizeRaw(t, pair[0])) == canon(normalizeRaw(t, pair[1])) {
				t.Errorf("difference in an unmasked field was masked away: %s vs %s", pair[0], pair[1])
			}
		}
	})
	// ---- structure additions ----

	dbRec := func(id string, rows ...map[string]any) map[string]any {
		added := make([]any, len(rows))
		for i, r := range rows {
			added[i] = r
		}
		return map[string]any{"id": id, "db": map[string]any{"roles": map[string]any{"added": added}}}
	}
	capture := map[string][]string{"roles": {"id", "name"}}
	live := map[string][]string{"roles": {"id", "name", "builtin_key"}, "authz_state": {"id", "version"}}
	declared := schemaAdditions{Version: 1, Additions: []schemaAddition{{
		Migration: "20261016_authz_permission_model",
		Tables:    []string{"authz_state"},
		Columns:   map[string][]string{"roles": {"builtin_key"}},
	}}}
	projectFresh := func(fresh map[string]map[string]any, adds schemaAdditions) {
		projectRecords(fresh, projectionSchema(live, adds), live)
	}

	t.Run("schema_additions_only_new_columns_compare_equal", func(t *testing.T) {
		oldRecs := map[string]map[string]any{"R/S02/POST /api/v1/x": dbRec("R/S02/POST /api/v1/x", map[string]any{"id": 1.0, "name": "a"})}
		fresh := map[string]map[string]any{"R/S02/POST /api/v1/x": dbRec("R/S02/POST /api/v1/x",
			map[string]any{"id": 1.0, "name": "a", "builtin_key": "user"})}
		fresh["R/S02/POST /api/v1/x"]["db"].(map[string]any)["authz_state"] = map[string]any{"modified": []any{map[string]any{"id": 1.0, "version": 3.0}}}
		projectFresh(fresh, declared)
		if res := compareRecords(oldRecs, fresh, approvedDiffs{}); res.failed() {
			t.Fatalf("a record that differs only in declared new tables/columns must compare equal: %s", res.summary(5))
		}
	})
	t.Run("schema_additions_existing_column_difference_still_fails", func(t *testing.T) {
		oldRecs := map[string]map[string]any{"R/S02/POST /api/v1/x": dbRec("R/S02/POST /api/v1/x", map[string]any{"id": 1.0, "name": "a"})}
		fresh := map[string]map[string]any{"R/S02/POST /api/v1/x": dbRec("R/S02/POST /api/v1/x",
			map[string]any{"id": 1.0, "name": "CHANGED", "builtin_key": "user"})}
		projectFresh(fresh, declared)
		if res := compareRecords(oldRecs, fresh, approvedDiffs{}); !res.failed() {
			t.Fatal("a difference in a capture-time column must still fail after projection")
		}
		// An undeclared new column is not projected away either.
		oldRecs = map[string]map[string]any{"R/S02/POST /api/v1/x": dbRec("R/S02/POST /api/v1/x", map[string]any{"id": 1.0, "name": "a"})}
		fresh = map[string]map[string]any{"R/S02/POST /api/v1/x": dbRec("R/S02/POST /api/v1/x",
			map[string]any{"id": 1.0, "name": "a", "builtin_key": "user"})}
		projectFresh(fresh, schemaAdditions{Version: 1})
		if res := compareRecords(oldRecs, fresh, approvedDiffs{}); !res.failed() {
			t.Fatal("a new column that no declaration covers must not be projected away")
		}
		if got := undeclaredStructure(capture, live, schemaAdditions{Version: 1}); len(got) != 2 {
			t.Fatalf("undeclared structure must be listed: %v", got)
		}
		if got := undeclaredStructure(capture, live, declared); len(got) != 0 {
			t.Fatalf("declared structure must not be listed as undeclared: %v", got)
		}
	})
	t.Run("schema_additions_not_from_a_new_migration_refused", func(t *testing.T) {
		man, err := loadManifest()
		if err != nil {
			t.Fatal(err)
		}
		registered := database.MigrationVersions()
		if _, err := loadSchemaAdditions(schemaAdditionsPath(), man.Schema, man.CapturedAt, registered); err != nil {
			t.Fatalf("the real schema-additions.json must load: %v", err)
		}
		write := func(body string) string {
			p := filepath.Join(t.TempDir(), "schema-additions.json")
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}
		for name, body := range map[string]string{
			"migration older than the capture": `{"version":1,"additions":[{"migration":"20260929_notification_channel_min_severity","columns":{"roles":["builtin_key"]}}]}`,
			"migration not registered":         `{"version":1,"additions":[{"migration":"20261201_not_a_migration","columns":{"roles":["builtin_key"]}}]}`,
			"column existed at capture":        `{"version":1,"additions":[{"migration":"20261016_authz_permission_model","columns":{"roles":["name"]}}]}`,
			"table existed at capture":         `{"version":1,"additions":[{"migration":"20261016_authz_permission_model","tables":["roles"]}]}`,
			"column of a table that is new":    `{"version":1,"additions":[{"migration":"20261016_authz_permission_model","columns":{"authz_state":["version"]}}]}`,
			"entry without items":              `{"version":1,"additions":[{"migration":"20261016_authz_permission_model"}]}`,
		} {
			if _, err := loadSchemaAdditions(write(body), man.Schema, man.CapturedAt, registered); err == nil {
				t.Errorf("%s must be refused at load time", name)
			}
		}
	})

	t.Run("ad9_t03_steps_additive_only_two_fields", func(t *testing.T) {
		ad, err := loadApprovedDiffs(filepath.Join(authzBaselineDir, "approved-diffs.json"))
		if err != nil {
			t.Fatal(err)
		}
		// Use the repository's current-user response entry; the status is forced to active so the test
		// does not depend on the entry's lifecycle.
		var entries []approvedEntry
		for _, e := range ad.Entries {
			if e.ID == "AD-9" {
				e.Status = "active"
				entries = append(entries, e)
			}
		}
		step := func(extra map[string]any) map[string]any {
			body := map[string]any{"id": 9.0, "username": "u"}
			for k, v := range extra {
				body[k] = v
			}
			return map[string]any{"id": "T/T03", "steps": []any{map[string]any{"name": "before", "status": 200.0, "body": body}}}
		}
		oldRec := map[string]map[string]any{"T/T03": step(nil)}
		ok := compareRecords(oldRec, map[string]map[string]any{"T/T03": step(map[string]any{"permissions": []any{"asset:view"}, "scope_summary": map[string]any{}})}, approvedDiffs{Entries: entries})
		if ok.failed() || len(ok.Diffs) == 0 {
			t.Fatalf("T/T03 gaining permissions and scope_summary must be approved: %s", ok.summary(5))
		}
		bad := compareRecords(oldRec, map[string]map[string]any{"T/T03": step(map[string]any{"permissions": []any{}, "extra": 1.0})}, approvedDiffs{Entries: entries})
		if !bad.failed() {
			t.Fatal("a third new field in T/T03 steps must not be approved")
		}
		chg := step(nil)
		chg["steps"].([]any)[0].(map[string]any)["body"].(map[string]any)["username"] = "other"
		if r := compareRecords(oldRec, map[string]map[string]any{"T/T03": chg}, approvedDiffs{Entries: entries}); !r.failed() {
			t.Fatal("a changed existing field in T/T03 steps must not be approved")
		}
		// Only the current-user step ("before") may change, and it must gain both fields.
		two := map[string]any{"permissions": []any{"asset:view"}, "scope_summary": map[string]any{}}
		twoStep := func(second map[string]any) map[string]map[string]any {
			rec := step(two)
			rec["steps"] = append(rec["steps"].([]any), map[string]any{"name": "remove-from-group", "status": 200.0, "body": second})
			return map[string]map[string]any{"T/T03": rec}
		}
		oldTwo := step(nil)
		oldTwo["steps"] = append(oldTwo["steps"].([]any), map[string]any{"name": "remove-from-group", "status": 200.0, "body": map[string]any{"id": 1.0}})
		oldTwoRec := map[string]map[string]any{"T/T03": oldTwo}
		if r := compareRecords(oldTwoRec, twoStep(map[string]any{"id": 1.0}), approvedDiffs{Entries: entries}); r.failed() {
			t.Fatalf("control: the current-user step gaining both fields, other step unchanged, must be approved: %s", r.summary(5))
		}
		if r := compareRecords(oldTwoRec, twoStep(map[string]any{"id": 1.0, "permissions": []any{}}), approvedDiffs{Entries: entries}); !r.failed() {
			t.Fatal("a whitelisted key gained by the group-update step must not be approved")
		}
		if r := compareRecords(oldTwoRec, twoStep(map[string]any{"id": 1.0, "permissions": []any{}, "scope_summary": map[string]any{}}), approvedDiffs{Entries: entries}); !r.failed() {
			t.Fatal("both fields gained by the group-update step must not be approved")
		}
		for _, only := range []string{"permissions", "scope_summary"} {
			rec := step(map[string]any{only: two[only]})
			rec["steps"] = append(rec["steps"].([]any), map[string]any{"name": "remove-from-group", "status": 200.0, "body": map[string]any{"id": 1.0}})
			if r := compareRecords(oldTwoRec, map[string]map[string]any{"T/T03": rec}, approvedDiffs{Entries: entries}); !r.failed() {
				t.Fatalf("the current-user step gaining only %s must not be approved", only)
			}
		}
	})
	// A key that vanished is not the same as one that was null.
	t.Run("additive_body_missing_key_is_not_null", func(t *testing.T) {
		old := map[string]map[string]any{"R/S03/GET /api/v1/assets": {"id": "R/S03/GET /api/v1/assets", "status": 200.0, "body": map[string]any{"total": 1.0, "note": nil}}}
		mk := func(body map[string]any) map[string]map[string]any {
			return map[string]map[string]any{"R/S03/GET /api/v1/assets": {"id": "R/S03/GET /api/v1/assets", "status": 200.0, "body": body}}
		}
		add := approvedSelector{Group: "R", Subjects: []string{"S03"}, Keys: []string{"GET /api/v1/assets"}, Fields: []string{"body"}}
		ad := approvedDiffs{Entries: []approvedEntry{{ID: "AD-Z", Status: "active", Selector: add, Expect: map[string]any{"body": "additive"}, Reason: "test"}}}
		if res := compareRecords(old, mk(map[string]any{"total": 1.0, "note": nil, "extra": true}), ad); res.failed() {
			t.Fatalf("control: null kept and a key added must pass: %s", res.summary(5))
		}
		if res := compareRecords(old, mk(map[string]any{"total": 1.0, "extra": true}), ad); !res.failed() {
			t.Fatal("a key that held null and is now missing must not be treated as unchanged")
		}
	})
	t.Run("dates_are_frozen_across_days", func(t *testing.T) {
		capture := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
		const golden = `{"days":["2026-10-13","2026-10-14"],"fixed":"2026-01-02","path":"/days/2026-10-13"}`
		for _, shift := range []int{1, 2, 7, 30} {
			day := func(n int) string { return capture.AddDate(0, 0, shift+n).Format("2006-01-02") }
			fresh := `{"days":["` + day(-2) + `","` + day(-1) + `"],"fixed":"2026-01-02","path":"/days/` + day(-2) + `"}`
			if got := shiftBaselineDatesBy(fresh, capture, shift); got != golden {
				t.Fatalf("shift %d: got %s, want %s", shift, got, golden)
			}
		}
		if shiftBaselineDatesBy(golden, capture, 0) != golden {
			t.Fatal("no shift on the capture date")
		}
	})

}

func normalizeRaw(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return normalizeValue("", v)
}
