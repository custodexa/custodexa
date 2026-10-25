package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuthzBaselineToolingCases pins the comparator features that remove
// seed noise without widening any judgment: per-field approval, the audit
// and body edit expectations, the seed ledger with its id mapping, and the
// fixture markers. Each feature has a passing control and the regressions it
// must still report.
func TestAuthzBaselineToolingCases(t *testing.T) {
	decode := func(s string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("bad fixture: %v", err)
		}
		return m
	}
	recs := func(r map[string]any) map[string]map[string]any {
		return map[string]map[string]any{r["id"].(string): r}
	}
	entry := func(id string, sel approvedSelector, expect map[string]any) approvedEntry {
		return approvedEntry{ID: id, Status: "active", Selector: sel, Expect: expect, Reason: "synthetic"}
	}

	t.Run("per_field_approval", func(t *testing.T) {
		const id = "R/S01/GET /api/v1/assets"
		old := recs(decode(`{"id":"` + id + `","status":200,"body":{"a":1},"audit":[{"action":"read","resource":"asset","id":1}]}`))
		newBoth := recs(decode(`{"id":"` + id + `","status":200,"body":{"a":1,"b":2},"audit":[{"action":"read","resource":"asset","id":1},{"action":"x","resource":"asset","id":2}]}`))
		sel := func(f string) approvedSelector {
			return approvedSelector{Group: "R", Subjects: []string{"S01"}, Keys: []string{"GET /api/v1/assets"}, Fields: []string{f}}
		}
		body := entry("AD-B", sel("body"), map[string]any{"body_added_keys": []any{"b"}})
		audit := entry("AD-A", sel("audit"), map[string]any{auditEditKey: map[string]any{
			"added_rows": []any{map[string]any{"count": 1.0, "row": map[string]any{"action": "x", "resource": "asset"}}}}})
		if r := compareRecords(old, newBoth, approvedDiffs{Entries: []approvedEntry{body, audit}}); r.failed() {
			t.Fatalf("two fields approved by two entries must pass: %s", r.summary(5))
		}
		r := compareRecords(old, newBoth, approvedDiffs{Entries: []approvedEntry{body}})
		if !r.failed() {
			t.Fatal("a field without an approving entry must fail the record")
		}
		for _, d := range r.Diffs {
			if d.Field == "audit" && d.Verdict != "unapproved" || d.Field == "body" && d.Verdict != "approved" {
				t.Errorf("per-field verdicts wrong: %+v", d)
			}
		}
		wrongBody := entry("AD-B", sel("body"), map[string]any{"body_added_keys": []any{"c"}})
		if r := compareRecords(old, newBoth, approvedDiffs{Entries: []approvedEntry{wrongBody, audit}}); !r.failed() {
			t.Fatal("an approved field must not carry a field whose entry's expectation fails")
		}
	})

	t.Run("audit_edit", func(t *testing.T) {
		const id = "R/S01/PUT /api/v1/notification-channels/:id"
		mw := `{"action":"update","path":"/api/v1/notification-channels/1","resource":"notify_channel","status":"success"}`
		oldRow := `{"action":"update","details":"json:{\"event\":\"channel_min_severity_change\"}","error_msg":"min_severity old=low new=medium","resource":"notify_channel"}`
		newRow := `{"action":"update","details":"json:{\"change\":\"updated\",\"event\":\"notification_channel_change\"}","error_msg":"","resource":"notify_channel"}`
		mk := func(rows ...string) map[string]map[string]any {
			return recs(decode(`{"id":"` + id + `","status":200,"audit":[` + strings.Join(rows, ",") + `]}`))
		}
		withID := func(row string, n int) string { return strings.Replace(row, "{", fmt.Sprintf(`{"id":%d,`, n), 1) }
		old := mk(withID(mw, 124), withID(oldRow, 123))
		e := entry("AD-A", approvedSelector{Group: "R", Subjects: []string{"S01"}, Keys: []string{"PUT /api/v1/notification-channels/:id"}, Fields: []string{"audit"}},
			map[string]any{auditEditKey: map[string]any{
				"removed_rows": []any{map[string]any{"count": 1.0, "match": map[string]any{"details.event": "channel_min_severity_change", "error_msg": "min_severity old=low new=medium"}}},
				"added_rows": []any{map[string]any{"count": 1.0, "row": map[string]any{"action": "update", "error_msg": "", "resource": "notify_channel",
					"details": map[string]any{"change": "updated", "event": "notification_channel_change"}}}},
			}})
		ad := approvedDiffs{Entries: []approvedEntry{e}}
		if r := compareRecords(old, mk(withID(mw, 124), withID(newRow, 123)), ad); r.failed() {
			t.Fatalf("control must pass: %s", r.summary(5))
		}
		cases := map[string]map[string]map[string]any{
			"one more row":            mk(withID(mw, 124), withID(newRow, 123), withID(newRow, 125)),
			"old row kept":            mk(withID(mw, 124), withID(oldRow, 123), withID(newRow, 125)),
			"other row changed":       mk(strings.Replace(withID(mw, 124), "success", "denied", 1), withID(newRow, 123)),
			"middleware row missing":  mk(withID(newRow, 123)),
			"added row other content": mk(withID(mw, 124), strings.Replace(withID(newRow, 123), "updated", "created", 1)),
			"added row extra detail":  mk(withID(mw, 124), strings.Replace(withID(newRow, 123), `\"change\"`, `\"probe\":\"x\",\"change\"`, 1)),
			"added row extra column":  mk(withID(mw, 124), strings.Replace(withID(newRow, 123), `"error_msg"`, `"note":"x","error_msg"`, 1)),
			"added row column gone":   mk(withID(mw, 124), strings.Replace(withID(newRow, 123), `"error_msg":"",`, ``, 1)),
		}
		for name, n := range cases {
			if r := compareRecords(old, n, ad); !r.failed() {
				t.Errorf("%s must not be approved", name)
			}
		}
		// details_added_keys: exactly the named keys, nothing else in the row.
		ldap := `{"action":"update","details":"json:{\"directory_id\":1,\"event\":\"ldap_directory_save\"}","resource":"auth"}`
		ldapNew := `{"action":"update","details":"json:{\"correlation_id\":\"\\u003cnonce\\u003e\",\"directory_id\":1,\"event\":\"ldap_directory_save\"}","resource":"auth"}`
		ldapOther := `{"action":"update","details":"json:{\"correlation_id\":\"\\u003cnonce\\u003e\",\"directory_id\":2,\"event\":\"ldap_directory_save\"}","resource":"auth"}`
		const lid = "R/S01/PUT /api/v1/ldap-directory"
		mkl := func(row string) map[string]map[string]any {
			return recs(decode(`{"id":"` + lid + `","status":200,"audit":[` + row + `]}`))
		}
		le := entry("AD-L", approvedSelector{Group: "R", Subjects: []string{"S01"}, Keys: []string{"PUT /api/v1/ldap-directory"}, Fields: []string{"audit"}},
			map[string]any{auditEditKey: map[string]any{"details_added_keys": []any{map[string]any{"count": 1.0, "match": map[string]any{"resource": "auth"}, "keys": []any{"correlation_id"}}}}})
		lad := approvedDiffs{Entries: []approvedEntry{le}}
		if r := compareRecords(mkl(ldap), mkl(ldapNew), lad); r.failed() {
			t.Fatalf("added correlation key must pass: %s", r.summary(5))
		}
		if r := compareRecords(mkl(ldap), mkl(ldapOther), lad); !r.failed() {
			t.Error("an added key together with another changed detail must fail")
		}
	})

	// details_added_keys reads a golden details column holding the empty
	// string as an empty document, and only that: a real refusal entry and
	// real golden records, one whose details is "" and one whose details is
	// a document. Renaming one of the added keys, adding another detail or
	// dropping a golden detail is still reported.
	t.Run("details_added_keys_empty_golden", func(t *testing.T) {
		real, err := loadApprovedDiffs(filepath.Join(authzBaselineDir, "approved-diffs.json"))
		if err != nil {
			t.Fatal(err)
		}
		golden, err := readJSONL(filepath.Join(authzBaselineDir, "r-s02.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		const (
			emptyKey = "GET /api/v1/access-reviews"
			docKey   = "GET /api/v1/audit-logs"
		)
		var e approvedEntry
		for _, x := range real.Entries {
			if x.ID == "AD-8u01" {
				e = x
			}
		}
		if e.ID == "" || !containsStr(e.Selector.Subjects, "S02") || !containsStr(e.Selector.Keys, emptyKey) || !containsStr(e.Selector.Keys, docKey) {
			t.Fatalf("AD-8u01 must list S02, %q and %q", emptyKey, docKey)
		}
		edits, err := parseAuditEdit(e.Expect)
		if err != nil || len(edits.DetailsAdded) != 1 {
			t.Fatalf("AD-8u01 must declare one details_added_keys edit: %v", err)
		}
		added := map[string]any{}
		for col, v := range edits.DetailsAdded[0].Match {
			added[strings.TrimPrefix(col, "details.")] = v
		}
		for _, k := range edits.DetailsAdded[0].Keys {
			if _, ok := added[k]; !ok {
				t.Fatalf("AD-8u01 key %q has no matched value", k)
			}
		}
		check := func(key, wantGolden string) {
			id := "R/S02/" + key
			old, ok := golden[id]
			if !ok {
				t.Fatalf("golden has no %s", id)
			}
			rows, _ := alertRows(old["audit"])
			if len(rows) != 1 {
				t.Fatalf("%s: want one golden audit row, got %d", id, len(rows))
			}
			if d, _ := rows[0]["details"].(string); (wantGolden == "") != (d == "") {
				t.Fatalf("%s: golden details %q, want empty=%v", id, d, wantGolden == "")
			}
			one := e
			one.Selector.Subjects = []string{"S02"}
			one.Selector.Keys = []string{key}
			ad := approvedDiffs{Entries: []approvedEntry{one}}
			fresh := func(edit func(row, details map[string]any)) map[string]map[string]any {
				rec := deepCopyJSON(old).(map[string]any)
				row := rec["audit"].([]any)[0].(map[string]any)
				details := map[string]any{}
				if s, _ := row["details"].(string); s != "" {
					if err := json.Unmarshal([]byte(strings.TrimPrefix(s, "json:")), &details); err != nil {
						t.Fatal(err)
					}
				}
				for k, v := range added {
					details[k] = v
				}
				if edit != nil {
					edit(row, details)
				}
				b, _ := json.Marshal(details)
				row["details"] = "json:" + string(b)
				return map[string]map[string]any{id: rec}
			}
			olds := map[string]map[string]any{id: old}
			r := compareRecords(olds, fresh(nil), ad)
			if r.failed() {
				t.Fatalf("%s: control must pass: %s", id, r.summary(5))
			}
			t.Logf("%s golden details %q: control approved by %s", id, rows[0]["details"], e.ID)
			cases := map[string]func(row, details map[string]any){
				"added key renamed": func(_, d map[string]any) { d["required_permission"] = d["required"]; delete(d, "required") },
				"extra detail":      func(_, d map[string]any) { d["probe"] = "x" },
				"other column":      func(row, _ map[string]any) { row["status_code"] = 500.0 },
			}
			if wantGolden != "" {
				cases["golden detail dropped"] = func(_, d map[string]any) {
					for k := range d {
						if _, ok := added[k]; !ok {
							delete(d, k)
						}
					}
				}
				cases["golden detail renamed"] = func(_, d map[string]any) { d["query_x"] = d["query"]; delete(d, "query") }
			} else {
				cases["added keys missing"] = func(_, d map[string]any) {
					for k := range added {
						delete(d, k)
					}
				}
			}
			for name, edit := range cases {
				r := compareRecords(olds, fresh(edit), ad)
				var verdict string
				for _, d := range r.Diffs {
					if d.Field == "audit" {
						verdict = d.Verdict
					}
				}
				if !r.failed() || verdict == "approved" {
					t.Errorf("%s: %s must not be approved", id, name)
				}
				t.Logf("%s: %s -> audit %s", id, name, verdict)
			}
			if r := compareRecords(olds, fresh(nil), approvedDiffs{}); !r.failed() {
				t.Errorf("%s: without the entry the added keys must be unapproved", id)
			}
		}
		check(emptyKey, "")
		check(docKey, "document")
	})

	// The real OIDC settings entry: an added audit row is compared whole, so
	// a regression that writes a secret value into the details of the
	// service-level record is not approved by the entry that approves the
	// record itself.
	t.Run("added_row_whole_row", func(t *testing.T) {
		real, err := loadApprovedDiffs(filepath.Join(authzBaselineDir, "approved-diffs.json"))
		if err != nil {
			t.Fatal(err)
		}
		var e approvedEntry
		for _, x := range real.Entries {
			if x.ID == "AD-15b" {
				e = x
			}
		}
		// One record only: narrow the entry to its subject so that the
		// all-keys rule does not ask for the other subjects' records.
		e.Selector.Subjects = []string{"S01"}
		edits, err := parseAuditEdit(e.Expect)
		if err != nil || len(edits.Added) != 1 {
			t.Fatalf("AD-15b must declare one added row: %v", err)
		}
		const id = "R/S01/PUT /api/v1/oidc-providers/:id"
		mw := map[string]any{"id": 124.0, "action": "update", "method": "PUT", "path": "/api/v1/oidc-providers/2", "resource": "oidc_provider", "status": "success"}
		freshRow := func(subject string, edit func(details map[string]any)) map[string]any {
			v, ok := resolveSubjectTokens(deepCopyJSON(edits.Added[0].Row), subject)
			if !ok {
				t.Fatalf("subject %s does not resolve", subject)
			}
			row := v.(map[string]any)
			details := row["details"].(map[string]any)
			if edit != nil {
				edit(details)
			}
			b, _ := json.Marshal(details)
			row["details"] = "json:" + string(b)
			row["id"] = 123.0
			return row
		}
		rec := func(rows ...map[string]any) map[string]map[string]any {
			arr := make([]any, len(rows))
			for i, r := range rows {
				arr[i] = r
			}
			return map[string]map[string]any{id: {"id": id, "status": 200.0, "audit": arr}}
		}
		ad := approvedDiffs{Entries: []approvedEntry{e}}
		old := rec(mw)
		if r := compareRecords(old, rec(mw, freshRow("S01", nil)), ad); r.failed() {
			t.Fatalf("control: the declared row must be approved: %s", r.summary(5))
		}
		cases := map[string]map[string]map[string]any{
			"plaintext secret in details": rec(mw, freshRow("S01", func(d map[string]any) { d["client_secret_probe"] = "probe-secret-value" })),
			"detail value changed":        rec(mw, freshRow("S01", func(d map[string]any) { d["secret_changed"] = true })),
			"detail removed":              rec(mw, freshRow("S01", func(d map[string]any) { delete(d, "provider_id") })),
			"another actor":               rec(mw, freshRow("S06", nil)),
		}
		for name, n := range cases {
			r := compareRecords(old, n, ad)
			if !r.failed() {
				t.Errorf("%s must not be approved", name)
			}
			for _, d := range r.Diffs {
				if d.Field == "audit" && d.Verdict != "expect-mismatch" {
					t.Errorf("%s: audit verdict %s, want expect-mismatch", name, d.Verdict)
				}
			}
		}
		// A declared row may not leave out the whole row or carry the id.
		for _, bad := range []map[string]any{
			{"count": 1.0, "match": map[string]any{"action": "update", "resource": "auth"}},
			{"count": 1.0, "row": map[string]any{"id": 1.0, "action": "update"}},
		} {
			if _, err := parseAuditEdit(map[string]any{auditEditKey: map[string]any{"added_rows": []any{bad}}}); err == nil {
				t.Errorf("added_rows %v must be rejected", bad)
			}
		}
		if (seedLedgerFile{Version: 1, Golden: map[string]int{"audit_logs": 1},
			Additions: []seedAddition{{Table: "audit_logs", Count: 1, Reason: "r"}}}).validate() == nil {
			t.Error("a seed addition without its whole row must be rejected")
		}
	})

	// The complete-body check covers selectors without keys: a group-wide
	// entry (the pending forbidden-shape entries) cannot be activated to
	// approve the body of a route captured in full without stating the edit.
	t.Run("complete_body_group_scope", func(t *testing.T) {
		real, err := loadApprovedDiffs(filepath.Join(authzBaselineDir, "approved-diffs.json"))
		if err != nil {
			t.Fatal(err)
		}
		var checked []string
		for _, x := range real.Entries {
			if x.Status != "pending" || x.Selector.Group != "R" || len(x.Selector.Keys) > 0 || !containsStr(x.Selector.Fields, "body") {
				continue
			}
			checked = append(checked, x.ID)
			x.Status = "active"
			if err := (approvedDiffs{Entries: []approvedEntry{x}}).validate(); err == nil {
				t.Errorf("%s activated without keys must be rejected", x.ID)
			}
		}
		if !containsStr(checked, "AD-3") {
			t.Fatalf("expected the pending group-wide body entry AD-3, checked %v", checked)
		}
		byScenario := entry("AD-S", approvedSelector{Scenarios: []string{"R/S01/GET /api/v1/security-policies"}, Fields: []string{"body"}}, nil)
		if (approvedDiffs{Entries: []approvedEntry{byScenario}}).validate() == nil {
			t.Error("a scenario selector naming a complete-body route must be rejected")
		}
	})

	t.Run("body_edit", func(t *testing.T) {
		const id = "R/S01/GET /api/v1/security-policies"
		item := func(k, v string) map[string]any { return map[string]any{"key": k, "value": v} }
		oldBody := map[string]any{"data": []any{item("a", "1"), item("b", "2")}, "count": 2.0}
		newBody := map[string]any{"data": []any{item("a", "1"), item("new", "9"), item("b", "2")}, "count": 3.0}
		sel := approvedSelector{Group: "R", Subjects: []string{"S01"}, Keys: []string{"GET /api/v1/security-policies"}, Fields: []string{"body"}}
		e := entry("AD-P", sel, map[string]any{bodyEditKey: map[string]any{
			"added_items": []any{map[string]any{"path": "data", "match": map[string]any{"key": "new"}, "count": 1.0}},
			"incremented": []any{map[string]any{"path": "count", "by": 1.0}},
		}})
		ad := approvedDiffs{Entries: []approvedEntry{e}}
		rec := func(b any) map[string]map[string]any {
			return map[string]map[string]any{id: {"id": id, "status": 200.0, "body": deepCopyJSON(b)}}
		}
		for name, golden := range map[string]any{"full golden": oldBody, "summarized golden": forceSummarizeBody(deepCopyJSON(oldBody))} {
			if r := compareRecords(rec(golden), rec(newBody), ad); r.failed() {
				t.Errorf("%s: the declared addition must pass: %s", name, r.summary(5))
			}
			changed := deepCopyJSON(newBody).(map[string]any)
			changed["data"].([]any)[0].(map[string]any)["value"] = "7"
			if r := compareRecords(rec(golden), rec(changed), ad); !r.failed() {
				t.Errorf("%s: another item changing must fail", name)
			}
			if r := compareRecords(rec(golden), rec(oldBody), approvedDiffs{}); name == "summarized golden" && r.failed() {
				t.Errorf("%s: an unchanged full body must equal its summary: %s", name, r.summary(5))
			}
			two := deepCopyJSON(newBody).(map[string]any)
			two["data"] = append(two["data"].([]any), item("new", "9"))
			if r := compareRecords(rec(golden), rec(two), ad); !r.failed() {
				t.Errorf("%s: the item added twice must fail", name)
			}
		}
		// An active entry may not approve the body of a route captured in
		// full with no stated edit.
		bad := entry("AD-Q", sel, nil)
		if err := (approvedDiffs{Entries: []approvedEntry{bad}}).validate(); err == nil {
			t.Error("an active null-expectation entry on a complete-body route must be rejected")
		}
	})

	t.Run("body_item_edits", func(t *testing.T) {
		const id = "R/S01/GET /api/v1/security-policies"
		item := func(k, v string) map[string]any { return map[string]any{"key": k, "value": v, "owner": "system"} }
		oldBody := map[string]any{"data": []any{item("a", "1"), item("b", "2"), item("c", "3")}}
		newBody := deepCopyJSON(oldBody).(map[string]any)
		newBody["data"].([]any)[0].(map[string]any)["min"] = 7.0
		newBody["data"].([]any)[1].(map[string]any)["owner"] = "u1"
		sel := approvedSelector{Group: "R", Subjects: []string{"S01"}, Keys: []string{"GET /api/v1/security-policies"}, Fields: []string{"body"}}
		edits := []any{
			map[string]any{"path": "data", "match": map[string]any{"key": "a"}, "count": 1.0, "added": map[string]any{"min": 7.0}},
			map[string]any{"path": "data", "match": map[string]any{"key": "b"}, "count": 1.0,
				"changed": map[string]any{"owner": map[string]any{"from": "system", "to": "u1"}}},
		}
		ad := approvedDiffs{Entries: []approvedEntry{entry("AD-P", sel, map[string]any{bodyEditKey: map[string]any{"item_edits": edits}})}}
		if err := ad.validate(); err != nil {
			t.Fatalf("valid item_edits rejected: %v", err)
		}
		rec := func(b any) map[string]map[string]any {
			return map[string]map[string]any{id: {"id": id, "status": 200.0, "body": deepCopyJSON(b)}}
		}
		for name, golden := range map[string]any{"full golden": oldBody, "summarized golden": forceSummarizeBody(deepCopyJSON(oldBody))} {
			if r := compareRecords(rec(golden), rec(newBody), ad); r.failed() {
				t.Errorf("%s: the declared item edits must pass: %s", name, r.summary(5))
			}
			mutate := map[string]func(m map[string]any){
				"added field with another value":   func(m map[string]any) { m["data"].([]any)[0].(map[string]any)["min"] = 8.0 },
				"changed field with another value": func(m map[string]any) { m["data"].([]any)[1].(map[string]any)["owner"] = "u2" },
				"an undeclared field on the item":  func(m map[string]any) { m["data"].([]any)[0].(map[string]any)["max"] = 9.0 },
				"another item edited too":          func(m map[string]any) { m["data"].([]any)[2].(map[string]any)["min"] = 7.0 },
				"declared addition missing":        func(m map[string]any) { delete(m["data"].([]any)[0].(map[string]any), "min") },
				"declared change missing":          func(m map[string]any) { m["data"].([]any)[1].(map[string]any)["owner"] = "system" },
			}
			for what, f := range mutate {
				b := deepCopyJSON(newBody).(map[string]any)
				f(b)
				if r := compareRecords(rec(golden), rec(b), ad); !r.failed() {
					t.Errorf("%s: %s must fail", name, what)
				}
			}
			two := deepCopyJSON(newBody).(map[string]any)
			two["data"] = append(two["data"].([]any), deepCopyJSON(two["data"].([]any)[0]))
			if r := compareRecords(rec(golden), rec(two), ad); !r.failed() {
				t.Errorf("%s: a match reaching more items than count must fail", name)
			}
			short := approvedDiffs{Entries: []approvedEntry{entry("AD-P", sel, map[string]any{bodyEditKey: map[string]any{"item_edits": []any{
				map[string]any{"path": "data", "match": map[string]any{"key": "a"}, "count": 2.0, "added": map[string]any{"min": 7.0}},
				edits[1],
			}}})}}
			if r := compareRecords(rec(golden), rec(newBody), short); !r.failed() {
				t.Errorf("%s: a match reaching fewer items than count must fail", name)
			}
		}
		for what, bad := range map[string]map[string]any{
			"no edit":             {"path": "data", "match": map[string]any{"key": "a"}, "count": 1.0},
			"match on edited key": {"path": "data", "match": map[string]any{"min": 7.0}, "count": 1.0, "added": map[string]any{"min": 7.0}},
			"from equals to":      {"path": "data", "match": map[string]any{"key": "b"}, "count": 1.0, "changed": map[string]any{"owner": map[string]any{"from": "x", "to": "x"}}},
			"unknown key":         {"path": "data", "match": map[string]any{"key": "a"}, "count": 1.0, "added": map[string]any{"min": 7.0}, "extra": true},
			"zero count":          {"path": "data", "match": map[string]any{"key": "a"}, "count": 0.0, "added": map[string]any{"min": 7.0}},
		} {
			x := approvedDiffs{Entries: []approvedEntry{entry("AD-P", sel, map[string]any{bodyEditKey: map[string]any{"item_edits": []any{bad}}})}}
			if x.validate() == nil {
				t.Errorf("item_edits with %s must be rejected", what)
			}
		}
	})

	t.Run("seed_ledger", func(t *testing.T) {
		l := seedLedgerFile{Version: 1, Golden: map[string]int{"audit_logs": 3},
			Additions: []seedAddition{{Table: "audit_logs", Count: 1, Row: map[string]any{"resource": "x", "action": "create"}, Reason: "r"}}}
		row := func(id float64, res string) map[string]any {
			return map[string]any{"@rowid": id, "resource": res, "action": "create"}
		}
		tpl := map[string][]map[string]any{"audit_logs": {row(1, "a"), row(2, "x"), row(3, "a"), row(4, "a")}}
		added := map[string][]float64{}
		if p := checkSeedLedger(l, map[string]int{"audit_logs": 4}, tpl, added); len(p) != 0 {
			t.Fatalf("exact ledger must hold: %v", p)
		}
		m := seedMapping(added)
		if m.mapID("audit_logs", 1.0) != 1.0 || m.mapID("audit_logs", 3.0) != 2.0 || m.mapID("audit_logs", 7.0) != 6.0 || m.mapID("audit_logs", 2.0) != seedAddedID {
			t.Errorf("id mapping wrong: %v %v %v %v", m.mapID("audit_logs", 1.0), m.mapID("audit_logs", 3.0), m.mapID("audit_logs", 7.0), m.mapID("audit_logs", 2.0))
		}
		if m.mapCount("audit_logs", 4.0) != 3.0 {
			t.Error("count mapping wrong")
		}
		more := map[string][]map[string]any{"audit_logs": append(append([]map[string]any(nil), tpl["audit_logs"]...), row(5, "a"))}
		if p := checkSeedLedger(l, map[string]int{"audit_logs": 5}, more, map[string][]float64{}); len(p) == 0 {
			t.Error("seeding that writes one undeclared row more must fail")
		}
		fewer := map[string][]map[string]any{"audit_logs": tpl["audit_logs"][:3]}
		if p := checkSeedLedger(l, map[string]int{"audit_logs": 3}, fewer, map[string][]float64{}); len(p) == 0 {
			t.Error("seeding that writes one row less must fail")
		}
		noMatch := map[string][]map[string]any{"audit_logs": {row(1, "a"), row(2, "a"), row(3, "a"), row(4, "a")}}
		if p := checkSeedLedger(l, map[string]int{"audit_logs": 4}, noMatch, map[string][]float64{}); len(p) == 0 {
			t.Error("a declared addition that matches no template row must fail even when the count adds up")
		}
		twice := map[string][]map[string]any{"audit_logs": {row(1, "x"), row(2, "x"), row(3, "a"), row(4, "a")}}
		if p := checkSeedLedger(l, map[string]int{"audit_logs": 4}, twice, map[string][]float64{}); len(p) == 0 {
			t.Error("a declaration matching more rows than it declares must fail")
		}
		// The declared row is compared whole: the same row with one more
		// column, or another value in a column the declaration states, is
		// another row.
		extra := map[string][]map[string]any{"audit_logs": {row(1, "a"), row(2, "x"), row(3, "a"), row(4, "a")}}
		extra["audit_logs"][1]["details"] = `json:{"client_secret_probe":"probe-secret-value"}`
		if p := checkSeedLedger(l, map[string]int{"audit_logs": 4}, extra, map[string][]float64{}); len(p) == 0 {
			t.Error("a declared seed row carrying an undeclared column must fail")
		}
		changed := map[string][]map[string]any{"audit_logs": {row(1, "a"), row(2, "x"), row(3, "a"), row(4, "a")}}
		changed["audit_logs"][1]["action"] = "update"
		if p := checkSeedLedger(l, map[string]int{"audit_logs": 4}, changed, map[string][]float64{}); len(p) == 0 {
			t.Error("a declared seed row with another value must fail")
		}
		// Mapped fresh records: scenario ids move back; a row more or less still differs.
		const id = "R/S01/GET /api/v1/audit-logs"
		golden := recs(decode(`{"id":"` + id + `","status":200,"body":{"data":[{"id":3},{"id":1}],"total":3},"audit":[{"action":"read","id":4}]}`))
		fresh := func(audit string) map[string]map[string]any {
			r := recs(decode(`{"id":"` + id + `","status":200,"body":{"data":[{"id":4},{"id":1}],"total":4},"audit":[` + audit + `]}`))
			applySeedMapping(r, m, nil)
			return r
		}
		if r := compareRecords(golden, fresh(`{"action":"read","id":5}`), approvedDiffs{}); r.failed() {
			t.Fatalf("mapped ids, counts and listed ids must compare equal: %s", r.summary(5))
		}
		if r := compareRecords(golden, fresh(`{"action":"read","id":5},{"action":"read","id":6}`), approvedDiffs{}); !r.failed() {
			t.Error("a scenario writing one audit row more must still differ")
		}
		if r := compareRecords(golden, fresh(``), approvedDiffs{}); !r.failed() {
			t.Error("a scenario writing one audit row less must still differ")
		}
		// Flow setup additions are taken out of that record's ids only.
		const fid = "B1/S01/group-connect"
		fgold := recs(decode(`{"id":"` + fid + `","status":200,"audit":[{"action":"create","id":6}]}`))
		ffresh := func(setup map[string]seedMapping) map[string]map[string]any {
			r := recs(decode(`{"id":"` + fid + `","status":200,"audit":[{"action":"create","id":8}]}`))
			applySeedMapping(r, m, setup)
			return r
		}
		if r := compareRecords(fgold, ffresh(map[string]seedMapping{fid: {"audit_logs": {6}}}), approvedDiffs{}); r.failed() {
			t.Errorf("a declared setup row must be taken out of the step ids: %s", r.summary(5))
		}
		if r := compareRecords(fgold, ffresh(map[string]seedMapping{"B1/S02/other": {"audit_logs": {6}}}), approvedDiffs{}); !r.failed() {
			t.Error("another scenario's setup rows must not move this record's ids")
		}
	})

	t.Run("fixture_markers", func(t *testing.T) {
		route := routeEntry{Method: "POST", Path: "/api/v1/command-alerts/:id/review", Params: map[string]any{"id": "{commandAlert.1}"}}
		const id = "R/S01/POST /api/v1/command-alerts/:id/review"
		rec := func(n int, resID int) map[string]map[string]any {
			return recs(decode(fmt.Sprintf(`{"id":"%s","status":200,"audit":[{"path":"/api/v1/command-alerts/%d/review","resource":"command_alert","resource_id":%d}],
				"db":{"command_alerts":{"modified":[{"@rowid":[%d,%d],"disposition":["pending","benign"]}]}}}`, id, n, resID, n, n)))
		}
		m := seedMapping{"command_alerts": {1, 2, 3}}
		mark := func(o, n map[string]map[string]any) compareResult {
			applySeedMapping(n, m, nil)
			a, b := withFixtureMarkers(o, n, []routeEntry{route}, map[string]any{"commandAlert.1": uint(4)}, m)
			return compareRecords(a, b, approvedDiffs{})
		}
		if r := mark(rec(1, 1), rec(4, 4)); r.failed() {
			t.Fatalf("the same operation on the moved fixture must compare equal: %s", r.summary(5))
		}
		if r := mark(rec(1, 1), rec(4, 5)); !r.failed() {
			t.Error("an audit record naming another alert must still differ")
		}
		other := rec(4, 4)
		other[id]["db"].(map[string]any)["command_alerts"].(map[string]any)["modified"].([]any)[0].(map[string]any)["@rowid"] = []any{6.0, 6.0}
		if r := mark(rec(1, 1), other); !r.failed() {
			t.Error("a write to another alert row must still differ")
		}
		golden := rec(1, 1)
		if _, _ = withFixtureMarkers(golden, rec(4, 4), []routeEntry{route}, map[string]any{"commandAlert.1": uint(4)}, m); canon(golden[id]["audit"]) != canon(rec(1, 1)[id]["audit"]) {
			t.Error("markers must be applied to copies, never to the golden records")
		}
	})

	// The ledger's golden counts must agree with the golden records: every
	// scenario starts from that template, so the first row any scenario adds
	// to a ledger table has id golden+1 and none has a lower one.
	t.Run("ledger_matches_golden_records", func(t *testing.T) {
		l, err := loadSeedLedger(seedLedgerPath())
		if err != nil {
			t.Fatal(err)
		}
		files, _ := filepath.Glob(filepath.Join(authzBaselineDir, "*.jsonl"))
		minID := map[string]float64{}
		for _, f := range files {
			recs, err := readJSONL(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range recs {
				for _, field := range []string{"audit", "alerts"} {
					rows, _ := r[field].([]any)
					for _, x := range rows {
						row, _ := x.(map[string]any)
						tbl := "audit_logs"
						if field == "alerts" {
							tbl, _ = row["@table"].(string)
						}
						if id, ok := row["id"].(float64); ok && (minID[tbl] == 0 || id < minID[tbl]) {
							minID[tbl] = id
						}
					}
				}
			}
		}
		for tbl, n := range l.Golden {
			if got, ok := minID[tbl]; ok && got != float64(n+1) {
				t.Errorf("seed ledger golden %s=%d, but the lowest scenario row id in the golden records is %v", tbl, n, got)
			}
		}
		if _, ok := minID["audit_logs"]; !ok {
			t.Error("golden records hold no audit rows; the ledger cannot be checked")
		}
		raw, _ := os.ReadFile(seedLedgerPath())
		if strings.Contains(string(raw), "*") {
			t.Error("seed ledger must not use wildcards")
		}
	})
}
