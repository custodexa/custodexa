package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// auditEditKey is an opt-in expectation for the audit field, the
// counterpart of alerts_edit. An entry that declares it approves only the
// listed edits to the audit rows of a record, never the whole field.
// Entries that match the same record are judged together: their edits,
// applied to the golden rows, must reproduce the fresh rows exactly.
//
//	"audit_edit": {
//	  "added_rows":         [{"count": 1, "row": {"action": "update", "details": {...}, ...}}],
//	  "removed_rows":       [{"count": 1, "match": {...}}],
//	  "details_added_keys": [{"count": 1, "match": {...}, "keys": ["correlation_id"]}]
//	}
//
// added_rows: exactly count fresh rows that are not golden rows and equal
// the declared row as a whole (see declaredRowEquals): every column except
// the id is declared, so an added row cannot carry anything the entry does
// not state.
// removed_rows: exactly count golden rows that match are gone.
// details_added_keys: exactly count golden rows that match reappear with
// these keys added to their details document and nothing else changed.
// A match column "details.<key>" reads a key of the details document;
// values compare as JSON, so a list or object can be matched exactly.
//
// Row ids are not compared under this expectation: an added row takes an id
// in the middle of the scenario's rows and moves the ids of the rows written
// after it. Row content and the number of rows are compared exactly.
const auditEditKey = "audit_edit"

type auditRowEdit struct {
	Count int
	Match map[string]any // removed_rows, details_added_keys
	Row   map[string]any // added_rows: the whole row except its id
	Keys  []string
}

type auditEdit struct {
	Added, Removed, DetailsAdded []auditRowEdit
}

func parseAuditEdit(expect map[string]any) (auditEdit, error) {
	var out auditEdit
	raw, ok := expect[auditEditKey].(map[string]any)
	if !ok || len(raw) == 0 {
		return out, fmt.Errorf("%s must hold at least one edit", auditEditKey)
	}
	if len(expect) != 1 {
		return out, fmt.Errorf("an entry with %s must not carry other expectations", auditEditKey)
	}
	for kind, v := range raw {
		list, ok := v.([]any)
		if !ok || len(list) == 0 {
			return out, fmt.Errorf("%s.%s must be a non-empty list", auditEditKey, kind)
		}
		for _, x := range list {
			m, _ := x.(map[string]any)
			cnt, _ := m["count"].(float64)
			match, _ := m["match"].(map[string]any)
			ed := auditRowEdit{Count: int(cnt), Match: match}
			want := 2
			switch kind {
			case "added_rows":
				row, _ := m["row"].(map[string]any)
				if err := validateDeclaredRow(row); err != nil {
					return out, fmt.Errorf("added_rows: %w", err)
				}
				ed.Match, ed.Row = nil, row
			case "removed_rows":
				if len(match) < 2 {
					return out, fmt.Errorf("%s needs at least two match columns", kind)
				}
			case "details_added_keys":
				want = 3
				ed.Keys = anyStrings(m["keys"])
				if len(match) < 1 || len(ed.Keys) == 0 {
					return out, fmt.Errorf("details_added_keys needs a match and keys")
				}
				for _, k := range ed.Keys {
					if k == "" {
						return out, fmt.Errorf("details_added_keys keys must be non-empty")
					}
				}
			default:
				return out, fmt.Errorf("unknown %s edit %q", auditEditKey, kind)
			}
			if cnt < 1 || len(m) != want {
				return out, fmt.Errorf("%s.%s entries need count >= 1 and only the documented keys", auditEditKey, kind)
			}
			switch kind {
			case "added_rows":
				out.Added = append(out.Added, ed)
			case "removed_rows":
				out.Removed = append(out.Removed, ed)
			default:
				out.DetailsAdded = append(out.DetailsAdded, ed)
			}
		}
	}
	return out, nil
}

// validateAuditEdit is called from approvedDiffs.validate.
func validateAuditEdit(e approvedEntry) error {
	if _, ok := e.Expect[auditEditKey]; !ok {
		return nil
	}
	if _, err := parseAuditEdit(e.Expect); err != nil {
		return fmt.Errorf("%s: %w", e.ID, err)
	}
	if len(e.Selector.Fields) != 1 || e.Selector.Fields[0] != "audit" {
		return fmt.Errorf("%s: an %s entry must select the audit field only", e.ID, auditEditKey)
	}
	return nil
}

// rowDetails decodes the details document of an audit row ("json:" prefix
// as written by the normalizer).
func rowDetails(row map[string]any) (map[string]any, bool) {
	s, _ := row["details"].(string)
	var d map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(s, "json:")), &d); err != nil {
		return nil, false
	}
	return d, true
}

// rowValue reads a match column: a plain column, or "details.<key>".
func rowValue(row map[string]any, col string) (any, bool) {
	if key, ok := strings.CutPrefix(col, "details."); ok {
		d, ok := rowDetails(row)
		if !ok {
			return nil, false
		}
		v, ok := d[key]
		return v, ok
	}
	v, ok := row[col]
	return v, ok
}

func auditRowMatches(row map[string]any, match map[string]any) bool {
	for col, want := range match {
		v, ok := rowValue(row, col)
		if !ok || canon(v) != canon(want) {
			return false
		}
	}
	return true
}

// withoutID copies rows dropping the id column.
func withoutID(rows []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		c := map[string]any{}
		for k, v := range r {
			if k != "id" {
				c[k] = v
			}
		}
		out = append(out, c)
	}
	return out
}

// stripDetailsKeys returns a copy of row whose details document no longer
// carries keys; ok is false unless every key was present.
func stripDetailsKeys(row map[string]any, keys []string) (map[string]any, bool) {
	d, ok := rowDetails(row)
	if !ok {
		return nil, false
	}
	for _, k := range keys {
		if _, has := d[k]; !has {
			return nil, false
		}
		delete(d, k)
	}
	b, _ := json.Marshal(d)
	c := map[string]any{}
	for k, v := range row {
		c[k] = v
	}
	c["details"] = "json:" + string(b)
	return c, true
}

// emptyGoldenDetails is the one place where a golden details column holding
// the empty string counts as an empty document, and it serves
// details_added_keys only: a stripped row whose details document is empty
// stands for a golden row whose details is "". ok is false unless the
// stripped details is exactly the empty document and such a golden row
// exists; any other remaining detail still has to match a parsed golden
// document.
func emptyGoldenDetails(expected []map[string]any, stripped map[string]any) (map[string]any, bool) {
	if s, _ := stripped["details"].(string); s != "json:{}" {
		return nil, false
	}
	c := make(map[string]any, len(stripped))
	for k, v := range stripped {
		c[k] = v
	}
	c["details"] = ""
	return c, containsRow(expected, c)
}

func removeRow(rows []map[string]any, r map[string]any) ([]map[string]any, bool) {
	for i, x := range rows {
		if canon(x) == canon(r) {
			return append(append([]map[string]any(nil), rows[:i]...), rows[i+1:]...), true
		}
	}
	return rows, false
}

// auditEditHolds reports whether the audit edits declared by the active
// entries that match the record explain the difference exactly.
func auditEditHolds(entries []approvedEntry, id string, old, new map[string]any) bool {
	_, subject, _ := scenarioParts(id)
	oldRows, ok1 := alertRows(old["audit"])
	newRows, ok2 := alertRows(new["audit"])
	if !ok1 || !ok2 {
		return false
	}
	var edits []auditEdit
	for _, e := range entries {
		if e.Status != "active" || e.Expect == nil || e.Expect[auditEditKey] == nil {
			continue
		}
		if !e.Selector.matches(id, old, []string{"audit"}) {
			continue
		}
		ed, err := parseAuditEdit(e.Expect)
		if err != nil {
			return false
		}
		edits = append(edits, ed)
	}
	if len(edits) == 0 {
		return false
	}
	expected := withoutID(oldRows)
	rest := withoutID(newRows)
	for _, ed := range edits {
		for _, rm := range ed.Removed {
			n := 0
			var kept []map[string]any
			for _, r := range expected {
				if n < rm.Count && auditRowMatches(r, rm.Match) && !containsRow(rest, r) {
					n++
					continue
				}
				kept = append(kept, r)
			}
			if n != rm.Count {
				return false
			}
			expected = kept
		}
	}
	for _, ed := range edits {
		for _, da := range ed.DetailsAdded {
			n := 0
			for i, r := range rest {
				if n >= da.Count || !auditRowMatches(r, da.Match) {
					continue
				}
				stripped, ok := stripDetailsKeys(r, da.Keys)
				if ok && !containsRow(expected, stripped) {
					stripped, ok = emptyGoldenDetails(expected, stripped)
				}
				// The stripped row lacks the keys, so a golden row equal to it
				// did not carry them either.
				if !ok || !containsRow(expected, stripped) {
					continue
				}
				rest[i] = stripped
				n++
			}
			if n != da.Count {
				return false
			}
		}
	}
	for _, ed := range edits {
		for _, ad := range ed.Added {
			n := 0
			var kept []map[string]any
			for _, r := range rest {
				if n < ad.Count && declaredRowEquals(r, ad.Row, subject) && !containsRow(expected, r) {
					n++
					continue
				}
				kept = append(kept, r)
			}
			if n != ad.Count {
				return false
			}
			rest = kept
		}
	}
	if len(rest) != len(expected) {
		return false
	}
	for _, r := range rest {
		var ok bool
		if expected, ok = removeRow(expected, r); !ok {
			return false
		}
	}
	return len(expected) == 0
}

// ---- whole declared rows ----
//
// A declared row (audit_edit and alerts_edit added_rows, seed ledger
// additions) states a row of an append-only table as a whole. A row equals
// it when it holds exactly the declared columns besides its id (and the
// template row id "@rowid"), each with the declared value. Columns are taken
// as normalized: time columns read "<time>", nonces "<nonce>". An embedded
// document column ("json:..." after normalization, such as details or
// cause_params) may be declared as the decoded object or list, which is
// compared with the decoded document.
//
// The actor of an R-group scenario differs per subject. A declared value
// "<subject.id>" or "<subject.username>" stands for the scenario subject's
// user id or username, read from subjects-auth-me.json (which the coverage
// test keeps equal to the live /auth/me answers). Where the subject has no
// such value (S00, flow and seed rows) the row never equals.

const (
	subjectIDToken       = "<subject.id>"
	subjectUsernameToken = "<subject.username>"
)

// declaredRowSkip are the columns a declared row leaves out.
var declaredRowSkip = map[string]bool{"id": true, "@rowid": true}

func validateDeclaredRow(row map[string]any) error {
	if len(row) == 0 {
		return fmt.Errorf("needs the whole row in \"row\"")
	}
	for k := range row {
		if declaredRowSkip[k] {
			return fmt.Errorf("a declared row must not carry %q", k)
		}
	}
	return nil
}

type subjectIdentity struct {
	ID       any
	Username any
}

var (
	subjectIdentityOnce sync.Once
	subjectIdentityVal  map[string]subjectIdentity
)

// subjectIdentities reads the user id and username of every subject from
// subjects-auth-me.json; subjects without them are absent.
func subjectIdentities() map[string]subjectIdentity {
	subjectIdentityOnce.Do(func() {
		subjectIdentityVal = map[string]subjectIdentity{}
		raw, err := os.ReadFile(filepath.Join(authzBaselineDir, subjectsAuthMeFile))
		if err != nil {
			return
		}
		var all map[string]struct {
			Body map[string]any `json:"body"`
		}
		if json.Unmarshal(raw, &all) != nil {
			return
		}
		for s, v := range all {
			id, okID := v.Body["id"].(float64)
			name, okName := v.Body["username"].(string)
			if okID && okName && name != "" {
				subjectIdentityVal[s] = subjectIdentity{ID: id, Username: name}
			}
		}
	})
	return subjectIdentityVal
}

// resolveSubjectTokens returns a copy of v with the subject tokens replaced;
// ok is false when v uses a token the subject cannot resolve.
func resolveSubjectTokens(v any, subject string) (any, bool) {
	switch x := v.(type) {
	case string:
		if x != subjectIDToken && x != subjectUsernameToken {
			return x, true
		}
		who, ok := subjectIdentities()[subject]
		if !ok {
			return nil, false
		}
		if x == subjectIDToken {
			return who.ID, true
		}
		return who.Username, true
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			r, ok := resolveSubjectTokens(val, subject)
			if !ok {
				return nil, false
			}
			out[k] = r
		}
		return out, true
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			r, ok := resolveSubjectTokens(val, subject)
			if !ok {
				return nil, false
			}
			out[i] = r
		}
		return out, true
	}
	return v, true
}

// declaredRowEquals reports whether row equals the declared row as a whole
// (see above). subject names the scenario subject, "" when there is none.
func declaredRowEquals(row, decl map[string]any, subject string) bool {
	if len(decl) == 0 {
		return false
	}
	r, ok := resolveSubjectTokens(decl, subject)
	if !ok {
		return false
	}
	want := r.(map[string]any)
	n := 0
	for k, v := range row {
		if declaredRowSkip[k] {
			continue
		}
		n++
		dv, ok := want[k]
		if !ok || !declaredValueEquals(v, dv) {
			return false
		}
	}
	return n == len(want)
}

func declaredValueEquals(v, decl any) bool {
	switch decl.(type) {
	case map[string]any, []any:
		s, ok := v.(string)
		if !ok {
			return canon(v) == canon(decl)
		}
		var doc any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(s, "json:")), &doc); err != nil || !strings.HasPrefix(s, "json:") {
			return false
		}
		return canon(doc) == canon(decl)
	}
	return canon(v) == canon(decl)
}
