package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Authorization decision baseline: golden files, comparator and approved
// differences.

const authzBaselineDir = "testdata/authz-baseline"

// approvedDiffs is testdata/authz-baseline/approved-diffs.json.
type approvedDiffs struct {
	Version int             `json:"version"`
	Entries []approvedEntry `json:"entries"`
}

type approvedEntry struct {
	ID       string           `json:"id"`
	Status   string           `json:"status"` // "pending" | "active"
	Selector approvedSelector `json:"selector"`
	Expect   map[string]any   `json:"expect"`
	// RequireAllKeys makes an active entry fail unless it matches a
	// difference on every subject x key record its selector lists (group
	// selectors only). Without it one matching record is enough, so a
	// regression that returns one of several covered records to its old
	// value goes unnoticed.
	RequireAllKeys bool   `json:"require_all_keys,omitempty"`
	Reason         string `json:"reason"`
}

type approvedSelector struct {
	Scenarios  []string `json:"scenarios,omitempty"`
	Group      string   `json:"group,omitempty"`
	Subjects   []string `json:"subjects,omitempty"`
	Keys       []string `json:"keys,omitempty"`
	FromStatus []int    `json:"from_status,omitempty"`
	Fields     []string `json:"fields"`
}

// validate rejects entries whose selector does not bound the scenario set.
func (a approvedDiffs) validate() error {
	seen := map[string]bool{}
	for _, e := range a.Entries {
		if e.ID == "" || seen[e.ID] {
			return fmt.Errorf("approved diff entry with empty or duplicate id %q", e.ID)
		}
		seen[e.ID] = true
		if e.Status != "pending" && e.Status != "active" {
			return fmt.Errorf("%s: status must be pending or active", e.ID)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("%s: reason is required", e.ID)
		}
		s := e.Selector
		if len(s.Fields) == 0 {
			return fmt.Errorf("%s: selector must list fields", e.ID)
		}
		all := append(append(append([]string{s.Group}, s.Scenarios...), s.Subjects...), s.Keys...)
		all = append(all, s.Fields...)
		for _, v := range all {
			if strings.Contains(v, "*") {
				return fmt.Errorf("%s: wildcards are not allowed in selectors", e.ID)
			}
		}
		if len(s.Scenarios) == 0 && (s.Group == "" || (len(s.Subjects) == 0 && len(s.Keys) == 0)) {
			return fmt.Errorf("%s: selector must name scenarios, or a group plus subjects or keys", e.ID)
		}
		if err := s.targetsExist(); err != nil {
			return fmt.Errorf("%s: %w", e.ID, err)
		}
		if err := validateAlertsEdit(e); err != nil {
			return err
		}
		if err := validateAuditEdit(e); err != nil {
			return err
		}
		if err := validateBodyEdit(e); err != nil {
			return err
		}
		if err := s.completeBodyNeedsEdit(e); err != nil {
			return err
		}
	}
	return nil
}

// targetsExist rejects a selector naming a group, subject or scenario id
// that the baseline does not declare. Such an entry would never be in
// scope of any comparison, so it could neither approve a difference nor be
// reported as stale: a typo would go unnoticed.
func (s approvedSelector) targetsExist() error {
	u, err := approvedTargetUniverse()
	if err != nil {
		return err
	}
	if s.Group != "" && !u.groups[s.Group] {
		return fmt.Errorf("selector group %q is not a baseline group", s.Group)
	}
	for _, subj := range s.Subjects {
		if !u.subjects[subj] {
			return fmt.Errorf("selector subject %q is not a baseline subject", subj)
		}
	}
	if s.Group == "E" && len(s.Scenarios) > 0 {
		// The entry comparator reads subjects and keys only, so scenarios on a
		// group E entry would be silently ignored.
		return fmt.Errorf("selector group E selects by subjects or keys, not scenarios")
	}
	for _, id := range s.Scenarios {
		if g, _, _ := scenarioParts(id); g == "E" {
			// The entry comparator selects by subjects and keys only.
			return fmt.Errorf("selector scenario %q: group E entries select by subjects or keys", id)
		}
		if !u.scenarios[id] {
			return fmt.Errorf("selector scenario %q is not a declared baseline scenario", id)
		}
	}
	return nil
}

// targetUniverse groups, subjects and back-end scenario ids the baseline
// declares (R from the request catalog, flow groups from their declaration
// table; E is front-end only and has no ids here).
type targetUniverse struct {
	groups, subjects, scenarios map[string]bool
	// completeBody route keys whose body is captured in full (body_mode
	// "complete") instead of being summarized.
	completeBody map[string]bool
}

// completeBodyNeedsEdit refuses an active entry that would approve the body
// of a route captured in full without saying what changed in it: for those
// routes the comparison can tell which items changed, so an approval must
// name them (body_edit, or the exact added keys).
func (s approvedSelector) completeBodyNeedsEdit(e approvedEntry) error {
	if e.Status != "active" || !containsStr(s.Fields, "body") {
		return nil
	}
	if _, ok := e.Expect[bodyEditKey]; ok {
		return nil
	}
	if _, ok := e.Expect["body_added_keys"]; ok {
		return nil
	}
	u, err := approvedTargetUniverse()
	if err != nil {
		return err
	}
	for _, k := range s.Keys {
		if u.completeBody[k] {
			return fmt.Errorf("%s: approving the body of %s requires a %s expectation", e.ID, k, bodyEditKey)
		}
	}
	for _, id := range s.Scenarios {
		if g, _, k := scenarioParts(id); g == "R" && u.completeBody[k] {
			return fmt.Errorf("%s: approving the body of %s requires a %s expectation", e.ID, id, bodyEditKey)
		}
	}
	// A group R scope without keys reaches every route, the complete-body
	// routes included (from_status and subjects only narrow it per record).
	if s.Group == "R" && len(s.Keys) == 0 && len(u.completeBody) > 0 {
		return fmt.Errorf("%s: a body approval over every route of group R reaches routes captured in full; list the keys or add a %s expectation", e.ID, bodyEditKey)
	}
	return nil
}

var (
	targetUniverseOnce sync.Once
	targetUniverseVal  targetUniverse
	targetUniverseErr  error
)

func approvedTargetUniverse() (targetUniverse, error) {
	targetUniverseOnce.Do(func() {
		u := targetUniverse{
			groups:       map[string]bool{"R": true, "E": true},
			subjects:     map[string]bool{},
			scenarios:    map[string]bool{},
			completeBody: map[string]bool{},
		}
		for sub := range flowDeclaredSizes {
			u.groups[sub] = true
		}
		for _, s := range baselineSubjectIDs {
			u.subjects[s] = true
		}
		raw, err := os.ReadFile(filepath.Join(authzBaselineDir, "routes.json"))
		if err != nil {
			targetUniverseErr = err
			return
		}
		var c routeCatalog
		if err := json.Unmarshal(raw, &c); err != nil {
			targetUniverseErr = fmt.Errorf("routes.json: %w", err)
			return
		}
		for _, s := range rScenarios(c, baselineSubjectIDs) {
			u.scenarios[s.id()] = true
		}
		for _, r := range c.Routes {
			if r.BodyMode == bodyModeComplete {
				u.completeBody[routeKey(r)] = true
			}
		}
		for _, ids := range flowScenarioIDs() {
			for _, id := range ids {
				u.scenarios[id] = true
			}
		}
		targetUniverseVal = u
	})
	return targetUniverseVal, targetUniverseErr
}

func loadApprovedDiffs(path string) (approvedDiffs, error) {
	var a approvedDiffs
	raw, err := os.ReadFile(path)
	if err != nil {
		return a, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return a, err
	}
	return a, a.validate()
}

// scenarioParts splits "R/S03/GET /api/v1/x" into group, subject, key.
// "T/T02" has no subject.
func scenarioParts(id string) (group, subject, key string) {
	parts := strings.SplitN(id, "/", 3)
	switch len(parts) {
	case 2:
		return parts[0], "", parts[1]
	case 3:
		return parts[0], parts[1], parts[2]
	}
	return id, "", ""
}

func (s approvedSelector) matches(id string, old map[string]any, fields []string) bool {
	listed := len(s.Scenarios) > 0 && containsStr(s.Scenarios, id)
	if len(s.Scenarios) > 0 && s.Group == "" && !listed {
		return false
	}
	// A selector that names both scenarios and a group matches either: the listed
	// scenarios, or the group scope (subjects/keys/from_status). Scenarios only:
	// listed ones. from_status narrows the group scope only: a listed flow
	// scenario carries its own overall status (the current-user entry names T/T03, whose flow ends
	// in a 401 while its current-user step answers 200).
	if !listed {
		g, subj, key := scenarioParts(id)
		if g != s.Group {
			return false
		}
		if len(s.Subjects) > 0 && !containsStr(s.Subjects, subj) {
			return false
		}
		if len(s.Keys) > 0 && !containsStr(s.Keys, key) {
			return false
		}
	}
	if !listed && len(s.FromStatus) > 0 {
		st, _ := old["status"].(float64)
		ok := false
		for _, f := range s.FromStatus {
			if int(st) == f {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	for _, f := range fields {
		if !containsStr(s.Fields, f) {
			return false
		}
	}
	return true
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// expectHolds checks an entry's expected new value.
func expectHolds(expect map[string]any, old, new map[string]any) bool {
	for k, want := range expect {
		if k == alertsEditKey || k == auditEditKey || k == bodyEditKey {
			continue // judged by alertsEditHolds, auditEditHolds and bodyEditHolds
		}
		if k == "body" && want == "additive" {
			ob, _ := old["body"].(map[string]any)
			nb, _ := new["body"].(map[string]any)
			if ob == nil && nb == nil && old["body"] == nil && new["body"] == nil {
				continue // records without a body field (flow records): nothing to compare
			}
			if nb == nil {
				return false
			}
			for ok, ov := range ob {
				if !keyKept(nb, ok, ov) {
					return false
				}
			}
			continue
		}
		if k == "body_added_keys" {
			// Exact set of top-level keys the new body gains over the old one
			// (current-user entry): "additive" alone would also swallow an unplanned third key.
			// Flow records carry no top-level body (their bodies sit in steps,
			// checked by the "steps" expectation): nothing to compare here.
			ob, _ := old["body"].(map[string]any)
			nb, _ := new["body"].(map[string]any)
			if old["body"] == nil && new["body"] == nil {
				continue
			}
			if nb == nil || !sameStringSet(addedKeys(ob, nb), anyStrings(want)) {
				return false
			}
			continue
		}
		if k == "steps" && want == "additive" {
			if !stepsAdditive(old["steps"], new["steps"]) {
				return false
			}
			continue
		}
		if canon(new[k]) != canon(want) {
			return false
		}
	}
	return true
}

// addedKeys lists the top-level keys present in nb and absent from ob.
func addedKeys(ob, nb map[string]any) []string {
	var out []string
	for k := range nb {
		if _, ok := ob[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}

// anyStrings reads a JSON string list (decoded as []any, or built as []string).
func anyStrings(v any) []string {
	switch xs := v.(type) {
	case []string:
		return xs
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			s, _ := x.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

func sameStringSet(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return canon(x) == canon(y)
}

// keyKept reports whether nb still carries key k with the value ov. A key that
// is missing from nb is not the same as one holding null: an old null value
// does not excuse a vanished key.
func keyKept(nb map[string]any, k string, ov any) bool {
	nv, present := nb[k]
	return present && canon(nv) == canon(ov)
}

// additiveStepFields are the two keys the current-user step body must gain, together, under a
// "steps": "additive" expectation.
var additiveStepFields = []string{"permissions", "scope_summary"}

// additiveStepName is the only flow step that may change: the current-user read ("GET /auth/me").
// Every other step (a group update, a rejected request) must stay identical.
const additiveStepName = "before"

// stepsAdditive reports whether new equals old step by step, except that the current-user step
// body must gain exactly the keys in additiveStepFields (every existing key keeps its value).
// Any difference in any other step is not approved.
func stepsAdditive(old, new any) bool {
	if old == nil && new == nil {
		return true
	}
	os, ok1 := old.([]any)
	ns, ok2 := new.([]any)
	if !ok1 || !ok2 || len(os) != len(ns) {
		return false
	}
	for i := range os {
		om, ok1 := os[i].(map[string]any)
		nm, ok2 := ns[i].(map[string]any)
		if !ok1 || !ok2 {
			return false
		}
		for k, ov := range om {
			if k == "body" {
				continue
			}
			if canon(nm[k]) != canon(ov) {
				return false
			}
		}
		for k := range nm {
			if _, had := om[k]; !had {
				return false
			}
		}
		ob, _ := om["body"].(map[string]any)
		nb, _ := nm["body"].(map[string]any)
		if (ob == nil) != (nb == nil) {
			return false
		}
		for k, ov := range ob {
			if !keyKept(nb, k, ov) {
				return false
			}
		}
		var gained []string
		for k := range nb {
			if _, had := ob[k]; !had {
				gained = append(gained, k)
			}
		}
		if om["name"] != additiveStepName || ob == nil {
			if len(gained) != 0 {
				return false
			}
			continue
		}
		if !sameStringSet(gained, additiveStepFields) {
			return false
		}
	}
	return true
}

func canon(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// baselineDiff is one differing field of one scenario.
type baselineDiff struct {
	ID      string `json:"id"`
	Field   string `json:"field"`
	Old     any    `json:"old"`
	New     any    `json:"new"`
	Verdict string `json:"verdict"` // approved | unapproved | pending-only | expect-mismatch
	Entry   string `json:"entry,omitempty"`
}

// compareResult is the outcome of one comparison run.
type compareResult struct {
	Diffs       []baselineDiff `json:"diffs"`
	StaleActive []string       `json:"stale_active,omitempty"`
	// PartialActive entries that declare require_all_keys and matched
	// some, but not all, of the records their selector lists.
	PartialActive []string `json:"partial_active,omitempty"`
}

func (r compareResult) failed() bool {
	if len(r.StaleActive) > 0 || len(r.PartialActive) > 0 {
		return true
	}
	for _, d := range r.Diffs {
		if d.Verdict != "approved" {
			return true
		}
	}
	return false
}

// combinedEditKeys are expectations judged across every active entry that
// matches the same record and field (see alertsEditHolds, auditEditHolds):
// when one of them approves a record, all of them count as hit.
var combinedEditKeys = []string{alertsEditKey, auditEditKey}

// entryHolds reports whether an active entry's expectation holds for a
// record. Every expectation the entry declares is checked, whichever field
// it is being asked to approve.
func entryHolds(e approvedEntry, entries []approvedEntry, id string, o, n map[string]any) bool {
	if e.Expect == nil {
		return true
	}
	if !expectHolds(e.Expect, o, n) {
		return false
	}
	if _, ok := e.Expect[alertsEditKey]; ok && !alertsEditHolds(entries, id, o, n) {
		return false
	}
	if _, ok := e.Expect[auditEditKey]; ok && !auditEditHolds(entries, id, o, n) {
		return false
	}
	if _, ok := e.Expect[bodyEditKey]; ok && !bodyEditHolds(e.Expect, o, n) {
		return false
	}
	return true
}

// differingFields lists the fields in which two records differ ("id" is the
// record key, not a field).
func differingFields(o, n map[string]any) []string {
	if o == nil || n == nil {
		return []string{"@presence"}
	}
	keys := map[string]bool{}
	for k := range o {
		keys[k] = true
	}
	for k := range n {
		keys[k] = true
	}
	var fields []string
	for k := range keys {
		if k != "id" && !fieldEqual(k, o[k], n[k]) {
			fields = append(fields, k)
		}
	}
	sort.Strings(fields)
	return fields
}

// fieldEqual compares one field of a golden and a fresh record. The only
// special case is a body the golden holds as a summary while the fresh
// record holds it in full (routes captured without summary since): the
// fresh body is summarized the same way before comparing, which is exactly
// as strict as comparing two summaries.
func fieldEqual(k string, ov, nv any) bool {
	if k == "body" && isBodySummary(ov) && nv != nil && !isBodySummary(nv) {
		return canon(ov) == canon(forceSummarizeBody(nv))
	}
	return canon(ov) == canon(nv)
}

// compareRecords compares golden (old) against fresh (new) records. Each
// differing field of a record is judged on its own: it is approved when an
// active entry whose selector covers that field (and the record) holds its
// expectation. Different fields of one record may be approved by different
// entries; one field without an approving entry fails the record.
func compareRecords(old, new map[string]map[string]any, ad approvedDiffs) compareResult {
	ids := map[string]bool{}
	for id := range old {
		ids[id] = true
	}
	for id := range new {
		ids[id] = true
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	hits := map[string]int{}
	hitIDs := map[string]map[string]bool{}
	hit := func(entryID, id string) {
		if hitIDs[entryID] == nil {
			hitIDs[entryID] = map[string]bool{}
		}
		if !hitIDs[entryID][id] {
			hits[entryID]++
		}
		hitIDs[entryID][id] = true
	}
	var res compareResult
	for _, id := range sorted {
		o, n := old[id], new[id]
		fields := differingFields(o, n)
		if len(fields) == 0 {
			continue
		}
		for _, f := range fields {
			verdict, entry := "unapproved", ""
			pendingHit := ""
			for _, e := range ad.Entries {
				if o == nil || n == nil || !e.Selector.matches(id, o, []string{f}) {
					continue
				}
				if e.Status == "pending" {
					if pendingHit == "" {
						pendingHit = e.ID
					}
					continue
				}
				hit(e.ID, id)
				if !entryHolds(e, ad.Entries, id, o, n) {
					if verdict != "approved" {
						verdict, entry = "expect-mismatch", e.ID
					}
					continue
				}
				verdict, entry = "approved", e.ID
				for _, key := range combinedEditKeys {
					if _, ok := e.Expect[key]; !ok {
						continue
					}
					// The entries that explain this field together all count as hit.
					for _, e2 := range ad.Entries {
						if _, ok := e2.Expect[key]; ok && e2.Status == "active" && e2.ID != e.ID && e2.Selector.matches(id, o, []string{f}) {
							hit(e2.ID, id)
						}
					}
				}
				break
			}
			if verdict == "unapproved" && pendingHit != "" {
				verdict, entry = "pending-only", pendingHit
			}
			res.Diffs = append(res.Diffs, baselineDiff{ID: id, Field: f, Old: o[f], New: n[f], Verdict: verdict, Entry: entry})
		}
	}
	groups := map[string]bool{}
	for id := range ids {
		g, _, _ := scenarioParts(id)
		groups[g] = true
	}
	// An active entry is stale only when it targets scenarios of this
	// comparison: each group is compared separately, and an entry for
	// another group cannot be hit here.
	inScope := func(sel approvedSelector) bool {
		if sel.Group != "" {
			return groups[sel.Group]
		}
		for _, sc := range sel.Scenarios {
			if ids[sc] {
				return true
			}
		}
		return false
	}
	for _, e := range ad.Entries {
		if e.Status == "active" && hits[e.ID] == 0 && inScope(e.Selector) {
			res.StaleActive = append(res.StaleActive, e.ID)
		}
		if e.Status == "active" && e.RequireAllKeys && hits[e.ID] > 0 && e.Selector.Group != "" {
			var missing []string
			for _, subj := range e.Selector.Subjects {
				for _, key := range e.Selector.Keys {
					rid := e.Selector.Group + "/" + subj + "/" + key
					if !hitIDs[e.ID][rid] {
						missing = append(missing, rid)
					}
				}
			}
			if len(missing) > 0 {
				res.PartialActive = append(res.PartialActive, e.ID+": no difference matched "+strings.Join(missing, ", "))
			}
		}
	}
	return res
}

// summary renders the first n failing diffs and the total.
func (r compareResult) summary(n int) string {
	var b strings.Builder
	bad := 0
	for _, d := range r.Diffs {
		if d.Verdict == "approved" {
			continue
		}
		bad++
		if bad <= n {
			fmt.Fprintf(&b, "  [%s] %s field=%s old=%s new=%s %s\n", d.Verdict, d.ID, d.Field, clip(canon(d.Old)), clip(canon(d.New)), d.Entry)
		}
	}
	for _, s := range r.StaleActive {
		fmt.Fprintf(&b, "  [stale-active] %s matched no difference\n", s)
	}
	for _, s := range r.PartialActive {
		fmt.Fprintf(&b, "  [partial-active] %s\n", s)
	}
	fmt.Fprintf(&b, "  total failing differences: %d (shown %d)\n", bad, min(bad, n))
	return b.String()
}

func clip(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

// recordsToGeneric round-trips records through JSON so they compare with
// golden content on equal terms.
func recordsToGeneric(recs []baselineRecord) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, r := range recs {
		b, _ := json.Marshal(r)
		m := map[string]any{}
		_ = json.Unmarshal(b, &m)
		out[r.ID] = m
	}
	return out
}

func readJSONL(path string) (map[string]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]map[string]any{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		m := map[string]any{}
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		id, _ := m["id"].(string)
		out[id] = m
	}
	return out, sc.Err()
}

func writeJSONL(path string, recs map[string]map[string]any) error {
	ids := make([]string, 0, len(recs))
	for id := range recs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b bytes.Buffer
	for _, id := range ids {
		line, err := json.Marshal(recs[id])
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}
