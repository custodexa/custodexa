package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// Authorization decision baseline: seed ledger and fixture markers.
//
// Every scenario starts from the fixture template, so the ids of the rows a
// scenario adds to the append-only audit and alert tables continue from the
// number of rows the fixture seeding left there. When a later change makes a
// seeding call write one more audit row, every audit id of every scenario
// moves by one, and so do the ids of template rows that a response lists.
//
// The seed ledger (testdata/authz-baseline/seed-ledger.json) records how
// many rows those tables held in the template the golden records were
// captured on, and lists the rows later seeding adds on top of it, each
// declared as a whole row (every column except the id, see
// declaredRowEquals) and given a reason. Before comparing, fresh ids are
// mapped back onto the golden template by taking the declared rows out:
// an id loses one for every declared row below it. Row counts, row content
// and row order are still compared exactly. If the template holds any other
// number of rows than the golden count plus the declared additions, or a
// declaration does not match exactly its count of rows, nothing is mapped
// and the ledger itself is reported as a failing difference: seeding that
// writes more or fewer rows than declared fails the comparison.

func seedLedgerPath() string { return filepath.Join(authzBaselineDir, "seed-ledger.json") }

type seedLedgerFile struct {
	Version   int            `json:"version"`
	Note      string         `json:"note"`
	Golden    map[string]int `json:"golden"`
	Additions []seedAddition `json:"additions"`
	// SetupAdditions rows that a flow scenario's setup now writes on top of
	// what it wrote at capture time. Setup writes are the comparison base of
	// a flow and are never compared; only their ids are taken out of the
	// ids of the rows the steps write.
	SetupAdditions []seedSetupAddition `json:"setup_additions,omitempty"`
}

type seedSetupAddition struct {
	Table  string         `json:"table"`
	Match  map[string]any `json:"match"`
	Reason string         `json:"reason"`
}

type seedAddition struct {
	Table string `json:"table"`
	Count int    `json:"count"`
	// Row is the whole template row except its id; Count identical rows.
	Row    map[string]any `json:"row"`
	Reason string         `json:"reason"`
}

func loadSeedLedger(path string) (seedLedgerFile, error) {
	var l seedLedgerFile
	raw, err := os.ReadFile(path)
	if err != nil {
		return l, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return l, err
	}
	return l, l.validate()
}

func (l seedLedgerFile) validate() error {
	if l.Version != 1 {
		return fmt.Errorf("seed ledger: version must be 1")
	}
	if len(l.Golden) == 0 {
		return fmt.Errorf("seed ledger: golden counts are required")
	}
	for t, n := range l.Golden {
		if !baselineAuditTables[t] && !baselineAlertTables[t] {
			return fmt.Errorf("seed ledger: %s is not an audit or alert table", t)
		}
		if n < 0 {
			return fmt.Errorf("seed ledger: %s count must not be negative", t)
		}
	}
	for i, a := range l.SetupAdditions {
		if _, ok := l.Golden[a.Table]; !ok || len(a.Match) < 2 || strings.TrimSpace(a.Reason) == "" {
			return fmt.Errorf("seed ledger setup addition %d: needs a ledger table, at least two match columns and a reason", i)
		}
	}
	for i, a := range l.Additions {
		if _, ok := l.Golden[a.Table]; !ok {
			return fmt.Errorf("seed ledger addition %d: table %s has no golden count", i, a.Table)
		}
		if a.Count < 1 || strings.TrimSpace(a.Reason) == "" {
			return fmt.Errorf("seed ledger addition %d: needs count >= 1 and a reason", i)
		}
		if err := validateDeclaredRow(a.Row); err != nil {
			return fmt.Errorf("seed ledger addition %d: %w", i, err)
		}
	}
	return nil
}

// seedMapping lists, per table, the template ids of the declared additions
// (ascending).
type seedMapping map[string][]float64

// seedLedgerState is what one comparison learned about the template.
type seedLedgerState struct {
	Golden   map[string]int       `json:"golden"`
	Template map[string]int       `json:"template"`
	Added    map[string][]float64 `json:"declared_additions,omitempty"`
	Problems []string             `json:"problems,omitempty"`
	mapping  seedMapping
}

// ledgerTables lists the audit and alert tables the template has.
func (e *baselineEnv) ledgerTables() []string {
	var out []string
	for _, t := range e.tables {
		if baselineAuditTables[t] || baselineAlertTables[t] {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// resolveSeedLedger reads the template's ledger tables and resolves the
// declared additions. The mapping is set only when the template is exactly
// the golden template plus the declared rows.
func (e *baselineEnv) resolveSeedLedger(l seedLedgerFile) seedLedgerState {
	st := seedLedgerState{Golden: l.Golden, Template: map[string]int{}, Added: map[string][]float64{}}
	rows := map[string][]map[string]any{}
	for _, t := range e.ledgerTables() {
		for _, r := range e.queryRows(fmt.Sprintf(`SELECT rowid AS authz_rowid, * FROM tpl.%q ORDER BY rowid`, t)) {
			id := rowScalar(r["authz_rowid"])
			delete(r, "authz_rowid")
			n := normalizeRow(r)
			n["@rowid"] = id
			rows[t] = append(rows[t], n)
		}
		st.Template[t] = len(rows[t])
	}
	st.Problems = checkSeedLedger(l, st.Template, rows, st.Added)
	if len(st.Problems) == 0 {
		st.mapping = seedMapping(st.Added)
	}
	return st
}

// checkSeedLedger compares template row counts with the golden counts plus
// the declared additions, and resolves each declaration to its rows.
func checkSeedLedger(l seedLedgerFile, template map[string]int, rows map[string][]map[string]any, added map[string][]float64) []string {
	var problems []string
	for t := range template {
		if _, ok := l.Golden[t]; !ok {
			problems = append(problems, fmt.Sprintf("table %s is in the template but has no golden count", t))
		}
	}
	declared := map[string]int{}
	taken := map[string]map[float64]bool{}
	for i, a := range l.Additions {
		declared[a.Table] += a.Count
		var ids []float64
		for _, r := range rows[a.Table] {
			if declaredRowEquals(r, a.Row, "") {
				id, _ := r["@rowid"].(float64)
				ids = append(ids, id)
			}
		}
		if len(ids) != a.Count {
			problems = append(problems, fmt.Sprintf("addition %d (%s): declares %d rows, the template has %d equal rows", i, a.Table, a.Count, len(ids)))
			continue
		}
		if taken[a.Table] == nil {
			taken[a.Table] = map[float64]bool{}
		}
		for _, id := range ids {
			if taken[a.Table][id] {
				problems = append(problems, fmt.Sprintf("addition %d (%s): row %v is matched by another addition too", i, a.Table, id))
			}
			taken[a.Table][id] = true
			added[a.Table] = append(added[a.Table], id)
		}
	}
	tables := make([]string, 0, len(l.Golden))
	for t := range l.Golden {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	for _, t := range tables {
		got, ok := template[t]
		if !ok {
			problems = append(problems, fmt.Sprintf("table %s has a golden count but is not in the template", t))
			continue
		}
		if want := l.Golden[t] + declared[t]; got != want {
			problems = append(problems, fmt.Sprintf("table %s: template holds %d rows, golden %d plus %d declared additions is %d",
				t, got, l.Golden[t], declared[t], want))
		}
		sort.Float64s(added[t])
	}
	sort.Strings(problems)
	return problems
}

// seedAddedID marks an id that belongs to a declared seed addition: such a
// row has no counterpart in the golden template.
const seedAddedID = "<seed-addition>"

// mapID maps a fresh id of table t onto the golden template.
func (m seedMapping) mapID(t string, v any) any {
	f, ok := v.(float64)
	if !ok {
		return v
	}
	below := 0
	for _, a := range m[t] {
		if a == f {
			return seedAddedID
		}
		if a < f {
			below++
		}
	}
	return f - float64(below)
}

// mapKey maps the "id" column of a row of table t in place, if it has one.
func (m seedMapping) mapKey(row map[string]any, t string) {
	if v, ok := row["id"]; ok {
		row["id"] = m.mapID(t, v)
	}
}

// mapCount maps a fresh row count of table t (a count that includes every
// template row) onto the golden template.
func (m seedMapping) mapCount(t string, v any) any {
	f, ok := v.(float64)
	if !ok {
		return v
	}
	return f - float64(len(m[t]))
}

// seedBodyField is a response field that carries an id or a row count of a
// ledger table.
type seedBodyField struct {
	Path  string // dotted; "name[]" applies the rest to every element
	Table string
	Count bool
}

// seedBodyFields lists, per route, the response fields that carry audit row
// ids or counts that include the template rows.
var seedBodyFields = map[string][]seedBodyField{
	"GET /api/v1/audit-logs": {
		{Path: "data[].id", Table: "audit_logs"},
		{Path: "total", Table: "audit_logs", Count: true},
	},
	"GET /api/v1/audit-logs/resource/:resource/:id": {
		{Path: "logs[].id", Table: "audit_logs"},
	},
	"GET /api/v1/audit-integrity/verify": {
		{Path: "data.checked", Table: "audit_logs", Count: true},
		{Path: "data.passed", Table: "audit_logs", Count: true},
	},
	"GET /api/v1/audit-checkpoints/verify": {
		{Path: "data.chain.unsealed_rows", Table: "audit_logs", Count: true},
		{Path: "data.chain.unsealed_from_id", Table: "audit_logs"},
	},
}

// applySeedMapping maps the ids of fresh records onto the golden template
// in place (fresh records written by a re-capture are stored mapped). setup
// holds, per flow scenario, the ids of declared setup additions; they are
// taken out of that record's ids as well.
func applySeedMapping(recs map[string]map[string]any, base seedMapping, setup map[string]seedMapping) {
	if len(base) == 0 {
		return
	}
	for id, r := range recs {
		m := base
		if extra := setup[id]; len(extra) > 0 {
			m = seedMapping{}
			for t, ids := range base {
				m[t] = ids
			}
			for t, ids := range extra {
				m[t] = append(append([]float64(nil), m[t]...), ids...)
				sort.Float64s(m[t])
			}
		}
		if rows, ok := r["audit"].([]any); ok {
			for _, x := range rows {
				if row, ok := x.(map[string]any); ok {
					m.mapKey(row, "audit_logs")
				}
			}
		}
		if rows, ok := r["alerts"].([]any); ok {
			for _, x := range rows {
				if row, ok := x.(map[string]any); ok {
					t, _ := row["@table"].(string)
					m.mapKey(row, t)
				}
			}
		}
		if db, ok := r["db"].(map[string]any); ok {
			for t, v := range db {
				if _, mapped := m[t]; !mapped {
					continue
				}
				entry, _ := v.(map[string]any)
				for _, kind := range []string{"added", "removed"} {
					rows, _ := entry[kind].([]any)
					for _, x := range rows {
						if row, ok := x.(map[string]any); ok {
							m.mapKey(row, t)
						}
					}
				}
				mods, _ := entry["modified"].([]any)
				for _, x := range mods {
					row, _ := x.(map[string]any)
					if pair, ok := row["@rowid"].([]any); ok {
						for i := range pair {
							pair[i] = m.mapID(t, pair[i])
						}
					}
				}
			}
		}
		g, _, key := scenarioParts(id)
		if g == "R" && r["body"] != nil {
			mapBodyFields(r["body"], seedBodyFields[key], m)
		}
		steps, _ := r["steps"].([]any)
		for _, x := range steps {
			st, _ := x.(map[string]any)
			name, _ := st["name"].(string)
			if route, ok := seedStepRoutes[id][name]; ok && st["body"] != nil {
				mapBodyFields(st["body"], seedBodyFields[route], m)
			}
		}
	}
}

func mapBodyFields(body any, fields []seedBodyField, m seedMapping) {
	for _, f := range fields {
		f := f
		visitPath(body, f.Path, func(parent map[string]any, k string) {
			if f.Count {
				parent[k] = m.mapCount(f.Table, parent[k])
			} else {
				parent[k] = m.mapID(f.Table, parent[k])
			}
		})
	}
}

// seedStepRoutes names, per flow scenario, the route of each step whose
// body lists ledger rows (flow steps record only their name).
var seedStepRoutes = map[string]map[string]string{
	"T/T01": {"before": "GET /api/v1/audit-logs", "after": "GET /api/v1/audit-logs"},
	"T/T02": {"before": "GET /api/v1/audit-logs", "next-request": "GET /api/v1/audit-logs"},
}

// flowSetupAdded holds, per flow scenario id, the ids of the rows its setup
// wrote that match a declared setup addition (filled by runFlow).
var flowSetupAdded = map[string]seedMapping{}

// recordSetupAdditions finds the rows the setup of flow scenario id wrote to
// the ledger tables that match a declared setup addition.
func (e *baselineEnv) recordSetupAdditions(id string) {
	l, err := loadSeedLedger(seedLedgerPath())
	if err != nil {
		e.t.Fatalf("seed-ledger.json: %v", err)
	}
	found := seedMapping{}
	for _, t := range e.ledgerTables() {
		var decl []seedSetupAddition
		for _, a := range l.SetupAdditions {
			if a.Table == t {
				decl = append(decl, a)
			}
		}
		if len(decl) == 0 {
			continue
		}
		q := fmt.Sprintf(`SELECT rowid AS authz_rowid, * FROM main.%q WHERE rowid > (SELECT coalesce(max(rowid), 0) FROM tpl.%q) ORDER BY rowid`, t, t)
		for _, r := range e.queryRows(q) {
			rid, _ := rowScalar(r["authz_rowid"]).(float64)
			delete(r, "authz_rowid")
			n := normalizeRow(r)
			for _, a := range decl {
				if auditRowMatches(n, a.Match) {
					found[t] = append(found[t], rid)
					break
				}
			}
		}
	}
	if len(found) == 0 {
		delete(flowSetupAdded, id)
		return
	}
	flowSetupAdded[id] = found
}

// visitPath calls fn on every (parent object, key) the dotted path reaches;
// parts of the path that are absent are skipped.
func visitPath(node any, path string, fn func(parent map[string]any, key string)) {
	segs := strings.Split(path, ".")
	var walk func(n any, i int)
	walk = func(n any, i int) {
		m, ok := n.(map[string]any)
		if !ok {
			return
		}
		seg := segs[i]
		each := strings.HasSuffix(seg, "[]")
		key := strings.TrimSuffix(seg, "[]")
		next, ok := m[key]
		if !ok {
			return
		}
		if i == len(segs)-1 {
			if !each {
				fn(m, key)
			}
			return
		}
		if !each {
			walk(next, i+1)
			return
		}
		arr, _ := next.([]any)
		for _, el := range arr {
			walk(el, i+1)
		}
	}
	walk(node, 0)
}

// ---- fixture markers ----
//
// A route parameter that names a fixture ("{commandAlert.1}") is sent as the
// fixture's id, and the product records that id in the audit path, the audit
// resource id and the row id of the fixture's table. When seeding changes,
// the id can change while the operation is the same. For the comparison,
// both sides replace the id with the fixture's name wherever it stands for
// the fixture: the path segment of the parameter, a resource id whose
// resource is the fixture's kind, and the row id of the fixture's table.
// The golden id is read back from the golden record's own request path; when
// it cannot be read, neither side is rewritten. An operation that reaches a
// different object keeps a different id and still differs.

// fixtureKind turns a placeholder name into its resource and table name:
// "commandAlert.1" -> "command_alert", "command_alerts".
func fixtureKind(name string) (resource, table string) {
	kind, _, _ := strings.Cut(name, ".")
	var b strings.Builder
	for i, r := range kind {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String(), b.String() + "s"
}

type fixtureParam struct {
	seg  int
	name string
}

// routeFixtureParams lists the path parameters of a catalog row that name a
// fixture.
func routeFixtureParams(r routeEntry) []fixtureParam {
	var out []fixtureParam
	for i, s := range strings.Split(r.Path, "/") {
		if !strings.HasPrefix(s, ":") {
			continue
		}
		v, _ := r.Params[s[1:]].(string)
		if strings.HasPrefix(v, "{") && strings.HasSuffix(v, "}") && isPlaceholderName(v[1:len(v)-1]) {
			out = append(out, fixtureParam{seg: i, name: v[1 : len(v)-1]})
		}
	}
	return out
}

// pathMatchesRoute reports whether a request path (query removed) has the
// route's shape: same segment count and the same static segments.
func pathMatchesRoute(path, route string) ([]string, bool) {
	path, _, _ = strings.Cut(path, "?")
	ps, rs := strings.Split(path, "/"), strings.Split(route, "/")
	if len(ps) != len(rs) {
		return nil, false
	}
	for i := range rs {
		if !strings.HasPrefix(rs[i], ":") && rs[i] != ps[i] {
			return nil, false
		}
	}
	return ps, true
}

// paramFromAudit reads the value of a path segment from the record's audit
// rows; "" when no row carries the route's path or the rows disagree.
func paramFromAudit(rec map[string]any, r routeEntry, seg int) string {
	rows, _ := rec["audit"].([]any)
	val := ""
	for _, x := range rows {
		row, _ := x.(map[string]any)
		p, _ := row["path"].(string)
		segs, ok := pathMatchesRoute(p, r.Path)
		if !ok {
			continue
		}
		if val != "" && val != segs[seg] {
			return ""
		}
		val = segs[seg]
	}
	return val
}

// markFixture rewrites one fixture id to its marker in a record (in place).
// pathValue is the parameter as the normalized request path records it,
// value the id as sent, and rowValue the same id as it appears in the
// fixture table's row ids (fresh row ids are already mapped onto the golden
// template).
func markFixture(rec map[string]any, r routeEntry, p fixtureParam, pathValue, value, rowValue string) {
	marker := "{" + p.name + "}"
	resource, table := fixtureKind(p.name)
	same := func(v any) bool { return v != nil && toString(v) == value }
	sameRow := func(v any) bool { return v != nil && toString(v) == rowValue }
	if rows, ok := rec["audit"].([]any); ok {
		for _, x := range rows {
			row, _ := x.(map[string]any)
			if pth, ok := row["path"].(string); ok {
				if segs, ok := pathMatchesRoute(pth, r.Path); ok && segs[p.seg] == pathValue {
					segs[p.seg] = marker
					q := ""
					if i := strings.Index(pth, "?"); i >= 0 {
						q = pth[i:]
					}
					row["path"] = strings.Join(segs, "/") + q
				}
			}
			if row["resource"] == resource && same(row["resource_id"]) {
				row["resource_id"] = marker
			}
		}
	}
	db, _ := rec["db"].(map[string]any)
	entry, _ := db[table].(map[string]any)
	for _, kind := range []string{"added", "removed"} {
		rows, _ := entry[kind].([]any)
		for _, x := range rows {
			if row, ok := x.(map[string]any); ok && sameRow(row["id"]) {
				row["id"] = marker
			}
		}
	}
	mods, _ := entry["modified"].([]any)
	for _, x := range mods {
		row, _ := x.(map[string]any)
		if pair, ok := row["@rowid"].([]any); ok {
			for i := range pair {
				if sameRow(pair[i]) {
					pair[i] = marker
				}
			}
		}
	}
}

// withFixtureMarkers returns copies of the R-group records in which fixture
// ids are replaced by markers (see above). Records of other groups, and
// records whose golden id cannot be read back, are returned unchanged.
func withFixtureMarkers(old, new map[string]map[string]any, routes []routeEntry, objects map[string]any, m seedMapping) (map[string]map[string]any, map[string]map[string]any) {
	byKey := map[string]routeEntry{}
	for _, r := range routes {
		byKey[routeKey(r)] = r
	}
	o2 := make(map[string]map[string]any, len(old))
	n2 := make(map[string]map[string]any, len(new))
	for id, v := range old {
		o2[id] = v
	}
	for id, v := range new {
		n2[id] = v
	}
	for id, nrec := range new {
		orec := old[id]
		g, _, key := scenarioParts(id)
		r, ok := byKey[key]
		if g != "R" || orec == nil || !ok {
			continue
		}
		params := routeFixtureParams(r)
		if len(params) == 0 {
			continue
		}
		var oc, nc map[string]any
		for _, p := range params {
			fv, ok := objects[p.name]
			gv := paramFromAudit(orec, r, p.seg)
			if !ok || gv == "" {
				continue
			}
			if oc == nil {
				oc = deepCopyJSON(orec).(map[string]any)
				nc = deepCopyJSON(nrec).(map[string]any)
			}
			_, table := fixtureKind(p.name)
			fresh := toString(fv)
			freshRow := fresh
			var f float64
			if _, err := fmt.Sscanf(fresh, "%g", &f); err == nil {
				freshRow = toString(m.mapID(table, f))
			}
			freshPath := toString(normalizeString(url.PathEscape(fresh)))
			markFixture(oc, r, p, gv, gv, gv)
			markFixture(nc, r, p, freshPath, fresh, freshRow)
		}
		if oc != nil {
			o2[id], n2[id] = oc, nc
		}
	}
	return o2, n2
}

// seedLedgerDiffs reports a ledger that does not hold as one failing
// difference per problem, under the pseudo scenario "<group>/@seed".
func seedLedgerDiffs(group string, st seedLedgerState) []baselineDiff {
	var out []baselineDiff
	for _, p := range st.Problems {
		out = append(out, baselineDiff{ID: group + "/@seed", Field: "ledger", Old: st.Golden, New: st.Template, Verdict: "unapproved", Entry: p})
	}
	return out
}
