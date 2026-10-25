package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
)

// Authorization decision baseline: manifest, schema projection,
// re-capture gate and the R-group test.

type baselineManifest struct {
	Commit     string              `json:"commit"`
	CapturedAt string              `json:"captured_at"`
	Routes     int                 `json:"routes"`
	RoutesSHA  string              `json:"routes_sha256"`
	EntryRules int                 `json:"entry_rules"`
	Groups     map[string]int      `json:"groups"`
	Schema     map[string][]string `json:"schema"`
	Recaptures []string            `json:"recaptures"`
}

func manifestPath() string { return filepath.Join(authzBaselineDir, "manifest.json") }

func loadManifest() (baselineManifest, error) {
	var m baselineManifest
	raw, err := os.ReadFile(manifestPath())
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(raw, &m)
}

// schemaSnapshot lists every table's columns (framework tables excluded).
func (e *baselineEnv) schemaSnapshot() map[string][]string {
	out := map[string][]string{}
	for _, tbl := range e.sqlStrings(`SELECT name FROM main.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'authz_baseline_touched' ORDER BY name`) {
		out[tbl] = e.sqlStrings(fmt.Sprintf(`SELECT name FROM pragma_table_info(%s) ORDER BY name`, sqlQuote(tbl)))
	}
	return out
}

// projectionReport lists structure that is outside the capture-time schema.
type projectionReport struct {
	NewTables  []string            `json:"new_tables,omitempty"`
	NewColumns map[string][]string `json:"new_columns,omitempty"`
	// Undeclared lists structure outside the capture snapshot that no
	// schema-additions.json entry declares; it is compared, not projected away.
	Undeclared []string                             `json:"undeclared,omitempty"`
	Writes     map[string]map[string]map[string]int `json:"writes,omitempty"` // scenario -> table -> kind -> rows
}

// projectRecords restricts db/audit/alerts of fresh records to the schema
// snapshot and reports what was projected away.
func projectRecords(recs map[string]map[string]any, snap, live map[string][]string) projectionReport {
	rep := projectionReport{NewColumns: map[string][]string{}, Writes: map[string]map[string]map[string]int{}}
	cols := map[string]map[string]bool{}
	for t, cs := range snap {
		cols[t] = map[string]bool{}
		for _, c := range cs {
			cols[t][c] = true
		}
	}
	for t, cs := range live {
		if cols[t] == nil {
			rep.NewTables = append(rep.NewTables, t)
			continue
		}
		for _, c := range cs {
			if !cols[t][c] {
				rep.NewColumns[t] = append(rep.NewColumns[t], c)
			}
		}
	}
	sort.Strings(rep.NewTables)
	keepRow := func(t string, row map[string]any) {
		for c := range row {
			if !strings.HasPrefix(c, "@") && !cols[t][c] {
				delete(row, c)
			}
		}
	}
	for id, r := range recs {
		if db, ok := r["db"].(map[string]any); ok {
			for t, v := range db {
				entry, _ := v.(map[string]any)
				if cols[t] == nil {
					w := map[string]int{}
					for kind, rows := range entry {
						if arr, ok := rows.([]any); ok {
							w[kind] = len(arr)
						}
					}
					if rep.Writes[id] == nil {
						rep.Writes[id] = map[string]map[string]int{}
					}
					rep.Writes[id][t] = w
					delete(db, t)
					continue
				}
				for _, kind := range []string{"added", "removed", "modified"} {
					arr, _ := entry[kind].([]any)
					var kept []any
					for _, x := range arr {
						row, _ := x.(map[string]any)
						keepRow(t, row)
						if kind == "modified" && len(row) <= 1 {
							continue
						}
						kept = append(kept, row)
					}
					if len(kept) == 0 {
						delete(entry, kind)
					} else {
						entry[kind] = kept
					}
				}
				if len(entry) == 0 {
					delete(db, t)
				}
			}
			if len(db) == 0 {
				delete(r, "db")
			}
		}
		if arr, ok := r["audit"].([]any); ok {
			for _, x := range arr {
				if row, ok := x.(map[string]any); ok {
					keepRow("audit_logs", row)
				}
			}
		}
		if arr, ok := r["alerts"].([]any); ok {
			var kept []any
			for _, x := range arr {
				row, _ := x.(map[string]any)
				t, _ := row["@table"].(string)
				if cols[t] == nil {
					continue
				}
				keepRow(t, row)
				kept = append(kept, row)
			}
			if len(kept) == 0 {
				delete(r, "alerts")
			} else {
				r["alerts"] = kept
			}
		}
	}
	if len(rep.NewColumns) == 0 {
		rep.NewColumns = nil
	}
	if len(rep.Writes) == 0 {
		rep.Writes = nil
	}
	return rep
}

func gitCommit() string {
	if c := os.Getenv("AUTHZ_BASELINE_COMMIT"); c != "" {
		return c
	}
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func fileSHA(path string) string {
	raw, _ := os.ReadFile(path)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// goldenFiles maps golden file name -> records it holds.
type goldenSet map[string]map[string]map[string]any

// compareOrUpdate is the shared tail of every baseline test: in compare mode
// it diffs fresh records against the golden (after projection); in update
// mode (-update) it requires AUTHZ_BASELINE_RECAPTURE=<reason>, refuses to
// write while an existing record has an unapproved difference, and writes only
// records whose ID the golden does not hold yet (see reseedGolden).
func compareOrUpdate(t *testing.T, e *baselineEnv, fresh goldenSet, group string, declared int) {
	t.Helper()
	ad, err := loadApprovedDiffs(filepath.Join(authzBaselineDir, "approved-diffs.json"))
	if err != nil {
		t.Fatalf("approved-diffs.json: %v", err)
	}
	old := map[string]map[string]any{}
	for name := range fresh {
		recs, err := readJSONL(filepath.Join(authzBaselineDir, name))
		if err == nil {
			for k, v := range recs {
				old[k] = v
			}
		}
	}
	newAll := map[string]map[string]any{}
	for _, recs := range fresh {
		for k, v := range recs {
			newAll[k] = v
		}
	}
	if len(newAll) != declared {
		t.Fatalf("%s group expanded to %d scenarios; declared %d", group, len(newAll), declared)
	}
	man, manErr := loadManifest()
	var rep projectionReport
	if manErr == nil && man.Schema != nil {
		live := e.schemaSnapshot()
		adds, aerr := loadSchemaAdditions(schemaAdditionsPath(), man.Schema, man.CapturedAt, database.MigrationVersions())
		if aerr != nil {
			t.Fatalf("schema-additions.json: %v", aerr)
		}
		if stale := staleAdditions(live, adds); len(stale) > 0 {
			t.Fatalf("schema-additions.json declares structure the schema does not have: %v", stale)
		}
		rep = projectRecords(newAll, projectionSchema(live, adds), live)
		rep.Undeclared = undeclaredStructure(man.Schema, live, adds)
		if len(rep.Undeclared) > 0 {
			t.Logf("structure outside the capture-time schema that is NOT declared (compared, not projected): %v", rep.Undeclared)
		}
		if len(rep.NewTables) > 0 || len(rep.NewColumns) > 0 {
			raw, _ := json.MarshalIndent(rep, "", " ")
			t.Logf("structure outside the capture-time schema (not compared):\n%s", raw)
		}
	}
	// Seed ledger: map fresh ids onto the golden template (in place, so a
	// re-capture stores new records mapped), then compare copies in which
	// fixture ids are replaced by their markers.
	ledger, lerr := loadSeedLedger(seedLedgerPath())
	if lerr != nil {
		t.Fatalf("seed-ledger.json: %v", lerr)
	}
	seed := e.resolveSeedLedger(ledger)
	applySeedMapping(newAll, seed.mapping, flowSetupAdded)
	var routes []routeEntry
	if group == "R" {
		routes = loadRouteCatalog(t).Routes
	}
	prepare := func(o, n map[string]map[string]any) (map[string]map[string]any, map[string]map[string]any) {
		return withFixtureMarkers(o, n, routes, e.objects, seed.mapping)
	}
	compare := func() compareResult {
		o, n := prepare(old, newAll)
		res := compareRecords(o, n, ad)
		res.Diffs = append(seedLedgerDiffs(group, seed), res.Diffs...)
		return res
	}
	if out := baselineReportDir(t); out != "" {
		res := compare()
		raw, _ := json.MarshalIndent(map[string]any{"group": group, "result": res, "projection": rep, "seed_ledger": seed}, "", " ")
		_ = os.MkdirAll(out, 0o755)
		_ = os.WriteFile(filepath.Join(out, "report-"+group+".json"), raw, 0o644)
	}
	if !*updateFlag {
		if len(old) == 0 {
			t.Fatalf("no golden for group %s; capture with -update and AUTHZ_BASELINE_RECAPTURE=<reason>", group)
		}
		res := compare()
		if res.failed() {
			t.Fatalf("authorization baseline differences in group %s:\n%s", group, res.summary(50))
		}
		return
	}
	reason := strings.TrimSpace(os.Getenv("AUTHZ_BASELINE_RECAPTURE"))
	if reason == "" {
		t.Fatalf("-update requires AUTHZ_BASELINE_RECAPTURE=<reason>; nothing written")
	}
	if len(old) > 0 && len(seed.Problems) > 0 {
		t.Fatalf("re-capture refused: the seed ledger does not hold:\n  %s", strings.Join(seed.Problems, "\n  "))
	}
	if err := reseedGoldenWith(authzBaselineDir, fresh, old, ad, prepare); err != nil {
		t.Fatal(err)
	}
	if manErr != nil {
		man = baselineManifest{}
	}
	man = nextManifest(man, e.schemaSnapshot(), manifestStamp{
		Commit:     gitCommit(),
		Date:       time.Now().UTC().Format("2006-01-02"),
		Routes:     len(loadReleaseRoutes(t)),
		RoutesSHA:  fileSHA(releaseRoutesPath),
		EntryRules: baselineEntryRules,
	}, group, declared, reason)
	raw, _ := json.MarshalIndent(man, "", " ")
	if err := os.WriteFile(manifestPath(), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// manifestStamp is what a capture run measures about the tree it ran on.
type manifestStamp struct {
	Commit     string
	Date       string
	Routes     int
	RoutesSHA  string
	EntryRules int
}

// nextManifest returns the manifest after a capture of one group. Counts,
// and the recapture log are refreshed; the first capture's date and commit
// are kept (see below); Schema (the projection
// snapshot) is the exception: once the manifest holds one it stays exactly
// as it was taken at the first capture. Overwriting it with the live
// structure would pull tables and columns added by later changes into the
// snapshot, and the comparison would stop projecting them away. Only a
// manifest without a snapshot (first capture) takes the live structure.
func nextManifest(prev baselineManifest, live map[string][]string, st manifestStamp, group string, declared int, reason string) baselineManifest {
	man := prev
	man.Groups = map[string]int{}
	for k, v := range prev.Groups {
		man.Groups[k] = v
	}
	// A manifest that already holds a capture date and commit keeps them: the
	// baseline stands for the behavior at the first capture, and the
	// "migration must be newer than the capture" gate measures against it.
	// A re-capture only refreshes hash and counts, and records the commit it
	// ran at in its own log entry (never in the first-capture fields).
	recapture := prev.CapturedAt != ""
	if prev.Commit == "" {
		man.Commit = st.Commit
	}
	if !recapture {
		man.CapturedAt = st.Date
	}
	man.Routes = st.Routes
	man.RoutesSHA = st.RoutesSHA
	man.EntryRules = st.EntryRules
	man.Groups[group] = declared
	if man.Schema == nil {
		man.Schema = live
	}
	entry := fmt.Sprintf("%s %s: %s", st.Date, group, reason)
	if recapture {
		entry += fmt.Sprintf(" (recapture at commit %s)", st.Commit)
	}
	man.Recaptures = append(append([]string(nil), prev.Recaptures...), entry)
	return man
}

// reseedGolden is the write step of a re-capture. It refuses while any
// existing record (old) differs from its fresh counterpart without an active
// approved entry; approved differences do not block. It then writes every
// golden file with the existing records exactly as they are on disk and
// adds only the IDs the golden does not hold: a difference that has been
// approved keeps its old value in the golden, so the baseline stays the
// pre-replacement behavior the comparison is made against. A record the
// golden holds but fresh no longer does (a route removed from the inventory)
// is a presence difference that cannot be approved, so re-capture refuses,
// as before.
func reseedGolden(dir string, fresh goldenSet, old map[string]map[string]any, ad approvedDiffs) error {
	return reseedGoldenWith(dir, fresh, old, ad, nil)
}

// reseedGoldenWith is reseedGolden with the comparison inputs prepared the
// way compareOrUpdate prepares them (fixture markers); the records written
// are the unprepared ones.
func reseedGoldenWith(dir string, fresh goldenSet, old map[string]map[string]any, ad approvedDiffs,
	prepare func(o, n map[string]map[string]any) (map[string]map[string]any, map[string]map[string]any)) error {
	if len(old) > 0 {
		existing := map[string]map[string]any{}
		for _, recs := range fresh {
			for id, n := range recs {
				if _, ok := old[id]; ok {
					existing[id] = n
				}
			}
		}
		co, cn := old, existing
		if prepare != nil {
			co, cn = prepare(old, existing)
		}
		res := compareRecords(co, cn, ad)
		res.StaleActive = nil // an entry that hits nothing is not a difference
		res.PartialActive = nil
		if res.failed() {
			bad := 0
			for _, d := range res.Diffs {
				if d.Verdict != "approved" {
					bad++
				}
			}
			return fmt.Errorf("re-capture refused: %d unapproved differences in existing records (route them through approved-diffs.json):\n%s",
				bad, res.summary(50))
		}
	}
	for name, recs := range fresh {
		merged := make(map[string]map[string]any, len(recs))
		for id, n := range recs {
			if o, ok := old[id]; ok {
				merged[id] = o
			} else {
				merged[id] = n
			}
		}
		if err := writeJSONL(filepath.Join(dir, name), merged); err != nil {
			return err
		}
	}
	return nil
}

// baselineEntryRules declared number of front-end entry rules (E group);
// the E-group spec fails when ENTRY_RULES no longer has this many entries.
const baselineEntryRules = 35

// releaseRoutesPath route inventory the R group is expanded from.
var releaseRoutesPath = filepath.Join("testdata", "route-golden", "release-auditon.json")

// loadReleaseRoutes returns the (method, path) keys of the release inventory.
func loadReleaseRoutes(t testing.TB) []string {
	raw, err := os.ReadFile(releaseRoutesPath)
	if err != nil {
		t.Fatalf("route inventory: %v", err)
	}
	var inv struct {
		Routes []struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatalf("route inventory: %v", err)
	}
	out := make([]string, 0, len(inv.Routes))
	for _, r := range inv.Routes {
		out = append(out, r.Method+" "+r.Path)
	}
	sort.Strings(out)
	return out
}

// baselineGate runs the scenario-executing tests only with AUTHZ_BASELINE=1:
// a full pass takes minutes. Without the variable the test is
// skipped, or fails when REQUIRE_INTEGRATION=1 so CI cannot go silently green.
// AUTHZ_BASELINE=deferred skips explicitly: CI sets it on the race-enabled
// whole-module step because a dedicated step without the race detector runs
// these tests with AUTHZ_BASELINE=1.
func baselineGate(t *testing.T) {
	t.Helper()
	switch os.Getenv("AUTHZ_BASELINE") {
	case "1":
		return
	case "deferred":
		t.Skip("authorization baseline scenarios deferred to the dedicated step (AUTHZ_BASELINE=deferred)")
	}
	msg := "authorization baseline scenarios run only with AUTHZ_BASELINE=1"
	if os.Getenv("REQUIRE_INTEGRATION") == "1" {
		t.Fatal(msg + " (REQUIRE_INTEGRATION=1 forbids skipping)")
	}
	t.Skip(msg)
}

// baselineReportDir validates AUTHZ_BASELINE_REPORT_DIR: reports are written
// only to an absolute path outside the module tree, so a run never leaves
// untracked files next to the sources.
func baselineReportDir(t testing.TB) string {
	out := os.Getenv("AUTHZ_BASELINE_REPORT_DIR")
	if out == "" {
		return ""
	}
	if !filepath.IsAbs(out) {
		t.Fatalf("AUTHZ_BASELINE_REPORT_DIR must be absolute: %q", out)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err == nil {
		clean := filepath.Clean(out)
		if clean == root || strings.HasPrefix(clean, root+string(filepath.Separator)) {
			t.Fatalf("AUTHZ_BASELINE_REPORT_DIR must be outside the module tree (%s): %q", root, out)
		}
	}
	return out
}

// requireRecaptureReason fails fast, before any scenario runs, when -update
// is given without AUTHZ_BASELINE_RECAPTURE (compareOrUpdate checks again).
func requireRecaptureReason(t *testing.T) {
	t.Helper()
	if *updateFlag && strings.TrimSpace(os.Getenv("AUTHZ_BASELINE_RECAPTURE")) == "" {
		t.Fatalf("-update requires AUTHZ_BASELINE_RECAPTURE=<reason>; nothing written")
	}
}

// runBackendScenarios runs every backend scenario once, in canonical or
// reversed order, on env (replaced when a scenario forces a rebuild).
func runBackendScenarios(envp **baselineEnv, c routeCatalog, reverse bool) map[string]baselineRecord {
	type step struct {
		r    *rScenario
		flow *flowScenario
	}
	var all []step
	for _, s := range rScenarios(c, baselineSubjectIDs) {
		s := s
		all = append(all, step{r: &s})
	}
	for _, s := range flowScenarios() {
		s := s
		all = append(all, step{flow: &s})
	}
	if reverse {
		all = reversed(all)
	}
	out := make(map[string]baselineRecord, len(all))
	for _, s := range all {
		if s.r != nil {
			for k, v := range runR(envp, []rScenario{*s.r}) {
				out[k] = v
			}
			continue
		}
		out[s.flow.id] = runFlow(envp, *s.flow)
	}
	return out
}

// baselineProbe returns the value of an authoring probe variable. A probe
// run prints records without comparing them, so it sits behind the same
// gate as a comparison, is refused when REQUIRE_INTEGRATION=1, and ends in
// an explicit skip (endProbe) rather than a pass.
func baselineProbe(t *testing.T, name string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(name))
	if v != "" && os.Getenv("REQUIRE_INTEGRATION") == "1" {
		t.Fatalf("%s prints records without comparing them; REQUIRE_INTEGRATION=1 forbids it", name)
	}
	return v
}

func endProbe(t *testing.T, name string) {
	t.Helper()
	t.Skipf("%s set: records printed, nothing compared against the baseline", name)
}

// TestAuthzBaselineRoutes R group: every subject against every route.
// AUTHZ_BASELINE_PROBE=<S01,S02,...> instead runs only those subjects and
// prints one status line per scenario (catalog authoring aid; no compare).
func TestAuthzBaselineRoutes(t *testing.T) {
	baselineGate(t)
	c := loadRouteCatalog(t)
	if probe := baselineProbe(t, "AUTHZ_BASELINE_PROBE"); probe != "" {
		e := newBaselineEnv(t)
		var b strings.Builder
		for _, r := range recordList(runR(&e, rScenarios(c, strings.Split(probe, ",")))) {
			line, _ := json.Marshal(r)
			fmt.Fprintf(&b, "%d %s %s\n", r.Status, r.ID, clip(string(line)))
		}
		t.Log(b.String())
		if os.Getenv("AUTHZ_BASELINE_RESET_CHECK") != "" {
			// Reset self-check (task 3.5): after the scenarios every table
			// must again equal the template, and so must the file trees.
			mainDigest, tplDigest := e.dbDigest("main"), e.dbDigest("tpl")
			t.Logf("reset check: %d resets; main digest %s, template digest %s, fs diff %v",
				e.resetWrites, mainDigest, tplDigest, e.fsDiff())
			if mainDigest != tplDigest || e.fsDiff() != nil {
				t.Fatalf("reset check failed: database or files differ from the template")
			}
		}
		endProbe(t, "AUTHZ_BASELINE_PROBE")
	}
	requireRecaptureReason(t)
	e := newBaselineEnv(t)
	if os.Getenv("AUTHZ_BASELINE_SCHEMA_PROBE") != "" {
		e.addProjectionProbe()
	}
	start := time.Now()
	recs := runR(&e, rScenarios(c, baselineSubjectIDs))
	t.Logf("R group: %d scenarios in %s (environment rebuilds: seal); last environment: %d table resets taking %s",
		len(recs), time.Since(start), e.resetWrites, e.resetTime)
	fresh := goldenSet{}
	for subj, list := range groupBySubject(recs) {
		fresh["r-"+lower(subj)+".jsonl"] = recordsToGeneric(list)
	}
	compareOrUpdate(t, e, fresh, "R", len(baselineSubjectIDs)*len(c.Routes))
}

// TestAuthzBaselineDeterminism runs every backend scenario in canonical and
// in reversed order on separately built environments; the records must be
// identical, otherwise state leaks between scenarios.
func TestAuthzBaselineDeterminism(t *testing.T) {
	baselineGate(t)
	c := loadRouteCatalog(t)
	start := time.Now()
	e := newBaselineEnv(t)
	fwd := runBackendScenarios(&e, c, false)
	mid := time.Now()
	e = e.rebuild()
	rev := runBackendScenarios(&e, c, true)
	t.Logf("determinism: %d scenarios forward in %s, reversed in %s", len(fwd), mid.Sub(start), time.Since(mid))
	a := recordsToGeneric(recordList(fwd))
	b := recordsToGeneric(recordList(rev))
	res := compareRecords(a, b, approvedDiffs{})
	if len(res.Diffs) > 0 {
		t.Fatalf("forward and reversed runs differ:\n%s", res.summary(50))
	}
}

// addProjectionProbe adds an empty table and a column to an existing table,
// simulating structure a later stage introduces (task 3.10 check).
func (e *baselineEnv) addProjectionProbe() {
	e.projectionProbe = true
	e.sqlExec(`CREATE TABLE authz_projection_probe (id INTEGER PRIMARY KEY, note TEXT)`)
	e.sqlExec(`ALTER TABLE snippets ADD COLUMN projection_probe TEXT`)
	e.sqlExec(`ALTER TABLE tpl.snippets ADD COLUMN projection_probe TEXT`)
}
