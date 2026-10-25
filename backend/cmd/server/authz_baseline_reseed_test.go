package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuthzBaselineReseed guards the write step of a re-capture
// (reseedGolden): an approved difference must not block adding records for
// new IDs, an unapproved one must, and a record the golden already holds is
// never rewritten, whatever the fresh run says about it.
func TestAuthzBaselineReseed(t *testing.T) {
	const (
		approvedID = "R/S02/GET /api/v1/assets"   // differs, covered by an active entry
		steadyID   = "R/S03/GET /api/v1/assets"   // identical
		otherID    = "R/S03/GET /api/v1/sessions" // used for unapproved differences
		newA       = "R/S02/GET /api/v1/zeta"     // not in the golden
		newB       = "R/S03/GET /api/v1/alpha"    // not in the golden, sorts before newA's file mate
	)
	rec := func(id string, status float64, body any) map[string]any {
		return map[string]any{"id": id, "status": status, "body": body, "audit": []any{}}
	}
	activeAD := approvedDiffs{Entries: []approvedEntry{{
		ID: "AD-X", Status: "active", Reason: "synthetic",
		Selector: approvedSelector{Group: "R", Subjects: []string{"S02"}, Keys: []string{"GET /api/v1/assets"}, Fields: []string{"status", "body"}},
	}}}
	oldAll := func() map[string]map[string]any {
		return map[string]map[string]any{
			approvedID: rec(approvedID, 403, nil),
			steadyID:   rec(steadyID, 200, map[string]any{"total": 1.0, "rows": []any{"a", "<b>&"}}),
			otherID:    rec(otherID, 200, map[string]any{"total": 0.0}),
		}
	}
	// setup writes the golden of oldAll() into a temp dir (r-s02: approvedID,
	// r-s03: steadyID and otherID) and returns the dir and the old records as
	// read back from disk, which is what compareOrUpdate hands over.
	setup := func(t *testing.T) (string, map[string]map[string]any) {
		t.Helper()
		dir := t.TempDir()
		all := oldAll()
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(writeJSONL(filepath.Join(dir, "r-s02.jsonl"), map[string]map[string]any{approvedID: all[approvedID]}))
		must(writeJSONL(filepath.Join(dir, "r-s03.jsonl"), map[string]map[string]any{steadyID: all[steadyID], otherID: all[otherID]}))
		old := map[string]map[string]any{}
		for _, f := range []string{"r-s02.jsonl", "r-s03.jsonl"} {
			recs, err := readJSONL(filepath.Join(dir, f))
			must(err)
			for k, v := range recs {
				old[k] = v
			}
		}
		return dir, old
	}
	read := func(t *testing.T, dir, name string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	// fresh builds a run result: the old records, the approved difference
	// (approvedID now answers 200), plus the given extra records.
	fresh := func(extra ...map[string]any) goldenSet {
		s02 := map[string]map[string]any{approvedID: rec(approvedID, 200, map[string]any{"total": 2.0})}
		s03 := map[string]map[string]any{steadyID: oldAll()[steadyID], otherID: oldAll()[otherID]}
		for _, x := range extra {
			id := x["id"].(string)
			if strings.HasPrefix(id, "R/S02/") {
				s02[id] = x
			} else {
				s03[id] = x
			}
		}
		return goldenSet{"r-s02.jsonl": s02, "r-s03.jsonl": s03}
	}

	t.Run("approved_difference_does_not_block_new_ids", func(t *testing.T) {
		dir, old := setup(t)
		if err := reseedGolden(dir, fresh(rec(newA, 200, nil), rec(newB, 403, nil)), old, activeAD); err != nil {
			t.Fatalf("an approved difference must not block a re-capture: %v", err)
		}
		if got := read(t, dir, "r-s02.jsonl"); !strings.Contains(got, `"id":"`+newA+`"`) {
			t.Fatalf("new ID %q missing from r-s02.jsonl:\n%s", newA, got)
		}
		if got := read(t, dir, "r-s03.jsonl"); !strings.Contains(got, `"id":"`+newB+`"`) {
			t.Fatalf("new ID %q missing from r-s03.jsonl:\n%s", newB, got)
		}
	})

	t.Run("unapproved_difference_refuses_and_writes_nothing", func(t *testing.T) {
		dir, old := setup(t)
		beforeA, beforeB := read(t, dir, "r-s02.jsonl"), read(t, dir, "r-s03.jsonl")
		f := fresh(rec(newA, 200, nil), rec(newB, 403, nil))
		f["r-s03.jsonl"][otherID] = rec(otherID, 500, nil) // not covered by any entry
		err := reseedGolden(dir, f, old, activeAD)
		if err == nil || !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), otherID) {
			t.Fatalf("an unapproved difference must refuse and name the record, got: %v", err)
		}
		if read(t, dir, "r-s02.jsonl") != beforeA || read(t, dir, "r-s03.jsonl") != beforeB {
			t.Fatal("a refused re-capture must not touch the golden files")
		}
	})

	t.Run("pending_entry_is_not_an_approval", func(t *testing.T) {
		dir, old := setup(t)
		pending := approvedDiffs{Entries: []approvedEntry{activeAD.Entries[0]}}
		pending.Entries[0].Status = "pending"
		if err := reseedGolden(dir, fresh(rec(newA, 200, nil)), old, pending); err == nil {
			t.Fatal("a difference covered only by a pending entry must refuse")
		}
	})

	t.Run("difference_without_any_entry_refuses", func(t *testing.T) {
		dir, old := setup(t)
		if err := reseedGolden(dir, fresh(rec(newA, 200, nil)), old, approvedDiffs{}); err == nil {
			t.Fatal("the approved-difference record must refuse when no entry covers it")
		}
	})

	t.Run("existing_records_are_not_rewritten", func(t *testing.T) {
		dir, old := setup(t)
		beforeA, beforeB := read(t, dir, "r-s02.jsonl"), read(t, dir, "r-s03.jsonl")
		if err := reseedGolden(dir, fresh(rec(newA, 200, nil), rec(newB, 403, nil)), old, activeAD); err != nil {
			t.Fatal(err)
		}
		// The record with the approved difference keeps its old value.
		gotA := read(t, dir, "r-s02.jsonl")
		if !strings.Contains(gotA, beforeA[:len(beforeA)-1]) {
			t.Fatalf("approved-difference record was rewritten:\nwant line %s\ngot:\n%s", beforeA, gotA)
		}
		if strings.Contains(gotA, `"total":2`) {
			t.Fatalf("the new value of an approved difference leaked into the golden:\n%s", gotA)
		}
		// Every other existing line is present byte for byte.
		gotB := read(t, dir, "r-s03.jsonl")
		for _, line := range strings.Split(strings.TrimSpace(beforeB), "\n") {
			if !strings.Contains(gotB, line+"\n") {
				t.Fatalf("existing line changed or missing in r-s03.jsonl: %s\ngot:\n%s", line, gotB)
			}
		}
	})

	t.Run("new_ids_are_sorted_and_formatted_like_existing", func(t *testing.T) {
		dir, old := setup(t)
		extraA, extraB := rec(newA, 200, map[string]any{"k": "v"}), rec(newB, 403, nil)
		if err := reseedGolden(dir, fresh(extraA, extraB), old, activeAD); err != nil {
			t.Fatal(err)
		}
		// Expected files: the golden writer applied to old + new records.
		want := t.TempDir()
		all := oldAll()
		if err := writeJSONL(filepath.Join(want, "r-s02.jsonl"), map[string]map[string]any{approvedID: all[approvedID], newA: extraA}); err != nil {
			t.Fatal(err)
		}
		if err := writeJSONL(filepath.Join(want, "r-s03.jsonl"), map[string]map[string]any{steadyID: all[steadyID], otherID: all[otherID], newB: extraB}); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"r-s02.jsonl", "r-s03.jsonl"} {
			if got, exp := read(t, dir, f), read(t, want, f); got != exp {
				t.Fatalf("%s differs from old+new written by the golden writer:\ngot:\n%s\nwant:\n%s", f, got, exp)
			}
		}
		lines := strings.Split(strings.TrimSpace(read(t, dir, "r-s03.jsonl")), "\n")
		if len(lines) != 3 || !strings.Contains(lines[0], newB) {
			t.Fatalf("lines must be ordered by ID (alpha first): %v", lines)
		}
	})

	t.Run("first_capture_writes_everything", func(t *testing.T) {
		dir := t.TempDir()
		f := fresh()
		if err := reseedGolden(dir, f, map[string]map[string]any{}, approvedDiffs{}); err != nil {
			t.Fatal(err)
		}
		if got := read(t, dir, "r-s03.jsonl"); strings.Count(got, "\n") != 2 {
			t.Fatalf("first capture must write all fresh records:\n%s", got)
		}
	})
}

// TestAuthzBaselineGoldenRoundTrip pins the assumption behind "existing
// records are rewritten byte for byte": reading a real golden file and
// writing it back with the golden writer reproduces the file exactly.
func TestAuthzBaselineGoldenRoundTrip(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(authzBaselineDir, "*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden files under %s: %v", authzBaselineDir, err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		recs, err := readJSONL(f)
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), filepath.Base(f))
		if err := writeJSONL(out, recs); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(out)
		if !bytes.Equal(raw, got) {
			t.Errorf("%s does not survive read+write unchanged", f)
		}
	}
}

// TestAuthzBaselineReseedManifest guards the manifest step of a re-capture
// (nextManifest): the D11 projection snapshot (Schema) is kept exactly as
// taken at the first capture even when the live structure has grown, the first
// capture's date and commit are kept verbatim, and only hash, counts and the
// recapture log are refreshed.
func TestAuthzBaselineReseedManifest(t *testing.T) {
	marshal := func(m baselineManifest) []byte {
		raw, err := json.MarshalIndent(m.Schema, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	stamp := manifestStamp{Commit: "newcommit", Date: "2026-11-01", Routes: 321, RoutesSHA: "newsha", EntryRules: 40}
	// a live structure that grew: one new column on an old table, one new
	// table, and the old table "users" lost nothing.
	live := map[string][]string{
		"users":         {"id", "name", "perm_version"},
		"roles":         {"id", "name"},
		"perm_bindings": {"id", "role_id"},
	}

	t.Run("schema snapshot is byte-identical after re-capture", func(t *testing.T) {
		prev, err := loadManifest()
		if err != nil || prev.Schema == nil {
			t.Fatalf("real manifest: %v", err)
		}
		// grow the live structure on top of the real snapshot
		grown := map[string][]string{"zz_new_table": {"id"}}
		for tbl, cols := range prev.Schema {
			grown[tbl] = append([]string(nil), cols...)
		}
		for tbl := range grown {
			if tbl != "zz_new_table" {
				grown[tbl] = append(grown[tbl], "zz_new_column")
				break
			}
		}
		before := marshal(prev)
		next := nextManifest(prev, grown, stamp, "R", prev.Groups["R"]+3, "new routes")
		if !bytes.Equal(before, marshal(next)) {
			t.Errorf("schema snapshot changed by re-capture")
		}
		if bytes.Contains(marshal(next), []byte("zz_new")) {
			t.Errorf("live-only structure leaked into the snapshot")
		}
		if !bytes.Equal(before, marshal(prev)) {
			t.Errorf("previous manifest was mutated")
		}
	})

	t.Run("recapture keeps first capture date and commit, refreshes hash counts and log", func(t *testing.T) {
		prev := baselineManifest{
			Commit: "old", CapturedAt: "2026-10-15", Routes: 305, RoutesSHA: "oldsha", EntryRules: 34,
			Groups:     map[string]int{"B": 82, "R": 4575},
			Schema:     map[string][]string{"users": {"id", "name"}},
			Recaptures: []string{"2026-10-15 R: first"},
		}
		next := nextManifest(prev, live, stamp, "R", 4600, "new routes")
		if next.Commit != "old" || next.CapturedAt != "2026-10-15" {
			t.Errorf("first-capture commit/date overwritten: commit=%q captured_at=%q", next.Commit, next.CapturedAt)
		}
		if next.Routes != 321 || next.RoutesSHA != "newsha" || next.EntryRules != 40 {
			t.Errorf("hash and counts not refreshed: %+v", next)
		}
		if next.Groups["R"] != 4600 || next.Groups["B"] != 82 {
			t.Errorf("group counts wrong: %v", next.Groups)
		}
		if prev.Groups["R"] != 4575 {
			t.Errorf("previous Groups map mutated: %v", prev.Groups)
		}
		want := []string{"2026-10-15 R: first", "2026-11-01 R: new routes (recapture at commit newcommit)"}
		if len(next.Recaptures) != 2 || next.Recaptures[0] != want[0] || next.Recaptures[1] != want[1] {
			t.Errorf("recapture log = %v", next.Recaptures)
		}
		if len(prev.Recaptures) != 1 {
			t.Errorf("previous Recaptures mutated: %v", prev.Recaptures)
		}
		// a commit that could not be determined is only ever written in the log entry
		unk := stamp
		unk.Commit = "unknown"
		next = nextManifest(prev, live, unk, "R", 4600, "new routes")
		if next.Commit != "old" || next.CapturedAt != "2026-10-15" ||
			next.Recaptures[1] != "2026-11-01 R: new routes (recapture at commit unknown)" {
			t.Errorf("unknown commit leaked into first-capture fields: %+v", next)
		}
	})

	t.Run("first capture takes the live structure", func(t *testing.T) {
		next := nextManifest(baselineManifest{}, live, stamp, "B", 82, "initial")
		if next.Commit != "newcommit" || next.CapturedAt != "2026-11-01" {
			t.Errorf("first capture must take current commit/date: %+v", next)
		}
		if len(next.Recaptures) != 1 || next.Recaptures[0] != "2026-11-01 B: initial" {
			t.Errorf("first capture log = %v", next.Recaptures)
		}
		if len(next.Schema) != len(live) || len(next.Schema["users"]) != 3 {
			t.Errorf("first capture schema = %v", next.Schema)
		}
		if next.Groups["B"] != 82 {
			t.Errorf("groups = %v", next.Groups)
		}
	})
}
