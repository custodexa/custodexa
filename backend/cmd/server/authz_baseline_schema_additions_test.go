package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Authorization decision baseline: structure additions declared by later
// changes.
//
// New tables and columns created by migrations after the capture commit show
// up in the db/audit/alerts of fresh records as a normal side effect of the new
// implementation. They are excluded from the comparison **only when declared**
// in schema-additions.json, and every declaration is bound to the migration that
// creates it: the file is refused when a listed item already existed at capture
// time, or when its migration is not a registered migration newer than the
// capture. A new table or column that nobody declared is therefore compared like
// any other structure and shows up as a difference instead of being absorbed.

type schemaAddition struct {
	Migration string              `json:"migration"`
	Tables    []string            `json:"tables,omitempty"`
	Columns   map[string][]string `json:"columns,omitempty"`
}

type schemaAdditions struct {
	Version   int              `json:"version"`
	Additions []schemaAddition `json:"additions"`
}

func schemaAdditionsPath() string { return filepath.Join(authzBaselineDir, "schema-additions.json") }

// loadSchemaAdditions reads and validates the declaration file against the
// capture-time schema snapshot, the capture date and the registered migrations.
func loadSchemaAdditions(path string, capture map[string][]string, capturedAt string, registered []string) (schemaAdditions, error) {
	var out schemaAdditions
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("schema-additions.json: %w", err)
	}
	if out.Version != 1 {
		return out, fmt.Errorf("schema-additions.json: unsupported version %d", out.Version)
	}
	known := map[string]bool{}
	for _, v := range registered {
		known[v] = true
	}
	captureDay := strings.ReplaceAll(capturedAt, "-", "")
	seen := map[string]bool{}
	for i, a := range out.Additions {
		if a.Migration == "" || (len(a.Tables) == 0 && len(a.Columns) == 0) {
			return out, fmt.Errorf("schema-additions.json: entry %d needs a migration and at least one table or column", i)
		}
		if !known[a.Migration] {
			return out, fmt.Errorf("schema-additions.json: migration %q is not a registered migration", a.Migration)
		}
		day, _, _ := strings.Cut(a.Migration, "_")
		if len(day) != 8 || day <= captureDay {
			return out, fmt.Errorf("schema-additions.json: migration %q is not newer than the capture (%s)", a.Migration, capturedAt)
		}
		for _, tbl := range a.Tables {
			if _, existed := capture[tbl]; existed {
				return out, fmt.Errorf("schema-additions.json: table %q already existed at capture time; it cannot be a new-migration addition", tbl)
			}
			if seen["T:"+tbl] {
				return out, fmt.Errorf("schema-additions.json: table %q is declared twice", tbl)
			}
			seen["T:"+tbl] = true
		}
		for tbl, cols := range a.Columns {
			have, existed := capture[tbl]
			if !existed {
				return out, fmt.Errorf("schema-additions.json: column list for %q, which did not exist at capture time (declare the table instead)", tbl)
			}
			for _, c := range cols {
				for _, h := range have {
					if h == c {
						return out, fmt.Errorf("schema-additions.json: column %s.%s already existed at capture time", tbl, c)
					}
				}
				if seen["C:"+tbl+"."+c] {
					return out, fmt.Errorf("schema-additions.json: column %s.%s is declared twice", tbl, c)
				}
				seen["C:"+tbl+"."+c] = true
			}
		}
	}
	return out, nil
}

// projectionSchema is the structure the comparison keeps: the live schema minus
// the declared additions. Tables or columns outside the capture snapshot that
// are not declared stay in, so their writes are compared.
func projectionSchema(live map[string][]string, adds schemaAdditions) map[string][]string {
	dropTable := map[string]bool{}
	dropCol := map[string]map[string]bool{}
	for _, a := range adds.Additions {
		for _, t := range a.Tables {
			dropTable[t] = true
		}
		for t, cols := range a.Columns {
			if dropCol[t] == nil {
				dropCol[t] = map[string]bool{}
			}
			for _, c := range cols {
				dropCol[t][c] = true
			}
		}
	}
	out := map[string][]string{}
	for t, cols := range live {
		if dropTable[t] {
			continue
		}
		var kept []string
		for _, c := range cols {
			if !dropCol[t][c] {
				kept = append(kept, c)
			}
		}
		out[t] = kept
	}
	return out
}

// staleAdditions lists declared items that the live schema does not have.
func staleAdditions(live map[string][]string, adds schemaAdditions) []string {
	var stale []string
	for _, a := range adds.Additions {
		for _, t := range a.Tables {
			if _, ok := live[t]; !ok {
				stale = append(stale, "table "+t)
			}
		}
		for t, cols := range a.Columns {
			for _, c := range cols {
				found := false
				for _, h := range live[t] {
					if h == c {
						found = true
					}
				}
				if !found {
					stale = append(stale, "column "+t+"."+c)
				}
			}
		}
	}
	sort.Strings(stale)
	return stale
}

// undeclaredStructure lists tables and columns present live but neither in the
// capture snapshot nor declared. They are compared, not projected away.
func undeclaredStructure(capture, live map[string][]string, adds schemaAdditions) []string {
	kept := projectionSchema(live, adds)
	var out []string
	for t, cols := range kept {
		have, existed := capture[t]
		if !existed {
			out = append(out, "table "+t)
			continue
		}
		set := map[string]bool{}
		for _, c := range have {
			set[c] = true
		}
		for _, c := range cols {
			if !set[c] {
				out = append(out, "column "+t+"."+c)
			}
		}
	}
	sort.Strings(out)
	return out
}
