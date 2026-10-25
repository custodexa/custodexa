package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Authorization decision baseline: database template, change capture and reset.
//
// After fixtures are seeded the database is copied with VACUUM INTO and the
// copy is attached as schema "tpl" on a connection the framework pins for
// itself. Triggers on every table (created after the snapshot, so the
// template has none) record which tables a scenario wrote, whichever pool
// connection the product used. After a scenario only those tables are diffed
// against the template and restored by DELETE + INSERT ... SELECT.
//
// The product runs with a small connection pool in WAL mode rather than a
// single connection: several product paths read through the package-level
// handle while holding a transaction, which deadlocks on one connection.

const baselineTouchedTable = "main.authz_baseline_touched"

// takeTemplate snapshots DB and filesystem state and installs change capture.
func (e *baselineEnv) takeTemplate() {
	t := e.t
	e.pinConnection()
	tables := e.sqlStrings(`SELECT name FROM main.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if len(tables) < 50 {
		t.Fatalf("baseline: only %d tables found; schema did not migrate as expected", len(tables))
	}
	e.tables = tables
	e.requireInProcessCoverage()
	e.inProcess = e.collectInProcessSlots()

	e.template = filepath.Join(e.dir, "template.db")
	e.sqlExec(`VACUUM INTO ?`, e.template)
	e.templateFS = filepath.Join(e.dir, "fs-template")
	for name, live := range e.fsDirs {
		if err := copyTree(live, filepath.Join(e.templateFS, name)); err != nil {
			t.Fatalf("template fs %s: %v", name, err)
		}
	}
	e.sqlExec(`ATTACH DATABASE ? AS tpl`, e.template)
	e.sqlExec(`CREATE TABLE main.authz_baseline_touched (name TEXT PRIMARY KEY)`)
	for i, tbl := range tables {
		for _, op := range []string{"INSERT", "UPDATE", "DELETE"} {
			e.sqlExec(fmt.Sprintf(`CREATE TRIGGER main.authz_bt_%d_%s AFTER %s ON %q BEGIN INSERT OR IGNORE INTO authz_baseline_touched(name) VALUES (%s); END`,
				i, strings.ToLower(op), op, tbl, sqlQuote(tbl)))
		}
	}
}

func sqlQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// touched returns the tables written since the last reset. It fails the test
// if the capture table vanished (the connection was replaced).
func (e *baselineEnv) touched() []string {
	return e.sqlStrings(`SELECT name FROM ` + baselineTouchedTable + ` ORDER BY name`)
}

// rowDiff is the per-table change set of one scenario.
type rowDiff struct {
	Added    []map[string]any    `json:"added,omitempty"`
	Removed  []map[string]any    `json:"removed,omitempty"`
	Modified []map[string][2]any `json:"modified,omitempty"`
}

// wallClockColumns columns whose value is a measured duration. They are left
// out of the modified-column comparison so a loaded machine cannot create or
// remove a modified entry; every other column of the row is still compared.
var wallClockColumns = map[string]bool{"last_test_latency_ms": true}

// diffTables compares touched tables with the template.
func (e *baselineEnv) diffTables(tables []string) map[string]*rowDiff {
	return e.diffTablesFrom(tables, nil)
}

// diffTablesFrom compares touched tables with a base: the template, or for
// tables listed in base, a snapshot taken after a flow scenario's setup
// (see snapshotTables), so setup writes do not count as scenario effects.
func (e *baselineEnv) diffTablesFrom(tables []string, base map[string]string) map[string]*rowDiff {
	out := map[string]*rowDiff{}
	for _, tbl := range tables {
		before := fmt.Sprintf(`SELECT rowid AS authz_rowid, * FROM tpl.%q`, tbl)
		if snap, ok := base[tbl]; ok {
			before = fmt.Sprintf(`SELECT * FROM temp.%q`, snap)
		}
		cur := fmt.Sprintf(`SELECT rowid AS authz_rowid, * FROM main.%q`, tbl)
		added := e.queryRows(cur + ` EXCEPT ` + before)
		removed := e.queryRows(before + ` EXCEPT ` + cur)
		if len(added) == 0 && len(removed) == 0 {
			continue
		}
		d := &rowDiff{}
		prior := map[string]map[string]any{}
		for _, r := range removed {
			prior[fmt.Sprint(r["authz_rowid"])] = r
		}
		for _, r := range added {
			key := fmt.Sprint(r["authz_rowid"])
			if old, ok := prior[key]; ok {
				delete(prior, key)
				mod := map[string][2]any{}
				for col, v := range r {
					if col == "authz_rowid" || wallClockColumns[col] {
						continue
					}
					if fmt.Sprint(old[col]) != fmt.Sprint(v) {
						mod[col] = [2]any{old[col], v}
					}
				}
				if len(mod) == 0 {
					// The row differs only in wall-clock columns: the
					// capture-time rows record them as zero, so a row that
					// changed in nothing else was never a modification.
					continue
				}
				mod["@rowid"] = [2]any{r["authz_rowid"], r["authz_rowid"]}
				d.Modified = append(d.Modified, mod)
				continue
			}
			delete(r, "authz_rowid")
			d.Added = append(d.Added, r)
		}
		keys := make([]string, 0, len(prior))
		for k := range prior {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			r := prior[k]
			delete(r, "authz_rowid")
			d.Removed = append(d.Removed, r)
		}
		out[tbl] = d
	}
	return out
}

func (e *baselineEnv) queryRows(q string) []map[string]any {
	rows, err := e.conn.QueryContext(context.Background(), q)
	if err != nil {
		e.t.Fatalf("baseline query %q: %v", q, err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			e.t.Fatalf("scan: %v", err)
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			if b, ok := vals[i].([]byte); ok {
				m[c] = string(b)
			} else {
				m[c] = vals[i]
			}
		}
		out = append(out, m)
	}
	return out
}

// snapshotTables copies the current content of tables into temporary tables
// on the pinned connection and returns table -> snapshot name.
func (e *baselineEnv) snapshotTables(tables []string) map[string]string {
	out := map[string]string{}
	for i, tbl := range tables {
		name := fmt.Sprintf("authz_pre_%d", i)
		e.sqlExec(fmt.Sprintf(`DROP TABLE IF EXISTS temp.%q`, name))
		e.sqlExec(fmt.Sprintf(`CREATE TEMP TABLE %q AS SELECT rowid AS authz_rowid, * FROM main.%q`, name, tbl))
		out[tbl] = name
	}
	return out
}

// dropSnapshot removes the temporary tables of snapshotTables.
func (e *baselineEnv) dropSnapshot(snap map[string]string) {
	for _, name := range snap {
		e.sqlExec(fmt.Sprintf(`DROP TABLE IF EXISTS temp.%q`, name))
	}
}

// resetTables restores the given tables (and the autoincrement ledger) from
// the template and clears the capture table.
func (e *baselineEnv) resetTables(tables []string) {
	if len(tables) == 0 {
		return
	}
	start := time.Now()
	defer func() { e.resetTime += time.Since(start) }()
	fk := e.sqlInt(`PRAGMA foreign_keys`)
	if fk != 0 {
		e.sqlExec(`PRAGMA foreign_keys = OFF`)
	}
	stmts := []string{}
	for _, tbl := range tables {
		stmts = append(stmts,
			fmt.Sprintf(`DELETE FROM main.%q`, tbl),
			fmt.Sprintf(`INSERT INTO main.%q SELECT * FROM tpl.%q`, tbl, tbl))
	}
	if e.hasSequence() {
		stmts = append(stmts, `DELETE FROM main.sqlite_sequence`, `INSERT INTO main.sqlite_sequence SELECT * FROM tpl.sqlite_sequence`)
	}
	stmts = append(stmts, `DELETE FROM `+baselineTouchedTable)
	for _, s := range stmts {
		e.sqlExec(s)
	}
	if fk != 0 {
		e.sqlExec(`PRAGMA foreign_keys = ON`)
	}
	e.resetWrites++
}

func (e *baselineEnv) hasSequence() bool {
	return e.sqlInt(`SELECT count(*) FROM main.sqlite_master WHERE name='sqlite_sequence'`) > 0
}

// dbDigest hashes every table's full content (used by the reset self-check).
func (e *baselineEnv) dbDigest(schema string) string {
	h := sha256.New()
	for _, tbl := range e.tables {
		rows := e.queryRows(fmt.Sprintf(`SELECT * FROM %s.%q ORDER BY rowid`, schema, tbl))
		fmt.Fprintf(h, "%s:%d\n", tbl, len(rows))
		for _, r := range rows {
			keys := make([]string, 0, len(r))
			for k := range r {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(h, "%s=%v;", k, r[k])
			}
			h.Write([]byte{'\n'})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fsDiff compares live directories with their template copies.
func (e *baselineEnv) fsDiff() map[string]string {
	out := map[string]string{}
	for name, live := range e.fsDirs {
		cur := treeDigest(live)
		tpl := treeDigest(filepath.Join(e.templateFS, name))
		for p, d := range cur {
			if old, ok := tpl[p]; !ok {
				out[name+"/"+p] = "added"
			} else if old != d {
				out[name+"/"+p] = "modified"
			}
		}
		for p := range tpl {
			if _, ok := cur[p]; !ok {
				out[name+"/"+p] = "removed"
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// resetFS restores live directories from the template copies.
func (e *baselineEnv) resetFS() {
	for name, live := range e.fsDirs {
		if err := os.RemoveAll(live); err != nil {
			e.t.Fatalf("reset fs %s: %v", name, err)
		}
		if err := copyTree(filepath.Join(e.templateFS, name), live); err != nil {
			e.t.Fatalf("reset fs %s: %v", name, err)
		}
	}
}

func treeDigest(root string) map[string]string {
	out := map[string]string{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		h := sha256.New()
		_, _ = io.Copy(h, f)
		_ = f.Close()
		out[rel] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	return out
}

func copyTree(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

// pinConnection reserves one pool connection for the framework.
func (e *baselineEnv) pinConnection() {
	sqlDB, err := e.db.DB()
	if err != nil {
		e.t.Fatalf("sql.DB: %v", err)
	}
	c, err := sqlDB.Conn(context.Background())
	if err != nil {
		e.t.Fatalf("pin connection: %v", err)
	}
	e.conn = c
	e.t.Cleanup(func() { _ = c.Close() })
}

func (e *baselineEnv) sqlExec(q string, args ...any) {
	if _, err := e.conn.ExecContext(context.Background(), q, args...); err != nil {
		e.t.Fatalf("baseline sql %q: %v", clip(q), err)
	}
}

func (e *baselineEnv) sqlStrings(q string) []string {
	rows, err := e.conn.QueryContext(context.Background(), q)
	if err != nil {
		e.t.Fatalf("baseline sql %q: %v", clip(q), err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			e.t.Fatalf("scan: %v", err)
		}
		out = append(out, s)
	}
	return out
}

func (e *baselineEnv) sqlInt(q string) int {
	var n sql.NullInt64
	if err := e.conn.QueryRowContext(context.Background(), q).Scan(&n); err != nil {
		e.t.Fatalf("baseline sql %q: %v", clip(q), err)
	}
	return int(n.Int64)
}
