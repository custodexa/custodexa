package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Authorization decision baseline: R group (15 subjects x every route).

type routeCatalog struct {
	Version int          `json:"version"`
	Routes  []routeEntry `json:"routes"`
}

func loadRouteCatalog(t testing.TB) routeCatalog {
	raw, err := os.ReadFile(filepath.Join(authzBaselineDir, "routes.json"))
	if err != nil {
		t.Fatalf("routes.json: %v", err)
	}
	var c routeCatalog
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("routes.json: %v", err)
	}
	return c
}

func routeKey(r routeEntry) string { return r.Method + " " + r.Path }

// usesDynamic reports whether the entry references per-scenario tickets.
func usesDynamic(r routeEntry) bool {
	raw, _ := json.Marshal(r)
	for name := range dynamicPlaceholders {
		if strings.Contains(string(raw), "{"+name+"}") {
			return true
		}
	}
	return false
}

// rScenario is one (subject, route) pair.
type rScenario struct {
	subject string
	route   routeEntry
}

func (s rScenario) id() string { return "R/" + s.subject + "/" + routeKey(s.route) }

// rScenarios expands the R group in canonical order.
func rScenarios(c routeCatalog, subjects []string) []rScenario {
	var out []rScenario
	for _, s := range subjects {
		for _, r := range c.Routes {
			out = append(out, rScenario{subject: s, route: r})
		}
	}
	return out
}

// runR executes scenarios in the given order and returns records keyed by id.
// A successful seal releases the service graph; the environment is rebuilt
// before the next scenario (see baselineEnv.rebuild).
func runR(envp **baselineEnv, scen []rScenario) map[string]baselineRecord {
	out := make(map[string]baselineRecord, len(scen))
	for _, s := range scen {
		e := *envp
		subj := e.subjects[s.subject]
		if usesDynamic(s.route) {
			e.issueDynamic(subj)
		}
		rec := e.run(s.id(), subj, e.request(s.route))
		out[s.id()] = rec
		if routeKey(s.route) == "POST /api/v1/seal/seal" && rec.Status < 300 {
			*envp = e.rebuild()
		}
	}
	return out
}

func reversed[T any](xs []T) []T {
	out := make([]T, len(xs))
	for i, x := range xs {
		out[len(xs)-1-i] = x
	}
	return out
}

// groupBySubject splits R records into per-subject golden files.
func groupBySubject(recs map[string]baselineRecord) map[string][]baselineRecord {
	out := map[string][]baselineRecord{}
	for _, r := range recs {
		_, subj, _ := scenarioParts(r.ID)
		out[subj] = append(out[subj], r)
	}
	return out
}

func recordList(m map[string]baselineRecord) []baselineRecord {
	out := make([]baselineRecord, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
