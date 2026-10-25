package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Authorization decision baseline: coverage guard.
//
// Fails when the baseline no longer covers the product surface: a route in
// the release inventory without a catalog row, a catalog row without a
// matching route, a "minimal" row without a reason, a group whose golden
// record count differs from its declared size, an outbound receiver that no
// recorded scenario reached, or a subject whose current /auth/me answer
// differs from subjects-auth-me.json (the input of the front-end E group).

const subjectsAuthMeFile = "subjects-auth-me.json"

// subjectsCapabilitiesFile is the capability-projection input of the
// front-end E group (capability projection): the current /auth/me
// answer of every subject as the server now returns it (with the two added
// fields), recorded together with the baseline manifest hash and the program
// version it was captured with. subjects-auth-me.json stays as captured; the
// front end never derives permissions from roles.
const subjectsCapabilitiesFile = "subjects-auth-me-capabilities.json"

// ad9Keys are the only keys a successful /auth/me answer may gain (the current-user entry of approved-diffs.json).
var ad9Keys = []string{"permissions", "scope_summary"}

// stripProjection removes the added projection keys from every successful subject answer,
// giving the shape the stored legacy file records. problems lists answers that
// violate the exact-addition contract: a successful answer must carry both
// keys as arrays (permissions: sorted, unique strings) and a failed answer none.
func stripProjection(live map[string]any) (legacy map[string]any, problems []string) {
	legacy = map[string]any{}
	for id, v := range live {
		rec, _ := v.(map[string]any)
		out := map[string]any{}
		for k, x := range rec {
			out[k] = x
		}
		body, _ := rec["body"].(map[string]any)
		status, _ := rec["status"].(float64)
		if status == 200 && body != nil {
			stripped := map[string]any{}
			for k, x := range body {
				stripped[k] = x
			}
			perms, pok := body["permissions"].([]any)
			if _, sok := body["scope_summary"].([]any); !pok || !sok {
				problems = append(problems, fmt.Sprintf("%s: successful answer must carry permissions and scope_summary arrays", id))
			}
			var names []string
			for _, p := range perms {
				n, ok := p.(string)
				if !ok || n == "" {
					problems = append(problems, fmt.Sprintf("%s: permissions must be non-empty strings", id))
				}
				names = append(names, n)
			}
			if !sort.StringsAreSorted(names) {
				problems = append(problems, fmt.Sprintf("%s: permissions must be sorted", id))
			}
			for i := 1; i < len(names); i++ {
				if names[i] == names[i-1] {
					problems = append(problems, fmt.Sprintf("%s: permissions must be unique (%s)", id, names[i]))
				}
			}
			for _, k := range ad9Keys {
				delete(stripped, k)
			}
			out["body"] = stripped
		} else if body != nil {
			for _, k := range ad9Keys {
				if _, ok := body[k]; ok {
					problems = append(problems, fmt.Sprintf("%s: an unsuccessful answer must not carry %s", id, k))
				}
			}
		}
		legacy[id] = out
	}
	return legacy, problems
}

// baselineGroupFiles golden files per group.
func baselineGroupFiles(group string) []string {
	if group == "R" {
		out := make([]string, 0, len(baselineSubjectIDs))
		for _, s := range baselineSubjectIDs {
			out = append(out, "r-"+lower(s)+".jsonl")
		}
		return out
	}
	return []string{lower(group) + ".jsonl"}
}

// subjectsAuthMe queries /auth/me for every subject on a live environment.
func subjectsAuthMe(e *baselineEnv) map[string]any {
	out := map[string]any{}
	for _, id := range baselineSubjectIDs {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		e.subjects[id].authorize(req)
		w := e.serve(req)
		var body any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		out[id] = map[string]any{"status": w.Code, "body": normalizeValue("", body)}
	}
	// Round-trip so numbers compare with decoded file content.
	raw, _ := json.Marshal(out)
	var generic map[string]any
	_ = json.Unmarshal(raw, &generic)
	return generic
}

func TestAuthzBaselineCoverage(t *testing.T) {
	var problems []string
	fail := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	// 1. Catalog rows versus the release route inventory.
	inv := loadReleaseRoutes(t)
	c := loadRouteCatalog(t)
	rows := map[string]int{}
	for _, r := range c.Routes {
		k := routeKey(r)
		rows[k]++
		switch r.BodyMode {
		case "full", bodyModeComplete:
		case "minimal":
			if strings.TrimSpace(r.Reason) == "" {
				fail("routes.json %s: body_mode minimal without a reason", k)
			}
		default:
			fail("routes.json %s: body_mode must be full, complete or minimal, got %q", k, r.BodyMode)
		}
	}
	invSet := map[string]bool{}
	for _, k := range inv {
		invSet[k] = true
		if rows[k] == 0 {
			fail("route %s is in the release inventory but has no routes.json row", k)
		}
	}
	for k, n := range rows {
		if n > 1 {
			fail("routes.json has %d rows for %s", n, k)
		}
		if !invSet[k] {
			fail("routes.json row %s is not in the release inventory", k)
		}
	}

	// 2. Declared group sizes versus expansion and golden content.
	man, err := loadManifest()
	if err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	if man.Routes != len(inv) {
		fail("manifest records %d routes; the release inventory has %d (re-capture needed)", man.Routes, len(inv))
	}
	if man.RoutesSHA != fileSHA(releaseRoutesPath) {
		fail("manifest routes_sha256 does not match the release inventory (re-capture needed)")
	}
	if want := len(baselineSubjectIDs) * len(c.Routes); man.Groups["R"] != want {
		fail("group R declared %d in manifest; expansion gives %d", man.Groups["R"], want)
	}
	ids := flowScenarioIDs()
	for sub, want := range flowDeclaredSizes {
		if got := len(ids[sub]); got != want {
			fail("flow group %s expands to %d scenarios; design declares %d", sub, got, want)
		}
	}
	for sub := range ids {
		if _, ok := flowDeclaredSizes[sub]; !ok {
			fail("flow group %s is not declared", sub)
		}
	}
	seen := map[string]bool{}
	for _, s := range flowScenarios() {
		if seen[s.id] {
			fail("flow scenario %s declared twice", s.id)
		}
		seen[s.id] = true
	}
	for group, size := range baselineDeclaredGroups() {
		if man.Groups[group] != size {
			fail("group %s declared %d in manifest; declaration table gives %d", group, man.Groups[group], size)
		}
	}
	reached := map[string]bool{}
	groups := make([]string, 0, len(man.Groups))
	for g := range man.Groups {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		n := 0
		for _, f := range baselineGroupFiles(g) {
			recs, err := readJSONL(filepath.Join(authzBaselineDir, f))
			if err != nil {
				fail("group %s golden %s: %v", g, f, err)
				continue
			}
			n += len(recs)
			for _, r := range recs {
				arr, _ := r["remote"].([]any)
				for _, x := range arr {
					s, _ := x.(string)
					reached[strings.Fields(s)[0]] = true
				}
			}
		}
		if n != man.Groups[g] {
			fail("group %s golden holds %d records; declared %d", g, n, man.Groups[g])
		}
	}
	for g, size := range baselineDeclaredGroups() {
		if _, ok := man.Groups[g]; !ok && size > 0 {
			fail("group %s is declared (%d) but has never been captured", g, size)
		}
	}

	// 3. Every outbound receiver reached by at least one recorded scenario.
	for _, cat := range egressCategories() {
		if !reached[cat] {
			fail("outbound receiver %q was never reached by any recorded scenario", cat)
		}
	}

	// 4. subjects-auth-me.json equals the live /auth/me answers. Needs the
	// baseline environment; on the deferred CI step the dedicated step
	// checks it.
	if os.Getenv("AUTHZ_BASELINE") == "deferred" {
		if len(problems) > 0 {
			sort.Strings(problems)
			t.Fatalf("authorization baseline coverage gaps (%d):\n  %s", len(problems), strings.Join(problems, "\n  "))
		}
		t.Log("live /auth/me check deferred to the dedicated baseline step")
		return
	}
	e := newBaselineEnv(t)
	live := subjectsAuthMe(e)
	legacy, projectionProblems := stripProjection(live)
	for _, p := range projectionProblems {
		fail("%s", p)
	}
	path := filepath.Join(authzBaselineDir, subjectsAuthMeFile)
	capsPath := filepath.Join(authzBaselineDir, subjectsCapabilitiesFile)
	capsDoc := map[string]any{
		"manifest_sha256": fileSHA(manifestPath()),
		"program_version": Version,
		"subjects":        live,
	}
	if *updateFlag && strings.TrimSpace(os.Getenv("AUTHZ_BASELINE_RECAPTURE")) != "" {
		raw, _ := json.MarshalIndent(legacy, "", " ")
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		raw, _ = json.MarshalIndent(capsDoc, "", " ")
		if err := os.WriteFile(capsPath, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fail("%s: %v", subjectsAuthMeFile, err)
	} else {
		var stored map[string]any
		if err := json.Unmarshal(raw, &stored); err != nil {
			fail("%s: %v", subjectsAuthMeFile, err)
		}
		for _, id := range baselineSubjectIDs {
			if canon(stored[id]) != canon(legacy[id]) {
				fail("%s: %s differs from the live /auth/me answer (projection fields removed): stored %s live %s",
					subjectsAuthMeFile, id, clip(canon(stored[id])), clip(canon(legacy[id])))
			}
		}
	}

	// The capability input of the E group must be the live projection of this
	// very baseline: same subjects, same manifest, current answers.
	rawCaps, err := os.ReadFile(capsPath)
	if err != nil {
		fail("%s: %v", subjectsCapabilitiesFile, err)
	} else {
		var storedCaps map[string]any
		if err := json.Unmarshal(rawCaps, &storedCaps); err != nil {
			fail("%s: %v", subjectsCapabilitiesFile, err)
		} else {
			if storedCaps["manifest_sha256"] != capsDoc["manifest_sha256"] {
				fail("%s: manifest_sha256 does not match manifest.json (re-capture needed)", subjectsCapabilitiesFile)
			}
			if v, _ := storedCaps["program_version"].(string); v == "" {
				fail("%s: program_version is missing", subjectsCapabilitiesFile)
			}
			subs, _ := storedCaps["subjects"].(map[string]any)
			for _, id := range baselineSubjectIDs {
				if canon(subs[id]) != canon(live[id]) {
					fail("%s: %s differs from the live /auth/me answer: stored %s live %s",
						subjectsCapabilitiesFile, id, clip(canon(subs[id])), clip(canon(live[id])))
				}
			}
			if len(subs) != len(baselineSubjectIDs) {
				fail("%s holds %d subjects; baseline has %d", subjectsCapabilitiesFile, len(subs), len(baselineSubjectIDs))
			}
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		t.Fatalf("authorization baseline coverage gaps (%d):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
}

// baselineDeclaredGroups sizes of the declared flow file groups (B, I, T),
// derived from the flow declaration table; R is derived from the catalog.
func baselineDeclaredGroups() map[string]int {
	out := map[string]int{}
	for sub, ids := range flowScenarioIDs() {
		out[flowFileGroup(sub)] += len(ids)
	}
	return out
}
