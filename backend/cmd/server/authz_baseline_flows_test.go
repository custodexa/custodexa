package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

// Authorization decision baseline: flow groups B1-B4, I and T.
//
// A flow scenario first prepares object state (setup), then sends one or
// more requests (steps). Its record holds every step's outcome and the
// database, file, audit and outbound effects of the steps only: the tables
// written during setup are snapshotted after setup and serve as the
// comparison base, so setup writes never appear in the record. Afterwards
// everything is restored from the template like any other scenario.

// flowDeclaredSizes declared size of each flow sub-group.
var flowDeclaredSizes = map[string]int{"B1": 30, "B2": 26, "B3": 14, "B4": 12, "I": 27, "T": 9}

// flowFileGroup maps a sub-group to the golden file group (b.jsonl holds
// B1-B4).
func flowFileGroup(sub string) string {
	if strings.HasPrefix(sub, "B") {
		return "B"
	}
	return sub
}

// flowStep one request's outcome inside a flow scenario.
type flowStep struct {
	Name   string         `json:"name"`
	Status int            `json:"status"`
	Error  map[string]any `json:"error,omitempty"`
	Body   any            `json:"body,omitempty"`
	Tokens []string       `json:"tokens,omitempty"`
}

// flowScenario one declared flow scenario.
type flowScenario struct {
	id    string
	setup func(f *flowCtx) // optional; writes here are the comparison base
	steps func(f *flowCtx)
	// settle waits after the steps for work the product continues after
	// responding (asynchronous runners) before effects are captured.
	settle time.Duration
	// fresh runs the scenario on a newly built environment: process-wide
	// state that only a rebuild resets (the seal journal sequence, which a
	// restart writes into audit rows) must not depend on scenario order.
	fresh bool
}

// flowCtx state shared between a scenario's setup and steps.
type flowCtx struct {
	e     *baselineEnv
	steps []flowStep
	vars  map[string]any
	// rebuildAfter is set when a step restarted the service graph (T08);
	// the runner captures the effects, then continues on a fresh
	// environment because in-process state no longer matches the template.
	rebuildAfter bool
}

func (f *flowCtx) set(k string, v any) { f.vars[k] = v }

func (f *flowCtx) get(k string) any {
	v, ok := f.vars[k]
	if !ok {
		f.e.t.Fatalf("flow: variable %s not set", k)
	}
	return v
}

// send performs one step as subject and records it; it returns the decoded
// JSON body (nil when not JSON) for later steps.
func (f *flowCtx) send(name, subject string, br baselineRequest) map[string]any {
	e := f.e
	var body *bytes.Reader
	if br.Body != nil {
		body = bytes.NewReader(br.Body)
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(br.Method, br.Path, body)
	if br.ContentType != "" {
		req.Header.Set("Content-Type", br.ContentType)
	}
	if br.WS {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	}
	for k, v := range br.Headers {
		req.Header.Set(k, v)
	}
	if s, ok := e.subjects[subject]; ok {
		s.authorize(req)
	} else if subject != "" {
		e.t.Fatalf("flow: unknown subject %s", subject)
	}
	w := e.serve(req)
	var rec baselineRecord
	rec.Status = w.Code
	captureBody(&rec, w, false)
	f.steps = append(f.steps, flowStep{Name: name, Status: w.Code, Error: rec.Error, Body: rec.Body, Tokens: rec.Tokens})
	out := map[string]any{}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil {
		return nil
	}
	return out
}

// call is send with a JSON body (nil for none).
func (f *flowCtx) call(name, subject, method, path string, payload any) map[string]any {
	br := baselineRequest{Method: method, Path: path}
	if payload != nil {
		raw, err := json.Marshal(f.e.resolveValue(toGeneric(payload)))
		if err != nil {
			f.e.t.Fatalf("flow %s: marshal: %v", name, err)
		}
		br.Body = raw
		br.ContentType = "application/json"
	}
	return f.send(name, subject, br)
}

// ws sends a pre-upgrade WebSocket request (only the HTTP decision and the
// outbound attempt are observed).
func (f *flowCtx) ws(name, subject, path string) map[string]any {
	return f.send(name, subject, baselineRequest{Method: http.MethodGet, Path: path, WS: true})
}

// toGeneric round-trips through JSON so placeholders in nested Go values
// are resolved like catalog bodies.
func toGeneric(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(raw, &out) != nil {
		return v
	}
	return out
}

// str extracts a string at a dotted path from a decoded body ("data.id").
func str(m map[string]any, path string) string {
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[k]
	}
	switch x := cur.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%d", int64(x))
	}
	return ""
}

// runFlow executes one flow scenario and captures its record. When the
// scenario replaced the environment, *envp is updated.
func runFlow(envp **baselineEnv, s flowScenario) baselineRecord {
	if s.fresh {
		*envp = (*envp).rebuild()
	}
	e := *envp
	f := &flowCtx{e: e, vars: map[string]any{}}
	e.recv.take()
	if s.setup != nil {
		s.setup(f)
	}
	base := e.snapshotTables(e.touched())
	e.recordSetupAdditions(s.id)
	preFS := e.fsDiff()
	e.recv.take() // outbound attempts during setup are not scenario effects
	s.steps(f)
	if s.settle > 0 {
		time.Sleep(s.settle)
	}
	awaitBackground(e.t)
	rec := baselineRecord{ID: s.id, Steps: f.steps}
	if len(f.steps) > 0 {
		rec.Status = f.steps[len(f.steps)-1].Status
	}
	touched := e.touched()
	diff := e.diffTablesFrom(touched, base)
	postFS := e.fsDiff()
	rec.FS = subtractFS(postFS, preFS)
	rec.Remote = remoteList(e.recv.take())
	e.splitDiff(&rec, diff)
	e.dropSnapshot(base)
	e.resetTables(touched)
	if postFS != nil || preFS != nil {
		e.resetFS()
	}
	e.resetInProcess(touched)
	if f.rebuildAfter {
		*envp = e.rebuild()
	}
	return rec
}

// restartSameDB seals the instance through the product API and unseals it
// again on the same database: the stage-2 service graph (with every
// in-process ticket store) is torn down and rebuilt, as after a process
// restart, while the stored state stays.
func (f *flowCtx) restartSameDB() {
	e := f.e
	if code, out := e.api("S01", http.MethodPost, "/api/v1/seal/seal", nil); code >= 300 {
		e.t.Fatalf("flow restart: seal returned %d %v", code, out)
	}
	if w := e.seal.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		e.t.Fatalf("flow restart: unseal returned %d: %s", w.Code, w.Body.String())
	}
	graph, ok := e.seal.machine.Snapshot().Services.(*appGraph)
	if !ok || graph == nil {
		e.t.Fatalf("flow restart: stage-2 graph unavailable after unseal")
	}
	e.graph = graph
	// The sealed-period journal is replayed into the audit trail by a
	// background goroutine started during unseal; later steps would
	// interleave their own audit rows with it. Finish it first.
	awaitBackground(e.t)
	e.inProcess = e.collectInProcessSlots()
	e.lazyCollected = false
	f.rebuildAfter = true
}

// subtractFS keeps file changes made by the steps (relative to the state
// after setup).
func subtractFS(post, pre map[string]string) map[string]string {
	out := map[string]string{}
	for p, st := range post {
		if pre[p] != st {
			out[p] = st
		}
	}
	for p := range pre {
		if _, ok := post[p]; !ok {
			out[p] = "restored"
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// flowSub returns the sub-group of a flow scenario id ("B1/S02/x" -> "B1").
func flowSub(id string) string {
	g, _, _ := scenarioParts(id)
	return g
}

// runFlows executes flow scenarios in the given order.
func runFlows(envp **baselineEnv, scen []flowScenario) map[string]baselineRecord {
	out := make(map[string]baselineRecord, len(scen))
	for _, s := range scen {
		out[s.id] = runFlow(envp, s)
	}
	return out
}

// flowScenarioIDs ids of every declared flow scenario, by sub-group.
func flowScenarioIDs() map[string][]string {
	out := map[string][]string{}
	for _, s := range flowScenarios() {
		sub := flowSub(s.id)
		out[sub] = append(out[sub], s.id)
	}
	for _, ids := range out {
		sort.Strings(ids)
	}
	return out
}

// flowScenarios the full declaration table, canonical order.
func flowScenarios() []flowScenario {
	var out []flowScenario
	out = append(out, b1Scenarios()...)
	out = append(out, b2Scenarios()...)
	out = append(out, b3Scenarios()...)
	out = append(out, b4Scenarios()...)
	out = append(out, iScenarios()...)
	out = append(out, tScenarios()...)
	return out
}

// TestAuthzBaselineFlows B1-B4, I and T groups.
func TestAuthzBaselineFlows(t *testing.T) {
	baselineGate(t)
	requireRecaptureReason(t)
	scen := flowScenarios()
	if only := flowOnlyFilter(t); only != nil {
		var keep []flowScenario
		for _, s := range scen {
			if only(s.id) {
				keep = append(keep, s)
			}
		}
		e := newBaselineEnv(t)
		var b strings.Builder
		for _, r := range recordList(runFlows(&e, keep)) {
			line, _ := json.Marshal(r)
			fmt.Fprintf(&b, "%d %s %s\n", r.Status, r.ID, string(line))
		}
		t.Log(b.String())
		endProbe(t, "AUTHZ_BASELINE_FLOW_PROBE")
	}
	e := newBaselineEnv(t)
	start := time.Now()
	recs := runFlows(&e, scen)
	t.Logf("flow groups: %d scenarios in %s", len(recs), time.Since(start))
	byFile := map[string][]baselineRecord{}
	for _, r := range recs {
		g := flowFileGroup(flowSub(r.ID))
		byFile[g] = append(byFile[g], r)
	}
	for _, g := range []string{"B", "I", "T"} {
		g := g
		declared := 0
		for sub, n := range flowDeclaredSizes {
			if flowFileGroup(sub) == g {
				declared += n
			}
		}
		list := byFile[g]
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		t.Run(g, func(t *testing.T) {
			compareOrUpdate(t, e, goldenSet{lower(g) + ".jsonl": recordsToGeneric(list)}, g, declared)
		})
	}
}

// flowOnlyFilter AUTHZ_BASELINE_FLOW_PROBE=<prefix,...> runs only matching
// flow scenarios and prints their records (authoring aid; no compare, so
// the run ends in a skip; see baselineProbe).
func flowOnlyFilter(t *testing.T) func(string) bool {
	v := baselineProbe(t, "AUTHZ_BASELINE_FLOW_PROBE")
	if v == "" {
		return nil
	}
	prefixes := strings.Split(v, ",")
	return func(id string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(id, p) {
				return true
			}
		}
		return false
	}
}
