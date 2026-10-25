package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestAuthzBaselineProbeGate guards the authoring probes
// (AUTHZ_BASELINE_PROBE, AUTHZ_BASELINE_FLOW_PROBE): they print records
// without comparing them, so a stray probe variable must never turn a
// scenario test green. The scenario tests are re-run in a child process of
// this test binary with the probe set: without AUTHZ_BASELINE=1 the gate
// applies first, under REQUIRE_INTEGRATION=1 the probe is refused, and a
// probe run ends in a skip, not a pass.
func TestAuthzBaselineProbeGate(t *testing.T) {
	subject := baselineSubjectIDs[0]
	type probeCase struct {
		name, test string
		env        map[string]string
		gated      bool   // needs the baseline environment (AUTHZ_BASELINE=1)
		wantExit   bool   // child must exit non-zero
		want       string // child output must contain
	}
	cases := []probeCase{
		{
			name: "probe_without_gate_fails", test: "TestAuthzBaselineRoutes",
			env:      map[string]string{"AUTHZ_BASELINE_PROBE": subject, "REQUIRE_INTEGRATION": "1"},
			wantExit: true, want: "run only with AUTHZ_BASELINE=1",
		},
		{
			name: "route_probe_ends_in_skip", test: "TestAuthzBaselineRoutes", gated: true,
			env:  map[string]string{"AUTHZ_BASELINE": "1", "AUTHZ_BASELINE_PROBE": subject},
			want: "--- SKIP: TestAuthzBaselineRoutes",
		},
		{
			name: "flow_probe_refused_when_required", test: "TestAuthzBaselineFlows", gated: true,
			env:      map[string]string{"AUTHZ_BASELINE": "1", "AUTHZ_BASELINE_FLOW_PROBE": "T/T01", "REQUIRE_INTEGRATION": "1"},
			wantExit: true, want: "REQUIRE_INTEGRATION=1 forbids it",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if c.gated && os.Getenv("AUTHZ_BASELINE") != "1" {
				t.Skip("needs the baseline environment (AUTHZ_BASELINE=1)")
			}
			cmd := exec.Command(os.Args[0], "-test.run", "^"+c.test+"$", "-test.count=1", "-test.v")
			cmd.Env = probeChildEnv(c.env)
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if err != nil && !errors.As(err, &exitErr) {
				t.Fatalf("child test binary did not run: %v", err)
			}
			tail := string(out[max(0, len(out)-1500):])
			if c.wantExit != (err != nil) {
				t.Fatalf("child exit error %v, want non-zero exit %v; output tail:\n%s", err, c.wantExit, tail)
			}
			if !strings.Contains(string(out), c.want) {
				t.Fatalf("child output lacks %q; output tail:\n%s", c.want, tail)
			}
			if strings.Contains(string(out), "--- PASS: "+c.test) {
				t.Fatalf("%s passed with a probe set; output tail:\n%s", c.test, tail)
			}
		})
	}
}

// probeChildEnv is the current environment without any baseline or
// integration switches, plus the case's variables.
func probeChildEnv(set map[string]string) []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "AUTHZ_BASELINE") || k == "REQUIRE_INTEGRATION" {
			continue
		}
		out = append(out, kv)
	}
	for k, v := range set {
		out = append(out, k+"="+v)
	}
	return out
}
