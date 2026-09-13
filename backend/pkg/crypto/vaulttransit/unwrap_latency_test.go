//go:build latency

package vaulttransit

import (
	"bytes"
	"context"
	"github.com/custodexa/backend/pkg/crypto"
	"os/exec"
	"runtime"
	"sort"
	"testing"
	"time"
)

// Use only the initialized loopback fixture and a short-lived AppRole login.
func TestVaultUnwrapLatency(t *testing.T) {
	f := newAuthFixture(t)
	status, role := f.request("GET", "auth/approle/role/wave2c-transit/role-id", f.admin, nil)
	if status != 200 {
		t.Fatal("fixture role unavailable")
	}
	status, secret := f.request("POST", "auth/approle/role/wave2c-transit/secret-id", f.admin, struct{}{})
	if status != 200 {
		t.Fatal("fixture SecretID unavailable")
	}
	scope, id, err := ResolveScope("https://vault.fixture", "wave2c-kek")
	if err != nil {
		t.Fatal("fixture scope invalid")
	}
	c, err := startClient(context.Background(), Settings{Scope: scope, KeyID: id,
		RoleID: authFixtureField(t, role, "role_id"), SecretID: authFixtureField(t, secret, "secret_id")}, f.wire, wallClock{})
	if err != nil {
		t.Fatal("AppRole login failed")
	}
	defer func() {
		c.mu.Lock()
		token := c.token
		c.mu.Unlock()
		c.Close()
		status, _ := f.request("POST", "auth/token/revoke", f.admin, map[string]string{"token": token})
		if status != 204 {
			t.Error("fixture token cleanup failed")
		}
	}()
	p, err := c.Provider(context.Background(), id)
	if err != nil {
		t.Fatal("provider preflight failed")
	}
	measureUnwrapLatency(t, "vault-transit", p)
}

// Timing includes the real driver call, but excludes checks and buffer clearing.
func measureUnwrapLatency(t *testing.T, label string, p crypto.KEKProvider) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	plain := bytes.Repeat([]byte{37}, 32)
	defer clear(plain)
	aad := crypto.DEKAAD("data", 1)
	wrapped, err := p.Wrap(ctx, plain, aad)
	if err != nil {
		t.Fatal("sample wrap failed")
	}
	samples := make([]int64, 0, 100)
	load, err := exec.Command("uptime").Output()
	if err != nil {
		t.Fatal("host load unavailable")
	}
	t.Logf("LATENCY_HOST_LOAD provider=%s %s", label, bytes.TrimSpace(load))
	t.Logf("LATENCY_START provider=%s time=%s go=%s os=%s arch=%s cpus=%d", label, time.Now().Format(time.RFC3339Nano), runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	for i := 0; i < 105; i++ {
		start := time.Now()
		got, err := p.Unwrap(ctx, wrapped, aad)
		elapsed := time.Since(start).Nanoseconds()
		valid := bytes.Equal(got, plain)
		clear(got)
		if err != nil || !valid {
			t.Fatalf("unwrap failed at sample %d", i)
		}
		if i >= 5 {
			samples = append(samples, elapsed)
		}
	}
	t.Logf("LATENCY_RAW_NS provider=%s samples=%v", label, samples)
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("LATENCY_RESULT provider=%s warmup=5 n=100 p50_ms=%.6f p95_ms=%.6f max_ms=%.6f end=%s", label, float64(samples[49])/1e6, float64(samples[94])/1e6, float64(samples[99])/1e6, time.Now().Format(time.RFC3339Nano))
}
