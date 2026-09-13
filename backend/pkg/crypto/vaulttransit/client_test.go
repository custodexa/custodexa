package vaulttransit

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeVault struct {
	mu                       sync.Mutex
	calls                    map[string]int
	requests                 map[string]map[string]string
	loginBody                string
	loginStatus, renewStatus int
	deniedStatus             int
	lease                    int64
	renewable                bool
	badData, denied          string
	derived                  bool
	version                  int
}

func fixtureServer(t *testing.T) (*fakeVault, *httptest.Server) {
	t.Helper()
	f := &fakeVault{calls: map[string]int{}, requests: map[string]map[string]string{}, lease: 20, renewable: true, derived: true, version: 1}
	s := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(s.Close)
	return f, s
}
func (f *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	f.calls[path]++
	input := map[string]string{}
	_ = json.NewDecoder(r.Body).Decode(&input)
	f.requests[path] = input
	w.Header().Set("Content-Type", "application/json")
	send := func(value any) { _ = json.NewEncoder(w).Encode(value) }
	if path == "/v1/auth/approle/login" {
		if f.loginStatus != 0 {
			w.WriteHeader(f.loginStatus)
			send(map[string]string{"errors": "sensitive-role sensitive-secret sensitive-token sensitive-dek"})
			return
		}
		if f.loginBody != "" {
			fmt.Fprint(w, f.loginBody)
			return
		}
		send(map[string]any{"auth": map[string]any{"client_token": fmt.Sprintf("token-%d", f.calls[path]), "lease_duration": f.lease, "renewable": f.renewable}})
		return
	}
	if path == "/v1/auth/token/renew-self" {
		if f.renewStatus != 0 {
			w.WriteHeader(f.renewStatus)
			send(map[string]string{"errors": "sensitive-token"})
			return
		}
		send(map[string]any{"auth": map[string]any{"client_token": r.Header.Get("X-Vault-Token"), "lease_duration": f.lease, "renewable": f.renewable}})
		return
	}
	if strings.Contains(path, f.denied) && f.denied != "" {
		status := f.deniedStatus
		if status == 0 {
			status = 400
		}
		w.WriteHeader(status)
		send(map[string]string{"errors": "sensitive-dek"})
		return
	}
	if f.badData != "" {
		fmt.Fprint(w, f.badData)
		return
	}
	if strings.HasPrefix(path, "/v1/transit/keys/") {
		send(map[string]any{"data": map[string]any{"type": "aes256-gcm96", "derived": f.derived}})
		return
	}
	parts := strings.Split(path, "/")
	op, key := parts[3], parts[4]
	if input["context"] == "" {
		w.WriteHeader(400)
		return
	}
	payload := ""
	if op == "encrypt" {
		payload = key + "|" + input["context"] + "|" + input["plaintext"]
	} else {
		cipher := strings.Split(input["ciphertext"], ":")
		if len(cipher) != 3 {
			w.WriteHeader(400)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(cipher[2])
		if err != nil {
			w.WriteHeader(400)
			return
		}
		payload = string(raw)
		if !strings.HasPrefix(payload, key+"|"+input["context"]+"|") {
			w.WriteHeader(400)
			return
		}
	}
	if op == "decrypt" {
		send(map[string]any{"data": map[string]string{"plaintext": strings.SplitN(payload, "|", 3)[2]}})
		return
	}
	send(map[string]any{"data": map[string]string{"ciphertext": fmt.Sprintf("vault:v%d:%s", f.version, base64.StdEncoding.EncodeToString([]byte(payload)))}})
}
func (f *fakeVault) count(path string) int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls[path] }
func (f *fakeVault) change(fn func())      { f.mu.Lock(); defer f.mu.Unlock(); fn() }
func fixtureClient(t *testing.T, f *fakeVault, s *httptest.Server, clk clock) *Client {
	t.Helper()
	scope, id, err := ResolveScope("https://vault.example", "key")
	if err != nil {
		t.Fatal(err)
	}
	a, err := checkedAdapter(s.URL, &http.Transport{}, true)
	if err != nil {
		t.Fatal(err)
	}
	c, err := startClient(context.Background(), Settings{Address: scope.Origin(), KeyID: id, Scope: scope, RoleID: "sensitive-role", SecretID: "sensitive-secret"}, a, clk)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}
func waitFor(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !check() {
		select {
		case <-deadline:
			t.Fatal("worker did not reach expected state")
		case <-tick.C:
		}
	}
}

type fakeClock struct {
	mu     sync.Mutex
	at     time.Time
	timers []*fakeTimer
}
type fakeTimer struct {
	owner   *fakeClock
	due     time.Time
	ch      chan time.Time
	stopped bool
}

func newFakeClock() *fakeClock      { return &fakeClock{at: time.Unix(1000, 0)} }
func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *fakeClock) timer(d time.Duration) timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{owner: c, due: c.at.Add(d), ch: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	if d <= 0 {
		t.ch <- c.at
		t.stopped = true
	}
	return t
}
func (t *fakeTimer) channel() <-chan time.Time { return t.ch }
func (t *fakeTimer) stop()                     { t.owner.mu.Lock(); defer t.owner.mu.Unlock(); t.stopped = true }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
	for _, t := range c.timers {
		if !t.stopped && !c.at.Before(t.due) {
			t.ch <- c.at
			t.stopped = true
		}
	}
}
func (c *fakeClock) ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range c.timers {
		if !t.stopped {
			return true
		}
	}
	return false
}

func TestVaultAppRoleLogin(t *testing.T) {
	for _, body := range []string{`{}`, `{"auth":{"client_token":" ","lease_duration":20,"renewable":true}}`, `{"auth":{"client_token":"","lease_duration":20,"renewable":true}}`, `{"auth":{"client_token":"token","lease_duration":0,"renewable":true}}`, `{"auth":{"client_token":"token","lease_duration":-1,"renewable":true}}`, `{"auth":{"client_token":"token","lease_duration":20}}`, `{"auth":{"client_token":"token","lease_duration":"bad","renewable":true}}`, `not-json`} {
		t.Run(body, func(t *testing.T) {
			f, s := fixtureServer(t)
			f.loginBody = body
			a, _ := checkedAdapter(s.URL, &http.Transport{}, true)
			c, err := startClient(context.Background(), Settings{RoleID: "role", SecretID: "secret"}, a, wallClock{})
			if err == nil || c != nil {
				t.Fatal("invalid auth accepted")
			}
		})
	}
	t.Run("deployment-only-and-cancel", func(t *testing.T) {
		f, s := fixtureServer(t)
		c := fixtureClient(t, f, s, wallClock{})
		f.mu.Lock()
		got := f.requests["/v1/auth/approle/login"]
		f.mu.Unlock()
		if got["role_id"] != "sensitive-role" || got["secret_id"] != "sensitive-secret" {
			t.Fatal("credentials not explicit")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := c.call(ctx, "GET", "/v1/transit/keys/key", nil, &dataEnvelope{}); !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost")
		}
	})
}
func TestVaultAuthRedaction(t *testing.T) {
	for _, status := range []int{400, 401, 403, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f, s := fixtureServer(t)
			f.loginStatus = status
			a, _ := checkedAdapter(s.URL, &http.Transport{}, true)
			c, err := startClient(context.Background(), Settings{RoleID: "sensitive-role", SecretID: "sensitive-secret"}, a, wallClock{})
			if c != nil || err == nil {
				t.Fatal("authentication failure accepted")
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("secret exposed")
			}
			if f.count("/v1/auth/approle/login") != 1 {
				t.Fatal("login retries unbounded")
			}
		})
	}
}
func TestVaultTokenLifecycle(t *testing.T) {
	t.Run("new-lease-half-and-close", func(t *testing.T) {
		f, s := fixtureServer(t)
		clk := newFakeClock()
		c := fixtureClient(t, f, s, clk)
		waitFor(t, clk.ready)
		clk.advance(9 * time.Second)
		if f.count("/v1/auth/token/renew-self") != 0 {
			t.Fatal("early renewal")
		}
		f.change(func() { f.lease = 40 })
		clk.advance(time.Second)
		waitFor(t, func() bool { return f.count("/v1/auth/token/renew-self") == 1 && clk.ready() })
		clk.advance(19 * time.Second)
		if f.count("/v1/auth/token/renew-self") != 1 {
			t.Fatal("old lease reused")
		}
		clk.advance(time.Second)
		waitFor(t, func() bool { return f.count("/v1/auth/token/renew-self") == 2 })
		c.Close()
		select {
		case <-c.done:
		default:
			t.Fatal("worker remains")
		}
		clk.advance(time.Hour)
		if err := c.call(context.Background(), "GET", "/v1/transit/keys/key", nil, &dataEnvelope{}); !errors.Is(err, ErrClosed) {
			t.Fatal("closed client used")
		}
	})
	t.Run("nonrenewable-single-relogin", func(t *testing.T) {
		f, s := fixtureServer(t)
		f.renewable = false
		clk := newFakeClock()
		c := fixtureClient(t, f, s, clk)
		waitFor(t, clk.ready)
		clk.advance(20 * time.Second)
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = c.call(context.Background(), "GET", "/v1/transit/keys/key", nil, &dataEnvelope{})
			}()
		}
		wg.Wait()
		waitFor(t, func() bool { return f.count("/v1/auth/approle/login") == 2 })
		if f.count("/v1/auth/token/renew-self") != 0 {
			t.Fatal("nonrenewable token renewed")
		}
	})
	t.Run("bounded-retries-then-terminal-login", func(t *testing.T) {
		f, s := fixtureServer(t)
		clk := newFakeClock()
		c := fixtureClient(t, f, s, clk)
		f.change(func() { f.renewStatus = 503; f.loginStatus = 403 })
		waitFor(t, clk.ready)
		clk.advance(10 * time.Second)
		for n := 1; n <= 3; n++ {
			want := n
			waitFor(t, func() bool { return f.count("/v1/auth/token/renew-self") == want && clk.ready() })
			if n < 3 {
				clk.advance(time.Second)
			}
		}
		clk.advance(8 * time.Second)
		waitFor(t, func() bool {
			select {
			case <-c.done:
				return true
			default:
				return false
			}
		})
		if f.count("/v1/auth/approle/login") != 2 {
			t.Fatal("relogin count wrong")
		}
		for i := 0; i < 20; i++ {
			_ = c.call(context.Background(), "GET", "/v1/transit/keys/key", nil, &dataEnvelope{})
		}
		if f.count("/v1/auth/approle/login") != 2 {
			t.Fatal("failed credentials retried")
		}
	})
	t.Run("revoked-renewal-and-parent-cancel", func(t *testing.T) {
		f, s := fixtureServer(t)
		clk := newFakeClock()
		scope, id, _ := ResolveScope("https://vault.example", "key")
		a, _ := checkedAdapter(s.URL, &http.Transport{}, true)
		ctx, cancel := context.WithCancel(context.Background())
		c, err := startClient(ctx, Settings{RoleID: "role", SecretID: "secret", Scope: scope, KeyID: id}, a, clk)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		f.change(func() { f.renewStatus = 403; f.loginStatus = 403 })
		waitFor(t, clk.ready)
		clk.advance(10 * time.Second)
		waitFor(t, func() bool {
			select {
			case <-c.done:
				return true
			default:
				return false
			}
		})
		if c.token != "" {
			t.Fatal("revoked token retained")
		}
		cancel()
	})
	t.Run("cancel-waits-worker", func(t *testing.T) {
		f, s := fixtureServer(t)
		a, _ := checkedAdapter(s.URL, &http.Transport{}, true)
		ctx, cancel := context.WithCancel(context.Background())
		c, err := startClient(ctx, Settings{RoleID: "role", SecretID: "secret"}, a, wallClock{})
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		c.Close()
		select {
		case <-c.done:
		default:
			t.Fatal("worker not joined")
		}
		if f.count("/v1/auth/approle/login") != 1 {
			t.Fatal("unexpected login")
		}
	})
}

func TestVaultClientOwnership(t *testing.T) {
	f, s := fixtureServer(t)
	c := fixtureClient(t, f, s, wallClock{})
	first, _ := CanonicalKeyID("https://vault.example", "key")
	second, _ := CanonicalKeyID("https://vault.example", "next")
	p, err := c.Provider(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	q, err := c.Provider(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if p.client != q.client || f.count("/v1/auth/approle/login") != 1 {
		t.Fatal("providers did not borrow one client")
	}
	f.change(func() { f.derived = false })
	if bad, err := c.Provider(context.Background(), second); bad != nil || err == nil {
		t.Fatal("failed preflight published provider")
	}
	f.change(func() { f.derived = true })
	if _, err := p.Wrap(context.Background(), make([]byte, 32), []byte("aad")); err != nil {
		t.Fatal("failed target closed shared owner")
	}
	settings := Settings{Scope: c.scope, Address: c.scope.Origin(), RoleID: "sensitive-role", SecretID: "sensitive-secret"}
	if !c.MatchesDeployment(settings) {
		t.Fatal("owner deployment mismatch")
	}
	settings.SecretID = "different"
	if c.MatchesDeployment(settings) {
		t.Fatal("owner accepted different credentials")
	}

	c.Close()
}

func TestVaultEndpoint(t *testing.T) {
	for _, key := range []string{"VAULT_ADDR", "VAULT_AGENT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE", "VAULT_SKIP_VERIFY", "VAULT_TLS_SERVER_NAME", "VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY", "VAULT_PROXY_ADDR"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "sensitive-override")
			if a, err := productionAdapter("https://vault.example"); err == nil || a != nil {
				t.Fatal("ambient override accepted")
			}
		})
	}
	if a, err := productionAdapter("http://127.0.0.1:8200"); a != nil || err == nil {
		t.Fatal("production HTTP accepted")
	}
}
func TestVaultTransport(t *testing.T) {
	t.Run("redirect-no-credential-forwarding", func(t *testing.T) {
		hits := 0
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
		defer target.Close()
		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
		defer source.Close()
		a, _ := checkedAdapter(source.URL, &http.Transport{}, true)
		err := a.call(context.Background(), "POST", "/v1/auth/approle/login", "sensitive-token", map[string]string{"secret_id": "sensitive-secret"}, &authEnvelope{})
		if err == nil || hits != 0 {
			t.Fatal("redirect forwarded credentials")
		}
	})
	t.Run("TLS-and-injection", func(t *testing.T) {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"data":{}}`) }))
		defer s.Close()
		tr := s.Client().Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.InsecureSkipVerify = false
		a, err := checkedAdapter(s.URL, tr, false)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.call(context.Background(), "GET", "/v1/transit/keys/key", "", nil, &dataEnvelope{}); err != nil {
			t.Fatal(err)
		}
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		if _, err := checkedAdapter(s.URL, tr, false); err == nil {
			t.Fatal("TLS verification disabled")
		}
	})
	t.Run("proxy-and-default-transport-ignored", func(t *testing.T) {
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
		a, err := productionAdapter("https://vault.example")
		if err != nil {
			t.Fatal(err)
		}
		tr := a.http.Transport.(*http.Transport)
		if tr.Proxy != nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			t.Fatal("unsafe production transport")
		}
		if err := a.call(context.Background(), "POST", "//foreign/path", "secret", nil, &dataEnvelope{}); err == nil {
			t.Fatal("foreign request path accepted")
		}
	})
}

func TestVaultClientOwnershipFailedInitialPreflight(t *testing.T) {
	f, s := fixtureServer(t)
	c := fixtureClient(t, f, s, wallClock{})
	f.change(func() { f.derived = false })
	id, _ := CanonicalKeyID("https://vault.example", "key")
	owner, p, err := preflightClient(context.Background(), c, id)
	if owner != nil || p != nil || err == nil {
		t.Fatal("failed initial preflight published owner")
	}
	select {
	case <-c.done:
	default:
		t.Fatal("initial preflight left worker running")
	}
}

func TestVaultTokenLifecycleCloseDuringRenewal(t *testing.T) {
	started := make(chan struct{})
	exited := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			fmt.Fprint(w, `{"auth":{"client_token":"token","lease_duration":20,"renewable":true}}`)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
		close(exited)
	}))
	defer server.Close()
	clk := newFakeClock()
	a, _ := checkedAdapter(server.URL, &http.Transport{}, true)
	c, err := startClient(context.Background(), Settings{RoleID: "role", SecretID: "secret"}, a, clk)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitFor(t, clk.ready)
	clk.advance(10 * time.Second)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("renewal did not start")
	}
	c.Close()
	select {
	case <-c.done:
	default:
		t.Fatal("worker not joined")
	}
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight renewal not canceled")
	}
}
