package vaulttransit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/pkg/crypto"
)

// Capture only endpoint status codes. Credentials and response bodies never enter logs.
type authStatusTransport struct {
	base     http.RoundTripper
	mu       sync.Mutex
	statuses map[string][]int
}

func (r *authStatusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.base.RoundTrip(req)
	if err == nil {
		r.mu.Lock()
		r.statuses[req.URL.Path] = append(r.statuses[req.URL.Path], resp.StatusCode)
		r.mu.Unlock()
	}
	return resp, err
}
func (r *authStatusTransport) CloseIdleConnections() {
	r.base.(interface{ CloseIdleConnections() }).CloseIdleConnections()
}
func (r *authStatusTransport) count(path string, status int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, value := range r.statuses["/v1/"+path] {
		if value == status {
			n++
		}
	}
	return n
}

type authFixture struct {
	t     *testing.T
	admin string
	wire  *adapter
}

// The supported runner is the live Compose backend: its env_file already
// supplies the dev initialization credential, and Vault is a sibling service.
// Host integration runs retain the Compose-config source and loopback endpoint.
// Missing credentials or targets always fail; no integration case is skipped.
func vaultFixtureSettings(t *testing.T) (string, string) {
	t.Helper()
	if _, err := os.Stat("/.dockerenv"); err == nil {
		admin := os.Getenv("VAULT_DEV_ROOT_TOKEN_ID")
		if admin == "" {
			t.Fatal("fixture initialization credential missing: VAULT_DEV_ROOT_TOKEN_ID")
		}
		return "http://vault:8200", admin
	}
	cmd := exec.Command("docker", "compose", "-p", "wave2c", "-f", "docker-compose.dev.yml", "config", "--format", "json", "vault")
	cmd.Dir = "../../../.."
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal("cannot resolve fixture configuration")
	}
	defer clear(raw)
	var cfg struct {
		Services map[string]struct{ Environment map[string]string }
	}
	if json.Unmarshal(raw, &cfg) != nil {
		t.Fatal("invalid fixture configuration")
	}
	admin := cfg.Services["vault"].Environment["VAULT_DEV_ROOT_TOKEN_ID"]
	if admin == "" {
		t.Fatal("fixture initialization credential missing")
	}
	return "http://127.0.0.1:8200", admin
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	address, admin := vaultFixtureSettings(t)
	wire, err := checkedAdapter(address, &http.Transport{}, true)
	if err != nil {
		t.Fatal("fixture transport unavailable")
	}
	t.Cleanup(wire.http.CloseIdleConnections)
	f := &authFixture{t: t, admin: admin, wire: wire}
	status, value := f.request("GET", "sys/health", "", nil)
	if status != 200 || value["sealed"] != false || value["version"] != "2.1.0" {
		t.Fatal("fixture unhealthy or differs from pin")
	}
	t.Log("VAULT_EVIDENCE version=2.1.0")
	return f
}
func (f *authFixture) request(method, path, token string, input any) (int, map[string]any) {
	f.t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		f.t.Fatal("invalid fixture input")
	}
	defer clear(body)
	req, err := http.NewRequest(method, f.wire.origin+"/v1/"+path, bytes.NewReader(body))
	if err != nil {
		f.t.Fatal("invalid fixture request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", token)
	resp, err := f.wire.http.Do(req)
	if err != nil {
		f.t.Fatal("fixture unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit))
	if err != nil {
		f.t.Fatal("fixture response unreadable")
	}
	defer clear(raw)
	value := map[string]any{}
	if len(raw) != 0 && json.Unmarshal(raw, &value) != nil {
		f.t.Fatal("invalid fixture response")
	}
	return resp.StatusCode, value
}
func authFixtureField(t *testing.T, value map[string]any, name string) string {
	t.Helper()
	data, ok := value["data"].(map[string]any)
	if !ok {
		t.Fatal("fixture data missing")
	}
	out, ok := data[name].(string)
	if !ok || out == "" {
		t.Fatal("fixture field missing")
	}
	return out
}
func (f *authFixture) client(t *testing.T, role, tokenType string) (*Client, *authStatusTransport, string) {
	t.Helper()
	path := "auth/approle/role/" + role
	status, _ := f.request("POST", path, f.admin, map[string]any{
		"token_policies": []string{"wave2c-transit"}, "token_ttl": "4s", "token_max_ttl": "30s",
		"token_type": tokenType, "secret_id_num_uses": 1, "secret_id_ttl": "30s",
	})
	if status != 200 && status != 204 {
		t.Fatal("fixture role setup failed")
	}
	t.Cleanup(func() {
		status, _ := f.request("DELETE", path, f.admin, nil)
		if status != 204 {
			t.Error("fixture role cleanup failed")
		}
	})
	status, roleResult := f.request("GET", path+"/role-id", f.admin, nil)
	if status != 200 {
		t.Fatal("fixture role unavailable")
	}
	status, secretResult := f.request("POST", path+"/secret-id", f.admin, struct{}{})
	if status != 200 {
		t.Fatal("fixture secret creation failed")
	}
	wire, err := checkedAdapter(f.wire.origin, &http.Transport{}, true)
	if err != nil {
		t.Fatal("fixture adapter failed")
	}
	trace := &authStatusTransport{base: wire.http.Transport, statuses: map[string][]int{}}
	wire.http.Transport = trace
	scope, id, err := ResolveScope("https://vault.fixture", "wave2c-kek")
	if err != nil {
		t.Fatal(err)
	}
	c, err := startClient(context.Background(), Settings{Scope: scope, KeyID: id,
		RoleID: authFixtureField(t, roleResult, "role_id"), SecretID: authFixtureField(t, secretResult, "secret_id")}, wire, wallClock{})
	if err != nil {
		t.Fatal("fixture AppRole login failed")
	}
	t.Cleanup(c.Close)
	return c, trace, id
}

func TestVaultAuthContextIntegration(t *testing.T) {
	f := newAuthFixture(t)
	c, trace, id := f.client(t, "wave2c-contract-auth", "service")
	ctx := context.Background()
	p, err := c.Provider(ctx, id)
	if err != nil {
		t.Fatal("fixture provider preflight failed")
	}
	aad := crypto.DEKAAD("data", 1)
	plain := bytes.Repeat([]byte{29}, 32)
	defer clear(plain)
	wrapped, err := p.Wrap(ctx, plain, aad)
	if err != nil {
		t.Fatal("fixture wrap failed")
	}
	t.Run("login", func(t *testing.T) {
		c.mu.Lock()
		valid := c.token != "" && c.renewable && time.Now().Before(c.expiry)
		c.mu.Unlock()
		if !valid || trace.count("auth/approle/login", 200) != 1 {
			t.Fatal("AppRole lease missing")
		}
		t.Log("VAULT_EVIDENCE auth_case=login status=200 result=PASS")
	})
	t.Run("renewal", func(t *testing.T) {
		c.mu.Lock()
		before := c.expiry
		c.mu.Unlock()
		waitFor(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.expiry.After(before) })
		if trace.count("auth/token/renew-self", 200) < 1 {
			t.Fatal("no real renewal response")
		}
		if got, err := p.Unwrap(ctx, wrapped, aad); err != nil || !bytes.Equal(got, plain) {
			t.Fatal("renewed token unusable")
		} else {
			clear(got)
		}
		t.Log("VAULT_EVIDENCE auth_case=renewal status=200 result=PASS")
	})
	t.Run("derived-context", func(t *testing.T) {
		if got, err := p.Unwrap(ctx, wrapped, crypto.DEKAAD("data", 2)); err == nil || got != nil {
			t.Fatal("wrong context accepted")
		}
		if trace.count("transit/decrypt/wave2c-kek", 400) < 1 {
			t.Fatal("wrong context did not reach Vault")
		}
		t.Log("VAULT_EVIDENCE auth_case=derived-context status=400 result=PASS")
	})
	t.Run("other-key", func(t *testing.T) {
		status, value := f.request("POST", "transit/encrypt/wave2c-denied-kek", f.admin, map[string]string{
			"plaintext": base64.StdEncoding.EncodeToString(plain), "context": base64.StdEncoding.EncodeToString(aad)})
		if status != 200 {
			t.Fatal("foreign cipher setup failed")
		}
		foreign := authFixtureField(t, value, "ciphertext")
		if got, err := p.Unwrap(ctx, []byte(foreign), aad); err == nil || got != nil {
			t.Fatal("foreign cipher accepted")
		}
		// A separate identity keeps a policy denial from invalidating the renewal subject.
		other, otherTrace, _ := f.client(t, "wave2c-contract-denied", "service")
		otherID, _ := CanonicalKeyID("https://vault.fixture", "wave2c-denied-kek")
		if got, err := other.Provider(ctx, otherID); err == nil || got != nil {
			t.Fatal("foreign key policy accepted")
		}
		if otherTrace.count("transit/keys/wave2c-denied-kek", 403) != 1 {
			t.Fatal("no real policy denial")
		}
		t.Log("VAULT_EVIDENCE auth_case=other-key status=403 result=PASS")
	})
	t.Run("revocation", func(t *testing.T) {
		c.mu.Lock()
		token := c.token
		c.mu.Unlock()
		status, _ := f.request("POST", "auth/token/revoke", f.admin, map[string]string{"token": token})
		if status != 204 {
			t.Fatal("fixture revoke failed")
		}
		if got, err := p.Wrap(ctx, plain, aad); err == nil || got != nil {
			t.Fatal("revoked token accepted")
		}
		if trace.count("transit/encrypt/wave2c-kek", 403) != 1 {
			t.Fatal("no real revoked token denial")
		}
		waitFor(t, func() bool {
			select {
			case <-c.done:
				return true
			default:
				return false
			}
		})
		if trace.count("auth/approle/login", 400) != 1 {
			t.Fatal("spent SecretID did not terminate re-login")
		}
		if got, err := p.Wrap(ctx, plain, aad); err == nil || got != nil {
			t.Fatal("terminated client accepted operation")
		}
		t.Log("VAULT_EVIDENCE auth_case=revocation status=403 result=PASS")
	})
	t.Run("lease-expiry", func(t *testing.T) {
		expiring, expiryTrace, expiryID := f.client(t, "wave2c-contract-expiry", "batch")
		provider, err := expiring.Provider(ctx, expiryID)
		if err != nil {
			t.Fatal("expiry provider preflight failed")
		}
		expiring.mu.Lock()
		token, renewable := expiring.token, expiring.renewable
		expiring.mu.Unlock()
		if renewable {
			t.Fatal("batch token unexpectedly renewable")
		}
		select {
		case <-expiring.done:
		case <-time.After(7 * time.Second):
			t.Fatal("expiry did not terminate spent identity")
		}
		status, _ := f.request("POST", "transit/encrypt/wave2c-kek", token, map[string]string{
			"plaintext": base64.StdEncoding.EncodeToString(plain), "context": base64.StdEncoding.EncodeToString(aad)})
		if status != 403 {
			t.Fatal("expired token accepted remotely")
		}
		if got, err := provider.Wrap(ctx, plain, aad); err == nil || got != nil {
			t.Fatal("expired client accepted operation")
		}
		if expiryTrace.count("auth/token/renew-self", 200) != 0 || expiryTrace.count("auth/approle/login", 400) != 1 {
			t.Fatal("expiry recovery boundary differs")
		}
		t.Log("VAULT_EVIDENCE auth_case=lease-expiry status=403 result=PASS")
	})
}
