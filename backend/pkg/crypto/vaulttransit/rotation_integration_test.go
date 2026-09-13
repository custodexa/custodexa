package vaulttransit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
)

// This test requires the isolated fixture. Missing credentials or fixture fail,
// and administrator credentials come only from the Compose fixture settings.
func TestVaultRemoteRotationIntegration(t *testing.T) {
	address, admin := vaultFixtureSettings(t)
	wire, err := checkedAdapter(address, &http.Transport{}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer wire.http.CloseIdleConnections()
	request := func(method, path, token string, input any) (int, []byte, map[string]any) {
		t.Helper()
		body, _ := json.Marshal(input)
		defer clear(body)
		req, err := http.NewRequest(method, wire.origin+"/v1/"+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal("invalid fixture request")
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("X-Vault-Token", token)
		}
		resp, err := wire.http.Do(req)
		if err != nil {
			t.Fatal("fixture unavailable")
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit))
		if err != nil {
			t.Fatal("fixture response unreadable")
		}
		value := map[string]any{}
		if len(raw) > 0 && json.Unmarshal(raw, &value) != nil {
			t.Fatal("fixture response invalid")
		}
		return resp.StatusCode, raw, value
	}
	field := func(value map[string]any, key string) map[string]any {
		t.Helper()
		out, ok := value[key].(map[string]any)
		if !ok {
			t.Fatal("fixture response field missing")
		}
		return out
	}
	status, _, health := request("GET", "sys/health", "", nil)
	if status != 200 || health["sealed"] != false {
		t.Fatal("fixture unhealthy")
	}
	version, ok := health["version"].(string)
	if !ok || version != "2.1.0" {
		t.Fatal("fixture version differs from pin")
	}
	t.Logf("VAULT_EVIDENCE version=%s", version)
	status, _, role := request("GET", "auth/approle/role/wave2c-transit/role-id", admin, nil)
	if status != 200 {
		t.Fatal("fixture AppRole missing")
	}
	status, _, secret := request("POST", "auth/approle/role/wave2c-transit/secret-id", admin, struct{}{})
	if status != 200 {
		t.Fatal("fixture SecretID creation denied")
	}
	roleID, _ := field(role, "data")["role_id"].(string)
	secretID, _ := field(secret, "data")["secret_id"].(string)
	scope, id, _ := ResolveScope("https://vault.fixture", "wave2c-kek")
	c, err := startClient(context.Background(), Settings{Scope: scope, KeyID: id, RoleID: roleID, SecretID: secretID}, wire, wallClock{})
	if err != nil {
		t.Fatal("AppRole login failed")
	}
	defer c.Close()
	p, err := c.Provider(context.Background(), id)
	if err != nil {
		t.Fatal("provider preflight failed")
	}
	aad := crypto.DEKAAD("data", 1)
	plain := bytes.Repeat([]byte{23}, 32)
	old, err := p.Wrap(context.Background(), plain, aad)
	if err != nil {
		t.Fatal("initial wrap failed")
	}
	status, _, metadata := request("GET", "transit/keys/wave2c-kek", admin, nil)
	if status != 200 {
		t.Fatal("metadata unavailable")
	}
	before, ok := field(metadata, "data")["latest_version"].(float64)
	if !ok {
		t.Fatal("missing latest version")
	}
	status, rotateBody, _ := request("POST", "transit/keys/wave2c-kek/rotate", admin, struct{}{})
	if status < 200 || status >= 300 {
		t.Fatal("administrator rotate failed")
	}
	// Record an empty raw body exactly; redact any future nonempty schema.
	bodyShape := "redacted-json"
	if len(rotateBody) == 0 {
		bodyShape = "empty"
	}
	t.Logf("VAULT_EVIDENCE rotate_status=%d rotate_body=%s", status, bodyShape)
	if len(rotateBody) > 0 {
		var decoded any
		if json.Unmarshal(rotateBody, &decoded) != nil {
			t.Fatal("rotate body invalid")
		}
		safe, _ := json.Marshal(redactedJSON(decoded))
		t.Logf("VAULT_ROTATE_BODY %s", safe)
	}

	_, _, metadata = request("GET", "transit/keys/wave2c-kek", admin, nil)
	after, ok := field(metadata, "data")["latest_version"].(float64)
	if !ok || after != before+1 {
		t.Fatal("rotation version did not increase")
	}
	got, err := p.Unwrap(context.Background(), old, aad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("old version lost decryptability")
	}
	clear(got)
	updated, err := p.ReEncrypt(context.Background(), old, aad, p)
	if err != nil {
		t.Fatal("provider native rewrap failed")
	}
	fresh, err := p.Wrap(context.Background(), plain, aad)
	if err != nil {
		t.Fatal("new wrap failed")
	}
	prefix := fmt.Sprintf("vault:v%d:", int(after))
	if !strings.HasPrefix(string(updated), prefix) || !strings.HasPrefix(string(fresh), prefix) {
		t.Fatal("provider did not use latest version")
	}
	got, err = p.Unwrap(context.Background(), updated, aad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("rewrapped plaintext differs")
	}
	clear(got)
	t.Logf("VAULT_EVIDENCE version_before=%d version_after=%d old_decrypt=PASS native_rewrap=PASS fresh_wrap=PASS", int(before), int(after))
	c.mu.Lock()
	product := c.token
	c.mu.Unlock()
	// Probe associated_data independently; provider behavior remains context-only.
	ctxWire := base64.StdEncoding.EncodeToString(aad)
	associated := base64.StdEncoding.EncodeToString([]byte("probe-associated-data"))
	plainWire := base64.StdEncoding.EncodeToString(plain)
	status, _, associatedResult := request("POST", "transit/encrypt/wave2c-kek", product, map[string]string{"plaintext": plainWire, "context": ctxWire, "associated_data": associated})
	if status != 200 {
		t.Fatal("associated_data encrypt probe failed")
	}
	ciphertext, ok := field(associatedResult, "data")["ciphertext"].(string)
	if !ok {
		t.Fatal("associated_data cipher missing")
	}
	for _, include := range []bool{false, true} {
		payload := map[string]string{"ciphertext": ciphertext, "context": ctxWire}
		if include {
			payload["associated_data"] = associated
		}
		rewrapStatus, _, result := request("POST", "transit/rewrap/wave2c-kek", product, payload)
		if rewrapStatus != 200 && rewrapStatus != 400 {
			t.Fatal("unexpected associated_data rewrap status")
		}
		decryptStatus := 0
		if rewrapStatus == 200 {
			cipher, ok := field(result, "data")["ciphertext"].(string)
			if !ok {
				t.Fatal("rewrap probe ciphertext missing")
			}
			var decrypted map[string]any
			decryptStatus, _, decrypted = request("POST", "transit/decrypt/wave2c-kek", product, map[string]string{"ciphertext": cipher, "context": ctxWire, "associated_data": associated})
			if decryptStatus != 200 && decryptStatus != 400 {
				t.Fatal("unexpected probe decrypt status")
			}
			if decryptStatus == 200 && field(decrypted, "data")["plaintext"] != plainWire {
				t.Fatal("probe plaintext differs")
			}
		}
		t.Logf("VAULT_EVIDENCE associated_data=%t rewrap_status=%d decrypt_status=%d", include, rewrapStatus, decryptStatus)
	}
	status, _, _ = request("POST", "transit/keys/wave2c-kek/rotate", product, struct{}{})
	if status != 403 {
		t.Fatal("product identity can rotate")
	}
	t.Logf("VAULT_EVIDENCE product_rotate_status=%d", status)
}

// Preserve response structure and numeric metadata while removing string values.
func redactedJSON(value any) any {
	switch v := value.(type) {
	case string:
		return "<redacted>"
	case map[string]any:
		out := map[string]any{}
		for k, item := range v {
			out[k] = redactedJSON(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactedJSON(item)
		}
		return out
	default:
		return value
	}
}
