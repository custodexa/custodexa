package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/custodexa/backend/pkg/crypto"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEnvSealRestoreSourceHTTP(t *testing.T) {
	e, token, _ := modeFixture(t, "env")
	values := map[string]string{"KEK_PROVIDER": "env", "ENCRYPTION_KEY": testInitialKEK}
	reads := 0
	e.s1.deploymentSource = func(ctx context.Context) (crypto.KEKProvider, *material.Secret, error) {
		reads++
		d, err := config.DecideKEK(config.MapEnvLookup(values), config.HSMBuildEnabled)
		if err != nil {
			return nil, nil, err
		}
		return buildOwnedKEKProvider(ctx, d)
	}
	server := httptest.NewServer(e.swap)
	defer server.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	request := func(path string, want int) {
		t.Helper()
		r, err := restoreHTTP(client, server.URL+path, "POST", "{}", token)
		if err != nil || r.status != want {
			t.Fatalf("HTTP=%d expected=%d transport_error=%v", r.status, want, err != nil)
		}
	}
	request("/api/v1/seal/unseal", 200)
	request("/api/v1/seal/seal", 200)
	delete(values, "ENCRYPTION_KEY")
	request("/api/v1/seal/unseal", 400)
	missing := reads
	time.Sleep(1100 * time.Millisecond)
	values["ENCRYPTION_KEY"] = testOtherKEK
	request("/api/v1/seal/unseal", 400)
	wrong := reads
	time.Sleep(2100 * time.Millisecond)
	values["ENCRYPTION_KEY"] = testInitialKEK
	request("/api/v1/seal/unseal", 200)
	if missing < 1 || wrong <= missing || reads <= wrong {
		t.Fatal("source was not reread")
	}
	t.Logf("EVIDENCE env-source transport=TCP_HTTP missing=400 wrong=400 restored=200 source_reads=%d,%d,%d mode=env secrets_in_evidence=false", missing, wrong, reads)
}

func TestEnvSealRestoreDeploymentHTTP(t *testing.T) {
	password := testgate.Value(t, "UNSEAL_ADMIN_PASS")
	mode := os.Getenv("KEK_PROVIDER")
	if mode != "" && mode != "env" {
		t.Fatal("normal deployment is not env mode")
	}
	base := "http://localhost:8080"
	client := &http.Client{Timeout: 30 * time.Second}
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	response, err := client.Post(base+"/api/v1/auth/login", "application/json", strings.NewReader(string(body)))
	clear(body)
	if err != nil {
		t.Fatal("deployment login transport failed")
	}
	defer response.Body.Close()
	var login struct {
		Token string `json:"token"`
	}
	if err = json.NewDecoder(response.Body).Decode(&login); err != nil || response.StatusCode != 200 || login.Token == "" {
		t.Fatalf("deployment login HTTP=%d token_present=%v", response.StatusCode, login.Token != "")
	}
	defer func() { login.Token = "" }()
	sealed, err := restoreHTTP(client, base+"/api/v1/seal/seal", "POST", "{}", login.Token)
	if err != nil || sealed.status != 200 {
		t.Fatalf("deployment seal HTTP=%d transport_error=%v", sealed.status, err != nil)
	}
	// 解封自本版起要求授權脈絡，且這一支打的是**實際部署**——脈絡要以該部署的
	// 管理員密碼換取，不能用測試夾具的密碼。
	grant := deploymentSealGrant(t, client, base, password)
	restored, err := restoreHTTPAuth(client, base+"/api/v1/seal/unseal", "POST", "{}", "SealGrant "+grant)
	if err != nil || restored.status != 200 {
		t.Fatalf("deployment restore HTTP=%d transport_error=%v", restored.status, err != nil)
	}
	if restored.generation <= sealed.generation {
		t.Fatal("deployment generation did not advance")
	}
	health, err := client.Get(base + "/health")
	if err != nil {
		t.Fatal("deployment health transport failed")
	}
	defer health.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(health.Body, 65536))
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if json.Unmarshal(raw, &h) != nil || health.StatusCode != 200 || h["status"] != "ok" {
		t.Fatal("deployment health not ok")
	}
	t.Log(fmt.Sprintf("EVIDENCE env-deployment transport=TCP_HTTP seal=200 restore=200 generation=%d,%d health=ok authorizer=existing_identity", sealed.generation, restored.generation))
}

// deploymentSealGrant 以實際部署的管理員憑證取得解封授權脈絡。
func deploymentSealGrant(t *testing.T, client *http.Client, base, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	res, err := client.Post(base+"/api/v1/seal/authorize", "application/json", strings.NewReader(string(body)))
	clear(body)
	if err != nil {
		t.Fatal("deployment authorize transport failed")
	}
	defer res.Body.Close()
	var out struct {
		Grant string `json:"grant"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || res.StatusCode != 200 || out.Grant == "" {
		t.Fatalf("deployment authorize HTTP=%d grant_present=%v", res.StatusCode, out.Grant != "")
	}
	return out.Grant
}
