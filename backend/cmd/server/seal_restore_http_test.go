package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/seal"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type restoreResponse struct {
	status     int
	state      string
	generation uint64
	guidance   string
	mode       string
}

func restoreHTTP(client *http.Client, url, method, body, token string) (restoreResponse, error) {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return restoreResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// 解封自委託拓撲與憑證改由介面管理之後要求授權脈絡：先過第一段
	// （帳密），再送材料——與解封頁實際的兩步相同。封存（`/seal/seal`）仍走 Bearer。
	// 要驗「脈絡不成立時的拒絕」請改用 restoreHTTPAuth 自行指定標頭。
	if method == http.MethodPost && strings.HasSuffix(url, "/seal/unseal") {
		if grant := restoreSealGrant(client, url); grant != "" {
			req.Header.Set("Authorization", "SealGrant "+grant)
		}
	}
	res, err := client.Do(req)
	if err != nil {
		return restoreResponse{}, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil {
		return restoreResponse{}, err
	}
	var parsed struct {
		State      string `json:"state"`
		Generation uint64 `json:"generation"`
		Guidance   string `json:"restore_guidance"`
		Mode       string `json:"mode"`
	}
	_ = json.Unmarshal(raw, &parsed)
	return restoreResponse{res.StatusCode, parsed.State, parsed.Generation, parsed.Guidance, parsed.Mode}, nil
}
func retainedGraphMaterials(g *appGraph) [][]byte {
	km := reflect.ValueOf(g.keyManager).Elem()
	var raws [][]byte
	for _, versions := range km.FieldByName("keys").MapKeys() {
		entries := km.FieldByName("keys").MapIndex(versions)
		for _, version := range entries.MapKeys() {
			raws = append(raws, entries.MapIndex(version).Bytes())
		}
	}
	provider := km.FieldByName("kek").Elem().Elem()
	if field := provider.FieldByName("aes"); field.IsValid() {
		raws = append(raws, field.Elem().FieldByName("key").Bytes())
	}
	return raws
}
func TestUISealRestoreHTTP(t *testing.T) {
	e, token, _ := modeFixture(t, "ui")
	server := httptest.NewServer(e.swap)
	defer server.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	request := func(path, method, body, auth string) restoreResponse {
		t.Helper()
		r, err := restoreHTTP(client, server.URL+path, method, body, auth)
		if err != nil {
			t.Fatal("HTTP request failed")
		}
		return r
	}
	if r := request("/api/v1/seal/unseal", "POST", initPayload(testInitialKEK), ""); r.status != 200 {
		t.Fatalf("initialization HTTP=%d", r.status)
	}
	g := e.machine.Snapshot().Services.(*appGraph)
	raws := retainedGraphMaterials(g)
	cipher, err := g.keyManager.EncryptBytesFor(context.Background(), lifecycleProbeRef, []byte("restore-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := g.MaterialGate().Borrow()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan restoreResponse, 1)
	go func() { r, _ := restoreHTTP(client, server.URL+"/api/v1/seal/seal", "POST", "{}", token); done <- r }()
	deadline := time.Now().Add(5 * time.Second)
	for e.machine.Snapshot().State != seal.StateSealed && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if e.machine.Snapshot().State != seal.StateSealed {
		lease.Finish(func(bool) {})
		t.Fatal("seal did not close generation")
	}
	if r := request("/api/v1/seal/unseal", "POST", fmt.Sprintf(`{"kek":%q}`, testInitialKEK), ""); r.status != 409 {
		lease.Finish(func(bool) {})
		t.Fatalf("cleanup restore HTTP=%d", r.status)
	}
	lease.Finish(func(bool) {})
	if r := <-done; r.status != 200 {
		t.Fatalf("seal HTTP=%d", r.status)
	}
	if r := request("/api/v1/seal/status", "GET", "", ""); r.state != "sealed" {
		t.Fatalf("status=%s", r.state)
	}
	for _, raw := range raws {
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("original DEK or KEK not zero")
		}
	}
	if r := request("/api/v1/seal/unseal", "POST", fmt.Sprintf(`{"kek":%q}`, testOtherKEK), ""); r.status != 400 {
		t.Fatalf("wrong material HTTP=%d", r.status)
	}
	time.Sleep(1100 * time.Millisecond)
	go func() {
		r, _ := restoreHTTP(client, server.URL+"/api/v1/seal/unseal", "POST", fmt.Sprintf(`{"kek":%q}`, testInitialKEK), "")
		done <- r
	}()
	sawUnsealing := false
	finished := false
	var restored restoreResponse
	for !finished {
		select {
		case restored = <-done:
			finished = true
		default:
			r := request("/api/v1/seal/status", "GET", "", "")
			if r.state == "unsealing" {
				sawUnsealing = true
			}
		}
	}
	if restored.status != 200 || !sawUnsealing {
		t.Fatalf("restore HTTP=%d observed_unsealing=%v", restored.status, sawUnsealing)
	}
	if r := request("/api/v1/seal/status", "GET", "", ""); r.state != "unsealed" {
		t.Fatalf("restored status=%s", r.state)
	}
	current := e.machine.Snapshot().Services.(*appGraph)
	owner, err := current.keyManager.DecryptBytesFor(context.Background(), lifecycleProbeRef, cipher)
	if err != nil {
		t.Fatal("original ciphertext unreadable")
	}
	defer owner.Destroy()
	if err = owner.Borrow(func(raw []byte) error {
		if string(raw) != "restore-fixture" {
			return fmt.Errorf("plaintext changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Log("EVIDENCE ui-seal-restore transport=TCP_HTTP states=sealed,unsealing,unsealed cleanup_restore=409 wrong_material=400 original_DEK_KEK_zero=true original_ciphertext=readable auth=existing_identity ui_restore=anonymous_explicit_body")
}

// restoreSealGrant 走 `/seal/authorize` 取一個脈絡（真實 HTTP 面）。
func restoreSealGrant(client *http.Client, unsealURL string) string {
	url := strings.TrimSuffix(unsealURL, "/seal/unseal") + "/seal/authorize"
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, testAdminUser, testAdminPassword)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil || res.StatusCode != http.StatusOK {
		return ""
	}
	var out struct {
		Grant string `json:"grant"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return ""
	}
	return out.Grant
}

// restoreHTTPAuth 以**指定的授權標頭**送一次請求（不代取脈絡）。
//
// 供「脈絡不成立即拒」這類案例使用：restoreHTTP 會代取一個有效脈絡，
// 那正是這些案例要排除的前提。
func restoreHTTPAuth(client *http.Client, url, method, body, authHeader string) (restoreResponse, error) {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return restoreResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	res, err := client.Do(req)
	if err != nil {
		return restoreResponse{}, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil {
		return restoreResponse{}, err
	}
	var parsed struct {
		State      string `json:"state"`
		Generation uint64 `json:"generation"`
		Guidance   string `json:"restore_guidance"`
		Mode       string `json:"mode"`
	}
	_ = json.Unmarshal(raw, &parsed)
	return restoreResponse{status: res.StatusCode, state: parsed.State,
		generation: parsed.Generation, guidance: parsed.Guidance, mode: parsed.Mode}, nil
}
