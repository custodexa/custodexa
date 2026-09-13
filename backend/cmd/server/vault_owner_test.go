package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
)

// sealGrantRequest 帶著解封授權脈絡送一次請求。
//
// **解封流程自本版起先過帳密**（委託拓撲與憑證改由介面管理）：
// /seal/unseal 一律要求 `Authorization: SealGrant <grant>`，脈絡由
// /seal/authorize 以管理員帳密換得，且解封成功後即全數撤銷（故每次解封前重取）。
// 業務工作階段的 Bearer 權杖不再能單獨觸發解封——兩者的授權語義不同。
func sealGrantRequest(t *testing.T, e *sealIntegrationEnv, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	grant := issueSealGrant(t, e)
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "SealGrant "+grant)
	w := httptest.NewRecorder()
	e.swap.ServeHTTP(w, r)
	return w
}

func issueSealGrant(t *testing.T, e *sealIntegrationEnv) string {
	t.Helper()
	w := e.do("POST", "/api/v1/seal/authorize",
		fmt.Sprintf(`{"username":%q,"password":%q}`, testAdminUser, testAdminPassword))
	if w.Code != http.StatusOK {
		t.Fatalf("seal authorize HTTP=%d", w.Code)
	}
	var out struct {
		Grant string `json:"grant"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Grant == "" {
		t.Fatal("seal authorize did not return a grant")
	}
	return out.Grant
}

// The child trusts a temporary CA before system roots are loaded. All Transit
// and AppRole operations reach the real dev Vault through a TLS reverse proxy.
func TestVaultClientOwnership(t *testing.T) {
	if os.Getenv("VAULT_OWNER_TEST_CHILD") == "1" {
		testVaultAssemblyOwnership(t)
		return
	}
	if os.Getenv("VAULT_DEV_ROOT_TOKEN_ID") == "" {
		t.Fatal("VAULT_DEV_ROOT_TOKEN_ID and the bootstrapped dev Vault service are required")
	}
	target, _ := url.Parse("http://vault:8200")
	proxy := httputil.NewSingleHostReverseProxy(target)
	var renewals atomic.Int64
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/renew-self" {
			renewals.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer remote.Close()
	ca := filepath.Join(t.TempDir(), "vault-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVaultClientOwnership$", "-test.v")
	cmd.Env = append(os.Environ(), "VAULT_OWNER_TEST_CHILD=1", "VAULT_OWNER_TEST_ORIGIN="+remote.URL, "SSL_CERT_FILE="+ca)
	output, err := cmd.CombinedOutput()
	// Redact deployment credentials even if a dependency starts logging them.
	safe := strings.ReplaceAll(string(output), os.Getenv("VAULT_DEV_ROOT_TOKEN_ID"), "<redacted>")
	t.Log(safe)
	if err != nil {
		t.Fatalf("assembly child failed: %v", err)
	}
	if renewals.Load() == 0 {
		t.Fatal("real Vault renewal was not exercised")
	}
	t.Logf("real Vault renewal requests=%d; child completed all ownership paths", renewals.Load())
}

func testVaultAssemblyOwnership(t *testing.T) {
	origin := os.Getenv("VAULT_OWNER_TEST_ORIGIN")
	admin := os.Getenv("VAULT_DEV_ROOT_TOKEN_ID")
	request := func(method, path string, body any) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, origin+"/v1/"+path, bytes.NewReader(raw))
		req.Header.Set("X-Vault-Token", admin)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("Vault fixture transport failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("Vault fixture HTTP=%d", resp.StatusCode)
		}
		out := make(map[string]any)
		if resp.StatusCode != http.StatusNoContent {
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatal("Vault fixture response invalid")
			}
		}
		return out
	}
	role := fmt.Sprintf("assembly-owner-%d", os.Getpid())
	path := "auth/approle/role/" + role
	request("POST", path, map[string]any{"token_policies": []string{"wave2c-transit"}, "token_ttl": "2s", "token_max_ttl": "60s", "secret_id_num_uses": 0})
	t.Cleanup(func() { request("DELETE", path, nil) })
	roleID := request("GET", path+"/role-id", nil)["data"].(map[string]any)["role_id"].(string)
	secretID := request("POST", path+"/secret-id", struct{}{})["data"].(map[string]any)["secret_id"].(string)
	// **語義變更（委託拓撲與憑證改由介面管理）**：環境只剩服務商
	// 一鍵；位址、角色識別與 Transit 金鑰名是介面設定（資料庫持久化），角色密鑰
	// 是解封時的輸入。本測試因此以「拓撲結構 ＋ 世代秘密」取代原本的五個 t.Setenv。
	t.Setenv(config.EnvKeyKMSProvider, "vault")
	deployment := func() config.KMSSettings {
		s := config.KMSSettings{Provider: "vault", KeyID: "wave2c-kek"}
		s.Vault.Address, s.Vault.RoleID = origin, roleID
		return s
	}
	generationSecrets := func() delegatedSecrets {
		return delegatedSecrets{vaultSecretID: []byte(secretID)}
	}
	keyID, err := vaulttransit.CanonicalKeyID(origin, "wave2c-kek")
	if err != nil {
		t.Fatal("invalid fixture key")
	}
	for _, mode := range []string{config.KEKModeUI, config.KEKModeEnv, config.KEKModeKMS} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv(config.EnvKeyKEKProvider, mode)
			t.Setenv(config.EnvKeyEncryptionKey, "")
			if mode == config.KEKModeEnv {
				t.Setenv(config.EnvKeyEncryptionKey, testInitialKEK)
			}
			e := newSealIntegrationEnv(t)
			d, err := config.DecideKEK(config.OSEnvLookup, false)
			if err != nil {
				t.Fatal("mode configuration rejected")
			}
			e.s1.kekDecision = d
			e.s1.credentials = newCredentialOwner()
			initial := e.s1.credentials
			t.Cleanup(initial.Close)
			// **只有 env 模式仍於段 1 建構**：ui 的材料與委託模式的憑證都只由
			// 解封端點進入記憶體。委託模式的冷啟動因此進入已封存等待人工解封，
			// 段 1 的持有者從未拿到憑證，也就不會被轉交給服務圖。
			if mode == config.KEKModeEnv {
				e.s1.kekProvider, e.s1.kekOwner, err = initial.buildStartup(context.Background(), d)
				if err != nil || e.s1.kekProvider == nil {
					t.Fatal("startup construction failed")
				}
				e.s1.initialKEKRef = e.s1.kekProvider.KeyRef()
			}
			e.handler.SetAuthorizer(mode, identity.NewSealAuthorizer(e.s1.cfg.Security.JWTSecret, database.DB).Authorize)
			token, err := crypto.NewJWTManager(e.s1.cfg.Security.JWTSecret, time.Hour).GenerateToken(1, testAdminUser, "", "admin", crypto.AuthContext{})
			if err != nil {
				t.Fatal("identity fixture failed")
			}
			payload := "{}"
			switch mode {
			case config.KEKModeUI:
				payload = initPayload(testInitialKEK)
			case config.KEKModeKMS:
				// 委託模式的初始化解封：憑證與拓撲都由本次請求提供。
				payload = fmt.Sprintf(`{"username":%q,"password":%q,"address":%q,"transit_key_name":%q,"role_id":%q,"vault_secret_id":%q}`,
					testAdminUser, testAdminPassword, origin, "wave2c-kek", roleID, secretID)
			}
			if w := sealGrantRequest(t, e, http.MethodPost, "/api/v1/seal/unseal", payload); w.Code != 200 {
				t.Fatalf("unseal HTTP=%d", w.Code)
			}
			g := e.machine.Snapshot().Services.(*appGraph)
			if mode == config.KEKModeKMS {
				// 委託模式：本世代的持有者由解封驗證新建（憑證只由請求提供），
				// 段 1 的持有者不被轉交也不被取用。
				if g.credentials == initial || g.credentials == nil || e.s1.credentials != initial {
					t.Fatal("delegated generation did not own its own credentials")
				}
			} else if g.credentials != initial || e.s1.credentials != nil {
				t.Fatal("startup owner was not transferred to the service graph")
			}
			generation := g.credentials
			// **語義變更**：委託目標的憑證只存在於**委託解封世代**。ui／env 的
			// 世代從來沒有收到過保管處憑證（解封頁在這兩種模式不收秘密），故其
			// 目標建構 SHALL 拒絕而非以任何回落憑證成立——若哪天它成功了，代表
			// 憑證又從別處（環境、資料庫、SDK 預設鏈）被撿了回來。
			delegated := mode == config.KEKModeKMS
			var wg sync.WaitGroup
			errs := make(chan error, 4)
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					p, err := generation.buildDelegated(context.Background(), crypto.KeyRefProviderVault, keyID)
					if err == nil && p == nil {
						err = errors.New("nil provider")
					}
					errs <- err
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if delegated && err != nil {
					t.Fatalf("shared target construction failed: %v", err)
				}
				if !delegated && err == nil {
					t.Fatal("a credential-free generation constructed a delegated target")
				}
			}
			client := generation.client
			if delegated != (client != nil) {
				t.Fatal("shared client presence does not match the generation's credentials")
			}
			if delegated {
				// Allow the real two-second lease to renew while the graph owns it.
				time.Sleep(1200 * time.Millisecond)
				p, err := generation.buildDelegated(context.Background(), crypto.KeyRefProviderVault, keyID)
				if err != nil || p == nil || generation.client != client {
					t.Fatal("client replaced between target constructions")
				}
			}
			if w := modeRequest(t, e, "/api/v1/seal/seal", "{}", token); w.Code != 200 {
				t.Fatalf("seal HTTP=%d", w.Code)
			}
			if e.machine.Snapshot().State != seal.StateSealed || generation.client != nil {
				t.Fatal("seal retained the owner client")
			}
			// 封存後本世代的憑證一律取用失敗（抹除的可觀察面）。
			if _, err := generation.settings(); !errors.Is(err, errCredentialOwnerClosed) {
				t.Fatalf("sealed generation still yielded credentials: %v", err)
			}
			if delegated {
				if p, err := client.Provider(context.Background(), keyID); p != nil || !errors.Is(err, vaulttransit.ErrClosed) {
					t.Fatal("released client still usable")
				}
			}
			if mode == config.KEKModeUI {
				payload = fmt.Sprintf(`{"kek":%q}`, testInitialKEK)
			}
			if mode == config.KEKModeKMS {
				// 既有部署的委託解封：只送本世代的秘密，並附上必須相符的拓撲摘要
				// ——舊的核對結果不授權新的目的地。
				view, _, err := delegatedTopologySnapshot("vault")
				if err != nil || view.Digest == "" {
					t.Fatal("topology digest unavailable")
				}
				payload = fmt.Sprintf(`{"vault_secret_id":%q,"topology_digest":%q}`, secretID, view.Digest)
			}
			if w := sealGrantRequest(t, e, http.MethodPost, "/api/v1/seal/unseal", payload); w.Code != 200 {
				t.Fatalf("restore HTTP=%d", w.Code)
			}
			next := e.machine.Snapshot().Services.(*appGraph)
			if next.credentials == generation {
				t.Fatal("restore reused a closed generation")
			}
			p, err := next.credentials.buildDelegated(context.Background(), crypto.KeyRefProviderVault, keyID)
			if delegated && (err != nil || p == nil || next.credentials.client == client) {
				t.Fatalf("restore did not obtain a fresh shared client: %v", err)
			}
			if !delegated && (err == nil || next.credentials.client != nil) {
				t.Fatal("restored credential-free generation constructed a delegated target")
			}
			nextClient := next.credentials.client
			if err := next.Release(context.Background()); err != nil {
				t.Fatal("shutdown release failed")
			}
			if delegated {
				if p, err := nextClient.Provider(context.Background(), keyID); p != nil || !errors.Is(err, vaulttransit.ErrClosed) {
					t.Fatal("shutdown retained a usable client")
				}
			}
			t.Log("generation owns its credentials; seal closes them; restore creates a new generation; shutdown closes")
		})
	}
	t.Run("partial-startup-and-preflight-failure", func(t *testing.T) {
		e := newSealIntegrationEnv(t)
		d := &config.KEKDecision{Mode: config.KEKModeKMS, KMS: config.KMSSettings{Provider: "vault"}}
		o := newCredentialOwner()
		defer o.Close()
		o.adopt(deployment(), generationSecrets())
		p, material, err := o.buildStartup(context.Background(), d)
		if err != nil || p == nil {
			t.Fatal("startup provider unavailable")
		}
		client := o.client
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		g, err := runStage2(ctx, e.s1, p, o, nil, material)
		if err == nil || g == nil {
			t.Fatal("cancelled startup did not return its partial graph")
		}
		if err := g.Release(context.Background()); err != nil {
			t.Fatal("partial graph release failed")
		}
		if p, err := client.Provider(context.Background(), keyID); p != nil || !errors.Is(err, vaulttransit.ErrClosed) {
			t.Fatal("partial startup retained a client")
		}
		bad := newCredentialOwner()
		defer bad.Close()
		denied := deployment()
		denied.KeyID = "wave2c-denied-kek"
		bad.adopt(denied, generationSecrets())
		p, material, err = bad.buildStartup(context.Background(), d)
		if err == nil || p != nil || material != nil || bad.client != nil {
			t.Fatal("failed preflight published an owner or non-nil provider")
		}
		// 收束後取用一律失敗：封存抹除的可觀察面（不得拿到一段全零的位元組）。
		bad.Close()
		if _, err := bad.settings(); !errors.Is(err, errCredentialOwnerClosed) {
			t.Fatalf("closed generation still yielded settings: %v", err)
		}
		e.s1.credentials = newCredentialOwner()
		e.s1.credentials.Close()
		e.s1.closeStartupVault()
		t.Log("cancelled partial graph released; denied preflight returns true nil; startup close is idempotent")
	})
}
