package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/observability"
	"github.com/custodexa/backend/internal/sealjournal"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/sshmaterial"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
	"golang.org/x/crypto/ssh"
)

// Assigned only by a temporary _test.go overlay in the child. Ordinary product
// builds contain neither this declaration nor the package-private HTTP bridge.
var vaultWizardHTTPClient func(context.Context, vaulttransit.Settings, string, func(string, int)) (*vaulttransit.Client, error)

type vaultWizardJournal struct {
	mu      sync.Mutex
	file    *os.File
	secrets []string
}

func (j *vaultWizardJournal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	safe := string(p)
	for _, secret := range j.secrets {
		if secret != "" {
			safe = strings.ReplaceAll(safe, secret, "[REDACTED]")
		}
	}
	if _, err := j.file.WriteString(safe); err != nil {
		return 0, err
	}
	if err := j.file.Sync(); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (j *vaultWizardJournal) hide(values ...string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.secrets = append(j.secrets, values...)
}
func (j *vaultWizardJournal) step(t *testing.T, format string, args ...any) {
	t.Helper()
	if _, err := fmt.Fprintf(j, "VAULT_EVIDENCE "+format+"\n", args...); err != nil {
		t.Fatal("cannot persist wizard evidence")
	}
}

// wizardGeneration 以本解封世代的憑證持有者供給拓撲與秘密。
// 原本這兩者分別來自 KEK_VAULT_ADDR／KEK_VAULT_ROLE_ID／KEK_KMS_KEY_ID 與
// KEK_VAULT_SECRET_ID；五鍵已退場，建構路徑改自持有者取得。
func wizardGeneration(topology config.KMSSettings, secretID string) *credentialOwner {
	o := newCredentialOwner()
	o.adopt(topology, delegatedSecrets{vaultSecretID: []byte(secretID)})
	return o
}

func TestVaultWizardE2E(t *testing.T)          { vaultTestAssembly(t, "wizard") }
func TestVaultPartialRollbackE2E(t *testing.T) { vaultTestAssembly(t, "partial") }
func TestVaultAbandonE2E(t *testing.T)         { vaultTestAssembly(t, "abandon") }
func TestVaultSameRefE2E(t *testing.T)         { vaultTestAssembly(t, "same-ref") }
func TestVaultColdStartE2E(t *testing.T)       { vaultTestAssembly(t, "cold-start") }
func TestVaultBackupRecoveryE2E(t *testing.T)  { vaultTestAssembly(t, "backup") }
func TestVaultOutageE2E(t *testing.T)          { vaultTestAssembly(t, "outage") }

// TestVaultSealCycleE2E 任務 10.1 的 Vault 段：真保管處的「封存 → 帳密授權 →
// 重新提供憑證 → 解封 → 業務可用」整圈，角色密鑰與直接權杖各走一次。
//
// **真保管處**：Transit 與 AppRole 的每一次請求都送到 dev 的 Vault 2.1.0，
// 只有傳輸層經測試專用的 HTTP 橋（拓撲驗證要求 HTTPS，dev 靶機只有 HTTP）。
func TestVaultSealCycleE2E(t *testing.T) { vaultTestAssembly(t, "seal-cycle") }

func vaultTestAssembly(t *testing.T, scenario string) {
	path := os.Getenv("VAULT_WIZARD_LOG")
	if path == "" {
		// 未指定落檔位置時寫進本次測試的暫存目錄：驅動腳本一律以 VAULT_WIZARD_LOG
		// 指定持久路徑，此處只服務臨時單跑，不該在工作樹留下證據檔。
		path = filepath.Join(t.TempDir(), "vault-wizard-"+scenario+"-"+time.Now().UTC().Format("20060102T150405.000000000Z")+".log")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal("cannot create evidence directory")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("cannot open wizard evidence")
	}
	j := &vaultWizardJournal{file: file}
	j.hide(os.Getenv("VAULT_DEV_ROOT_TOKEN_ID"), testInitialKEK, testAdminPassword)
	t.Cleanup(func() { file.Sync(); file.Close() })
	if vaultWizardHTTPClient == nil {
		if os.Getenv("VAULT_WIZARD_CHILD") != "" {
			t.Fatal("test HTTP bridge not connected")
		}
		root, err := filepath.Abs("../..")
		if err != nil {
			t.Fatal("cannot resolve backend directory")
		}
		dir := t.TempDir()
		injected := filepath.Join(dir, "injected_test.go")
		source := "package main\nimport \"github.com/custodexa/backend/pkg/crypto/vaulttransit\"\nfunc init(){vaultWizardHTTPClient=vaulttransit.WizardHTTPClient}\n"
		if err := os.WriteFile(injected, []byte(source), 0600); err != nil {
			t.Fatal("cannot write test bridge")
		}
		overlay := map[string]any{"Replace": map[string]string{
			filepath.Join(root, "cmd/server/vault_wizard_injected_test.go"):      injected,
			filepath.Join(root, "pkg/crypto/vaulttransit/wizard_http_bridge.go"): filepath.Join(root, "pkg/crypto/vaulttransit/wizard_http_test.go"),
		}}
		raw, _ := json.Marshal(overlay)
		overlayPath := filepath.Join(dir, "overlay.json")
		if err := os.WriteFile(overlayPath, raw, 0600); err != nil {
			t.Fatal("cannot write test overlay")
		}
		j.step(t, "assembly=full-service real_vault=true transport=http-test-only log=%s", path)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-overlay", overlayPath, "-count=1", "-v", "./cmd/server", "-run", "^"+t.Name()+"$")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "VAULT_WIZARD_CHILD=1", "VAULT_WIZARD_LOG="+path)
		cmd.Stdout = j
		cmd.Stderr = j
		err = cmd.Run()
		j.step(t, "child_finished success=%t evidence_synced_before_overlay_cleanup=true", err == nil)
		if err != nil {
			t.Fatalf("Vault wizard failed; see %s", path)
		}
		t.Logf("PASS real Vault %s; evidence=%s", scenario, path)
		return
	}
	previous := log.Writer()
	log.SetOutput(j)
	t.Cleanup(func() { log.SetOutput(previous) })
	runVaultWizard(t, j, scenario)
}

func runVaultWizard(t *testing.T, j *vaultWizardJournal, scenario string) {
	ctx := context.Background()
	address := "http://vault:8200"
	// A disposable forwarding socket interrupts only this fixture's route to
	// the real dev Vault; no fake Transit responses or shared Vault shutdown.
	upstream, _ := url.Parse(address)
	proxy := httptest.NewServer(httputil.NewSingleHostReverseProxy(upstream))
	t.Cleanup(proxy.Close)
	clientAddress := proxy.URL
	admin := os.Getenv("VAULT_DEV_ROOT_TOKEN_ID")
	if admin == "" {
		t.Fatal("bootstrapped Vault initialization credential required")
	}
	httpClient := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect rejected") }}
	t.Cleanup(httpClient.CloseIdleConnections)
	request := func(method, path string, body any) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(body)
		defer clear(raw)
		req, err := http.NewRequest(method, address+"/v1/"+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal("invalid fixture request")
		}
		req.Header.Set("X-Vault-Token", admin)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			j.step(t, "fixture_transport=FAIL")
			t.Fatal("Vault fixture unavailable")
		}
		defer resp.Body.Close()
		j.step(t, "fixture %s /v1/%s HTTP=%d", method, path, resp.StatusCode)
		if resp.StatusCode >= 300 {
			t.Fatal("Vault fixture request rejected")
		}
		out := map[string]any{}
		if resp.StatusCode != http.StatusNoContent {
			if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
				t.Fatal("invalid fixture response")
			}
		}
		return out
	}
	health := request("GET", "sys/health", nil)
	if health["sealed"] != false || health["version"] != "2.1.0" {
		t.Fatal("Vault health or version mismatch")
	}
	field := func(out map[string]any, name string) string {
		t.Helper()
		data, ok := out["data"].(map[string]any)
		if !ok {
			t.Fatal("fixture data missing")
		}
		value, ok := data[name].(string)
		if !ok || value == "" {
			t.Fatal("fixture credential missing")
		}
		j.hide(value)
		return value
	}
	roleID := field(request("GET", "auth/approle/role/wave2c-transit/role-id", nil), "role_id")
	scope, id, err := vaulttransit.ResolveScope("https://vault.fixture", "wave2c-kek")
	if err != nil {
		t.Fatal("canonical scope rejected")
	}
	// **語義變更（委託拓撲與憑證改由介面管理）**：部署檔只剩服務商
	// 一鍵。位址、角色識別與金鑰引用是介面設定（資料庫持久化），角色密鑰是解封時
	// 的輸入——本檔因此把原本的四個 KEK_* 環境變數改為「拓撲結構 ＋ 世代秘密」，
	// 由 credentialOwner 承載。
	t.Setenv(config.EnvKeyKMSProvider, "vault")
	deployment := func() config.KMSSettings {
		s := config.KMSSettings{Provider: "vault", KeyID: id}
		s.Vault.Address, s.Vault.RoleID = scope.Origin(), roleID
		return s
	}
	// currentSecretID 是**本世代**的角色密鑰：每次換發即換世代。
	var currentSecretID string
	generation := func() *credentialOwner { return wizardGeneration(deployment(), currentSecretID) }
	// Fresh single-use SecretIDs for each generation; never reuse a spent login.
	newClient := func() *vaulttransit.Client {
		t.Helper()
		secret := field(request("POST", "auth/approle/role/wave2c-transit/secret-id", struct{}{}), "secret_id")
		currentSecretID = secret
		s := vaulttransit.Settings{Address: scope.Origin(), Scope: scope, KeyID: id, RoleID: roleID, SecretID: secret}
		client, err := vaultWizardHTTPClient(ctx, s, clientAddress, func(path string, status int) { j.step(t, "transit %s HTTP=%d", path, status) })
		if err != nil {
			t.Fatal("real AppRole client failed")
		}
		t.Cleanup(client.Close)
		return client
	}
	e, token, _ := modeFixture(t, "env")
	// Serialize this SQLite fixture's background journal and handler writes.
	// The production transaction/locking paths and their errors stay unchanged.
	sqlDB, err := database.DB.DB()
	if err != nil {
		t.Fatal("cannot configure fixture connection pool")
	}
	sqlDB.SetMaxOpenConns(1)
	j.hide(token)
	local := e.s1.kekProvider
	localOwner := e.s1.kekOwner
	// Goexit also executes this defer, before any testing cleanup closes clients.
	defer func() { j.step(t, "before_cleanup failed=%t backend_log_synced=true", t.Failed()) }()
	call := func(method, path, body string) map[string]any {
		t.Helper()
		// 解封自本版起先過帳密：/seal/unseal 收的是 SealGrant 脈絡而非業務權杖
		// （見 vault_owner_test.go 的 sealGrantRequest）。其餘端點維持 Bearer。
		w := sealGrantRequest(t, e, method, path, body)
		if path != "/api/v1/seal/unseal" {
			w = modeRequestMethod(t, e, method, path, body, token)
		}
		j.step(t, "handler %s %s HTTP=%d", method, path, w.Code)
		if w.Code != http.StatusOK {
			t.Fatalf("wizard handler failed: %s HTTP=%d", path, w.Code)
		}
		out := map[string]any{}
		if json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal("invalid handler JSON")
		}
		return out
	}
	call("POST", "/api/v1/seal/unseal", "{}")
	old := e.machine.Snapshot().Services.(*appGraph)
	before := call("GET", "/api/v1/keys", "")
	if before["provider"] != "env" || before["key_ref"] != local.KeyRef().String() || before["rewrap_pending"] != false {
		t.Fatal("initial inventory differs")
	}
	j.step(t, "inventory_before mode=%s key_ref=%s pending=false", before["provider"], before["key_ref"])
	ciphertext, err := old.keyManager.EncryptBytesFor(ctx, lifecycleProbeRef, []byte("vault-wizard-readable"))
	if err != nil {
		t.Fatal("data fixture encryption failed")
	}
	// Persist the sample so comparison after the generation restart cannot be a
	// tautology over the same local ciphertext variable.
	if err := database.DB.Exec("CREATE TABLE vault_wizard_payload (id INTEGER PRIMARY KEY, ciphertext TEXT NOT NULL)").Error; err != nil {
		t.Fatal("payload fixture table failed")
	}
	if err := database.DB.Exec("INSERT INTO vault_wizard_payload VALUES (1, ?)", ciphertext).Error; err != nil {
		t.Fatal("payload fixture write failed")
	}
	var originals []model.DataKey
	if err := database.DB.Order("id").Find(&originals).Error; err != nil || len(originals) == 0 {
		t.Fatal("initial key rows missing")
	}
	hashes := map[string][32]byte{}
	slot := func(row model.DataKey) string { return fmt.Sprintf("%s:%d", row.Purpose, row.Version) }
	for _, row := range originals {
		_, wrapped, err := crypto.ParseWrappedKey(row.WrappedKey)
		if err != nil {
			t.Fatal("initial wrapped row invalid")
		}
		plain, err := local.Unwrap(ctx, wrapped, crypto.DEKAAD(row.Purpose, row.Version))
		if err != nil {
			t.Fatal("initial row unwrap failed")
		}
		hashes[slot(row)] = sha256.Sum256(plain)
		clear(plain)
	}
	targetClient := newClient()
	partial := &vaultSecondWrapFailure{}
	inserted := 0
	if scenario == "partial" {
		if err := database.DB.Callback().Create().After("gorm:create").Register("vault_partial_observer", func(tx *gorm.DB) {
			if tx.Statement.Table == "data_keys" && tx.Error == nil && tx.RowsAffected > 0 {
				inserted++
			}
		}); err != nil {
			t.Fatal("cannot register transaction observer")
		}
		t.Cleanup(func() { database.DB.Callback().Create().Remove("vault_partial_observer") })
	}
	// Keep the shared factory's mode/config/scope/identity checks. Inject only
	// the concrete real Transit client, with Provider running metadata + canary.
	old.deps.keyManagement.SetDelegatedProviderFactory(func(ctx context.Context, mode, ref string) (crypto.KEKProvider, error) {
		// 委託目標的拓撲與憑證改自本解封世代的持有者取得（原為 KEK_* 環境變數）。
		o := generation()
		defer o.Close()
		return buildDelegatedRewrapProviderWithConstructors(ctx, mode, ref, o, func(ctx context.Context, s vaulttransit.Settings) (crypto.KEKProvider, error) {
			p, err := targetClient.Provider(ctx, s.KeyID)
			if err != nil {
				return nil, err
			}
			j.step(t, "preflight=PASS metadata_and_canary=true")
			if scenario == "partial" {
				partial.KEKProvider = p
				return partial, nil
			}
			return p, nil
		}, nil)
	})
	// 委託重包的請求體自本版起帶目的地拓撲（位址與角色識別）：引用指向新家、
	// 位址還留在舊家的「半套目的地」因此不可能成立。憑證仍**不**經精靈傳遞。
	body, _ := json.Marshal(map[string]string{"mode": "vault", "key_ref": id,
		"address": scope.Origin(), "role_id": roleID})
	if scenario == "partial" {
		w := modeRequestMethod(t, e, "POST", "/api/v1/keys/rewrap", string(body), token)
		j.step(t, "handler POST /api/v1/keys/rewrap HTTP=%d", w.Code)
		var rows []model.DataKey
		if database.DB.Order("id").Find(&rows).Error != nil {
			t.Fatal("row snapshot failed")
		}
		if w.Code != 500 || partial.calls != 2 || inserted != 1 || !reflect.DeepEqual(rows, originals) || old.keyManager.RewrapPending() {
			t.Fatal("partial failure was not atomic")
		}
		j.step(t, "partial=PASS first_insert_observed=true second_wrap_failed=true pending=0 rows_equal_snapshot=true")
		return
	}
	result := call("POST", "/api/v1/keys/rewrap", string(body))
	if result["target_mode"] != "vault" || result["rewrapped_keys"] != float64(len(originals)) {
		t.Fatal("rewrap response differs")
	}
	pending := call("GET", "/api/v1/keys", "")
	var pendingCount int64
	if err := database.DB.Model(&model.DataKey{}).Where("kek_id = ? AND kek_pending = ?", id, true).Count(&pendingCount).Error; err != nil {
		t.Fatal("pending count failed")
	}
	if pending["rewrap_pending"] != true || pending["provider"] != "env" || pendingCount != int64(len(originals)) {
		t.Fatal("pending state missing")
	}
	j.step(t, "pending=PASS rows=%d inventory_mode=%s key_ref=%s", pendingCount, pending["provider"], pending["key_ref"])
	if scenario == "abandon" {
		if plain, err := old.keyManager.DecryptFor(ctx, lifecycleProbeRef, ciphertext); err != nil || plain != "vault-wizard-readable" {
			t.Fatal("pending local data unreadable")
		}
		j.step(t, "unswitched=PASS local_readable=true recovery_point=current loss=none")
		abandoned := call("DELETE", "/api/v1/keys/rewrap", "{}")
		inventory := call("GET", "/api/v1/keys", "")
		var targets []model.DataKey
		if database.DB.Where("kek_id = ?", id).Find(&targets).Error != nil {
			t.Fatal("abandoned rows unavailable")
		}
		if abandoned["deleted"] != float64(len(originals)) || len(targets) != len(originals) || inventory["rewrap_pending"] != false || inventory["provider"] != "env" {
			t.Fatal("abandon did not converge")
		}
		for _, row := range targets {
			if row.KEKRetiredAt == nil || row.KEKRetiredReason != model.KEKRetireReasonAbandoned || row.KEKPending || row.WrappedKey == "" {
				t.Fatal("abandon retirement differs")
			}
		}
		if plain, err := old.keyManager.DecryptFor(ctx, lifecycleProbeRef, ciphertext); err != nil || plain != "vault-wizard-readable" {
			t.Fatal("abandon local data unreadable")
		}
		var audits int64
		if database.DB.Model(&model.AuditLog{}).Where("path = ? AND method = ? AND status_code = ?", "/api/v1/keys/rewrap", "DELETE", 200).Count(&audits).Error != nil || audits == 0 {
			t.Fatal("abandon audit missing")
		}
		j.step(t, "abandon=PASS pending=0 retired_reason=abandoned material_retained=true local_readable=true audit=true loss=none")
		return
	}
	j.step(t, "before_seal backend_log_synced=true")
	call("POST", "/api/v1/seal/seal", "{}")
	e.machine.WaitCleanup()
	targetClient.Close()
	if !localOwner.IsEmpty() {
		t.Fatal("local material owner survived seal")
	}
	if _, err := old.keyManager.DecryptFor(ctx, lifecycleProbeRef, ciphertext); err == nil {
		t.Fatal("old graph still decrypts after seal")
	}
	local = nil
	t.Setenv(config.EnvKeyEncryptionKey, "")
	t.Setenv(config.EnvKeyKEKProvider, "kms")
	e.s1.kekDecision = &config.KEKDecision{Mode: config.KEKModeKMS}
	e.s1.initialKEKRef = crypto.KeyRef{Provider: crypto.KeyRefProviderVault, KeyID: id}
	e.handler.SetAuthorizer(config.KEKModeKMS, identity.NewSealAuthorizer(e.s1.cfg.Security.JWTSecret, database.DB).Authorize)
	e.s1.kekDecision.KMS.Provider = vaulttransit.ProviderVault
	restartedClient := newClient()
	var restartedProvider crypto.KEKProvider
	// **委託解封的接縫**（委託拓撲與憑證改由介面管理）：委託模式的
	// 解封不再經 stage1.deploymentSource，改走本世代的憑證持有者；接縫因此換成
	// delegatedProviderSource，它收的正是**已 adopt 憑證的持有者**——故「憑證有
	// 沒有被交出去」在這裡仍然看得見（下面的斷言即檢查它）。
	// 本測試的靶機位址（https://vault.fixture）不可解析，只能經
	// vaultWizardHTTPClient 這座橋以另一個撥號位址連上真 Vault，故需要這個接縫。
	e.s1.delegatedProviderSource = func(ctx context.Context, o *credentialOwner) (crypto.KEKProvider, error) {
		settings, err := o.settings()
		if err != nil {
			return nil, err
		}
		if settings.Vault.SecretID == "" && settings.Vault.Token == "" {
			return nil, fmt.Errorf("世代持有者未收到 Vault 秘密")
		}
		p, err := restartedClient.Provider(ctx, settings.KeyID)
		restartedProvider = p
		return p, err
	}
	if e.s1.kekProvider != nil || e.s1.kekOwner != nil || os.Getenv(config.EnvKeyEncryptionKey) != "" {
		t.Fatal("local startup material retained")
	}
	j.step(t, "removed_local_material=PASS owner_destroyed=true env_empty=true source=kms/vault")
	j.step(t, "before_restart backend_log_synced=true")
	// 委託解封的請求體：該服務商的精確鍵集 ＋ 拓撲核對摘要。
	// 拓撲先以介面設定的同一條服務層函式寫入（位址與角色識別是非秘密，
	// 本來就該在解封前已經設定好）。
	if _, _, err := keyvault.SaveKEKTopology(database.DB, keyvault.KEKTopologyInput{
		Provider: vaulttransit.ProviderVault, Address: scope.Origin(),
		// 拓撲欄位收的是 Transit 具名金鑰**本身**（非正規化後的完整引用）——
		// 完整引用是金鑰列的 kek_id 的形態，兩者不是同一個欄位。
		TransitKeyName: "wave2c-kek", RoleID: roleID, UpdatedBy: "e2e",
	}); err != nil {
		t.Fatalf("拓撲設定失敗: %v", err)
	}
	call("POST", "/api/v1/seal/unseal", delegatedUnsealBody(t, "vault"))
	current := e.machine.Snapshot().Services.(*appGraph)
	if current == old || current.keyManager == old.keyManager || restartedProvider == nil {
		t.Fatal("service generation not rebuilt")
	}
	j.step(t, "restart=PASS mode=kms provider=vault fresh_client=true fresh_service_graph=true")
	after := call("GET", "/api/v1/keys", "")
	if after["provider"] != "kms" || after["key_ref"] != e.s1.initialKEKRef.String() || after["rewrap_pending"] != false {
		t.Fatal("switched inventory differs")
	}
	j.step(t, "inventory_after mode=%s provider=%s key_ref=%s pending=false", after["provider"], current.keyManager.KEKRef().Provider, after["key_ref"])
	var live []model.DataKey
	if err := database.DB.Where("kek_id = ? AND kek_retired_at IS NULL", id).Find(&live).Error; err != nil || len(live) != len(originals) {
		t.Fatal("switched row count differs")
	}
	for _, row := range live {
		tag, wrapped, err := crypto.ParseWrappedKey(row.WrappedKey)
		if err != nil || tag != crypto.WrappedFormatVault || row.KEKPending {
			t.Fatal("live Vault row invalid")
		}
		plain, err := restartedProvider.Unwrap(ctx, wrapped, crypto.DEKAAD(row.Purpose, row.Version))
		if err != nil {
			t.Fatal("live row unwrap failed")
		}
		digest := sha256.Sum256(plain)
		clear(plain)
		want, ok := hashes[slot(row)]
		if !ok || digest != want {
			t.Fatal("DEK changed across rewrap")
		}
	}
	j.step(t, "all_rows_unwrapped=PASS rows=%d same_deks=true", len(live))
	for _, row := range originals {
		var retired model.DataKey
		if err := database.DB.First(&retired, row.ID).Error; err != nil {
			t.Fatal("old row physically deleted")
		}
		if retired.KEKRetiredAt == nil || retired.KEKRetiredReason != model.KEKRetireReasonSwitched || retired.KEKRetiredBy != id || retired.KEKPending || retired.WrappedKey != row.WrappedKey {
			t.Fatal("old row not correctly soft retired")
		}
	}
	j.step(t, "old_rows_soft_retired=PASS rows=%d reason=switched wrapped_material_preserved=true", len(originals))
	var stored string
	if err := database.DB.Raw("SELECT ciphertext FROM vault_wizard_payload WHERE id = 1").Scan(&stored).Error; err != nil || stored != ciphertext {
		t.Fatal("persisted ciphertext changed")
	}
	plain, err := current.keyManager.DecryptFor(ctx, lifecycleProbeRef, stored)
	if err != nil || plain != "vault-wizard-readable" {
		t.Fatal("persisted data unreadable")
	}
	j.step(t, "ciphertext_unchanged=PASS persisted_bytes_equal=true readable=PASS")
	if scenario == "seal-cycle" {
		// ── 任務 10.1（Vault）：封存 → 帳密授權 → 重新提供憑證 → 解封 → 業務可用 ──
		//
		// 前置已把本部署切到真 Vault（上方的重包與解封皆走實 Transit），此處驗的是
		// **世代邊界**：封存抹掉憑證之後，不重新提供就解不開；重新提供即可，且解封
		// 後真的能用（以 dev 的 ssh-test 靶機建立一段真 SSH 會話）。
		const drillSSHPassword = "testpass123"
		sealedCredential, err := current.keyManager.EncryptBytesFor(ctx, lifecycleProbeRef, []byte(drillSSHPassword))
		if err != nil {
			t.Fatal("ssh credential fixture encryption failed")
		}
		if err := database.DB.Exec("CREATE TABLE vault_drill_credential (id INTEGER PRIMARY KEY, ciphertext TEXT NOT NULL)").Error; err != nil {
			t.Fatal("credential fixture table failed")
		}
		if err := database.DB.Exec("INSERT INTO vault_drill_credential VALUES (1, ?)", sealedCredential).Error; err != nil {
			t.Fatal("credential fixture write failed")
		}

		// sshSession：以**當下世代**的金鑰管理器解回落庫的憑證，再實際建線並跑一個
		// 指令。它同時證明兩件事：DEK 真的由 Vault 解開了，而且解出來的是對的。
		sshSession := func(label string) {
			t.Helper()
			graph, ok := e.machine.Snapshot().Services.(*appGraph)
			if !ok || graph == nil {
				t.Fatal("service graph absent for ssh probe")
			}
			var stored string
			if err := database.DB.Raw("SELECT ciphertext FROM vault_drill_credential WHERE id = 1").Scan(&stored).Error; err != nil {
				t.Fatal("credential fixture read failed")
			}
			secret, err := graph.keyManager.DecryptFor(ctx, lifecycleProbeRef, stored)
			if err != nil || secret != drillSSHPassword {
				t.Fatal("credential not recoverable in this generation")
			}
			conn, err := sshproxy.Dial(sshproxy.ConnConfig{
				HostKey: ssh.InsecureIgnoreHostKey(), Host: "ssh-test", Port: 2222,
				Username: "testuser", Password: sshmaterial.CopyPassword([]byte(secret)),
				Cols: 80, Rows: 24,
			})
			if err != nil {
				t.Fatalf("ssh session failed at %s", label)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("echo custodexa-drill-ok\n")); err != nil {
				t.Fatal("ssh write failed")
			}
			var sb strings.Builder
			buf := make([]byte, 4096)
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) && !strings.Contains(sb.String(), "custodexa-drill-ok\r\n") {
				n, rerr := conn.Read(buf)
				if n > 0 {
					sb.Write(buf[:n])
				}
				if rerr != nil {
					break
				}
			}
			if !strings.Contains(sb.String(), "custodexa-drill-ok") {
				t.Fatalf("ssh command output missing at %s", label)
			}
			j.step(t, "ssh_session=%s host=ssh-test user=testuser established=true command_echoed=true", label)
		}
		sshSession("generation-1")

		// 解封請求的拓撲核對摘要：取自後端當下的拓撲與金鑰列（與解封頁同一來源）。
		digest := func() string {
			t.Helper()
			row, terr := keyvault.LoadKEKTopology(database.DB)
			if terr != nil {
				t.Fatal("topology unreadable")
			}
			keyRef, kerr := keyvault.CurrentKEKID(database.DB)
			if kerr != nil {
				t.Fatal("current kek ref unreadable")
			}
			return keyvault.TopologyDigest(row, keyRef)
		}

		// 每一次解封都建一個**全新的** Vault 客戶端，且其認證材料只能來自請求本文
		// 送來的那一份（持有者）——拓撲來自資料庫，秘密來自這一次的解封。
		e.s1.delegatedProviderSource = func(ctx context.Context, o *credentialOwner) (crypto.KEKProvider, error) {
			s, serr := o.settings()
			if serr != nil {
				return nil, serr
			}
			if s.Vault.SecretID == "" && s.Vault.Token == "" {
				return nil, fmt.Errorf("世代持有者未收到 Vault 秘密")
			}
			// Scope 由部署位址與具名金鑰導出（與正式建構同一個 ResolveScope 結果）：
			// 少了它，建出的引用會落在本部署範圍之外而被解封閘擋下。
			c, cerr := vaultWizardHTTPClient(ctx, vaulttransit.Settings{
				Address: s.Vault.Address, RoleID: s.Vault.RoleID,
				SecretID: s.Vault.SecretID, Token: s.Vault.Token, KeyID: s.KeyID, Scope: scope,
			}, clientAddress, func(path string, status int) { j.step(t, "transit %s HTTP=%d", path, status) })
			if cerr != nil {
				return nil, cerr
			}
			t.Cleanup(c.Close)
			return c.Provider(ctx, s.KeyID)
		}

		cycle := func(label, material string) {
			t.Helper()
			// 封存：服務圖釋放，業務端點回 503。
			call("POST", "/api/v1/seal/seal", "{}")
			e.machine.WaitCleanup()
			if e.machine.Snapshot().Services != nil {
				t.Fatalf("services still published after seal (%s)", label)
			}
			if w := modeRequestMethod(t, e, "GET", "/api/v1/keys", "", token); w.Code != http.StatusServiceUnavailable {
				t.Fatalf("sealed business endpoint HTTP=%d (%s)", w.Code, label)
			}
			// 封存後憑證不可用：不重新提供秘密即解不開（鍵集不成立，整筆拒絕）。
			noSecret := sealGrantRequest(t, e, "POST", "/api/v1/seal/unseal",
				fmt.Sprintf(`{"topology_digest":%q}`, digest()))
			j.step(t, "handler POST /api/v1/seal/unseal without_secret HTTP=%d", noSecret.Code)
			if noSecret.Code == http.StatusOK || e.machine.Snapshot().Services != nil {
				t.Fatalf("unseal without a freshly supplied credential accepted (%s)", label)
			}
			// 重新提供憑證：帳密授權（sealGrantRequest 內先打 /seal/authorize）後送出。
			//
			// 上一步那次「不帶秘密」是一次真的失敗，會啟動解封退避——這裡等退避過去
			// 再送出。退避本身就是被驗的行為，不繞過它，只是把它等完。
			var w *httptest.ResponseRecorder
			for attempt := 0; attempt < 8; attempt++ {
				w = sealGrantRequest(t, e, "POST", "/api/v1/seal/unseal", material)
				if w.Code != http.StatusTooManyRequests {
					break
				}
				j.step(t, "unseal_backoff_wait attempt=%d HTTP=429", attempt+1)
				time.Sleep(1500 * time.Millisecond)
			}
			j.step(t, "handler POST /api/v1/seal/unseal credential=%s HTTP=%d", label, w.Code)
			if w.Code != http.StatusOK {
				t.Fatalf("delegated unseal HTTP=%d (%s)", w.Code, label)
			}
			graph, ok := e.machine.Snapshot().Services.(*appGraph)
			if !ok || graph == nil {
				t.Fatalf("service graph not rebuilt (%s)", label)
			}
			if got := graph.keyManager.KEKRef().Provider; got != crypto.KeyRefProviderVault {
				t.Fatalf("unsealed generation is not Vault-backed: %v (%s)", got, label)
			}
			if inv := call("GET", "/api/v1/keys", ""); inv["provider"] != "kms" {
				t.Fatalf("inventory provider %v after unseal (%s)", inv["provider"], label)
			}
			j.step(t, "unseal_cycle=%s state=unsealed kek_provider=vault key_ref=%s", label, id)
			sshSession(label)
		}

		// 其一：角色密鑰（AppRole SecretID），現場向真 Vault 換發一份新的。
		roleSecret := field(request("POST", "auth/approle/role/wave2c-transit/secret-id", struct{}{}), "secret_id")
		cycle("vault-role-secret-id", fmt.Sprintf(`{"vault_secret_id":%q,"topology_digest":%q}`, roleSecret, digest()))

		// 其二：直接權杖。向真 Vault 簽發一枚**具名政策**的權杖（Transit 政策
		// ＋ default，後者提供權杖自我查詢與續期）——AppRole 登入取回的權杖只帶
		// Transit 政策，`auth/token/lookup-self` 會 403，無法承載權杖路徑的租期語義。
		// 這正是「長壽命權杖非建議做法」那段文件所描述的形態：一枚人為簽發的權杖。
		login := request("POST", "auth/token/create", map[string]any{
			"policies": []string{"wave2c-transit", "default"}, "ttl": "30m", "renewable": true,
		})
		auth, ok := login["auth"].(map[string]any)
		if !ok {
			t.Fatal("AppRole login response missing auth")
		}
		clientToken, ok := auth["client_token"].(string)
		if !ok || clientToken == "" {
			t.Fatal("AppRole login returned no client token")
		}
		j.hide(clientToken)
		cycle("vault-direct-token", fmt.Sprintf(`{"vault_token":%q,"topology_digest":%q}`, clientToken, digest()))

		j.step(t, "seal_cycle=PASS custodian=vault real_transit=true cycles=2 paths=role-secret-id,direct-token")
		return
	}
	if scenario == "same-ref" {
		current.deps.keyManagement.SetDelegatedProviderFactory(func(ctx context.Context, mode, ref string) (crypto.KEKProvider, error) {
			o := generation()
			defer o.Close()
			return buildDelegatedRewrapProviderWithConstructors(ctx, mode, ref, o, func(ctx context.Context, s vaulttransit.Settings) (crypto.KEKProvider, error) {
				return restartedClient.Provider(ctx, s.KeyID)
			}, nil)
		})
		w := modeRequestMethod(t, e, "POST", "/api/v1/keys/rewrap", string(body), token)
		j.step(t, "handler POST /api/v1/keys/rewrap HTTP=%d", w.Code)
		if w.Code != 409 || !strings.Contains(w.Body.String(), "KEY_REWRAP_TARGET_CURRENT") {
			t.Fatal("same KeyRef not rejected")
		}
		j.step(t, "same_ref=PASS pending=false")
		return
	}
	if scenario == "outage" || scenario == "cold-start" {
		// Establish an actual keep-alive HTTP connection to the formal router.
		app := httptest.NewServer(e.swap)
		defer app.Close()
		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		probe := func(requireReused bool) {
			t.Helper()
			reused := false
			req, _ := http.NewRequest("GET", app.URL+"/api/v1/ping", nil)
			req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal("existing HTTP connection failed")
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			j.step(t, "handler GET /api/v1/ping HTTP=%d reused_connection=%t", resp.StatusCode, reused)
			if resp.StatusCode != 200 || (requireReused && !reused) {
				t.Fatal("existing HTTP connection unavailable")
			}
		}
		probe(false)
		j.step(t, "before_outage backend_log_synced=true real_vault_route=disconnect")
		proxy.CloseClientConnections()
		proxy.Close()
		if scenario == "outage" {
			probe(true)
			var beforeAudit, afterAudit int64
			if database.DB.Model(&model.AuditLog{}).Count(&beforeAudit).Error != nil {
				t.Fatal("audit count failed")
			}
			w := modeRequestMethod(t, e, "POST", "/api/v1/keys/rotate", `{"purpose":"data"}`, token)
			j.step(t, "handler POST /api/v1/keys/rotate HTTP=%d", w.Code)
			if w.Code != 500 {
				t.Fatal("Vault-required rotation did not fail")
			}
			if database.DB.Model(&model.AuditLog{}).Count(&afterAudit).Error != nil || afterAudit <= beforeAudit {
				t.Fatal("new outage audit not persisted")
			}
			fresh, err := current.keyManager.EncryptBytesFor(ctx, lifecycleProbeRef, []byte("outage-readable"))
			if err != nil {
				t.Fatal("cached encryption failed")
			}
			if plain, err := current.keyManager.DecryptFor(ctx, lifecycleProbeRef, fresh); err != nil || plain != "outage-readable" {
				t.Fatal("cached roundtrip failed")
			}
			if plain, err := current.keyManager.DecryptFor(ctx, lifecycleProbeRef, ciphertext); err != nil || plain != "vault-wizard-readable" {
				t.Fatal("old data unreadable during outage")
			}
			j.step(t, "outage=PASS existing_http_connection=true new_audit=true general_encrypt_decrypt=true vault_operation_rejected=true")
			return
		}
		j.step(t, "before_cold_start backend_log_synced=true")
		call("POST", "/api/v1/seal/seal", "{}")
		e.machine.WaitCleanup()
		// Fresh client construction against the disconnected real-Vault route.
		e.s1.delegatedProviderSource = func(ctx context.Context, o *credentialOwner) (crypto.KEKProvider, error) {
			settings, err := o.settings()
			if err != nil {
				return nil, err
			}
			c, cerr := vaultWizardHTTPClient(ctx, vaulttransit.Settings{
				Address: settings.Vault.Address, RoleID: settings.Vault.RoleID,
				SecretID: settings.Vault.SecretID, KeyID: settings.KeyID,
			}, clientAddress, func(path string, status int) { j.step(t, "transit %s HTTP=%d", path, status) })
			if cerr != nil {
				return nil, cerr
			}
			defer c.Close()
			return c.Provider(ctx, settings.KeyID)
		}
		w := sealGrantRequest(t, e, "POST", "/api/v1/seal/unseal", delegatedUnsealBody(t, "vault"))
		j.step(t, "handler POST /api/v1/seal/unseal HTTP=%d", w.Code)
		if w.Code == 200 || e.machine.Snapshot().Services != nil {
			t.Fatal("unavailable cold start accepted")
		}
		j.step(t, "cold_start=PASS unseal_rejected=true services_absent=true")
		return
	}
	if scenario == "backup" {
		vaultBackupRecovery(t, j, e, token, id, scope.Origin(), ciphertext, newClient, generation)
		return
	}
	j.step(t, "wizard=PASS")
}

// Only the second transactional wrap is fault-injected. Preflight and the first
// wrap use real AppRole / Transit, and the ordinary handler owns the transaction.
type vaultSecondWrapFailure struct {
	crypto.KEKProvider
	calls int
}

func (p *vaultSecondWrapFailure) Wrap(ctx context.Context, plain, aad []byte) ([]byte, error) {
	p.calls++
	if p.calls == 2 {
		return nil, fmt.Errorf("injected second row wrap failure")
	}
	return p.KEKProvider.Wrap(ctx, plain, aad)
}

// Restores a complete isolated SQLite assembly backup (all DB tables, the seal
// journal, and configuration). This is not a PostgreSQL pg_dump/tar deployment
// rehearsal, and deliberately makes no assertion about image/schema upgrades.
func vaultBackupRecovery(t *testing.T, j *vaultWizardJournal, e *sealIntegrationEnv, token, id, origin, ciphertext string, newClient func() *vaulttransit.Client, generation func() *credentialOwner) {
	t.Helper()
	ctx := context.Background()
	call := func(env *sealIntegrationEnv, method, path, body string) {
		t.Helper()
		w := sealGrantRequest(t, env, method, path, body)
		if path != "/api/v1/seal/unseal" {
			w = modeRequestMethod(t, env, method, path, body, token)
		}
		j.step(t, "handler %s %s HTTP=%d", method, path, w.Code)
		if w.Code != 200 {
			t.Fatal("backup lifecycle handler failed")
		}
	}
	sourceDB := database.DB
	var dbFiles []struct {
		Name string
		File string
	}
	if sourceDB.Raw("PRAGMA database_list").Scan(&dbFiles).Error != nil {
		t.Fatal("database path unavailable")
	}
	var dbPath string
	for _, f := range dbFiles {
		if f.Name == "main" {
			dbPath = f.File
		}
	}
	if dbPath == "" {
		t.Fatal("file-backed database required")
	}
	// The existing fixture creates its DB and journal in sibling t.TempDir paths.
	var journalPath string
	err := filepath.WalkDir(filepath.Dir(filepath.Dir(dbPath)), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == "seal_journal.bin" {
			if journalPath != "" {
				return fmt.Errorf("ambiguous journal")
			}
			journalPath = path
		}
		return nil
	})
	if err != nil || journalPath == "" {
		t.Fatal("backup journal scope unresolved")
	}
	backupDir := t.TempDir()
	copyFile := func(from, to string) {
		t.Helper()
		raw, err := os.ReadFile(from)
		if err != nil {
			t.Fatal("backup read failed")
		}
		defer clear(raw)
		if os.WriteFile(to, raw, 0600) != nil {
			t.Fatal("backup write failed")
		}
		f, err := os.OpenFile(to, os.O_RDWR, 0600)
		if err != nil {
			t.Fatal("backup sync open failed")
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			t.Fatal("backup sync failed")
		}
		check, err := os.ReadFile(to)
		if err != nil || !bytes.Equal(raw, check) {
			clear(check)
			t.Fatal("backup copy differs")
		}
		clear(check)
	}
	j.step(t, "backup_step=freeze backend_log_synced=true")
	call(e, "POST", "/api/v1/seal/seal", "{}")
	e.machine.WaitCleanup()
	if e.s1.journal.Close() != nil {
		t.Fatal("cannot quiesce journal")
	}
	point := time.Now().UTC().Format(time.RFC3339Nano)
	snapshot := filepath.Join(backupDir, "database.sqlite")
	if sourceDB.Exec("VACUUM INTO ?", snapshot).Error != nil {
		t.Fatal("whole database snapshot failed")
	}
	copyFile(journalPath, filepath.Join(backupDir, "seal_journal.bin"))
	raw, err := json.Marshal(e.s1.cfg)
	if err != nil {
		t.Fatal("configuration snapshot failed")
	}
	if os.WriteFile(filepath.Join(backupDir, "config.json"), raw, 0600) != nil {
		t.Fatal("configuration backup failed")
	}
	clear(raw)
	cfgFile, err := os.OpenFile(filepath.Join(backupDir, "config.json"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal("config backup sync open failed")
	}
	err = cfgFile.Sync()
	cfgFile.Close()
	if err != nil {
		t.Fatal("config backup sync failed")
	}
	var keys []model.DataKey
	var auditCount int64
	if sourceDB.Order("id").Find(&keys).Error != nil || sourceDB.Model(&model.AuditLog{}).Count(&auditCount).Error != nil {
		t.Fatal("backup inventory failed")
	}
	var schema string
	if sourceDB.Raw("SELECT group_concat(sql, ';') FROM (SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type,name)").Scan(&schema).Error != nil {
		t.Fatal("schema signature unavailable")
	}
	schemaHash := sha256.Sum256([]byte(schema))
	binaryPath, err := os.Executable()
	if err != nil {
		t.Fatal("binary identity unavailable")
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal("binary hash unavailable")
	}
	binaryHash := sha256.Sum256(binary)
	j.step(t, "backup_step=captured point=%s mode=kms provider=vault key_ref=%s rows=%d audit_rows=%d toolchain=%s binary_sha256=%x schema_sha256=%x", point, id, len(keys), auditCount, runtime.Version(), binaryHash, schemaHash)
	versions := map[string]bool{}
	for _, row := range keys {
		if row.KEKRetiredAt != nil {
			continue
		}
		_, wrapped, err := crypto.ParseWrappedKey(row.WrappedKey)
		if err != nil {
			t.Fatal("backup version parse failed")
		}
		parts := strings.SplitN(string(wrapped), ":", 3)
		if len(parts) != 3 || parts[0] != "vault" {
			t.Fatal("backup version absent")
		}
		versions[parts[1]] = true
	}
	versionList := make([]string, 0, len(versions))
	for version := range versions {
		versionList = append(versionList, version)
	}
	sort.Strings(versionList)
	j.step(t, "backup_scope=whole_sqlite_database,seal_journal,configuration recordings=none external_storage=none credential_custody=fresh_approle origin=%s required_remote_versions=%s", origin, strings.Join(versionList, ","))
	// Fresh stage-one machine/router, never editing or reviving data_keys rows.
	assemble := func(dir string, db *gorm.DB) *sealIntegrationEnv {
		t.Helper()
		database.DB = db
		cfgRaw, err := os.ReadFile(filepath.Join(backupDir, "config.json"))
		if err != nil {
			t.Fatal("configuration recovery failed")
		}
		defer clear(cfgRaw)
		var cfg config.Config
		if json.Unmarshal(cfgRaw, &cfg) != nil {
			t.Fatal("configuration decode failed")
		}
		journal, err := sealjournal.Open(dir, sealjournal.WithCapacity(64, 64), sealjournal.WithMinAdmissionInterval(0))
		if err != nil {
			t.Fatal("journal recovery failed")
		}
		t.Cleanup(func() { journal.Close() })
		decision := &config.KEKDecision{Mode: config.KEKModeKMS}
		decision.KMS.Provider = vaulttransit.ProviderVault
		env := &sealIntegrationEnv{s1: &stage1{cfg: &cfg, kekDecision: decision, initialKEKRef: crypto.KeyRef{Provider: crypto.KeyRefProviderVault, KeyID: id}, corsMiddleware: e.s1.corsMiddleware, journal: journal, metrics: observability.New()}, swap: &swappableHandler{}}
		client := newClient()
		// 委託解封的接縫（見 TestVaultColdStartE2E 的說明）：還原後的實例同樣
		// 要由操作者提供憑證，接縫收的是已 adopt 憑證的世代持有者。
		env.s1.delegatedProviderSource = func(ctx context.Context, o *credentialOwner) (crypto.KEKProvider, error) {
			settings, err := o.settings()
			if err != nil {
				return nil, err
			}
			if settings.Vault.SecretID == "" && settings.Vault.Token == "" {
				return nil, fmt.Errorf("世代持有者未收到 Vault 秘密")
			}
			return client.Provider(ctx, settings.KeyID)
		}
		wiring, err := newSealMachine(env.s1, env.swap)
		if err != nil {
			t.Fatal("recovered machine failed")
		}
		env.wiring = wiring
		env.machine = wiring.machine
		env.handler = wiring.main
		env.handler.SetAuthorizer(config.KEKModeKMS, identity.NewSealAuthorizer(cfg.Security.JWTSecret, db).Authorize)
		r := newStageOneTestEngine(t, env.s1)
		registerRoutes(r, sealedStageOneDeps(stageOneRouteConfig{corsMiddleware: env.s1.corsMiddleware, metrics: env.s1.metrics}, wiring.main))
		env.engine = r
		env.swap.Set(r)
		t.Cleanup(func() {
			if snap := env.machine.Snapshot(); snap.Services != nil {
				snap.Services.Release(ctx)
			}
			env.machine.WaitCleanup()
		})
		return env
	}
	continued := assemble(filepath.Dir(journalPath), sourceDB)
	call(continued, "POST", "/api/v1/seal/unseal", delegatedUnsealBody(t, "vault"))
	laterGraph := continued.machine.Snapshot().Services.(*appGraph)
	later, err := laterGraph.keyManager.EncryptBytesFor(ctx, lifecycleProbeRef, []byte("after-backup"))
	if err != nil {
		t.Fatal("post-backup encryption failed")
	}
	if sourceDB.Exec("INSERT INTO vault_wizard_payload VALUES(2,?)", later).Error != nil {
		t.Fatal("post-backup write failed")
	}
	j.step(t, "backup_step=post_point_write committed_rows=1")
	j.step(t, "before_restore backend_log_synced=true writes=freeze")
	call(continued, "POST", "/api/v1/seal/seal", "{}")
	continued.machine.WaitCleanup()
	if continued.s1.journal.Close() != nil {
		t.Fatal("preserve current journal failed")
	}
	if sourceDB.Exec("VACUUM INTO ?", filepath.Join(backupDir, "pre-restore-evidence.sqlite")).Error != nil {
		t.Fatal("preserve current DB failed")
	}
	copyFile(journalPath, filepath.Join(backupDir, "pre-restore-journal.bin"))
	j.step(t, "backup_step=preserved_current db_and_journal=true")
	restoreDir := t.TempDir()
	copyFile(snapshot, filepath.Join(restoreDir, "database.sqlite"))
	copyFile(filepath.Join(backupDir, "seal_journal.bin"), filepath.Join(restoreDir, "seal_journal.bin"))
	restoredDB, err := gorm.Open(sqlite.Open(filepath.Join(restoreDir, "database.sqlite")), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal("restored database open failed")
	}
	sqlDB, err := restoredDB.DB()
	if err != nil {
		t.Fatal("restored pool failed")
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { database.DB = sourceDB; sqlDB.Close() })
	var restoredKeys []model.DataKey
	var restoredAudit int64
	var restoredSchema string
	if restoredDB.Order("id").Find(&restoredKeys).Error != nil || !reflect.DeepEqual(keys, restoredKeys) {
		t.Fatal("restored key rows differ from whole backup")
	}
	if restoredDB.Model(&model.AuditLog{}).Count(&restoredAudit).Error != nil || restoredAudit != auditCount {
		t.Fatal("restored audit differs")
	}
	if restoredDB.Raw("SELECT group_concat(sql, ';') FROM (SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type,name)").Scan(&restoredSchema).Error != nil || restoredSchema != schema {
		t.Fatal("incompatible schema")
	}
	var laterCount int64
	if restoredDB.Table("vault_wizard_payload").Where("id = 2").Count(&laterCount).Error != nil || laterCount != 0 {
		t.Fatal("backup loss boundary incorrect")
	}
	j.step(t, "backup_step=restore_verified whole_db=true rows_equal=true audit_equal=true journal_bytes_equal=true schema_equal=true same_binary=true post_point_rows_absent=1")
	recovered := assemble(restoreDir, restoredDB)
	call(recovered, "POST", "/api/v1/seal/unseal", delegatedUnsealBody(t, "vault"))
	graph := recovered.machine.Snapshot().Services.(*appGraph)
	var stored string
	if restoredDB.Raw("SELECT ciphertext FROM vault_wizard_payload WHERE id=1").Scan(&stored).Error != nil || stored != ciphertext {
		t.Fatal("restored ciphertext differs")
	}
	if plain, err := graph.keyManager.DecryptFor(ctx, lifecycleProbeRef, stored); err != nil || plain != "vault-wizard-readable" {
		t.Fatal("restored data unreadable")
	}
	w := modeRequestMethod(t, recovered, "GET", "/api/v1/keys", "", token)
	j.step(t, "handler GET /api/v1/keys HTTP=%d", w.Code)
	var inventory map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &inventory) != nil || inventory["provider"] != "kms" || inventory["key_ref"] != recovered.s1.initialKEKRef.String() || inventory["rewrap_pending"] != false {
		t.Fatal("restored inventory differs")
	}
	// Verify every live row with a new real AppRole provider independently of cache.
	verifier := newClient()
	provider, err := verifier.Provider(ctx, id)
	if err != nil {
		t.Fatal("restore preflight failed")
	}
	liveRows := 0
	for _, row := range restoredKeys {
		if row.KEKRetiredAt != nil {
			continue
		}
		_, wrapped, err := crypto.ParseWrappedKey(row.WrappedKey)
		if err != nil {
			t.Fatal("restore wrap invalid")
		}
		plain, err := provider.Unwrap(ctx, wrapped, crypto.DEKAAD(row.Purpose, row.Version))
		if err != nil {
			t.Fatal("restore unwrap failed")
		}
		clear(plain)
		liveRows++
	}
	if liveRows == 0 {
		t.Fatal("restore has no live rows")
	}
	j.step(t, "backup_recovery=PASS point=%s all_live_rows_unwrapped=%d ciphertext_unchanged=true readable=true inventory=kms/vault retired_rows_not_revived=true lost_post_point_rows=1 compatibility=same_binary_same_schema", point, liveRows)
	j.step(t, "before_recovery_cleanup backend_log_synced=true")
}
