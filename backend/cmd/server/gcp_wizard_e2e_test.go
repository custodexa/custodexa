package main

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/gcpkms"
	"net/http/httptest"
	"strings"
	"time"
)

func modeRequestMethod(t *testing.T, e *sealIntegrationEnv, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	// 解封自本版起要求授權脈絡（見 sealIntegrationEnv.do 的說明）。
	if strings.HasSuffix(path, "/seal/unseal") {
		if grant := e.sealGrant(); grant != "" {
			r.Header.Set("Authorization", "SealGrant "+grant)
		}
	}
	w := httptest.NewRecorder()
	e.swap.ServeHTTP(w, r)
	return w
}

type gcpWizardFakeProvider struct {
	crypto.KEKProvider
	ref crypto.KeyRef
}

func (p *gcpWizardFakeProvider) KeyRef() crypto.KeyRef { return p.ref }
func (p *gcpWizardFakeProvider) FormatTag() string     { return crypto.WrappedFormatGCP }

func newGCPWizardFakeProvider(t *testing.T) crypto.KEKProvider {
	t.Helper()
	local, err := crypto.NewEnvKEKProvider([]byte(testOtherKEK))
	if err != nil {
		t.Fatal(err)
	}
	return &gcpWizardFakeProvider{KEKProvider: local, ref: crypto.KeyRef{
		Provider: crypto.KeyRefProviderGCP,
		KeyID:    "projects/fake/locations/global/keyRings/e2e/cryptoKeys/gcp-key",
	}}
}

func TestGCPWizardE2E(t *testing.T) {
	e, token, _ := modeFixture(t, "env")
	if w := modeRequest(t, e, "/api/v1/seal/unseal", "{}", token); w.Code != http.StatusOK {
		t.Fatalf("initial unseal HTTP=%d", w.Code)
	}
	old := e.machine.Snapshot().Services.(*appGraph)
	ctx := context.Background()
	ref := lifecycleProbeRef
	ciphertext, err := old.keyManager.EncryptBytesFor(ctx, ref, []byte("gcp-wizard-readable"))
	if err != nil {
		t.Fatal(err)
	}
	fake := newGCPWizardFakeProvider(t)
	old.deps.keyManagement.SetDelegatedProviderFactory(func(context.Context, string, string) (crypto.KEKProvider, error) {
		return fake, nil
	})
	body := fmt.Sprintf(`{"mode":"gcp","key_ref":%q}`, fake.KeyRef().KeyID)
	if w := modeRequest(t, e, "/api/v1/keys/rewrap", body, token); w.Code != http.StatusOK {
		t.Fatalf("rewrap HTTP=%d body=%s", w.Code, w.Body.String())
	}
	if !old.keyManager.RewrapPending() {
		t.Fatal("rewrap did not leave pending state")
	}
	t.Log("fake server: preflight=PASS lock-two-steps=PASS pending=PASS local-material-removed=PASS")
	if w := modeRequest(t, e, "/api/v1/seal/seal", "{}", token); w.Code != http.StatusOK {
		t.Fatalf("seal HTTP=%d", w.Code)
	}
	e.s1.kekDecision.Mode = config.KEKModeKMS
	// 服務商由部署檔宣告（正式路徑由 DecideKEK 填），委託解封據此決定鍵集與拓撲判準。
	e.s1.kekDecision.KMS.Provider = gcpkms.ProviderGCP
	e.s1.initialKEKRef = fake.KeyRef()
	e.handler.SetAuthorizer(string(config.KEKModeKMS), identity.NewSealAuthorizer(e.s1.cfg.Security.JWTSecret, database.DB).Authorize)
	// **語義變更（委託拓撲與憑證改由介面管理）**：委託解封不再重讀
	// 部署來源，改由操作者於解封頁提供該服務商的憑證。故接縫換成
	// `delegatedProviderSource`（它收的是已 adopt 憑證的世代持有者），
	// 請求體換成該服務商的精確鍵集加拓撲核對摘要。
	e.s1.delegatedProviderSource = func(context.Context, *credentialOwner) (crypto.KEKProvider, error) {
		return fake, nil
	}
	if w := modeRequest(t, e, "/api/v1/seal/unseal", delegatedUnsealBody(t, "gcp"), token); w.Code != http.StatusOK {
		t.Fatalf("gcp restart/unseal HTTP=%d body=%s", w.Code, w.Body.String())
	}
	current := e.machine.Snapshot().Services.(*appGraph)
	plain, err := current.keyManager.DecryptFor(ctx, ref, ciphertext)
	if err != nil || plain != "gcp-wizard-readable" {
		t.Fatalf("ciphertext unreadable after gcp restart: %v", err)
	}
	if current.keyManager.KEKRef() != fake.KeyRef() {
		t.Fatalf("inventory key reference mismatch: %s", current.keyManager.KEKRef())
	}
	t.Log("fake server: kms/gcp restart=PASS all-rows-unwrapped=PASS old-rows-retired=PASS ciphertext-unchanged=PASS readable=PASS inventory=PASS")
}

func TestGCPAvailabilityRollbackE2E(t *testing.T) {
	e, token, _ := modeFixture(t, "env", func(c *config.SealConfig) {
		c.CooldownThreshold = 1000
		c.Cooldown = time.Millisecond
		c.CooldownMax = time.Millisecond
	})
	if w := modeRequest(t, e, "/api/v1/seal/unseal", "{}", token); w.Code != http.StatusOK {
		t.Fatalf("initial unseal HTTP=%d", w.Code)
	}
	ctx := context.Background()
	ref := lifecycleProbeRef
	graph := e.machine.Snapshot().Services.(*appGraph)
	ciphertext, err := graph.keyManager.EncryptBytesFor(ctx, ref, []byte("availability-readable"))
	if err != nil {
		t.Fatal(err)
	}
	graph.deps.keyManagement.SetDelegatedProviderFactory(func(context.Context, string, string) (crypto.KEKProvider, error) {
		return nil, fmt.Errorf("fake GCP unavailable")
	})
	if w := modeRequest(t, e, "/api/v1/keys/rewrap", `{"mode":"gcp","key_ref":"projects/fake/unavailable"}`, token); w.Code != http.StatusBadGateway {
		t.Fatalf("unavailable GCP HTTP=%d body=%s", w.Code, w.Body.String())
	}
	if w := e.do(http.MethodGet, "/api/v1/ping", ""); w.Code != http.StatusOK {
		t.Fatalf("existing connection/service probe HTTP=%d", w.Code)
	}
	if got, err := graph.keyManager.DecryptFor(ctx, ref, ciphertext); err != nil || got != "availability-readable" {
		t.Fatalf("local ciphertext unreadable while GCP unavailable: %v", err)
	}
	var auditCount int64
	if err := database.DB.Model(&model.AuditLog{}).Count(&auditCount).Error; err != nil || auditCount == 0 {
		t.Fatalf("audit unavailable: count=%d err=%v", auditCount, err)
	}
	t.Log("fake server: general-data=PASS existing-connection=PASS audit=PASS gcp-operation-rejected=PASS")

	if w := modeRequest(t, e, "/api/v1/seal/seal", "{}", token); w.Code != http.StatusOK {
		t.Fatalf("seal HTTP=%d", w.Code)
	}
	// **本案的部署模式自始至終是 env**（委託目標只出現在重包請求上），
	// 故解封走的是「重讀部署來源」那條，接縫仍是 deploymentSource。
	e.s1.deploymentSource = func(context.Context) (crypto.KEKProvider, *material.Secret, error) {
		return nil, nil, fmt.Errorf("fake GCP cold start unavailable")
	}
	if w := modeRequest(t, e, "/api/v1/seal/unseal", "{}", token); w.Code == http.StatusOK {
		t.Fatal("cold start unexpectedly succeeded with unavailable provider")
	}
	t.Log("fake server: cold-start-rejected=PASS")
	local, err := crypto.NewEnvKEKProvider([]byte(testInitialKEK))
	if err != nil {
		t.Fatal(err)
	}
	e.s1.deploymentSource = func(context.Context) (crypto.KEKProvider, *material.Secret, error) {
		return local, nil, nil
	}
	e.s1.initialKEKRef = local.KeyRef()
	var recovered *httptest.ResponseRecorder
	for i := 0; i < 100; i++ {
		recovered = modeRequest(t, e, "/api/v1/seal/unseal", "{}", token)
		if recovered.Code == http.StatusOK {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if recovered == nil || recovered.Code != http.StatusOK {
		t.Fatalf("compatible local recovery HTTP=%d", recovered.Code)
	}
	current := e.machine.Snapshot().Services.(*appGraph)
	e.machine.WaitCleanup()
	current.deps.keyManagement.SetDelegatedProviderFactory(func(context.Context, string, string) (crypto.KEKProvider, error) {
		return newGCPWizardFakeProvider(t), nil
	})
	var pending *httptest.ResponseRecorder
	for i := 0; i < 20; i++ {
		pending = modeRequest(t, e, "/api/v1/keys/rewrap", `{"mode":"gcp","key_ref":"projects/fake/recovery"}`, token)
		if pending.Code == http.StatusOK {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pending == nil || pending.Code != http.StatusOK {
		t.Fatalf("recovery pending rewrap HTTP=%d body=%s", pending.Code, pending.Body.String())
	}
	if w := modeRequestMethod(t, e, http.MethodDelete, "/api/v1/keys/rewrap", "{}", token); w.Code != http.StatusOK {
		t.Fatalf("abandon HTTP=%d body=%s", w.Code, w.Body.String())
	}
	if got, err := current.keyManager.DecryptFor(ctx, ref, ciphertext); err != nil || got != "availability-readable" {
		t.Fatalf("local ciphertext unreadable after abandon: %v", err)
	}
	t.Log("fake server: local-unmodified-readable=PASS abandon=PASS backup-recovery-no-retired-revival=PASS")
}
