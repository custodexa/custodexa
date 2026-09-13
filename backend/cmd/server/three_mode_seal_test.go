package main

import (
	"context"
	"fmt"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/custodexa/backend/pkg/crypto"
	kmsprovider "github.com/custodexa/backend/pkg/crypto/kms"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func modeRequest(t *testing.T, e *sealIntegrationEnv, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	// 解封自本版起要求授權脈絡（見 sealIntegrationEnv.do 的說明）。
	// **覆寫 Bearer 而非並存**：兩者是不同的授權語義，解封端點只認前者；
	// 封存（`/seal/seal`）仍走 Bearer，故只在解封路徑上替換。
	if strings.HasSuffix(path, "/seal/unseal") {
		if grant := e.sealGrant(); grant != "" {
			r.Header.Set("Authorization", "SealGrant "+grant)
		}
	}
	w := httptest.NewRecorder()
	e.swap.ServeHTTP(w, r)
	return w
}
func modeFixture(t *testing.T, mode string, opts ...func(*config.SealConfig)) (*sealIntegrationEnv, string, *int) {
	t.Helper()
	var endpoint string
	if mode == "delegated" {
		endpoint = testgate.Value(t, testgate.EnvKMSEndpoint)
	}
	e := newSealIntegrationEnv(t, opts...)
	reads := new(int)
	if mode != "ui" {
		e.s1.kekDecision.Mode = config.KEKModeEnv
		source := func(ctx context.Context) (crypto.KEKProvider, *material.Secret, error) {
			*reads++
			return buildOwnedKEKProvider(ctx, &config.KEKDecision{Mode: config.KEKModeEnv, Material: testInitialKEK})
		}
		if mode == "delegated" {
			e.s1.kekDecision.Mode = config.KEKModeKMS
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"), awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
			if err != nil {
				t.Fatal("KMS client setup failed")
			}
			client := awskms.NewFromConfig(cfg, func(o *awskms.Options) { o.BaseEndpoint = &endpoint })
			key, err := client.CreateKey(ctx, &awskms.CreateKeyInput{})
			if err != nil {
				t.Fatal("localstack CreateKey failed")
			}
			source = func(ctx context.Context) (crypto.KEKProvider, *material.Secret, error) {
				*reads++
				p, err := kmsprovider.New(ctx, kmsprovider.Settings{Provider: kmsprovider.ProviderAWS, KeyID: *key.KeyMetadata.Arn, Region: "us-east-1", Client: client})
				if err != nil {
					return nil, nil, err
				}
				return p, nil, nil
			}
		}
		e.s1.deploymentSource = source
		p, owner, err := source(context.Background())
		if err != nil {
			t.Fatal("deployment source failed")
		}
		e.s1.kekProvider = p
		e.s1.kekOwner = owner
		e.s1.initialKEKRef = p.KeyRef()
		e.handler.SetAuthorizer(string(e.s1.kekDecision.Mode), identity.NewSealAuthorizer(e.s1.cfg.Security.JWTSecret, database.DB).Authorize)
	}
	token, err := crypto.NewJWTManager(e.s1.cfg.Security.JWTSecret, time.Hour).GenerateToken(1, testAdminUser, "", "admin", crypto.AuthContext{})
	if err != nil {
		t.Fatal("token fixture failed")
	}
	return e, token, reads
}

func TestThreeModeSealAssembly(t *testing.T) {
	for _, mode := range []string{"ui", "env", "delegated"} {
		t.Run(mode, func(t *testing.T) {
			e, token, reads := modeFixture(t, mode)
			payload := initPayload(testInitialKEK)
			if mode != "ui" {
				payload = "{}"
			}
			w := modeRequest(t, e, "/api/v1/seal/unseal", payload, token)
			if w.Code != 200 {
				t.Fatalf("initial unseal HTTP=%d", w.Code)
			}
			old := e.machine.Snapshot()
			g := old.Services.(*appGraph)
			cipher, err := g.keyManager.EncryptBytesFor(context.Background(), lifecycleProbeRef, []byte("round-trip-fixture"))
			if err != nil {
				t.Fatal(err)
			}
			w = modeRequest(t, e, "/api/v1/seal/seal", "{}", token)
			if w.Code != 200 {
				t.Fatalf("seal HTTP=%d state=%s cleanup=%v", w.Code, e.machine.Snapshot().State, e.machine.Snapshot().CleanupPending)
			}
			if e.machine.Snapshot().State != seal.StateSealed {
				t.Fatal("seal did not withdraw services")
			}
			if plain, err := g.keyManager.DecryptFor(context.Background(), lifecycleProbeRef, cipher); err == nil || plain != "" {
				t.Fatal("old codec usable")
			}
			before := *reads
			payload = fmt.Sprintf(`{"kek":%q}`, testInitialKEK)
			if mode != "ui" {
				payload = "{}"
			}
			w = modeRequest(t, e, "/api/v1/seal/unseal", payload, token)
			if w.Code != 200 {
				t.Fatalf("restore HTTP=%d state=%s", w.Code, e.machine.Snapshot().State)
			}
			next := e.machine.Snapshot()
			if next.Generation <= old.Generation || next.Services == old.Services {
				t.Fatal("generation or graph reused")
			}
			if mode != "ui" && *reads <= before {
				t.Fatal("deployment source not reread")
			}
			owner, err := next.Services.(*appGraph).keyManager.DecryptBytesFor(context.Background(), lifecycleProbeRef, cipher)
			if err != nil {
				t.Fatal("original ciphertext unreadable")
			}
			defer owner.Destroy()
			if err = owner.Borrow(func(raw []byte) error {
				if string(raw) != "round-trip-fixture" {
					return fmt.Errorf("plaintext changed")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			t.Logf("mode=%s sealed->unsealed generation=%d->%d source_reads=%d old_codec=rejected original_ciphertext=readable", mode, old.Generation, next.Generation, *reads)
		})
	}
}
func TestThreeModeJournalRequired(t *testing.T) {
	for _, mode := range []string{config.KEKModeUI, config.KEKModeEnv, config.KEKModeKMS} {
		t.Run(string(mode), func(t *testing.T) {
			e := newSealIntegrationEnv(t)
			e.s1.kekDecision.Mode = mode
			e.s1.journal = nil
			if _, err := newSealMachine(e.s1, e.swap); err == nil {
				t.Fatal("missing journal accepted")
			}
			t.Log("missing journal rejected before publication")
		})
	}
}
func TestModeACSealRestore(t *testing.T) {
	for _, mode := range []string{"env", "delegated"} {
		t.Run(mode, func(t *testing.T) {
			e, token, _ := modeFixture(t, mode)
			if w := modeRequest(t, e, "/api/v1/seal/unseal", "{}", token); w.Code != 200 {
				t.Fatalf("startup HTTP=%d", w.Code)
			}
			if w := modeRequest(t, e, "/api/v1/seal/seal", "{}", token); w.Code != 200 {
				t.Fatalf("seal HTTP=%d", w.Code)
			}
			source := e.s1.deploymentSource
			e.s1.deploymentSource = func(context.Context) (crypto.KEKProvider, *material.Secret, error) {
				return nil, nil, fmt.Errorf("source unavailable")
			}
			if w := modeRequest(t, e, "/api/v1/seal/unseal", "{}", token); w.Code == 200 {
				t.Fatal("failed source restored")
			}
			if e.machine.Snapshot().State != seal.StateSealed {
				t.Fatal("source failure changed state")
			}
			e.s1.deploymentSource = source
			t.Log("restore source failure kept process and sealed state")
		})
	}
}
func TestUnsealedRejectsWithoutRerunningInit(t *testing.T) {
	e, token, reads := modeFixture(t, "env")
	if w := modeRequest(t, e, "/api/v1/seal/unseal", "{}", token); w.Code != 200 {
		t.Fatalf("initial HTTP=%d", w.Code)
	}
	before := *reads
	if w := modeRequest(t, e, "/api/v1/seal/unseal", "{}", token); w.Code != 409 {
		t.Fatalf("repeat HTTP=%d", w.Code)
	}
	if *reads != before {
		t.Fatal("unsealed reran source")
	}
	t.Log("already-unsealed request rejected before source access")
}
