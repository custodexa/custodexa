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
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestDelegatedSealRestoreHTTP(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvKMSEndpoint)
	e, token, _ := modeFixture(t, "env")
	e.s1.kekOwner.Destroy()
	e.s1.kekOwner = nil
	e.s1.kekProvider = nil
	e.s1.kekDecision.Mode = config.KEKModeKMS
	e.handler.SetAuthorizer(config.KEKModeKMS, identity.NewSealAuthorizer(e.s1.cfg.Security.JWTSecret, database.DB).Authorize)
	target, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal("invalid KMS target URL")
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var unwraps atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") == "TrentService.Decrypt" {
			unwraps.Add(1)
		}
		proxy.ServeHTTP(w, r)
	})
	remote := httptest.NewServer(handler)
	defer func() { remote.Close() }()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-1"), awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	if err != nil {
		t.Fatal("SDK config failed")
	}
	makeClient := func() *awskms.Client {
		return awskms.NewFromConfig(cfg, func(o *awskms.Options) { endpoint := remote.URL; o.BaseEndpoint = &endpoint; o.RetryMaxAttempts = 1 })
	}
	created, err := makeClient().CreateKey(context.Background(), &awskms.CreateKeyInput{})
	if err != nil {
		t.Fatal("localstack key creation failed")
	}
	key := *created.KeyMetadata.Arn
	source := func(ctx context.Context) (crypto.KEKProvider, *material.Secret, error) {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		p, err := kmsprovider.New(ctx, kmsprovider.Settings{Provider: kmsprovider.ProviderAWS, Region: "us-east-1", KeyID: key, Client: makeClient()})
		if err != nil {
			return nil, nil, err
		}
		return p, nil, nil
	}
	e.s1.deploymentSource = source
	p, _, err := source(context.Background())
	if err != nil {
		t.Fatal("remote KEK unavailable")
	}
	e.s1.kekProvider = p
	e.s1.initialKEKRef = p.KeyRef()
	app := httptest.NewServer(e.swap)
	defer app.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	request := func(path string, want int) {
		t.Helper()
		r, err := restoreHTTP(client, app.URL+path, "POST", "{}", token)
		if err != nil || r.status != want {
			t.Fatalf("HTTP=%d expected=%d transport_error=%v", r.status, want, err != nil)
		}
	}
	request("/api/v1/seal/unseal", 200)
	g := e.machine.Snapshot().Services.(*appGraph)
	cipher, err := g.keyManager.EncryptBytesFor(context.Background(), lifecycleProbeRef, []byte("remote-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	remote.Close()
	owner, err := g.keyManager.DecryptBytesFor(context.Background(), lifecycleProbeRef, cipher)
	if err != nil {
		t.Fatal("unsealed remote outage lost cached DEK")
	}
	owner.Destroy()
	request("/api/v1/seal/seal", 200)
	request("/api/v1/seal/unseal", 400)
	if e.machine.Snapshot().State != seal.StateSealed {
		t.Fatal("remote outage did not remain sealed")
	}
	if _, err = g.keyManager.DecryptBytesFor(context.Background(), lifecycleProbeRef, cipher); err == nil {
		t.Fatal("old graph fallback")
	}
	remote = httptest.NewServer(handler)
	before := unwraps.Load()
	time.Sleep(1100 * time.Millisecond)
	request("/api/v1/seal/unseal", 200)
	after := unwraps.Load()
	if after <= before {
		t.Fatal("no remote unwrap on restore")
	}
	owner, err = e.machine.Snapshot().Services.(*appGraph).keyManager.DecryptBytesFor(context.Background(), lifecycleProbeRef, cipher)
	if err != nil {
		t.Fatal("same ciphertext unreadable after remote restore")
	}
	defer owner.Destroy()
	if err = owner.Borrow(func(raw []byte) error {
		if string(raw) != "remote-fixture" {
			return fmt.Errorf("plaintext changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("EVIDENCE delegated-seal-restore transport=TCP_HTTP driver=AWS remote=localstack outgoing_unwrap=%d,%d no_KEK_input=true outage_unsealed_cache=usable outage_restore=400 state=sealed old_graph=rejected restored=200 original_ciphertext=readable", before, after)
}
