package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/gcpkms"
	kmskek "github.com/custodexa/backend/pkg/crypto/kms"
)

const gcpFactoryKey = "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/current"

// This fixture exercises constructor dispatch, not remote cryptographic behavior.
type gcpFactoryFixture struct {
	crypto.KEKProvider
	ref          crypto.KeyRef
	mode, format string
}

func (p *gcpFactoryFixture) KeyRef() crypto.KeyRef { return p.ref }
func (p *gcpFactoryFixture) Mode() string          { return p.mode }
func (p *gcpFactoryFixture) FormatTag() string     { return p.format }

// gcpFactoryServiceAccount 本解封世代持有的服務帳號金鑰檔（解封時輸入）。
const gcpFactoryServiceAccount = `{"type":"service_account","private_key":"gcp-credential-fixture-value"}`

// gcpFixtureSettings 委託部署的 GCP 拓撲。金鑰資源沿金鑰列的 KEK 引用，
// 憑證來自解封世代——兩者都不再自環境取得
// （委託拓撲與憑證改由介面管理：KEK_KMS_KEY_ID／KEK_KMS_REGION 退場）。
func gcpFixtureSettings() config.KMSSettings {
	return config.KMSSettings{Provider: "gcp", KeyID: gcpFactoryKey, Region: "ignored-region-value",
		GCPServiceAccountJSON: []byte(gcpFactoryServiceAccount)}
}

func gcpGeneration(t *testing.T, mutate func(*config.KMSSettings)) *credentialOwner {
	t.Helper()
	s := gcpFixtureSettings()
	if mutate != nil {
		mutate(&s)
	}
	return delegatedFixtureOwner(t, s, delegatedSecrets{gcpServiceAccountJSON: []byte(gcpFactoryServiceAccount)})
}

func gcpStartup(ctx context.Context, o *credentialOwner, construct gcpProviderConstructor) (crypto.KEKProvider, error) {
	p, _, err := buildOwnedKEKProviderWithConstructors(ctx, &config.KEKDecision{Mode: config.KEKModeKMS}, o, nil, construct)
	return p, err
}

func TestGCPFactory(t *testing.T) {
	ctx := context.Background()
	target := strings.Replace(gcpFactoryKey, "/current", "/next", 1)
	o := gcpGeneration(t, nil)
	fixture := func(id string) *gcpFactoryFixture {
		return &gcpFactoryFixture{ref: crypto.KeyRef{Provider: crypto.KeyRefProviderGCP, KeyID: id}, mode: crypto.KEKModeKMS, format: crypto.WrappedFormatGCP}
	}
	calls := 0
	construct := func(_ context.Context, settings gcpkms.Settings) (crypto.KEKProvider, error) {
		calls++
		if settings.Scope.Project() != "test-project" {
			t.Fatal("deployment scope changed")
		}
		// 憑證由本解封世代的持有者送達建構子，不再由 SDK 自行尋找
		// （resolveADC 已由 resolveExplicit 取代）。落空即代表憑證管道斷了。
		if string(settings.ServiceAccountJSON) != gcpFactoryServiceAccount {
			t.Fatal("generation credential did not reach the constructor")
		}
		if got, err := settings.Scope.ResolveKey(settings.KeyID); err != nil || got != settings.KeyID {
			t.Fatal("target outside deployment scope")
		}
		return fixture(settings.KeyID), nil
	}
	t.Run("startup-and-target-dispatch", func(t *testing.T) {
		before := calls
		p, err := gcpStartup(ctx, o, construct)
		if err != nil || p == nil || p.KeyRef().KeyID != gcpFactoryKey {
			t.Fatal("startup dispatch failed")
		}
		p, err = buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderGCP, target, o, nil, construct)
		if err != nil || p == nil || p.KeyRef().KeyID != target || calls != before+2 {
			t.Fatal("target dispatch failed")
		}
		// 建構參數型別仍不得攜帶部署區域。**ServiceAccountJSON 是本次新增的
		// 刻意例外**：憑證改由解封世代顯式注入，這一欄正是那條管道；
		// 允許它並不放寬本格要守的事——任何**其他**新欄位仍即刻紅。
		typ := reflect.TypeOf(gcpkms.Settings{})
		for i := 0; i < typ.NumField(); i++ {
			switch typ.Field(i).Name {
			case "KeyID", "Scope", "ServiceAccountJSON":
			default:
				t.Fatal("unexpected constructor configuration surface")
			}
		}
	})
	t.Run("invalid-target-zero-construction", func(t *testing.T) {
		for _, ref := range []string{"", "bare-key", target + "/cryptoKeyVersions/1", strings.Replace(target, "test-project", "foreign-project", 1), strings.Replace(target, "test-project", "123456789", 1)} {
			before := calls
			p, err := buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderGCP, ref, o, nil, construct)
			if p != nil || err == nil || calls != before || (ref != "" && strings.Contains(err.Error(), ref)) {
				t.Fatal("invalid target reached constructor or was reflected")
			}
		}
	})
	t.Run("invalid-deployment-zero-construction", func(t *testing.T) {
		// 拓撲與憑證的缺項改在設定層表達（環境鍵已退場）；缺項一律零建構，
		// 且錯誤指名欄位常數。
		for _, missing := range []struct {
			field string
			strip func(*config.KMSSettings)
		}{
			{config.FieldKMSKeyID, func(s *config.KMSSettings) { s.KeyID = "" }},
			{config.FieldKMSProvider, func(s *config.KMSSettings) { s.Provider = "" }},
			{config.FieldGCPServiceAccount, func(s *config.KMSSettings) { s.GCPServiceAccountJSON = nil }},
		} {
			t.Run(missing.field, func(t *testing.T) {
				before := calls
				stripped := gcpFixtureSettings()
				missing.strip(&stripped)
				secrets := delegatedSecrets{gcpServiceAccountJSON: []byte(gcpFactoryServiceAccount)}
				if missing.field == config.FieldGCPServiceAccount {
					// 憑證由世代持有者供給，缺席即整條管道沒有輸入：
					// 設定欄位與世代秘密都必須是空的，否則測的不是缺席。
					secrets = delegatedSecrets{}
				}
				incomplete := delegatedFixtureOwner(t, stripped, secrets)
				p, err := buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderGCP, target, incomplete, nil, construct)
				if p != nil || err == nil || calls != before || !strings.Contains(err.Error(), missing.field) {
					t.Fatalf("incomplete deployment reached constructor: %v", err)
				}
				if p, err := gcpStartup(ctx, incomplete, construct); p != nil || err == nil || calls != before {
					t.Fatalf("incomplete startup reached constructor: %v", err)
				}
			})
		}
		bad := gcpGeneration(t, func(s *config.KMSSettings) { s.KeyID = gcpFactoryKey + "/cryptoKeyVersions/1" })
		before := calls
		if p, err := gcpStartup(ctx, bad, construct); p != nil || err == nil || calls != before {
			t.Fatal("version deployment reached constructor")
		}
	})
	t.Run("provider-mismatch-zero-construction", func(t *testing.T) {
		before := calls
		for _, mode := range []string{crypto.KeyRefProviderKMS, crypto.KeyRefProviderVault} {
			if p, err := buildDelegatedRewrapProviderWithConstructors(ctx, mode, target, o, nil, construct); p != nil || err == nil || calls != before {
				t.Fatal("target mode differs from deployment")
			}
		}
		other := gcpGeneration(t, func(s *config.KMSSettings) { s.Provider = "aws" })
		if p, err := buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderGCP, target, other, nil, construct); p != nil || err == nil || calls != before {
			t.Fatal("GCP target accepted under another deployment")
		}
	})
	t.Run("invalid-constructor-results", func(t *testing.T) {
		for _, kind := range []string{"nil", "typed-nil", "error", "key", "provider", "mode", "format"} {
			t.Run(kind, func(t *testing.T) {
				bad := func(_ context.Context, s gcpkms.Settings) (crypto.KEKProvider, error) {
					p := fixture(s.KeyID)
					switch kind {
					case "nil":
						return nil, nil
					case "typed-nil":
						var p *gcpFactoryFixture
						return p, nil
					case "error":
						// **語義變更**：建構子錯誤原本被整段丟棄。委託解封需要分辨
						// 成因（不可達／憑證被拒／金鑰不符），故錯誤鏈自本版起保留；
						// 對外收斂改由 classifyDelegatedFailure 與 apierror 文案承擔。
						return p, fmt.Errorf("%w: service account rejected", gcpkms.ErrAuthentication)
					case "key":
						p.ref.KeyID = target
					case "provider":
						p.ref.Provider = crypto.KeyRefProviderLocal
					case "mode":
						p.mode = crypto.KEKModeEnv
					case "format":
						p.format = crypto.WrappedFormatKMS
					}
					return p, nil
				}
				for _, call := range []func() (crypto.KEKProvider, error){
					func() (crypto.KEKProvider, error) { return gcpStartup(ctx, o, bad) },
					func() (crypto.KEKProvider, error) {
						return buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderGCP, gcpFactoryKey, o, nil, bad)
					},
				} {
					p, err := call()
					if p != nil || err == nil {
						t.Fatal("invalid provider published")
					}
					if strings.Contains(err.Error(), gcpFactoryServiceAccount) {
						t.Fatal("generation credential leaked into the error")
					}
					if kind == "error" && !errors.Is(classifyDelegatedFailure(err), seal.ErrCredentialRejected) {
						t.Fatalf("constructor failure was not classified as a credential rejection: %v", err)
					}
				}
			})
		}
	})
	t.Run("production-constructor-unavailable", func(t *testing.T) {
		// 兩種缺席都必須拒絕：沒有建構子，或沒有世代持有者（委託模式冷啟動）。
		if p, err := gcpStartup(ctx, o, nil); p != nil || err == nil {
			t.Fatal("missing constructor became usable")
		}
		if p, err := buildKEKProvider(ctx, &config.KEKDecision{Mode: config.KEKModeKMS}); p != nil || err == nil {
			t.Fatal("missing generation became usable")
		}
		if p, err := buildDelegatedRewrapProvider(ctx, crypto.KeyRefProviderGCP, target); p != nil || err == nil {
			t.Fatal("missing target constructor became usable")
		}
	})
	t.Run("aws-entry-points-remain-exclusive", func(t *testing.T) {
		s := kmskek.Settings{Provider: "gcp", KeyID: gcpFactoryKey, Region: "ignored-region-value"}
		if p, err := kmskek.New(ctx, s); p != nil || err == nil {
			t.Fatal("AWS constructor accepted GCP")
		}
		if _, err := kmskek.ResolveAccountScope(ctx, s); err == nil {
			t.Fatal("AWS scope accepted GCP")
		}
	})
}

// TestGCPProductionConstructorConnected 守住「正式路徑的 GCP 建構子確實接上」。
//
// 接線之前，credentialOwner 對 GCP 傳 nil 建構子，委託目標一律停在
// buildGCPProvider 的「constructor is not connected」——那道防禦保留著（nil 仍拒），
// 但正式路徑不該再撞到它。本測試因此驗兩件事：走到的是 pkg/crypto/gcpkms 的正式
// client（以本世代的服務帳號金鑰檔認證，故 fixture 憑證被認證層拒絕，而不是「未接上」），
// 且端點覆寫在正式路徑上仍被拒。**不連外**：兩條都在建立連線之前就收場。
func TestGCPProductionConstructorConnected(t *testing.T) {
	ctx := context.Background()
	p, err := gcpGeneration(t, nil).buildDelegated(ctx, crypto.KeyRefProviderGCP, gcpFactoryKey)
	if p != nil || err == nil {
		t.Fatalf("fixture credential became a usable GCP provider: %v", err)
	}
	if strings.Contains(err.Error(), "not connected") {
		t.Fatalf("production path still lacks a GCP constructor: %v", err)
	}
	if !errors.Is(err, gcpkms.ErrAuthentication) {
		t.Fatalf("production client did not reject the fixture service account key: %v", err)
	}
	if strings.Contains(err.Error(), gcpFactoryServiceAccount) {
		t.Fatal("generation credential leaked into the error")
	}
	if !errors.Is(classifyDelegatedFailure(err), seal.ErrCredentialRejected) {
		t.Fatalf("production construction failure was not classified as a credential rejection: %v", err)
	}
	t.Run("endpoint-override-rejected", func(t *testing.T) {
		t.Setenv("GOOGLE_API_USE_MTLS_ENDPOINT", "always")
		p, err := gcpGeneration(t, nil).buildDelegated(ctx, crypto.KeyRefProviderGCP, gcpFactoryKey)
		if p != nil || !errors.Is(err, gcpkms.ErrEndpoint) {
			t.Fatalf("endpoint override was not rejected on the production path: %v", err)
		}
	})
}
