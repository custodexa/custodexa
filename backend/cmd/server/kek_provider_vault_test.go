package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
	kmskek "github.com/custodexa/backend/pkg/crypto/kms"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
)

// This fixture exercises factory wiring only, not a delivered Vault client.
type vaultFactoryFixture struct {
	crypto.KEKProvider
	id string
}

func (p *vaultFactoryFixture) KeyRef() crypto.KeyRef {
	return crypto.KeyRef{Provider: crypto.KeyRefProviderVault, KeyID: p.id}
}
func (p *vaultFactoryFixture) Mode() string      { return crypto.KEKModeKMS }
func (p *vaultFactoryFixture) FormatTag() string { return crypto.WrappedFormatVault }

// vaultFixtureSettings 委託部署的 Vault 拓撲（介面設定、資料庫持久化）。
// **不再自環境取得**：KEK_VAULT_ADDR／KEK_VAULT_ROLE_ID／KEK_VAULT_SECRET_ID
// 已退場（委託拓撲與憑證改由介面管理）。
func vaultFixtureSettings() config.KMSSettings {
	s := config.KMSSettings{Provider: "vault", KeyID: "current"}
	s.Vault.Address = "https://VAULT.example:443/"
	s.Vault.RoleID = "role-fixture"
	return s
}

// vaultFixtureSecrets 本解封世代持有的角色密鑰（解封時輸入）。
func vaultFixtureSecrets() delegatedSecrets {
	return delegatedSecrets{vaultSecretID: []byte("secret-fixture")}
}

// vaultGeneration 一個已接手 Vault 拓撲與秘密的解封世代持有者。
func vaultGeneration(t *testing.T, mutate func(*config.KMSSettings)) *credentialOwner {
	t.Helper()
	s := vaultFixtureSettings()
	if mutate != nil {
		mutate(&s)
	}
	return delegatedFixtureOwner(t, s, vaultFixtureSecrets())
}

func vaultStartup(ctx context.Context, o *credentialOwner, construct vaultProviderConstructor) (crypto.KEKProvider, error) {
	p, _, err := buildOwnedKEKProviderWithConstructors(ctx, &config.KEKDecision{Mode: config.KEKModeKMS}, o, construct, nil)
	return p, err
}

func TestVaultProviderFactoryTakesCredentialsFromGeneration(t *testing.T) {
	ctx := context.Background()
	o := vaultGeneration(t, nil)
	target, _ := vaulttransit.CanonicalKeyID("https://vault.example", "next")
	calls := 0
	construct := func(_ context.Context, s vaulttransit.Settings) (crypto.KEKProvider, error) {
		calls++
		// 拓撲與秘密**都必須由世代持有者送達建構子**：位址與角色識別來自拓撲，
		// 角色密鑰來自本次解封的輸入。任何一項落空即代表憑證管道斷了。
		if s.Address != "https://vault.example" || s.Scope.Origin() != s.Address || s.RoleID != "role-fixture" || s.SecretID != "secret-fixture" {
			t.Fatal("deployment settings not preserved")
		}
		if s.Token != "" {
			t.Fatal("token path must not be taken while a role secret is supplied")
		}
		return &vaultFactoryFixture{id: s.KeyID}, nil
	}
	t.Run("startup-and-wizard-dispatch", func(t *testing.T) {
		p, err := vaultStartup(ctx, o, construct)
		if err != nil || p == nil {
			t.Fatal("startup wiring failed")
		}
		p, err = buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderVault, target, o, construct, nil)
		if err != nil || p == nil || p.KeyRef().KeyID != target || calls != 2 {
			t.Fatal("wizard wiring failed")
		}
	})
	t.Run("direct-token-path", func(t *testing.T) {
		// 權杖路徑與角色路徑**二選一**：兩者不得同時送達建構子。
		s := vaultFixtureSettings()
		tokenOwner := delegatedFixtureOwner(t, s, delegatedSecrets{vaultToken: []byte("token-fixture")})
		seen := 0
		tokenConstruct := func(_ context.Context, s vaulttransit.Settings) (crypto.KEKProvider, error) {
			seen++
			if s.Token != "token-fixture" || s.SecretID != "" || !s.UsesToken() {
				t.Fatal("token generation did not reach the constructor")
			}
			return &vaultFactoryFixture{id: s.KeyID}, nil
		}
		if p, err := vaultStartup(ctx, tokenOwner, tokenConstruct); p == nil || err != nil || seen != 1 {
			t.Fatalf("token deployment refused: %v", err)
		}
		both := delegatedFixtureOwner(t, s, delegatedSecrets{
			vaultSecretID: []byte("secret-fixture"), vaultToken: []byte("token-fixture")})
		before := seen
		if p, err := vaultStartup(ctx, both, tokenConstruct); p != nil || err == nil || seen != before {
			t.Fatal("ambiguous credential reached the constructor")
		}
	})
	t.Run("foreign-origin-zero-construction", func(t *testing.T) {
		foreign, _ := vaulttransit.CanonicalKeyID("https://foreign.example", "next")
		before := calls
		p, err := buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderVault, foreign, o, construct, nil)
		if p != nil || !errors.Is(err, vaulttransit.ErrOutsideScope) || before != calls {
			t.Fatal("cross-origin target reached constructor")
		}
	})
	t.Run("provider-mismatch-zero-construction", func(t *testing.T) {
		before := calls
		p, err := buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderKMS, target, o, construct, nil)
		if p != nil || err == nil || calls != before {
			t.Fatal("AWS target accepted under Vault deployment")
		}
	})
	t.Run("http-and-long-target-zero-construction", func(t *testing.T) {
		before := calls
		insecure := vaultGeneration(t, func(s *config.KMSSettings) { s.Vault.Address = "http://vault.example" })
		p, err := vaultStartup(ctx, insecure, construct)
		if p != nil || err == nil || calls != before {
			t.Fatal("HTTP deployment reached constructor")
		}
		for _, ref := range []string{"", strings.Repeat("x", 256)} {
			p, err = buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderVault, ref, o, construct, nil)
			if p != nil || err == nil || calls != before {
				t.Fatal("invalid target reached constructor")
			}
		}
	})
	t.Run("both-paths-require-complete-settings", func(t *testing.T) {
		// 齊備驗證的**位置**已自啟動期的 env 讀取移到建構期的欄位檢查；
		// 錯誤因此指名欄位常數而非環境變數鍵名。缺項一律零建構。
		before := calls
		for _, missing := range []struct {
			field string
			strip func(*config.KMSSettings)
		}{
			{config.FieldVaultAddress, func(s *config.KMSSettings) { s.Vault.Address = "" }},
			{config.FieldVaultRoleID, func(s *config.KMSSettings) { s.Vault.RoleID = "" }},
			{config.FieldKMSKeyID, func(s *config.KMSSettings) { s.KeyID = "" }},
		} {
			t.Run(missing.field, func(t *testing.T) {
				incomplete := vaultGeneration(t, missing.strip)
				p, err := buildDelegatedRewrapProviderWithConstructors(ctx, crypto.KeyRefProviderVault, target, incomplete, construct, nil)
				if p != nil || err == nil || !strings.Contains(err.Error(), missing.field) || calls != before {
					t.Fatalf("wizard completeness guard failed: %v", err)
				}
				p, err = vaultStartup(ctx, incomplete, construct)
				if p != nil || err == nil || calls != before {
					t.Fatalf("startup completeness guard failed: %v", err)
				}
			})
		}
		// 秘密缺席（解封時未輸入角色密鑰）同樣零建構，且錯誤指名憑證欄位。
		noSecret := delegatedFixtureOwner(t, vaultFixtureSettings(), delegatedSecrets{})
		p, err := vaultStartup(ctx, noSecret, construct)
		if p != nil || err == nil || !strings.Contains(err.Error(), config.FieldVaultSecretID) || calls != before {
			t.Fatalf("missing generation secret reached the constructor: %v", err)
		}
	})
	t.Run("typed-nil-and-error-classification", func(t *testing.T) {
		// **語義變更**：建構子的錯誤原本被整段丟棄（只回「Vault constructor
		// failed」）。委託解封需要分辨「保管處不可達／憑證被拒／金鑰不符」三種
		// 成因，故錯誤鏈自本版起保留——對外的收斂改由 classifyDelegatedFailure
		// 與 apierror 文案承擔，原始回應只進伺服端日誌。
		// 本格因此改守兩件事：typed nil 不得被當成可用 provider；
		// 錯誤鏈必須完整到足以歸類。
		var typedNil = func(context.Context, vaulttransit.Settings) (crypto.KEKProvider, error) {
			var p *vaultFactoryFixture
			return p, nil
		}
		if p, err := vaultStartup(ctx, o, typedNil); p != nil || err == nil {
			t.Fatal("typed nil became a usable provider")
		}
		failing := func(context.Context, vaulttransit.Settings) (crypto.KEKProvider, error) {
			return nil, fmt.Errorf("%w: approle login refused", vaulttransit.ErrAuth)
		}
		p, err := vaultStartup(ctx, o, failing)
		if p != nil || !errors.Is(err, vaulttransit.ErrAuth) {
			t.Fatalf("constructor error chain was dropped: %v", err)
		}
		if !errors.Is(classifyDelegatedFailure(err), seal.ErrCredentialRejected) {
			t.Fatalf("constructor failure was not classified as a credential rejection: %v", err)
		}
	})
	t.Run("missing-generation-or-owner-refuses", func(t *testing.T) {
		// 兩種缺席都必須拒絕：沒有世代持有者（冷啟動），或有持有者但沒有
		// 接上 Vault client 建構子。前者是委託模式冷啟動的正常狀態。
		p, err := buildKEKProvider(ctx, &config.KEKDecision{Mode: config.KEKModeKMS})
		if p != nil || err == nil {
			t.Fatal("missing generation became usable")
		}
		p, err = buildDelegatedRewrapProvider(ctx, crypto.KeyRefProviderVault, target)
		if p != nil || err == nil {
			t.Fatal("missing wizard generation became usable")
		}
		p, err = vaultStartup(ctx, o, nil)
		if p != nil || err == nil {
			t.Fatal("missing lifetime owner became usable")
		}
	})
	t.Run("owner-rejects-invalid-deployment", func(t *testing.T) {
		bad := vaultFixtureSettings()
		bad.Vault.Address = "http://vault.example"
		bad.Vault.SecretID = "secret-fixture"
		c, construct, err := newVaultProviderOwner(ctx, bad)
		if c != nil || construct != nil || err == nil {
			t.Fatal("invalid deployment created an owner")
		}
	})
	t.Run("aws-constructors-remain-exclusive", func(t *testing.T) {
		settings := kmskek.Settings{Provider: "vault", KeyID: "fixture", Region: "fixture"}
		if p, err := kmskek.New(ctx, settings); p != nil || err == nil {
			t.Fatal("AWS constructor accepted Vault")
		}
		if _, err := kmskek.ResolveAccountScope(ctx, settings); err == nil {
			t.Fatal("AWS scope accepted Vault")
		}
	})
}
