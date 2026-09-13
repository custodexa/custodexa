package vaulttransit

import (
	"context"
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/internal/kekcontract"
)

func vaultContractCase() kekcontract.Case {
	build := func(t *testing.T, name string) crypto.KEKProvider {
		t.Helper()
		f, s := fixtureServer(t)
		c := fixtureClient(t, f, s, wallClock{})
		id, err := CanonicalKeyID("https://vault.example", name)
		if err != nil {
			t.Fatal(err)
		}
		p, err := c.Provider(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	return kekcontract.Case{Name: "vault", Build: func(t *testing.T) crypto.KEKProvider { return build(t, "key") }, Other: func(t *testing.T) crypto.KEKProvider { return build(t, "other") }, WantFormatTag: crypto.WrappedFormatVault, WantRefKind: crypto.KeyRefProviderVault}
}

// The fourth case uses the exact assertion runner used by the existing three.
func TestKEKProviderContract(t *testing.T) {
	kekcontract.Run(t, []kekcontract.Case{vaultContractCase()})
}
func TestCrossProviderReEncryptInterchange(t *testing.T) {
	kekcontract.Interchange(t, append(kekcontract.LocalCases(), vaultContractCase()))
}
