package gcpkms

import (
	"context"
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/internal/kekcontract"
)

func gcpContractCase() kekcontract.Case {
	build := func(t *testing.T, keyID string) crypto.KEKProvider {
		t.Helper()
		s := fixtureSettings(t)
		s.KeyID = keyID
		p, err := NewProvider(context.Background(), s, newFakeClient(t))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	return kekcontract.Case{Name: "gcp", Build: func(t *testing.T) crypto.KEKProvider { return build(t, fixtureKey) }, Other: func(t *testing.T) crypto.KEKProvider { return build(t, fixtureOtherKey) }, WantFormatTag: crypto.WrappedFormatGCP, WantRefKind: crypto.KeyRefProviderGCP}
}

// Use the same complete assertions as the existing provider entries.
func TestKEKProviderContract(t *testing.T) { kekcontract.Run(t, []kekcontract.Case{gcpContractCase()}) }
func TestCrossProviderReEncryptInterchange(t *testing.T) {
	kekcontract.Interchange(t, append(kekcontract.LocalCases(), gcpContractCase()))
}
