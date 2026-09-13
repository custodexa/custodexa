package kms

import (
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/internal/kekcontract"
)

func contractCases() []kekcontract.Case {
	return append(kekcontract.LocalCases(), kekcontract.Case{
		Name: "kms",
		Build: func(t *testing.T) crypto.KEKProvider {
			f := newFakeKMS()
			f.addKey(testKeyAlias, testKeyID, testKeyARN)
			return newTestProvider(t, f, testKeyAlias)
		},
		Other: func(t *testing.T) crypto.KEKProvider {
			f := newFakeKMS()
			f.addKey(otherKeyAlias, otherKeyID, otherKeyARN)
			return newTestProvider(t, f, otherKeyAlias)
		},
		WantFormatTag: crypto.WrappedFormatKMS,
		WantRefKind:   crypto.KeyRefProviderKMS,
	})
}

// Preserve the existing entry and all three cases on the common runner.
func TestKEKProviderContract(t *testing.T)               { kekcontract.Run(t, contractCases()) }
func TestCrossProviderReEncryptInterchange(t *testing.T) { kekcontract.Interchange(t, contractCases()) }
