package keyvault

import (
	"context"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// A source selects re-encryption of persisted ciphertext instead of cached plaintext.
type materialRewrapSource struct {
	ctx      context.Context
	provider crypto.KEKProvider
}

func usesGCPRewrap(from, to crypto.KEKProvider) bool {
	return from.KeyRef().Provider == crypto.KeyRefProviderGCP || to.KeyRef().Provider == crypto.KeyRefProviderGCP
}

// The caller supplies the row read under the existing lock and transaction.
// No cached plaintext is consulted, including when the source fails to decrypt.
func rewrapGCPRow(ctx context.Context, from, to crypto.KEKProvider, row model.DataKey) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if row.KEKRetiredAt != nil || row.WrappedKey == "" || row.KEKID != from.KeyRef().KeyID {
		return "", ErrKEKMismatch
	}
	tag, payload, err := crypto.ParseWrappedKey(row.WrappedKey)
	if err != nil {
		return "", err
	}
	if tag != from.FormatTag() {
		return "", crypto.ErrKEKFormatMismatch
	}
	return wrapMaterial(to, row.Purpose, row.Version, payload, materialRewrapSource{ctx: ctx, provider: from})
}
