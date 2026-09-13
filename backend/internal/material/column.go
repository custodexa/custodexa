package material

import (
	"context"
	"github.com/custodexa/backend/pkg/crypto"
)

// BytesColumnCodec borrows plaintext for encryption and transfers ownership of
// decrypted bytes to the caller, who must Destroy the result after its last use.
// Errors return no owner. Ciphertext and column identity are not secret buffers.
type BytesColumnCodec interface {
	EncryptBytesFor(context.Context, crypto.CipherRef, []byte) (string, error)
	DecryptBytesFor(context.Context, crypto.CipherRef, string) (*Secret, error)
}
