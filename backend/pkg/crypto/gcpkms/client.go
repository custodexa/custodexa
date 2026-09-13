// Package gcpkms defines the Cloud KMS boundary for delegated key wrapping.
package gcpkms

import (
	"context"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// API accepts SDK messages with raw AAD bytes and optional CRC32C wrappers.
// Callers borrow this interface; transport ownership belongs to its constructor.
// Administrative version changes are deliberately outside this operation set.
type API interface {
	GetCryptoKey(context.Context, *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error)
	Encrypt(context.Context, *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error)
	Decrypt(context.Context, *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error)
}
