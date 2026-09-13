package gcpkms

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"hash/crc32"
	"reflect"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/custodexa/backend/pkg/crypto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var ErrIntegrity = errors.New("GCP KMS response integrity rejected")
var ErrMetadata = errors.New("GCP KMS key metadata rejected")
var ErrMaterial = errors.New("GCP KMS material length rejected")
var crcTable = crc32.MakeTable(crc32.Castagnoli)

// Provider borrows its API. It owns no credential material or refresh worker.
// The service transaction adapter supplies the persisted source ciphertext.
type Provider struct {
	api   API
	keyID string
}

// New returns an owner and a preflighted provider. Failed preflight closes the owner.
func New(ctx context.Context, s Settings) (*Client, *Provider, error) {
	c, err := NewClient(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	return preflightOwner(ctx, c, s.KeyID)
}

func preflightOwner(ctx context.Context, c *Client, keyID string) (*Client, *Provider, error) {
	p, err := c.Provider(ctx, keyID)
	if err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	return c, p, nil
}
func (c *Client) Provider(ctx context.Context, keyID string) (*Provider, error) {
	return NewProvider(ctx, Settings{KeyID: keyID, Scope: c.scope}, c)
}

// NewProvider preflights a borrowed narrow API within the deployment scope.
// Client.Provider supplies the owned production client; callers retain ownership.
func NewProvider(ctx context.Context, s Settings, api API) (*Provider, error) {
	return newProvider(ctx, s, api)
}
func newProvider(ctx context.Context, s Settings, api API) (*Provider, error) {
	if _, err := s.Scope.ResolveKey(s.KeyID); err != nil {
		return nil, err
	}
	if api == nil || (reflect.ValueOf(api).Kind() == reflect.Pointer && reflect.ValueOf(api).IsNil()) {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	meta, err := api.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: s.KeyID})
	if err != nil {
		return nil, safeError(err)
	}
	if meta == nil || meta.Name != s.KeyID || meta.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT || meta.Primary == nil || meta.Primary.State != kmspb.CryptoKeyVersion_ENABLED || meta.Primary.Algorithm != kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION || ValidateVersionParent(s.KeyID, meta.Primary.Name) != nil {
		return nil, ErrMetadata
	}
	p := &Provider{api: api, keyID: s.KeyID}
	canary := make([]byte, 32)
	defer clear(canary)
	if _, err := rand.Read(canary); err != nil {
		return nil, ErrUnavailable
	}
	aad := crypto.DEKAAD("preflight", 1)
	wrapped, err := p.Wrap(ctx, canary, aad)
	if err != nil {
		return nil, err
	}
	decoded, err := p.Unwrap(ctx, wrapped, aad)
	defer clear(decoded)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canary, decoded) {
		return nil, ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *Provider) KeyRef() crypto.KeyRef {
	return crypto.KeyRef{Provider: crypto.KeyRefProviderGCP, KeyID: p.keyID}
}
func (p *Provider) Mode() string      { return crypto.KEKModeKMS }
func (p *Provider) FormatTag() string { return crypto.WrappedFormatGCP }
func (p *Provider) ValidateKeyIDSyntax(keyID string) error {
	_, err := ParseKeyResource(keyID)
	return err
}
func checksum(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(data, crcTable)))
}
func validChecksum(data []byte, sum *wrapperspb.Int64Value) bool {
	return sum != nil && sum.Value == checksum(data).Value
}

func (p *Provider) Wrap(ctx context.Context, plain, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, crypto.ErrAADRequired
	}
	if len(plain) == 0 || len(plain)+len(aad) > 64*1024 {
		return nil, ErrMaterial
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := p.api.Encrypt(ctx, &kmspb.EncryptRequest{Name: p.keyID, Plaintext: plain, AdditionalAuthenticatedData: aad, PlaintextCrc32C: checksum(plain), AdditionalAuthenticatedDataCrc32C: checksum(aad)})
	if err != nil {
		return nil, safeError(err)
	}
	if out == nil || len(out.Ciphertext) == 0 || ValidateVersionParent(p.keyID, out.Name) != nil || !out.VerifiedPlaintextCrc32C || !out.VerifiedAdditionalAuthenticatedDataCrc32C || !validChecksum(out.Ciphertext, out.CiphertextCrc32C) {
		return nil, ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return bytes.Clone(out.Ciphertext), nil
}
func (p *Provider) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, crypto.ErrAADRequired
	}
	if len(wrapped) == 0 {
		return nil, ErrMaterial
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := p.api.Decrypt(ctx, &kmspb.DecryptRequest{Name: p.keyID, Ciphertext: wrapped, AdditionalAuthenticatedData: aad, CiphertextCrc32C: checksum(wrapped), AdditionalAuthenticatedDataCrc32C: checksum(aad)})
	if out != nil {
		defer clear(out.Plaintext)
	}
	if err != nil {
		return nil, safeError(err)
	}
	if out == nil || len(out.Plaintext) == 0 || !validChecksum(out.Plaintext, out.PlaintextCrc32C) {
		return nil, ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return bytes.Clone(out.Plaintext), nil
}

var _ crypto.KEKProvider = (*Provider)(nil)

// ReEncrypt performs two operations under one bounded request context.
// The owned plaintext buffer is cleared on success, failure, or cancellation.
func (p *Provider) ReEncrypt(ctx context.Context, wrapped, aad []byte, from crypto.KEKProvider) ([]byte, error) {
	if len(aad) == 0 {
		return nil, crypto.ErrAADRequired
	}
	if from == nil || (reflect.ValueOf(from).Kind() == reflect.Pointer && reflect.ValueOf(from).IsNil()) {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := from.Unwrap(ctx, wrapped, aad)
	defer clear(raw)
	if err != nil {
		return nil, safeError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := p.Wrap(ctx, raw, aad)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
