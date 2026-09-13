package vaulttransit

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/custodexa/backend/pkg/crypto"
)

var ErrAADRequired = errors.New("Vault context is required")

type Provider struct {
	client   *Client
	id, name string
}
type dataEnvelope struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
		Plaintext  string `json:"plaintext"`
		Derived    bool   `json:"derived"`
		Type       string `json:"type"`
	} `json:"data"`
}

// Provider performs metadata and canary checks before publishing a borrowed client.
func (c *Client) Provider(ctx context.Context, keyID string) (*Provider, error) {
	if _, err := c.scope.ResolveKey(keyID); err != nil {
		return nil, err
	}
	_, name, err := ParseKeyID(keyID)
	if err != nil {
		return nil, err
	}
	p := &Provider{client: c, id: keyID, name: name}
	if err := p.Preflight(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Provider) KeyRef() crypto.KeyRef {
	return crypto.KeyRef{Provider: crypto.KeyRefProviderVault, KeyID: p.id}
}
func (p *Provider) Mode() string      { return crypto.KEKModeKMS }
func (p *Provider) FormatTag() string { return crypto.WrappedFormatVault }

func validCiphertext(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") {
		return false
	}
	version, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "v"), 10, 64)
	if err != nil || version == 0 || "v"+strconv.FormatUint(version, 10) != parts[1] {
		return false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(parts[2])
	return err == nil && len(decoded) >= 28
}

func (p *Provider) Wrap(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	if len(plaintext) == 0 {
		return nil, ErrResponse
	}
	var out dataEnvelope
	err := p.client.call(ctx, "POST", "/v1/transit/encrypt/"+p.name, map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext), "context": base64.StdEncoding.EncodeToString(aad)}, &out)
	if err != nil {
		return nil, err
	}
	if !validCiphertext(out.Data.Ciphertext) {
		return nil, ErrResponse
	}
	return []byte(out.Data.Ciphertext), nil
}

func (p *Provider) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	if !validCiphertext(string(wrapped)) {
		return nil, ErrResponse
	}
	var out dataEnvelope
	err := p.client.call(ctx, "POST", "/v1/transit/decrypt/"+p.name, map[string]string{
		"ciphertext": string(wrapped), "context": base64.StdEncoding.EncodeToString(aad)}, &out)
	if err != nil {
		return nil, err
	}
	plain, err := base64.StdEncoding.Strict().DecodeString(out.Data.Plaintext)
	if err != nil || len(plain) == 0 {
		clear(plain)
		return nil, ErrResponse
	}
	return plain, nil
}

func (p *Provider) Preflight(ctx context.Context) error {
	var meta dataEnvelope
	if err := p.client.call(ctx, "GET", "/v1/transit/keys/"+p.name, nil, &meta); err != nil {
		return err
	}
	if !meta.Data.Derived || (meta.Data.Type != "aes256-gcm96" && meta.Data.Type != "aes128-gcm96" && meta.Data.Type != "chacha20-poly1305") {
		return ErrResponse
	}
	probe := make([]byte, 32)
	defer clear(probe)
	if _, err := rand.Read(probe); err != nil {
		return ErrResponse
	}
	aad := crypto.DEKAAD("vault-preflight", 0)
	wrapped, err := p.Wrap(ctx, probe, aad)
	if err != nil {
		return err
	}
	got, err := p.Unwrap(ctx, wrapped, aad)
	defer clear(got)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(probe, got) != 1 {
		return ErrResponse
	}
	return nil
}

func (p *Provider) ReEncrypt(ctx context.Context, wrapped, aad []byte, from crypto.KEKProvider) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if src, ok := from.(*Provider); ok && src != nil && src.id == p.id && src.client.wire.origin == p.client.wire.origin {
		if !validCiphertext(string(wrapped)) {
			return nil, ErrResponse
		}
		var out dataEnvelope
		err := p.client.call(ctx, "POST", "/v1/transit/rewrap/"+p.name, map[string]string{
			"ciphertext": string(wrapped), "context": base64.StdEncoding.EncodeToString(aad)}, &out)
		if err != nil {
			return nil, err
		}
		if !validCiphertext(out.Data.Ciphertext) {
			return nil, ErrResponse
		}
		return []byte(out.Data.Ciphertext), nil
	}
	if from == nil {
		return nil, ErrResponse
	}
	bounded, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	plain, err := from.Unwrap(bounded, wrapped, aad)
	defer clear(plain)
	if err != nil {
		return nil, ErrDenied
	}
	return p.Wrap(bounded, plain, aad)
}

// New returns both the lifetime owner and its initial provider. Failed initial
// preflight closes and joins the worker; subsequent targets borrow Client.Provider.
func New(lifetime context.Context, s Settings) (*Client, *Provider, error) {
	c, err := NewClient(lifetime, s)
	if err != nil {
		return nil, nil, err
	}
	_, id, err := ResolveScope(s.Address, s.KeyID)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	return preflightClient(lifetime, c, id)
}

func preflightClient(ctx context.Context, c *Client, id string) (*Client, *Provider, error) {
	p, err := c.Provider(ctx, id)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	return c, p, nil
}
