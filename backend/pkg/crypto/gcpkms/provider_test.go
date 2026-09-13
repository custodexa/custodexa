package gcpkms

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/custodexa/backend/pkg/crypto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func fixtureSettings(t *testing.T) Settings {
	t.Helper()
	scope, err := ResolveProjectScope(fixtureKey)
	if err != nil {
		t.Fatal(err)
	}
	return Settings{KeyID: fixtureKey, Scope: scope}
}
func fixtureProvider(t *testing.T, f API) *Provider {
	t.Helper()
	p, err := newProvider(context.Background(), fixtureSettings(t), f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestGCPWrapUnwrap(t *testing.T) {
	f := newFakeClient(t)
	p := fixtureProvider(t, f)
	ctx := context.Background()
	aad := crypto.DEKAAD("data", 3)
	plain := bytes.Repeat([]byte{7}, 32)
	blob, err := p.Wrap(ctx, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := p.Unwrap(ctx, blob, aad)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("roundtrip mismatch")
	}
	if p.KeyRef().Provider != "gcp" || p.KeyRef().KeyID != fixtureKey || p.Mode() != "kms" || p.FormatTag() != "gcp" {
		t.Fatal("identity mismatch")
	}
	for _, test := range []struct {
		name string
		p    *Provider
		aad  []byte
	}{
		{"wrong-aad", p, crypto.DEKAAD("data", 4)},
		{"other-key", &Provider{api: f, keyID: fixtureOtherKey}, aad},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := test.p.Unwrap(ctx, blob, test.aad); err == nil || got != nil {
				t.Fatal("binding bypass")
			}
		})
	}
	t.Run("empty-aad-zero-egress", func(t *testing.T) {
		before := len(f.snapshot())
		for _, a := range [][]byte{nil, {}} {
			if out, err := p.Wrap(ctx, plain, a); !errors.Is(err, crypto.ErrAADRequired) || out != nil {
				t.Fatal("wrap accepted empty AAD")
			}
			if out, err := p.Unwrap(ctx, blob, a); !errors.Is(err, crypto.ErrAADRequired) || out != nil {
				t.Fatal("unwrap accepted empty AAD")
			}
		}
		if len(f.snapshot()) != before {
			t.Fatal("empty AAD left process")
		}
	})
}
func TestGCPPreflight(t *testing.T) {
	mutations := map[string]func(*kmspb.CryptoKey){
		"wrong-name":           func(k *kmspb.CryptoKey) { k.Name = fixtureOtherKey },
		"purpose":              func(k *kmspb.CryptoKey) { k.Purpose = kmspb.CryptoKey_ASYMMETRIC_SIGN },
		"missing-primary":      func(k *kmspb.CryptoKey) { k.Primary = nil },
		"disabled":             func(k *kmspb.CryptoKey) { k.Primary.State = kmspb.CryptoKeyVersion_DISABLED },
		"algorithm":            func(k *kmspb.CryptoKey) { k.Primary.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256 },
		"wrong-primary-parent": func(k *kmspb.CryptoKey) { k.Primary.Name = fixtureOtherKey + "/cryptoKeyVersions/1" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newFakeClient(t)
			meta := proto.Clone(f.keys[fixtureKey].meta).(*kmspb.CryptoKey)
			mutate(meta)
			f.inject("metadata", fakeFault{replace: true, response: meta})
			p, err := newProvider(context.Background(), fixtureSettings(t), f)
			if err == nil || p != nil || len(f.snapshot()) != 1 {
				t.Fatal("metadata failure did not stop canary")
			}
		})
	}
	for _, method := range []string{"metadata", "encrypt", "decrypt"} {
		t.Run(method+"-permission-denied", func(t *testing.T) {
			f := newFakeClient(t)
			f.inject(method, fakeFault{err: status.Error(codes.PermissionDenied, "secret-marker")})
			p, err := newProvider(context.Background(), fixtureSettings(t), f)
			if p != nil || !errors.Is(err, ErrPermission) || strings.Contains(err.Error(), "secret-marker") {
				t.Fatal("permission failure not closed")
			}
		})
	}
	t.Run("canary-mismatch", func(t *testing.T) {
		f := newFakeClient(t)
		raw := bytes.Repeat([]byte{1}, 32)
		f.inject("decrypt", fakeFault{replace: true, response: &kmspb.DecryptResponse{Plaintext: raw, PlaintextCrc32C: fakeCRC(raw)}})
		if p, err := newProvider(context.Background(), fixtureSettings(t), f); p != nil || !errors.Is(err, ErrIntegrity) {
			t.Fatal("mismatched canary accepted")
		}
	})
	t.Run("nil-metadata", func(t *testing.T) {
		f := newFakeClient(t)
		f.inject("metadata", fakeFault{replace: true})
		if p, err := newProvider(context.Background(), fixtureSettings(t), f); p != nil || err == nil {
			t.Fatal("nil metadata accepted")
		}
	})
	t.Run("success-sequence", func(t *testing.T) {
		f := newFakeClient(t)
		fixtureProvider(t, f)
		calls := f.snapshot()
		if len(calls) != 3 || calls[0].method != "metadata" || calls[1].method != "encrypt" || calls[2].method != "decrypt" {
			t.Fatal("preflight sequence changed")
		}
	})
}
func TestGCPIntegrity(t *testing.T) {
	blob := []byte("ciphertext")
	valid := func() *kmspb.EncryptResponse {
		return &kmspb.EncryptResponse{Name: fixtureKey + "/cryptoKeyVersions/1", Ciphertext: bytes.Clone(blob), CiphertextCrc32C: fakeCRC(blob), VerifiedPlaintextCrc32C: true, VerifiedAdditionalAuthenticatedDataCrc32C: true}
	}
	cases := map[string]func(*kmspb.EncryptResponse){
		"parent":               func(r *kmspb.EncryptResponse) { r.Name = fixtureOtherKey + "/cryptoKeyVersions/1" },
		"empty-name":           func(r *kmspb.EncryptResponse) { r.Name = "" },
		"empty-ciphertext":     func(r *kmspb.EncryptResponse) { r.Ciphertext = nil; r.CiphertextCrc32C = fakeCRC(nil) },
		"crc-absent":           func(r *kmspb.EncryptResponse) { r.CiphertextCrc32C = nil },
		"crc-mismatch":         func(r *kmspb.EncryptResponse) { r.CiphertextCrc32C = wrapperspb.Int64(-1) },
		"crc-overflow":         func(r *kmspb.EncryptResponse) { r.CiphertextCrc32C = wrapperspb.Int64(1 << 32) },
		"plaintext-unverified": func(r *kmspb.EncryptResponse) { r.VerifiedPlaintextCrc32C = false },
		"aad-unverified":       func(r *kmspb.EncryptResponse) { r.VerifiedAdditionalAuthenticatedDataCrc32C = false },
	}
	for name, mutate := range cases {
		t.Run("encrypt-"+name, func(t *testing.T) {
			f := newFakeClient(t)
			p := fixtureProvider(t, f)
			out := valid()
			mutate(out)
			f.inject("encrypt", fakeFault{replace: true, response: out})
			if got, err := p.Wrap(context.Background(), []byte("key"), []byte("aad")); got != nil || !errors.Is(err, ErrIntegrity) {
				t.Fatal("bad response accepted")
			}
		})
	}
	for _, method := range []string{"encrypt", "decrypt"} {
		t.Run(method+"-nil", func(t *testing.T) {
			f := newFakeClient(t)
			p := fixtureProvider(t, f)
			f.inject(method, fakeFault{replace: true})
			var got []byte
			var err error
			if method == "encrypt" {
				got, err = p.Wrap(context.Background(), []byte("key"), []byte("aad"))
			} else {
				got, err = p.Unwrap(context.Background(), blob, []byte("aad"))
			}
			if got != nil || !errors.Is(err, ErrIntegrity) {
				t.Fatal("nil response accepted")
			}
		})
	}
	for name, response := range map[string]*kmspb.DecryptResponse{
		"empty": {PlaintextCrc32C: fakeCRC(nil)}, "missing-crc": {Plaintext: []byte("key")}, "mismatch": {Plaintext: []byte("key"), PlaintextCrc32C: fakeCRC([]byte("other"))},
	} {
		t.Run("decrypt-"+name, func(t *testing.T) {
			f := newFakeClient(t)
			p := fixtureProvider(t, f)
			f.inject("decrypt", fakeFault{replace: true, response: response})
			if got, err := p.Unwrap(context.Background(), blob, []byte("aad")); got != nil || !errors.Is(err, ErrIntegrity) {
				t.Fatal("bad plaintext accepted")
			}
		})
	}
}
