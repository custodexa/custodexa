package keyvault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

func bytesContractManager(t *testing.T) *KeyManagerService {
	t.Helper()
	c, err := crypto.NewAESCrypto(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &KeyManagerService{active: map[string]int{model.DataKeyPurposeData: 1}, ciphers: map[int]*crypto.AESCrypto{1: c}}
}

func TestBytesColumnContract(t *testing.T) {
	ctx := context.Background()
	var codec material.BytesColumnCodec = bytesContractManager(t)
	ref := crypto.CipherRef{Table: "assets", Column: "password_enc"}
	input := []byte{1, 0, 2, 255}
	ciphertext, err := codec.EncryptBytesFor(ctx, ref, input)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := codec.DecryptBytesFor(ctx, ref, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err := owner.Borrow(func(raw []byte) error {
		original = raw
		if !bytes.Equal(input, raw) {
			t.Error("round trip changed plaintext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	owner.Destroy()
	if !bytes.Equal(original, make([]byte, len(original))) {
		t.Fatal("owned output not erased")
	}
	if !bytes.Equal(input, []byte{1, 0, 2, 255}) {
		t.Fatal("encryption modified borrowed input")
	}
	for _, tc := range []struct {
		name  string
		ref   crypto.CipherRef
		value string
	}{
		{"wrong AAD", crypto.CipherRef{Table: "assets", Column: "private_key_enc"}, ciphertext},
		{"missing AAD", crypto.CipherRef{}, ciphertext},
		{"unknown format", ref, "enc:unknown:v1:AA=="},
		{"unversioned", ref, "AA=="},
		{"without AAD", ref, "enc:v1:AA=="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := codec.DecryptBytesFor(ctx, tc.ref, tc.value)
			if err == nil || result != nil {
				if result != nil {
					result.Destroy()
				}
				t.Fatal("invalid input returned plaintext ownership")
			}
		})
	}
	partial := []byte{3, 4, 5}
	result, err := material.AdoptResult(partial, errors.New("partial output failed"))
	if err == nil || result != nil || !bytes.Equal(partial, []byte{0, 0, 0}) {
		t.Fatal("error left partial output")
	}
}

func TestSecretOwnership(t *testing.T) {
	raw := []byte{1, 2, 3}
	owner := material.Adopt(raw)
	alias := *owner
	for i := 0; i < 2; i++ {
		if err := owner.Borrow(func(b []byte) error {
			if &b[0] != &raw[0] {
				t.Error("borrow copied buffer")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	next, err := owner.Transfer()
	if err != nil {
		t.Fatal(err)
	}
	owner.Destroy()
	alias.Destroy()
	if !bytes.Equal(raw, []byte{1, 2, 3}) {
		t.Fatal("old owner destroyed transferred bytes")
	}
	if err := alias.Borrow(func([]byte) error { return nil }); !errors.Is(err, material.ErrDestroyed) {
		t.Fatal("copied handle retained ownership")
	}
	if _, err := owner.Transfer(); !errors.Is(err, material.ErrDestroyed) {
		t.Fatal("transfer repeated")
	}
	expected := errors.New("borrow failed")
	if err := next.Borrow(func(b []byte) error {
		if _, err := next.Transfer(); !errors.Is(err, material.ErrBorrowed) {
			t.Error("transfer allowed active borrow")
		}
		next.Destroy()
		next.Destroy()
		if !bytes.Equal(b, []byte{1, 2, 3}) {
			t.Error("destroy erased active borrow early")
		}
		return expected
	}); !errors.Is(err, expected) {
		t.Fatal("borrow error changed")
	}
	next.Destroy()
	if !bytes.Equal(raw, []byte{0, 0, 0}) {
		t.Fatal("last borrow did not erase buffer")
	}
	if err := next.Borrow(func([]byte) error { return nil }); !errors.Is(err, material.ErrDestroyed) {
		t.Fatal("destroyed owner accepted borrow")
	}
	var empty material.Secret
	empty.Destroy()
}

func TestBytesAdapterParity(t *testing.T) {
	km := bytesContractManager(t)
	ctx := context.Background()
	ref := crypto.CipherRef{Table: "assets", Column: "password_enc"}
	oldCipher, err := km.EncryptFor(ctx, ref, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	newCipher, err := km.EncryptBytesFor(ctx, ref, []byte("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, value string
		ref         crypto.CipherRef
	}{
		{"old ciphertext", oldCipher, ref}, {"bytes ciphertext", newCipher, ref},
		{"empty", "", crypto.CipherRef{}},
		{"AAD mismatch", newCipher, crypto.CipherRef{Table: "other", Column: "password_enc"}},
		{"incomplete AAD", newCipher, crypto.CipherRef{}},
		{"unknown format", "enc:other:v1:AA==", ref},
		{"unknown version", "enc:a1:v99:AA==", ref},
		{"malformed", "enc:a1:v1:!", ref},
		{"no prefix", "AA==", ref}, {"no AAD", "enc:v1:AA==", ref},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, oldErr := km.DecryptFor(ctx, tc.ref, tc.value)
			owner, newErr := km.DecryptBytesFor(ctx, tc.ref, tc.value)
			if (oldErr == nil) != (newErr == nil) {
				t.Fatal("adapter error parity differs")
			}
			if oldErr != nil {
				if oldErr.Error() != newErr.Error() || owner != nil || old != "" {
					t.Fatal("error or empty-output parity differs")
				}
				return
			}
			defer owner.Destroy()
			if err := owner.Borrow(func(raw []byte) error {
				if !bytes.Equal(raw, []byte(old)) {
					t.Error("adapter plaintext differs")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, r := range []crypto.CipherRef{ref, {}} {
		for _, plain := range []string{"", "fixture"} {
			_, a := km.EncryptFor(ctx, r, plain)
			_, b := km.EncryptBytesFor(ctx, r, []byte(plain))
			if (a == nil) != (b == nil) || a != nil && a.Error() != b.Error() {
				t.Fatal("encryption error parity differs")
			}
		}
	}
}
