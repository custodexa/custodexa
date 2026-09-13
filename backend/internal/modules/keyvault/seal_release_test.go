package keyvault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/custodexa/backend/pkg/crypto"
	"testing"
)

type observedUnwrap struct {
	crypto.KEKProvider
	originals [][]byte
	failAt    int
}

func (p *observedUnwrap) Unwrap(ctx context.Context, cipher, aad []byte) ([]byte, error) {
	raw, err := p.KEKProvider.Unwrap(ctx, cipher, aad)
	p.originals = append(p.originals, raw)
	if len(p.originals) == p.failAt {
		return raw, errors.New("partial unwrap failure")
	}
	return raw, err
}
func assertReleasedBytes(t *testing.T, raws [][]byte) {
	t.Helper()
	if len(raws) == 0 {
		t.Fatal("no original buffers observed")
	}
	for _, raw := range raws {
		if len(raw) == 0 || !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("original buffer not zero")
		}
	}
}
func TestProbeMaterialZeroize(t *testing.T) {
	for _, failAt := range []int{0, 2} {
		km := newTestKeyManager(t, newKeyManagerDB(t), 1)
		p := &observedUnwrap{KEKProvider: km.kek, failAt: failAt}
		err := ProbeKEKUnwrap(km.db, p)
		if (err != nil) != (failAt > 0) {
			t.Fatal(err)
		}
		assertReleasedBytes(t, p.originals)
		t.Logf("probe failAt=%d: %d original buffers zero", failAt, len(p.originals))
	}
}
func TestPartialInitZeroize(t *testing.T) {
	km := newTestKeyManager(t, newKeyManagerDB(t), 1)
	p := &observedUnwrap{KEKProvider: km.kek, failAt: 2}
	out, err := InitKeyManager(km.db, p)
	if err == nil || out != nil {
		t.Fatal("partial initialization published")
	}
	assertReleasedBytes(t, p.originals)
	t.Log("partial initialization and failing unwrap outputs zero")
}
func TestSealGraphRelease(t *testing.T) {
	km := newTestKeyManager(t, newKeyManagerDB(t), 1)
	var originals [][]byte
	for _, versions := range km.keys {
		for _, raw := range versions {
			originals = append(originals, raw)
		}
	}
	signing := &ExportSigningService{gate: km.MaterialGate(), priv: ed25519.PrivateKey(bytes.Repeat([]byte{3}, 64))}
	checkpoints := &CheckpointSigningService{gate: km.MaterialGate(), keys: map[int]ed25519.PrivateKey{1: bytes.Repeat([]byte{4}, 64), 2: bytes.Repeat([]byte{5}, 64)}, activeVersion: 2}
	originals = append(originals, signing.priv, checkpoints.keys[1], checkpoints.keys[2])
	km.ZeroizeForRelease()
	signing.ZeroizeForRelease()
	checkpoints.ZeroizeForRelease()
	assertReleasedBytes(t, originals)
	if len(km.ciphers)+len(km.active)+len(km.keys)+len(checkpoints.keys) != 0 || checkpoints.activeVersion != 0 {
		t.Fatal("cache or active versions retained")
	}
	if _, err := km.DecryptFor(context.Background(), RefCredentialVersionPassword, ""); err == nil {
		t.Fatal("released codec usable")
	}
	t.Log("all DEK/HMAC/signing versions zero; caches and active versions empty; old codec rejected")
}
