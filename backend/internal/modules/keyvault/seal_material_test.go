package keyvault

import (
	"bytes"
	"context"
	"errors"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/seal"
	"runtime"
	"testing"
	"time"
)

func TestSealRejectsStaleCodec(t *testing.T) {
	km := bytesContractManager(t)
	ctx := context.Background()
	km.MaterialGate().CloseWith(nil)
	for _, v := range []string{"", "invalid"} {
		if p, e := km.DecryptBytesFor(ctx, RefCredentialVersionPassword, v); !errors.Is(e, seal.ErrMaterialSealed) || p != nil {
			t.Fatal("bytes decrypt bypassed closed gate")
		}
		if p, e := km.DecryptFor(ctx, RefCredentialVersionPassword, v); !errors.Is(e, seal.ErrMaterialSealed) || p != "" {
			t.Fatal("string adapter bypassed closed gate")
		}
		if _, e := km.EncryptBytesFor(ctx, RefCredentialVersionPassword, []byte(v)); !errors.Is(e, seal.ErrMaterialSealed) {
			t.Fatal("encrypt bypassed closed gate")
		}
	}
	t.Log("stale bytes/string codecs rejected including empty input")
}
func TestSealInFlightDecrypt(t *testing.T) {
	km := newTestKeyManager(t, newKeyManagerDB(t), 1)
	ctx := context.Background()
	ciphertext, err := km.EncryptBytesFor(ctx, RefCredentialVersionPassword, []byte("sentinel"))
	if err != nil {
		t.Fatal(err)
	}
	km.mu.Lock()
	var original []byte
	for _, versions := range km.keys {
		for _, raw := range versions {
			original = raw
			break
		}
		break
	}
	done := make(chan error, 1)
	go func() {
		p, e := km.DecryptBytesFor(ctx, RefCredentialVersionPassword, ciphertext)
		if p != nil {
			p.Destroy()
			done <- errors.New("late plaintext delivery")
			return
		}
		done <- e
	}()
	deadline := time.Now().Add(time.Second)
	for km.MaterialGate().InFlight() == 0 {
		if time.Now().After(deadline) {
			km.mu.Unlock()
			t.Fatal("decrypt did not borrow")
		}
		runtime.Gosched()
	}
	km.MaterialGate().CloseWith(nil)
	if bytes.Equal(original, make([]byte, len(original))) {
		km.mu.Unlock()
		t.Fatal("key wiped before drain")
	}
	km.mu.Unlock()
	if e := <-done; !errors.Is(e, seal.ErrMaterialSealed) {
		t.Fatalf("in-flight result: %v", e)
	}
	km.ZeroizeForRelease()
	if !bytes.Equal(original, make([]byte, len(original))) {
		t.Fatal("raw key not zero after drain")
	}
	t.Log("blocked decrypt rejected after closure; original key wiped only after drain")
}
func TestSealKeyOperations(t *testing.T) {
	km := newTestKeyManager(t, newKeyManagerDB(t), 1)
	_, raw := km.ActiveHMACKey()
	defer material.Wipe(raw)
	if len(raw) == 0 {
		t.Fatal("missing active HMAC key")
	}
	km.MaterialGate().CloseWith(nil)
	if v, k := km.ActiveHMACKey(); v != 0 || k != nil {
		t.Fatal("HMAC source bypassed gate")
	}
	if _, e := km.RotateDataDEK(); !errors.Is(e, seal.ErrMaterialSealed) {
		t.Fatal("DEK rotation bypassed gate")
	}
	if _, e := km.RotateAuditKey(); !errors.Is(e, seal.ErrMaterialSealed) {
		t.Fatal("HMAC rotation bypassed gate")
	}
	if _, e := km.CleanupRetiredMaterial(); !errors.Is(e, seal.ErrMaterialSealed) {
		t.Fatal("cleanup bypassed gate")
	}
	if _, e := km.RewrapKEK(context.Background(), nil); !errors.Is(e, seal.ErrMaterialSealed) {
		t.Fatal("rewrap bypassed gate")
	}
	signer := &ExportSigningService{gate: km.MaterialGate()}
	if signer.Sign(nil) != "" {
		t.Fatal("signing bypassed gate")
	}
	checkpoint := &CheckpointSigningService{gate: km.MaterialGate()}
	if v, s := checkpoint.Sign(nil); v != 0 || s != "" {
		t.Fatal("checkpoint signing bypassed gate")
	}
	t.Log("HMAC, signing, rotation, rewrap and cleanup rejected without material use")
}
