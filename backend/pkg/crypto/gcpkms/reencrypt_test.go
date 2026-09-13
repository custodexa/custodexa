package gcpkms

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/pkg/crypto"
)

type sourceSpy struct {
	crypto.KEKProvider
	unwrap func(context.Context, []byte, []byte) ([]byte, error)
}

func (s sourceSpy) Unwrap(ctx context.Context, b, a []byte) ([]byte, error) {
	return s.unwrap(ctx, b, a)
}
func TestGCPReEncrypt(t *testing.T) {
	ctx := context.Background()
	aad := crypto.DEKAAD("data", 1)
	plain := bytes.Repeat([]byte{4}, 32)
	f := newFakeClient(t)
	source := fixtureProvider(t, f)
	settings := fixtureSettings(t)
	settings.KeyID = fixtureOtherKey
	target, err := NewProvider(ctx, settings, f)
	if err != nil {
		t.Fatal(err)
	}
	local, err := crypto.NewEnvKEKProvider(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		from, to crypto.KEKProvider
	}{{"gcp-to-gcp", source, target}, {"local-to-gcp", local, target}, {"gcp-to-local", source, local}} {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := tc.from.Wrap(ctx, plain, aad)
			if err != nil {
				t.Fatal(err)
			}
			start := len(f.snapshot())
			rewrapped, err := tc.to.ReEncrypt(ctx, blob, aad, tc.from)
			if err != nil {
				t.Fatal(err)
			}
			calls := f.snapshot()[start:]
			if tc.name == "gcp-to-gcp" && (len(calls) != 2 || calls[0].method != "decrypt" || calls[1].method != "encrypt") {
				t.Fatal("two-step order changed")
			}
			got, err := tc.to.Unwrap(ctx, rewrapped, aad)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatal("cross-provider result mismatch")
			}
		})
	}
	t.Run("intermediate-lifetime", func(t *testing.T) {
		raw := bytes.Clone(plain)
		spy := sourceSpy{unwrap: func(call context.Context, _, a []byte) ([]byte, error) {
			deadline, ok := call.Deadline()
			if !ok || time.Until(deadline) > operationTimeout || !bytes.Equal(a, aad) {
				t.Fatal("request bounds changed")
			}
			return raw, nil
		}}
		if _, err := target.ReEncrypt(ctx, []byte("source"), aad, spy); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("owned plaintext retained")
		}
	})
}
func TestGCPReEncryptFailure(t *testing.T) {
	for _, phase := range []string{"first-step", "second-step"} {
		t.Run(phase, func(t *testing.T) {
			f := newFakeClient(t)
			p := fixtureProvider(t, f)
			raw := bytes.Repeat([]byte{9}, 32)
			calls := 0
			spy := sourceSpy{unwrap: func(context.Context, []byte, []byte) ([]byte, error) {
				calls++
				if phase == "first-step" {
					return raw, errors.New("secret-marker")
				}
				return raw, nil
			}}
			if phase == "second-step" {
				f.inject("encrypt", fakeFault{err: errors.New("secret-marker")})
			}
			before := len(f.snapshot())
			out, err := p.ReEncrypt(context.Background(), []byte("wrapped"), []byte("aad"), spy)
			if out != nil || err == nil || calls != 1 {
				t.Fatal("failure returned success")
			}
			want := 0
			if phase == "second-step" {
				want = 1
			}
			if len(f.snapshot())-before != want {
				t.Fatal("unexpected second-step request")
			}
			if !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("failed plaintext retained")
			}
		})
	}
}
func TestGCPReEncryptCancellation(t *testing.T) {
	for _, phase := range []string{"before-source", "between-steps", "during-encrypt"} {
		t.Run(phase, func(t *testing.T) {
			f := newFakeClient(t)
			p := fixtureProvider(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sourceCalls := 0
			raw := bytes.Repeat([]byte{1}, 32)
			spy := sourceSpy{unwrap: func(context.Context, []byte, []byte) ([]byte, error) {
				sourceCalls++
				if phase == "between-steps" {
					cancel()
				}
				return raw, nil
			}}
			if phase == "before-source" {
				cancel()
			}
			if phase == "during-encrypt" {
				f.inject("encrypt", fakeFault{hook: func(context.Context) { cancel() }})
			}
			before := len(f.snapshot())
			out, err := p.ReEncrypt(ctx, []byte("blob"), []byte("aad"), spy)
			if out != nil || !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation ignored")
			}
			wantSource, wantTarget := 1, 0
			if phase == "before-source" {
				wantSource = 0
			}
			if phase == "during-encrypt" {
				wantTarget = 1
			}
			if sourceCalls != wantSource || len(f.snapshot())-before != wantTarget {
				t.Fatal("canceled flow continued")
			}
		})
	}
}
