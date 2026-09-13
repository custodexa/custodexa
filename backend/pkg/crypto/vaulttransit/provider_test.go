package vaulttransit

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/pkg/crypto"
)

func fixtureProvider(t *testing.T) (*fakeVault, *Provider) {
	t.Helper()
	f, s := fixtureServer(t)
	c := fixtureClient(t, f, s, wallClock{})
	id, _ := CanonicalKeyID("https://vault.example", "key")
	p, err := c.Provider(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return f, p
}
func TestVaultWrapUnwrap(t *testing.T) {
	f, p := fixtureProvider(t)
	aad := crypto.DEKAAD("data", 2)
	plain := bytes.Repeat([]byte{19}, 32)
	wrapped, err := p.Wrap(context.Background(), plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Unwrap(context.Background(), wrapped, aad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("roundtrip failed")
	}
	f.mu.Lock()
	contextValue := f.requests["/v1/transit/encrypt/key"]["context"]
	decryptContext := f.requests["/v1/transit/decrypt/key"]["context"]
	f.mu.Unlock()
	if contextValue != base64.StdEncoding.EncodeToString(aad) || decryptContext != contextValue {
		t.Fatal("context wire encoding differs")
	}
	for _, bad := range [][]byte{nil, []byte("wrong-context")} {
		if result, err := p.Unwrap(context.Background(), wrapped, bad); err == nil || result != nil {
			t.Fatal("wrong context accepted")
		}
	}
	otherID, _ := CanonicalKeyID("https://vault.example", "other")
	q, err := p.client.Provider(context.Background(), otherID)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := q.Unwrap(context.Background(), wrapped, aad); result != nil || err == nil {
		t.Fatal("other key accepted")
	}
	before := f.count("/v1/transit/encrypt/key")
	if result, err := p.Wrap(context.Background(), plain, nil); result != nil || err == nil {
		t.Fatal("empty AAD accepted")
	}
	if f.count("/v1/transit/encrypt/key") != before {
		t.Fatal("empty AAD sent")
	}
	for _, body := range []string{`{}`, `{"data":{"ciphertext":"vault:v0:eA==","plaintext":""}}`, `{"data":{"ciphertext":"bad","plaintext":"%%%"}}`, `not-json`} {
		f.change(func() { f.badData = body })
		if v, e := p.Wrap(context.Background(), plain, aad); e == nil || v != nil {
			t.Fatal("malformed ciphertext accepted")
		}
		if v, e := p.Unwrap(context.Background(), wrapped, aad); e == nil || v != nil {
			t.Fatal("malformed plaintext accepted")
		}
	}
}
func TestVaultPreflight(t *testing.T) {
	for _, problem := range []string{"non-derived", "encrypt", "decrypt", "empty-metadata"} {
		t.Run(problem, func(t *testing.T) {
			f, s := fixtureServer(t)
			c := fixtureClient(t, f, s, wallClock{})
			f.change(func() {
				switch problem {
				case "non-derived":
					f.derived = false
				case "empty-metadata":
					f.badData = `{}`
				default:
					f.denied = "/" + problem + "/"
				}
			})
			id, _ := CanonicalKeyID("https://vault.example", "key")
			p, err := c.Provider(context.Background(), id)
			if p != nil || err == nil {
				t.Fatal("preflight failure published provider")
			}
		})
	}
	t.Run("canceled-no-metadata", func(t *testing.T) {
		f, s := fixtureServer(t)
		c := fixtureClient(t, f, s, wallClock{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		id, _ := CanonicalKeyID("https://vault.example", "key")
		if p, e := c.Provider(ctx, id); p != nil || e == nil {
			t.Fatal("canceled preflight accepted")
		}
		if f.count("/v1/transit/keys/key") != 0 {
			t.Fatal("canceled preflight sent")
		}
	})
}
func TestVaultReEncryptNative(t *testing.T) {
	f, p := fixtureProvider(t)
	aad := crypto.DEKAAD("data", 1)
	plain := bytes.Repeat([]byte{4}, 32)
	wrapped, err := p.Wrap(context.Background(), plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	before := f.count("/v1/transit/decrypt/key")
	f.change(func() { f.version = 2 })
	updated, err := p.ReEncrypt(context.Background(), wrapped, aad, p)
	if err != nil || !strings.HasPrefix(string(updated), "vault:v2:") {
		t.Fatal("native rewrap failed")
	}
	if f.count("/v1/transit/decrypt/key") != before || f.count("/v1/transit/rewrap/key") != 1 {
		t.Fatal("native rewrap disclosed plaintext")
	}
	got, err := p.Unwrap(context.Background(), updated, aad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("rewrap changed plaintext")
	}
	f.mu.Lock()
	value := f.requests["/v1/transit/rewrap/key"]["context"]
	f.mu.Unlock()
	if value != base64.StdEncoding.EncodeToString(aad) {
		t.Fatal("rewrap context differs")
	}
}

type sourceFixture struct {
	crypto.KEKProvider
	plain []byte
	err   error
	block bool
	calls int
	aad   []byte
}

func (s *sourceFixture) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	s.calls++
	s.aad = append([]byte(nil), aad...)
	if s.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.plain, s.err
}
func TestVaultReEncryptFallback(t *testing.T) {
	f, p := fixtureProvider(t)
	aad := crypto.DEKAAD("data", 1)
	source := &sourceFixture{plain: bytes.Repeat([]byte{7}, 32)}
	result, err := p.ReEncrypt(context.Background(), []byte("source-blob"), aad, source)
	if err != nil || len(result) == 0 || source.calls != 1 || !bytes.Equal(source.aad, aad) {
		t.Fatal("fallback failed")
	}
	if !bytes.Equal(source.plain, make([]byte, 32)) {
		t.Fatal("intermediate not cleared")
	}
	if f.count("/v1/transit/rewrap/key") != 0 {
		t.Fatal("fallback used native rewrap")
	}
	id, _ := CanonicalKeyID("https://vault.example", "other")
	q, err := p.client.Provider(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.ReEncrypt(context.Background(), result, aad, p); err != nil {
		t.Fatal(err)
	}
	if f.count("/v1/transit/rewrap/other") != 0 {
		t.Fatal("different key used native rewrap")
	}
}
func TestVaultReEncryptFailure(t *testing.T) {
	f, p := fixtureProvider(t)
	aad := crypto.DEKAAD("data", 1)
	before := f.count("/v1/transit/encrypt/key")
	source := &sourceFixture{plain: bytes.Repeat([]byte{7}, 32), err: errors.New("sensitive-dek")}
	result, err := p.ReEncrypt(context.Background(), []byte("source"), aad, source)
	if result != nil || err == nil || strings.Contains(err.Error(), "sensitive") || f.count("/v1/transit/encrypt/key") != before {
		t.Fatal("source failure continued or leaked")
	}
	if !bytes.Equal(source.plain, make([]byte, 32)) {
		t.Fatal("error material not cleared")
	}
	f.change(func() { f.denied = "/encrypt/" })
	source = &sourceFixture{plain: bytes.Repeat([]byte{7}, 32)}
	if result, err = p.ReEncrypt(context.Background(), []byte("source"), aad, source); err == nil || result != nil || !bytes.Equal(source.plain, make([]byte, 32)) {
		t.Fatal("target failure accepted or retained material")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	source = &sourceFixture{block: true}
	if result, err = p.ReEncrypt(ctx, []byte("source"), aad, source); err == nil || result != nil {
		t.Fatal("timeout accepted")
	}
	source = &sourceFixture{}
	if _, err = p.ReEncrypt(context.Background(), nil, nil, source); err == nil || source.calls != 0 {
		t.Fatal("empty AAD reached source")
	}
}
