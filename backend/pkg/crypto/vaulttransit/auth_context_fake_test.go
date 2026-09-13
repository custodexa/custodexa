package vaulttransit

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/custodexa/backend/pkg/crypto"
)

// Scenario names match the real fixture entry; neither entry substitutes for the other.
func TestVaultAuthContextFake(t *testing.T) {
	for _, name := range []string{"login", "renewal", "derived-context", "other-key", "revocation", "lease-expiry"} {
		t.Run(name, func(t *testing.T) {
			f, server := fixtureServer(t)
			clk := newFakeClock()
			if name == "lease-expiry" {
				f.change(func() { f.renewable = false })
			}
			c := fixtureClient(t, f, server, clk)
			id, _ := CanonicalKeyID("https://vault.example", "key")
			p, err := c.Provider(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			plain, aad := bytes.Repeat([]byte{29}, 32), crypto.DEKAAD("data", 1)
			wrapped, err := p.Wrap(context.Background(), plain, aad)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "login":
				if f.count("/v1/auth/approle/login") != 1 {
					t.Fatal("login count differs")
				}
			case "renewal":
				waitFor(t, clk.ready)
				clk.advance(10 * time.Second)
				waitFor(t, func() bool { return f.count("/v1/auth/token/renew-self") == 1 })
				if got, err := p.Unwrap(context.Background(), wrapped, aad); err != nil || !bytes.Equal(got, plain) {
					t.Fatal("renewed token unusable")
				}
			case "derived-context":
				if got, err := p.Unwrap(context.Background(), wrapped, crypto.DEKAAD("data", 2)); err == nil || got != nil {
					t.Fatal("wrong context accepted")
				}
			case "other-key":
				otherID, _ := CanonicalKeyID("https://vault.example", "other")
				other, err := c.Provider(context.Background(), otherID)
				if err != nil {
					t.Fatal(err)
				}
				foreign, err := other.Wrap(context.Background(), plain, aad)
				if err != nil {
					t.Fatal(err)
				}
				if got, err := p.Unwrap(context.Background(), foreign, aad); err == nil || got != nil {
					t.Fatal("foreign cipher accepted")
				}
				f.change(func() { f.denied, f.deniedStatus, f.loginStatus = "/keys/other", 403, 400 })
				if got, err := c.Provider(context.Background(), otherID); err == nil || got != nil {
					t.Fatal("foreign policy accepted")
				}
			case "revocation":
				f.change(func() { f.denied, f.deniedStatus, f.loginStatus = "/encrypt/", 403, 400 })
				if got, err := p.Wrap(context.Background(), plain, aad); err == nil || got != nil {
					t.Fatal("revoked token accepted")
				}
				waitFor(t, func() bool {
					select {
					case <-c.done:
						return true
					default:
						return false
					}
				})
				if f.count("/v1/auth/approle/login") != 2 {
					t.Fatal("re-login count differs")
				}
			case "lease-expiry":
				f.change(func() { f.loginStatus = 400 })
				waitFor(t, clk.ready)
				clk.advance(20 * time.Second)
				waitFor(t, func() bool {
					select {
					case <-c.done:
						return true
					default:
						return false
					}
				})
				before := f.count("/v1/transit/encrypt/key")
				if got, err := p.Wrap(context.Background(), plain, aad); err == nil || got != nil {
					t.Fatal("expired client accepted operation")
				}
				if f.count("/v1/auth/token/renew-self") != 0 || f.count("/v1/auth/approle/login") != 2 || f.count("/v1/transit/encrypt/key") != before {
					t.Fatal("expiry boundary differs")
				}
			}
		})
	}
}
