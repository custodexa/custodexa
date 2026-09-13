package vaulttransit

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestVaultKeyRef(t *testing.T) {
	first, err := CanonicalKeyID("https://VAULT.Example:443/", "key_1-A")
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalKeyID("https://vault.example", "key_1-A")
	if err != nil || first != second {
		t.Fatal("equivalent origins differ")
	}
	origin, name, err := ParseKeyID(first)
	if err != nil || origin != "https://vault.example" || name != "key_1-A" {
		t.Fatal("canonical roundtrip failed")
	}
	other, _ := CanonicalKeyID("https://other.example", "key_1-A")
	if first == other {
		t.Fatal("different origins collided")
	}
	for _, address := range []string{"http://vault.example", "https://user:secret@vault.example", "https://vault.example/transit", "https://vault.example?", "https://vault.example#", "https://vault.example/%2f", "https://vault.example:0", "https://vault.example:65536", "https://-invalid.example", "https://vault.example:", "https://vault.example\\evil"} {
		t.Run("reject-origin-"+address, func(t *testing.T) {
			if id, err := CanonicalKeyID(address, "key"); err == nil || id != "" {
				t.Fatal("unsafe origin accepted")
			}
		})
	}
	for _, name := range []string{"", "../key", "key/name", "key:2", "key%2fother", strings.Repeat("a", 256)} {
		if id, err := CanonicalKeyID("https://vault.example", name); err == nil || id != "" {
			t.Fatal("invalid or oversized key accepted")
		}
	}
	for _, id := range []string{first + ":v1", strings.Replace(first, "transit:", "other:", 1), "vault:" + base64.RawURLEncoding.EncodeToString([]byte("https://VAULT.example:443/")) + ":transit:key", "vault:bad=:transit:key"} {
		if _, _, err := ParseKeyID(id); err == nil {
			t.Fatal("noncanonical reference accepted")
		}
	}
	t.Run("column-length-boundary", func(t *testing.T) {
		prefix, _ := CanonicalKeyID("https://vault.example", "x")
		name := strings.Repeat("x", MaxKeyIDBytes-len(prefix)+1)
		id, err := CanonicalKeyID("https://vault.example", name)
		if err != nil || len(id) != MaxKeyIDBytes {
			t.Fatal("valid boundary rejected")
		}
		if _, err := CanonicalKeyID("https://vault.example", name+"x"); err == nil {
			t.Fatal("oversized persisted reference accepted")
		}
	})
}

func TestVaultKeyRefScope(t *testing.T) {
	scope, current, err := ResolveScope("https://VAULT.example:443/", "current")
	if err != nil {
		t.Fatal(err)
	}
	same, id, err := ResolveScope("https://vault.example", current)
	if err != nil || same != scope || id != current {
		t.Fatal("deployment aliases differ")
	}
	target, _ := CanonicalKeyID("https://vault.example", "different-key")
	if _, err := scope.ResolveKey(target); err != nil {
		t.Fatal("scope incorrectly restricts key identity")
	}
	foreign, _ := CanonicalKeyID("https://other.example", "current")
	if _, err := scope.ResolveKey(foreign); !errors.Is(err, ErrOutsideScope) {
		t.Fatal("foreign origin accepted")
	}
	if _, _, err := ResolveScope("https://vault.example", foreign); !errors.Is(err, ErrOutsideScope) {
		t.Fatal("inconsistent deployment accepted")
	}
	if _, err := (Scope{}).ResolveKey(target); !errors.Is(err, ErrOutsideScope) {
		t.Fatal("zero scope accepted")
	}
	if _, _, err := ResolveScope("https://vault.example", ""); err == nil {
		t.Fatal("missing deployment anchor accepted")
	}
}
