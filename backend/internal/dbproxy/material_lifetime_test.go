package dbproxy

import (
	"bytes"
	"github.com/custodexa/backend/internal/material"
	"testing"
)

func TestNonSSHMaterialLifetime(t *testing.T) {
	raw := []byte("db-sentinel")
	owner := material.Adopt(raw)
	target := Target{Protocol: "postgres", Host: "db", Username: "user", Password: owner}
	_, args, env, err := BuildCommand(target, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range append(args, env...) {
		if bytes.Contains([]byte(s), raw) {
			t.Fatal("secret in argv or environ")
		}
	}
	if PasswordPrompt(target).Password != owner || owner.IsEmpty() {
		t.Fatal("prompt lost source before injection")
	}
	target.Protocol = "unsupported"
	if c, err := Start(target, 80, 24); err == nil {
		c.Close()
		t.Fatal("expected unsupported protocol")
	}
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatal("failed startup did not erase owner")
	}
}

func passwordEquals(owner *material.Secret, want string) bool {
	same := false
	_ = owner.Borrow(func(raw []byte) error { same = bytes.Equal(raw, []byte(want)); return nil })
	return same
}
