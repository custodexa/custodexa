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

// TestPasswordPromptTerminator redis-cli --askpass 是 raw 讀取、Enter 為 CR；
// psql／mariadb 為 canonical 讀取，維持零值（LF）。
func TestPasswordPromptTerminator(t *testing.T) {
	for proto, want := range map[string]byte{"redis": '\r', "postgres": 0, "mysql": 0, "mssql": 0} {
		got := PasswordPrompt(Target{Protocol: proto, Username: "u", Password: material.Adopt([]byte("x"))}).Terminator
		if got != want {
			t.Errorf("%s Terminator = %q，預期 %q", proto, got, want)
		}
	}
}

func passwordEquals(owner *material.Secret, want string) bool {
	same := false
	_ = owner.Borrow(func(raw []byte) error { same = bytes.Equal(raw, []byte(want)); return nil })
	return same
}
