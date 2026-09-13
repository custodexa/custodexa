package asset

import (
	"bytes"
	"context"
	"github.com/custodexa/backend/internal/material"
	"io"
	"testing"
	"time"
)

func TestRotationStdinZeroize(t *testing.T) {
	for _, kind := range []string{"root", "sudo", "windows"} {
		for _, early := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/written", true: "/failed"}[early], func(t *testing.T) {
				old, next := []byte("old-sentinel"), []byte("new-sentinel")
				oldOwner, newOwner := material.Adopt(old), material.Adopt(next)
				err := withProtocolPair(oldOwner, newOwner, func(a, b []byte) error {
					var raw []byte
					switch kind {
					case "root":
						raw = rotationStdin("root", a, b)
					case "sudo":
						raw = rotationStdin("user", a, b)
					case "windows":
						raw = windowsRotationStdin(b, a, "user")
					}
					if !bytes.Contains(raw, b) {
						t.Fatal("new secret missing from stdin")
					}
					if kind != "root" && !bytes.Contains(raw, a) {
						t.Fatal("old secret missing before last use")
					}
					input := newSecretInput(raw)
					if !early {
						if _, e := io.Copy(io.Discard, input); e != nil {
							return e
						}
					}
					input.Close()
					if !bytes.Equal(raw, make([]byte, len(raw))) {
						t.Fatal("stdin not zero")
					}
					if !bytes.Equal(a, []byte("old-sentinel")) || !bytes.Equal(b, []byte("new-sentinel")) {
						t.Fatal("flow owner erased before verify or restore")
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				oldOwner.Destroy()
				newOwner.Destroy()
				if !bytes.Equal(old, make([]byte, len(old))) || !bytes.Equal(next, make([]byte, len(next))) {
					t.Fatal("flow owner not zero")
				}
			})
		}
	}
}
func TestNonSSHMaterialLifetime(t *testing.T) {
	f := newFakeWinRMServer(t, "old")
	raw := []byte("old")
	owner := material.Adopt(raw)
	err := owner.Borrow(func(auth []byte) error {
		session, e := newWinRMSession(context.Background(), winrmTarget(f).asset, "Administrator", auth, f.security, 5*time.Second)
		if e != nil {
			return e
		}
		stdin := windowsRotationStdin([]byte("next"), auth, "Administrator")
		out := session.run(buildWindowsCommand(windowsRotationScript), stdin, 5*time.Second, 5*time.Second)
		if !bytes.Equal(stdin, make([]byte, len(stdin))) {
			t.Fatal("WS-Man stdin not zero")
		}
		if session.tr.password != nil {
			t.Fatal("transport retains password reference")
		}
		if !bytes.Equal(auth, []byte("old")) {
			t.Fatal("flow source erased before verification")
		}
		return out.err
	})
	owner.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatal("source not zero")
	}
}
