package localpty

import (
	"bytes"
	"errors"
	"github.com/custodexa/backend/internal/material"
	"testing"
)

func TestPromptPasswordZeroize(t *testing.T) {
	for _, mode := range []string{"written", "write_failed", "no_prompt", "closed"} {
		t.Run(mode, func(t *testing.T) {
			raw := []byte("prompt-sentinel")
			owner := material.Adopt(raw)
			var sent []byte
			a := newPromptAuth(PasswordAuth{Password: owner, Prompt: "Password:"}, nil, func(p []byte) (int, error) {
				if !bytes.Equal(p, []byte("prompt-sentinel\n")) {
					t.Fatal("incorrect injection")
				}
				sent = p
				if mode == "write_failed" {
					return 0, errors.New("write failed")
				}
				return len(p), nil
			})
			switch mode {
			case "no_prompt":
				a.process([]byte("ready"))
			case "closed":
				(&Conn{auth: a}).Close()
			default:
				a.process([]byte("Password:"))
			}
			if !bytes.Equal(raw, make([]byte, len(raw))) || !bytes.Equal(sent, make([]byte, len(sent))) {
				t.Fatal("source or injection buffer not zero")
			}
		})
	}
}
