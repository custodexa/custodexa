// Package testkit exercises the production authentication paths against a dev target.
package testkit

import (
	"bytes"
	"context"
	"errors"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/sshmaterial"
	"github.com/custodexa/backend/internal/testgate"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

type Dial func(context.Context, string, int, string, *material.Secret, *sshmaterial.Password, ssh.HostKeyCallback) (*ssh.Client, func(), error)

func Run(t *testing.T, integration bool, dial Dial, checks ...func(*ssh.Client) error) {
	t.Helper()
	target := os.Getenv("UNSEAL_SSH_TARGET")
	if integration {
		target = testgate.Value(t, "UNSEAL_SSH_TARGET")
	}
	if target == "" {
		target = "ssh-test:2222"
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	user := os.Getenv("UNSEAL_SSH_USER")
	if user == "" {
		user = "testuser"
	}
	secret := os.Getenv("UNSEAL_SSH_PASSWORD")
	if secret == "" {
		secret = "testpass123"
	}
	modes := []string{"success", "wrong_password"}
	if !integration {
		modes = append(modes, "cancelled", "no_callback")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			// Let the dev SSH source-address penalty expire between rejected attempts.
			if mode == "wrong_password" || mode == "no_callback" {
				defer time.Sleep(20 * time.Second)
			}
			raw := []byte(secret)
			if mode == "wrong_password" {
				raw = []byte("deliberately-invalid-authentication")
			}
			owner := material.Adopt(raw)
			password := sshmaterial.NewPassword(owner)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			key := ssh.InsecureIgnoreHostKey()
			if mode == "cancelled" {
				cancel()
			}
			if mode == "no_callback" {
				key = func(string, net.Addr, ssh.PublicKey) error { return errors.New("test host key rejection") }
			}
			client, closeFn, err := dial(ctx, host, port, user, owner, password, key)
			if closeFn != nil {
				defer closeFn()
			}
			if !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("authentication owner not zero after Dial")
			}
			expected := int64(1)
			if mode == "cancelled" || mode == "no_callback" {
				expected = 0
			}
			if password.Calls() != expected {
				t.Fatalf("callback count=%d want=%d handshake_error=%v", password.Calls(), expected, err)
			}
			if mode == "success" {
				if err != nil {
					t.Fatalf("handshake failed: %v", err)
				}
				for _, check := range checks {
					if e := check(client); e != nil {
						t.Fatal(e)
					}
				}
				session, e := client.NewSession()
				if e != nil {
					t.Fatal(e)
				}
				defer session.Close()
				command := "sleep 1; true"
				if integration {
					command = "sleep 10; true"
				}
				if e = session.Run(command); e != nil {
					t.Fatal(e)
				}
			} else if err == nil {
				t.Fatal("expected rejection")
			}
			t.Logf("EVIDENCE %s callbacks=%d owner_zero=true session_usable=%t dependency=x/crypto@v0.55.0", mode, password.Calls(), mode == "success")
		})
	}
}
