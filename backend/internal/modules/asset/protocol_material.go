package asset

import (
	"github.com/custodexa/backend/internal/material"
	"golang.org/x/crypto/ssh"
	"strings"
)

// Executors borrow bytes until delivery, verification, or restoration returns.
func withProtocolSecret(secret *material.Secret, fn func([]byte) error) error {
	_, err := material.Use(secret, func(raw []byte) (struct{}, error) { return struct{}{}, fn(raw) })
	return err
}
func withProtocolPair(a, b *material.Secret, fn func([]byte, []byte) error) error {
	return withProtocolSecret(a, func(left []byte) error {
		return withProtocolSecret(b, func(right []byte) error { return fn(left, right) })
	})
}

func publicLineFromOwnedKey(key *material.Secret) (string, error) {
	return material.Use(key, func(raw []byte) (string, error) {
		signer, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
	})
}
