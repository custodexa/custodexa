package asset

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// 測試用鑰匙一律於執行期產生，不入庫存檔。

func genEd25519OpenSSHPEM(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "test")
	require.NoError(t, err)
	return string(pem.EncodeToMemory(block)), priv
}

func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func TestPrivateKeyAcceptsUnencryptedFormats(t *testing.T) {
	edPEM, _ := genEd25519OpenSSHPEM(t)

	rsaPEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(genRSAKey(t)),
	}))

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))

	cases := map[string]string{
		"Ed25519_OpenSSH": edPEM,
		"RSA_PKCS1":       rsaPEM,
		"ECDSA_PKCS8":     ecPEM,
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			signer, err := ParsePrivateKey([]byte(key))
			require.NoError(t, err)
			require.NotNil(t, signer)
			require.NoError(t, ValidatePrivateKey(key))
		})
	}
}

func TestPrivateKeyRejectsUnparsable(t *testing.T) {
	edPEM, edPriv := genEd25519OpenSSHPEM(t)

	edEncBlock, err := ssh.MarshalPrivateKeyWithPassphrase(edPriv, "test", []byte("secret-phrase"))
	require.NoError(t, err)
	edEncrypted := string(pem.EncodeToMemory(edEncBlock))

	rsaEncBlock, err := ssh.MarshalPrivateKeyWithPassphrase(genRSAKey(t), "test", []byte("secret-phrase"))
	require.NoError(t, err)
	rsaEncrypted := string(pem.EncodeToMemory(rsaEncBlock))

	pub, err := ssh.NewPublicKey(edPriv.Public())
	require.NoError(t, err)
	publicKeyLine := string(ssh.MarshalAuthorizedKey(pub))

	cases := map[string]string{
		"Malformed":          "not a private key",
		"Truncated":          edPEM[:len(edPEM)/2],
		"PublicKeyPasted":    publicKeyLine,
		"Ed25519_Passphrase": edEncrypted,
		"RSA_Passphrase":     rsaEncrypted,
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			signer, err := ParsePrivateKey([]byte(key))
			require.Nil(t, signer)
			require.True(t, errors.Is(err, ErrPrivateKeyInvalid), "ParsePrivateKey 須回 ErrPrivateKeyInvalid，得 %v", err)
			require.True(t, errors.Is(ValidatePrivateKey(key), ErrPrivateKeyInvalid))
		})
	}
}

func TestPrivateKeyValidateEmptyIsNil(t *testing.T) {
	require.NoError(t, ValidatePrivateKey(""))
}
