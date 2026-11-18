package asset

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
			_, verr := ValidatePrivateKey(key)
			require.NoError(t, verr)
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
			_, verr := ValidatePrivateKey(key)
			require.True(t, errors.Is(verr, ErrPrivateKeyInvalid))
		})
	}
}

func TestPrivateKeyValidateEmptyIsNil(t *testing.T) {
	pub, err := ValidatePrivateKey("")
	require.NoError(t, err)
	require.Empty(t, pub)
}

// --- 公鑰取得與公私鑰一致性 ---

// wireFingerprint 以 RFC 4253 的線路格式手工組出公鑰位元組後計算 SHA256 指紋。
// 不經 ssh 套件的私鑰解析器與指紋函式，作為「預期值」的獨立來源。
func wireFingerprint(parts ...[]byte) string {
	var buf []byte
	for _, p := range parts {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		buf = append(buf, l[:]...)
		buf = append(buf, p...)
	}
	sum := sha256.Sum256(buf)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ed25519WireFingerprint Ed25519 公鑰的預期指紋（型別字串＋32 位元組公鑰）。
func ed25519WireFingerprint(pub ed25519.PublicKey) string {
	return wireFingerprint([]byte("ssh-ed25519"), pub)
}

// mpint RFC 4251 的 mpint 編碼（正整數，最高位為 1 時補一個零位元組）。
func mpint(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) > 0 && b[0]&0x80 != 0 {
		return append([]byte{0}, b...)
	}
	return b
}

// rsaWireFingerprint RSA 公鑰的預期指紋（型別、e、n）。
func rsaWireFingerprint(pub *rsa.PublicKey) string {
	e := big.NewInt(int64(pub.E)).Bytes()
	return wireFingerprint([]byte("ssh-rsa"), mpint(e), mpint(pub.N.Bytes()))
}

// ecdsaP256WireFingerprint ECDSA P-256 公鑰的預期指紋（型別、曲線名、未壓縮點）。
func ecdsaP256WireFingerprint(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	point, err := pub.Bytes()
	require.NoError(t, err)
	return wireFingerprint([]byte("ecdsa-sha2-nistp256"), []byte("nistp256"), point)
}

func TestValidatePrivateKeyReturnsMatchingPublicKey(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edBlock, err := ssh.MarshalPrivateKey(edPriv, "test")
	require.NoError(t, err)
	edPKCS8, err := x509.MarshalPKCS8PrivateKey(edPriv)
	require.NoError(t, err)

	rsaKey := genRSAKey(t)
	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	rsaOpenSSH, err := ssh.MarshalPrivateKey(rsaKey, "test")
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	ecSEC1, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	ecOpenSSH, err := ssh.MarshalPrivateKey(ecKey, "test")
	require.NoError(t, err)

	edWant := ed25519WireFingerprint(edPriv.Public().(ed25519.PublicKey))
	rsaWant := rsaWireFingerprint(&rsaKey.PublicKey)
	ecWant := ecdsaP256WireFingerprint(t, &ecKey.PublicKey)

	cases := []struct {
		name, pem, want string
	}{
		{"Ed25519_OpenSSH", string(pem.EncodeToMemory(edBlock)), edWant},
		{"Ed25519_PKCS8", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edPKCS8})), edWant},
		{"RSA_PKCS1", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})), rsaWant},
		{"RSA_PKCS8", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaPKCS8})), rsaWant},
		{"RSA_OpenSSH", string(pem.EncodeToMemory(rsaOpenSSH)), rsaWant},
		{"ECDSA_PKCS8", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecPKCS8})), ecWant},
		{"ECDSA_SEC1", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecSEC1})), ecWant},
		{"ECDSA_OpenSSH", string(pem.EncodeToMemory(ecOpenSSH)), ecWant},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pub, err := ValidatePrivateKey(c.pem)
			require.NoError(t, err)
			require.Len(t, strings.Fields(pub), 2, "公鑰只含型別與 base64 兩段，不含註解：%q", pub)
			assert.Equal(t, c.want, PrivateKeyFingerprint(pub), "指紋須等於由產生時的公鑰獨立算出的值")
			assert.Equal(t, pub, versionPublicKeyFromPlaintext([]byte(c.pem)), "明文路徑取得的公鑰與驗證路徑相同")
		})
	}
}

// mismatchedEd25519PEM 刻意拼湊的 OpenSSH Ed25519 私鑰：私鑰本體取 A 的種子，內含的公鑰取 B。
// 兩把鑰都在測試當下產生，不是任何真實金鑰。
func mismatchedEd25519PEM(t *testing.T) (string, ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	forged := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(forged, privA.Seed())
	copy(forged[ed25519.SeedSize:], pubB)
	block, err := ssh.MarshalPrivateKey(forged, "test")
	require.NoError(t, err)
	return string(pem.EncodeToMemory(block)), pubA, pubB
}

func TestValidatePrivateKeyRejectsMismatchedKeyPair(t *testing.T) {
	forgedPEM, pubA, pubB := mismatchedEd25519PEM(t)

	// 前提：解析器確實接受這把鑰，且回報的是內含的 B 公鑰而非由種子推導的 A——
	// 少了這個前提，下面的拒絕可能只是解析失敗，證明不了一致性檢查有作用
	signer, err := ssh.ParsePrivateKey([]byte(forgedPEM))
	require.NoError(t, err, "PRECONDITION: 解析器應接受拼湊的鑰")
	got := ssh.FingerprintSHA256(signer.PublicKey())
	require.Equal(t, ed25519WireFingerprint(pubB), got, "PRECONDITION: 解析器回報內含的公鑰")
	require.NotEqual(t, ed25519WireFingerprint(pubA), got)

	pub, err := ValidatePrivateKey(forgedPEM)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPrivateKeyInvalid), "以無效私鑰拒絕：%v", err)
	assert.Empty(t, pub)
	assert.Empty(t, versionPublicKeyFromPlaintext([]byte(forgedPEM)), "明文路徑同樣不給公鑰")
}

func TestPrivateKeyFingerprintUnknownInputs(t *testing.T) {
	assert.Empty(t, PrivateKeyFingerprint(""))
	assert.Empty(t, PrivateKeyFingerprint("   "))
	assert.Empty(t, PrivateKeyFingerprint("not-a-key"))
	assert.Empty(t, versionPublicKeyFromPlaintext(nil))
	assert.Empty(t, versionPublicKeyFromPlaintext([]byte("garbage")))
	assert.Empty(t, versionPublicKeyFromLine("garbage"))

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(priv.Public())
	require.NoError(t, err)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " some-comment"
	stripped := versionPublicKeyFromLine(line)
	assert.Len(t, strings.Fields(stripped), 2, "去掉註解")
	assert.Equal(t, ed25519WireFingerprint(priv.Public().(ed25519.PublicKey)), PrivateKeyFingerprint(stripped))
}
