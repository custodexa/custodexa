package asset

import (
	"crypto/dsa" //nolint:staticcheck // 測試既有 DSA 私鑰的處理方式
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/model"
)

// 每一種接受的私鑰型別：公鑰由私鑰本體確定者回報與其一致的公鑰；無法確定者照常接受但不回報公鑰。
// 測試金鑰與參數一律於執行期產生。

// dsaPrivateKeyASN1 OpenSSL 傳統 DSA 私鑰（"DSA PRIVATE KEY"）的 ASN.1 結構。
type dsaPrivateKeyASN1 struct {
	Version       int
	P, Q, G, Y, X *big.Int
}

func dsaPEM(t *testing.T, p, q, g, y, x *big.Int) string {
	t.Helper()
	der, err := asn1.Marshal(dsaPrivateKeyASN1{P: p, Q: q, G: g, Y: y, X: x})
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: der}))
}

func genDSAKey(t *testing.T) *dsa.PrivateKey {
	t.Helper()
	var key dsa.PrivateKey
	require.NoError(t, dsa.GenerateParameters(&key.Parameters, rand.Reader, dsa.L1024N160))
	require.NoError(t, dsa.GenerateKey(&key, rand.Reader))
	return &key
}

// singleSignVerifyPasses 只以「簽一次、以檔案內的公鑰驗一次」判定一致的舊作法是否放行。
func singleSignVerifyPasses(signer ssh.Signer) bool {
	return verifyKeyPairConsistent(signer) == nil
}

func TestValidatePrivateKeyDSAAcceptedWithoutPublicKey(t *testing.T) {
	key := genDSAKey(t)
	normal := dsaPEM(t, key.P, key.Q, key.G, key.Y, key.X)

	// 退化參數：G=1、Y=P-1。由 G 與 X 算出的公鑰是 1，與 Y 不符
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(key.P, one)
	require.NotEqual(t, 0, new(big.Int).Exp(one, key.X, key.P).Cmp(pMinus1), "PRECONDITION: Y 與私鑰不相符")
	degenerate := dsaPEM(t, key.P, key.Q, one, pMinus1, key.X)

	// 前提：解析器接受退化參數，且「簽一次驗一次」在有限次數內會放行它——
	// 少了這個前提，下面的斷言證明不了不回報公鑰是必要的
	signer, err := ssh.ParsePrivateKey([]byte(degenerate))
	require.NoError(t, err, "PRECONDITION: 解析器接受退化參數的 DSA 私鑰")
	fooled := false
	for i := 0; i < 64 && !fooled; i++ {
		fooled = singleSignVerifyPasses(signer)
	}
	require.True(t, fooled, "PRECONDITION: 單次簽驗會放行退化參數的 DSA 私鑰")

	for name, k := range map[string]string{"normal": normal, "degenerate": degenerate} {
		t.Run(name, func(t *testing.T) {
			_, err := ParsePrivateKey([]byte(k))
			require.NoError(t, err, "DSA 私鑰照常可解析（既有連線用法不受影響）")
			for i := 0; i < 16; i++ {
				pub, err := ValidatePrivateKey(k)
				require.NoError(t, err, "DSA 私鑰照常接受")
				require.Empty(t, pub, "DSA 私鑰不回報公鑰")
			}
			assert.Empty(t, versionPublicKeyFromPlaintext([]byte(k)), "明文路徑同樣不給公鑰")
		})
	}
}

func TestPrivateKeyFingerprintNotForDSAPublicKey(t *testing.T) {
	key := genDSAKey(t)
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	require.NoError(t, err)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	require.True(t, strings.HasPrefix(line, ssh.KeyAlgoDSA+" "), "PRECONDITION: ssh-dss 公鑰行")
	assert.Empty(t, PrivateKeyFingerprint(line), "ssh-dss 公鑰不回報指紋")
	assert.Empty(t, versionPublicKeyFromLine(line+" comment"), "ssh-dss 公鑰行不保存")
}

func TestValidatePrivateKeyECDSAHigherCurves(t *testing.T) {
	for _, c := range []struct {
		curve      elliptic.Curve
		algo, name string
	}{
		{elliptic.P384(), "ecdsa-sha2-nistp384", "nistp384"},
		{elliptic.P521(), "ecdsa-sha2-nistp521", "nistp521"},
	} {
		key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		require.NoError(t, err)
		point, err := key.PublicKey.Bytes()
		require.NoError(t, err)
		want := wireFingerprint([]byte(c.algo), []byte(c.name), point)

		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		sec1, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		openssh, err := ssh.MarshalPrivateKey(key, "test")
		require.NoError(t, err)
		for format, k := range map[string]string{
			"PKCS8":   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
			"SEC1":    string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})),
			"OpenSSH": string(pem.EncodeToMemory(openssh)),
		} {
			t.Run(c.name+"_"+format, func(t *testing.T) {
				pub, err := ValidatePrivateKey(k)
				require.NoError(t, err)
				assert.Equal(t, want, PrivateKeyFingerprint(pub), "指紋須等於由產生時的公鑰獨立算出的值")
				assert.Equal(t, pub, versionPublicKeyFromPlaintext([]byte(k)))
			})
		}
	}
}

// --- Ed25519：內含公鑰為「真公鑰加上小階點」的拼湊 ---

var (
	ed25519P = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	ed25519D = func() *big.Int {
		num := new(big.Int).Neg(big.NewInt(121665))
		den := new(big.Int).ModInverse(big.NewInt(121666), ed25519P)
		return new(big.Int).Mod(new(big.Int).Mul(num, den), ed25519P)
	}()
)

func edMod(x *big.Int) *big.Int { return x.Mod(x, ed25519P) }

func edInv(x *big.Int) *big.Int { return new(big.Int).ModInverse(x, ed25519P) }

// edDecode 將 32 位元組編碼還原為曲線點（仿射座標）；僅供測試建構輸入。
func edDecode(t *testing.T, b []byte) (x, y *big.Int) {
	t.Helper()
	le := make([]byte, 32)
	copy(le, b)
	sign := le[31] >> 7
	le[31] &= 0x7f
	be := make([]byte, 32)
	for i := range le {
		be[31-i] = le[i]
	}
	y = new(big.Int).SetBytes(be)
	y2 := edMod(new(big.Int).Mul(y, y))
	num := edMod(new(big.Int).Sub(y2, big.NewInt(1)))
	den := edMod(new(big.Int).Add(new(big.Int).Mul(ed25519D, y2), big.NewInt(1)))
	x2 := edMod(new(big.Int).Mul(num, edInv(den)))
	x = new(big.Int).ModSqrt(x2, ed25519P)
	require.NotNil(t, x, "公鑰點可解碼")
	if x.Bit(0) != uint(sign) {
		x = new(big.Int).Sub(ed25519P, x)
	}
	return x, y
}

func edEncode(x, y *big.Int) []byte {
	be := y.FillBytes(make([]byte, 32))
	le := make([]byte, 32)
	for i := range be {
		le[31-i] = be[i]
	}
	if x.Bit(0) == 1 {
		le[31] |= 0x80
	}
	return le
}

// edAdd 扭曲愛德華曲線（a=-1）的仿射加法。
func edAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	x1x2 := new(big.Int).Mul(x1, x2)
	y1y2 := new(big.Int).Mul(y1, y2)
	dxy := edMod(new(big.Int).Mul(ed25519D, new(big.Int).Mul(x1x2, y1y2)))
	x3num := edMod(new(big.Int).Add(new(big.Int).Mul(x1, y2), new(big.Int).Mul(y1, x2)))
	x3den := edMod(new(big.Int).Add(big.NewInt(1), dxy))
	y3num := edMod(new(big.Int).Add(y1y2, x1x2))
	y3den := edMod(new(big.Int).Sub(big.NewInt(1), dxy))
	return edMod(new(big.Int).Mul(x3num, edInv(x3den))), edMod(new(big.Int).Mul(y3num, edInv(y3den)))
}

func TestValidatePrivateKeyRejectsEd25519TorsionOffset(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	// 四階點 (sqrt(-1), 0)
	t4x := new(big.Int).ModSqrt(new(big.Int).Sub(ed25519P, big.NewInt(1)), ed25519P)
	require.NotNil(t, t4x)
	ax, ay := edDecode(t, pubA)
	require.Equal(t, []byte(pubA), edEncode(ax, ay), "PRECONDITION: 測試用的點編解碼正確")
	bx, by := edAdd(ax, ay, t4x, big.NewInt(0))
	pubB := ed25519.PublicKey(edEncode(bx, by))
	require.NotEqual(t, []byte(pubA), []byte(pubB))

	forged := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(forged, privA.Seed())
	copy(forged[ed25519.SeedSize:], pubB)
	block, err := ssh.MarshalPrivateKey(forged, "test")
	require.NoError(t, err)
	forgedPEM := string(pem.EncodeToMemory(block))

	// 前提：解析器接受並回報 B；「簽一次驗一次」在有限次數內會放行這把鑰
	signer, err := ssh.ParsePrivateKey([]byte(forgedPEM))
	require.NoError(t, err, "PRECONDITION: 解析器接受拼湊的鑰")
	require.Equal(t, ed25519WireFingerprint(pubB), ssh.FingerprintSHA256(signer.PublicKey()), "PRECONDITION: 解析器回報內含的 B")
	fooled := false
	for i := 0; i < 64 && !fooled; i++ {
		fooled = singleSignVerifyPasses(signer)
	}
	require.True(t, fooled, "PRECONDITION: 單次簽驗會放行內含公鑰偏移小階點的拼湊鑰")

	for i := 0; i < 16; i++ {
		pub, err := ValidatePrivateKey(forgedPEM)
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrPrivateKeyInvalid), "以無效私鑰拒絕：%v", err)
		require.Empty(t, pub)
	}
	assert.Empty(t, versionPublicKeyFromPlaintext([]byte(forgedPEM)), "明文路徑同樣不給公鑰")
}

// DSA 私鑰經寫入路徑照常保存，版本不帶公鑰、讀取不帶指紋；之後換成 Ed25519 才有指紋。
func TestFingerprintWritePathDSAKeyStoresNoPublicKey(t *testing.T) {
	f := newFPFixture(t)
	key := genDSAKey(t)
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: "fp-dsa", Username: "ops",
		ProtocolFamily: model.ProtocolFamilySSH, PrivateKey: dsaPEM(t, key.P, key.Q, key.G, key.Y, key.X)})
	require.NoError(t, err, "DSA 私鑰照常接受")
	v := f.currentVersion(t, cred.ID)
	require.NotEmpty(t, v.PrivateKeyEnc, "私鑰照常保存")
	assert.Empty(t, v.PublicKey, "DSA 私鑰的版本不保存公鑰")
	got, err := f.creds.Get(adminCtx(), cred.ID)
	require.NoError(t, err)
	assert.Empty(t, got.PrivateKeyFingerprint, "DSA 私鑰沒有指紋")

	k := newFPKey(t)
	_, err = f.creds.SetSecret(adminCtx(), cred.ID, &SetCredentialSecretRequest{PrivateKey: k.pem})
	require.NoError(t, err)
	got, err = f.creds.Get(adminCtx(), cred.ID)
	require.NoError(t, err)
	assert.Equal(t, k.fp, got.PrivateKeyFingerprint, "換成可確定公鑰的型別後回報指紋")
}
