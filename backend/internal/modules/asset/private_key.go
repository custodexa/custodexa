package asset

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // 只用於辨識既有的 DSA 私鑰型別，不產生也不簽署
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ErrPrivateKeyInvalid 私鑰無法解析為可用的簽章金鑰（格式錯誤、內容不完整、
// 貼成公鑰、受 passphrase 保護、內含的公鑰與私鑰本體不相符等）。
//
// 寫入時驗證、終端撥號、SFTP 撥號與連線測試共用這一個 sentinel 與判準：
// 驗證與連線用同一個解析函式，才不會出現「建立時擋下、實際連得上」或反過來的情形。
var ErrPrivateKeyInvalid = errors.New("私鑰無法解析")

// errKeyPairMismatch 私鑰本體推導出的公鑰與解析器回報的公鑰不同，或簽章無法以該公鑰驗證。
var errKeyPairMismatch = errors.New("私鑰與其公鑰不相符")

// ParsePrivateKey 將私鑰解析為 SSH signer；失敗時回包裝 ErrPrivateKeyInvalid 的錯誤。
//
// 系統不支援受 passphrase 保護的私鑰，故一律以不帶 passphrase 的方式解析。
// 庫的原始錯誤只包進 error 供伺服端日誌，呼叫端不得把它放進對外回應。
func ParsePrivateKey(raw []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPrivateKeyInvalid, err)
	}
	return signer, nil
}

// ValidatePrivateKey 供人工輸入私鑰的寫入路徑在加密落庫前檢查，並回傳該私鑰對應的公鑰
// （authorized_keys 行的型別與 base64 兩段，不含註解）。
// 空字串回 ("", nil)：是否必填、空值是否代表沿用現行私鑰，由呼叫端判斷。
//
// 回傳的公鑰會成為對外的公鑰指紋，所以只回傳能由私鑰本體確定的公鑰：RSA、ECDSA 與 Ed25519
// 由私鑰本體重新推導公鑰，與檔案內記載的公鑰比對，不同即以 ErrPrivateKeyInvalid 拒絕。
// 無法由私鑰本體確定公鑰的型別（DSA）照常接受，但回空字串，該版本即沒有公鑰、不提供指紋。
func ValidatePrivateKey(pem string) (string, error) {
	if pem == "" {
		return "", nil
	}
	signer, err := ParsePrivateKey([]byte(pem))
	if err != nil {
		return "", err
	}
	pub, err := consistentPublicKey([]byte(pem), signer)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrPrivateKeyInvalid, err)
	}
	if pub == nil {
		return "", nil
	}
	return authorizedKeyType(pub), nil
}

// consistentPublicKey 由私鑰本體推導公鑰，並確認它與解析器回報的公鑰相同、且簽章可以它驗證。
//
// 回 (nil, nil) 表示此型別不提供公鑰（DSA 與其他無法由私鑰本體確定公鑰的型別）：
// 這類私鑰照常可用於連線，只是不保存公鑰、不回報指紋。
func consistentPublicKey(raw []byte, signer ssh.Signer) (ssh.PublicKey, error) {
	key, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errKeyPairMismatch, err)
	}
	derived, supported, err := derivePublicKey(key)
	if err != nil {
		return nil, err
	}
	if !supported {
		return nil, nil
	}
	pub, err := ssh.NewPublicKey(derived)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errKeyPairMismatch, err)
	}
	if !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
		return nil, errKeyPairMismatch
	}
	if err := verifyKeyPairConsistent(signer); err != nil {
		return nil, err
	}
	return pub, nil
}

// derivePublicKey 由私鑰本體得出公鑰。supported 為假表示此型別不提供公鑰。
func derivePublicKey(key any) (pub any, supported bool, err error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		// 模數須等於質因數乘積、私鑰指數須與公鑰指數互逆：公鑰 (N, E) 因此由私鑰本體決定
		if err := k.Validate(); err != nil {
			return nil, false, fmt.Errorf("%w: %v", errKeyPairMismatch, err)
		}
		return &k.PublicKey, true, nil
	case *ecdsa.PrivateKey:
		// 以私鑰純量重新算出公鑰點，與記載的公鑰點比對
		priv, err := k.ECDH()
		if err != nil {
			return nil, false, fmt.Errorf("%w: %v", errKeyPairMismatch, err)
		}
		recorded, err := k.PublicKey.ECDH()
		if err != nil {
			return nil, false, fmt.Errorf("%w: %v", errKeyPairMismatch, err)
		}
		if !priv.PublicKey().Equal(recorded) {
			return nil, false, errKeyPairMismatch
		}
		return &k.PublicKey, true, nil
	case ed25519.PrivateKey:
		return deriveEd25519(k)
	case *ed25519.PrivateKey:
		if k == nil {
			return nil, false, errKeyPairMismatch
		}
		return deriveEd25519(*k)
	case *dsa.PrivateKey:
		// 參數的有效性無法由解析器保證，公鑰不一定由私鑰本體決定
		return nil, false, nil
	default:
		return nil, false, nil
	}
}

// deriveEd25519 以種子重新推導公鑰，與私鑰內記載的公鑰逐位元組比對。
func deriveEd25519(k ed25519.PrivateKey) (any, bool, error) {
	if len(k) != ed25519.PrivateKeySize {
		return nil, false, errKeyPairMismatch
	}
	derived := ed25519.NewKeyFromSeed(k.Seed()).Public().(ed25519.PublicKey)
	if !bytes.Equal(derived, k[ed25519.SeedSize:]) {
		return nil, false, errKeyPairMismatch
	}
	return derived, true, nil
}

// verifyKeyPairConsistent 以私鑰簽、以其公鑰驗；作為推導比對之外的第二道確認。
func verifyKeyPairConsistent(signer ssh.Signer) error {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("產生驗證資料失敗: %w", err)
	}
	sig, err := signer.Sign(rand.Reader, challenge)
	if err != nil {
		return fmt.Errorf("%w: %v", errKeyPairMismatch, err)
	}
	if err := signer.PublicKey().Verify(challenge, sig); err != nil {
		return fmt.Errorf("%w: %v", errKeyPairMismatch, err)
	}
	return nil
}

// authorizedKeyType 公鑰的 authorized_keys 表示（型別與 base64 兩段，不含註解）。
func authorizedKeyType(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// fingerprintKeyType 提供公鑰指紋的金鑰型別：公鑰能由私鑰本體確定者。
func fingerprintKeyType(keyType string) bool {
	switch keyType {
	case ssh.KeyAlgoRSA, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoED25519:
		return true
	}
	return false
}

// versionPublicKeyFromPlaintext 由既有流程已持有的私鑰明文取得版本列要保存的公鑰。
//
// 用於系統產生或候選轉正等路徑：流程本來就為了加密成新版本而持有明文，在同一處取得公鑰
// 不構成新的解密途徑。取不到（解析失敗、公私鑰不一致或型別不提供公鑰）時回空字串，
// 該版本的公鑰即為未知；呼叫端不得改以其他版本的公鑰代替。
func versionPublicKeyFromPlaintext(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return ""
	}
	pub, err := consistentPublicKey(raw, signer)
	if err != nil || pub == nil {
		return ""
	}
	return authorizedKeyType(pub)
}

// versionPublicKeyFromLine 由 authorized_keys 行取型別與 base64 兩段（去掉註解）；
// 行格式不合或型別不提供指紋時回空字串。
func versionPublicKeyFromLine(line string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || !fingerprintKeyType(pub.Type()) {
		return ""
	}
	return authorizedKeyType(pub)
}

// PrivateKeyFingerprint 由版本列保存的公鑰計算對外的公鑰指紋（SHA256: 開頭）。
// 公鑰為空、無法解析或型別不提供指紋時回空字串（未知）；不解密任何私鑰。
func PrivateKeyFingerprint(publicKey string) string {
	if strings.TrimSpace(publicKey) == "" {
		return ""
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil || !fingerprintKeyType(pub.Type()) {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}
