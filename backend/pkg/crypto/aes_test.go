package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
)

// testAAD 本檔預設的列身分綁定（內容不重要，只要非空且前後一致）
var testAAD = []byte("assets|password_enc")

// sealNoAAD **測試層 stdlib 助手**：以 crypto/aes＋cipher.NewGCM 直接封出
// 無 AAD 的 nonce+ciphertext。
//
// 為何在測試裡手工封：無 AAD 的寫出能力（AESCrypto.Encrypt／EncryptBytes）已於
// release-transitional-cleanup P2 M1 刪除，EncryptBytesAAD 亦對空 aad 回
// ErrAADRequired——那正是被驗收的事實。負向測試仍需要這種值來模擬「拆除前建立的
// 資料庫」或「繞過 API 的資料庫直寫」，故由測試自備。
//
// **刻意只存在於 _test.go**：生產碼引用不到，故此助手不會反過來成為新的
// 無 AAD 寫出入口。
func sealNoAAD(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

func TestNewAESCrypto(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{"Valid 32 bytes key", 32, false},
		{"Invalid 16 bytes key", 16, true},
		{"Invalid 24 bytes key", 24, true},
		{"Invalid 0 bytes key", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			_, err := NewAESCrypto(key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAESCrypto() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAESCrypto_EncryptDecryptAAD(t *testing.T) {
	// 生成測試金鑰
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	crypto, err := NewAESCrypto(key)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"Empty string", ""},
		{"Simple password", "password123"},
		{"Complex password", "P@ssw0rd!#$%^&*()"},
		{"Long text", "This is a very long password with many characters 你好世界 🔐"},
		{"Unicode", "密碼測試 🔑🔐"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := crypto.EncryptBytesAAD([]byte(tt.plaintext), testAAD)
			if err != nil {
				t.Errorf("EncryptBytesAAD() error = %v", err)
				return
			}

			decrypted, err := crypto.DecryptBytesAAD(ciphertext, testAAD)
			if err != nil {
				t.Errorf("DecryptBytesAAD() error = %v", err)
				return
			}

			if string(decrypted) != tt.plaintext {
				t.Errorf("DecryptBytesAAD() got = %v, want %v", string(decrypted), tt.plaintext)
			}
		})
	}
}

// TestAESCryptoRejectsEmptyAAD 原語層的建構保證（release-transitional-cleanup
// P2 M1）：加解密兩端對 nil 與空切片一律回 ErrAADRequired，且**不執行**加解密
// （回傳值為 nil）。少了這兩格，「無 AAD 寫出能力已刪除」就只是「入口改名」。
func TestAESCryptoRejectsEmptyAAD(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := NewAESCrypto(key)
	if err != nil {
		t.Fatal(err)
	}

	// 一份合法的帶 AAD 密文——用來證明「解密端拒絕」不是因為密文本身壞掉
	valid, err := c.EncryptBytesAAD([]byte("bound"), testAAD)
	if err != nil {
		t.Fatalf("EncryptBytesAAD: %v", err)
	}

	for _, aad := range [][]byte{nil, {}, []byte("")} {
		out, err := c.EncryptBytesAAD([]byte("plain"), aad)
		if !errors.Is(err, ErrAADRequired) {
			t.Fatalf("空 AAD 加密 MUST 回 ErrAADRequired，得 %v", err)
		}
		if out != nil {
			t.Fatalf("空 AAD 加密 MUST NOT 產出密文，得 %x", out)
		}

		plain, err := c.DecryptBytesAAD(valid, aad)
		if !errors.Is(err, ErrAADRequired) {
			t.Fatalf("空 AAD 解密 MUST 回 ErrAADRequired，得 %v", err)
		}
		if plain != nil {
			t.Fatalf("空 AAD 解密 MUST NOT 回明文，得 %q", plain)
		}
	}

	// 無 AAD 密文（測試層 stdlib 封出的發佈前形態）在讀端亦無任何入口可解
	legacy := sealNoAAD(t, key, []byte("legacy"))
	if _, err := c.DecryptBytesAAD(legacy, nil); !errors.Is(err, ErrAADRequired) {
		t.Fatalf("無 AAD 密文 MUST 無讀取路徑，得 %v", err)
	}
	if _, err := c.DecryptBytesAAD(legacy, testAAD); err == nil {
		t.Fatal("無 AAD 密文以任何 AAD 解讀皆 MUST 失敗（GCM 驗證）")
	}
}

func TestAESCrypto_EncryptTwice(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	crypto, err := NewAESCrypto(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("test password")

	// 加密兩次應該產生不同的密文（因為 nonce 是隨機的）
	ciphertext1, err := crypto.EncryptBytesAAD(plaintext, testAAD)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext2, err := crypto.EncryptBytesAAD(plaintext, testAAD)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("兩次加密相同明文應該產生不同密文")
	}

	// 但解密後都應該得到相同明文
	decrypted1, _ := crypto.DecryptBytesAAD(ciphertext1, testAAD)
	decrypted2, _ := crypto.DecryptBytesAAD(ciphertext2, testAAD)

	if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
		t.Error("解密失敗")
	}
}

func TestAESCrypto_DecryptInvalid(t *testing.T) {
	key := make([]byte, 32)
	crypto, _ := NewAESCrypto(key)

	tests := []struct {
		name string
		data []byte
	}{
		{"Nil", nil},
		{"Too short", []byte("a")},
		{"Garbage of valid length", bytes.Repeat([]byte{0xAB}, 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.DecryptBytesAAD(tt.data, testAAD)
			if err == nil {
				t.Error("DecryptBytesAAD() should return error for invalid ciphertext")
			}
		})
	}
}

// TestAESCrypto_WrongAAD AAD 不符即 GCM 驗證失敗（不回明文）
func TestAESCrypto_WrongAAD(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	c, _ := NewAESCrypto(key)

	ct, err := c.EncryptBytesAAD([]byte("secret"), testAAD)
	if err != nil {
		t.Fatalf("EncryptBytesAAD: %v", err)
	}
	if plain, err := c.DecryptBytesAAD(ct, []byte("assets|private_key_enc")); err == nil {
		t.Fatalf("以他欄 AAD 解密竟成功，得 %q", plain)
	}
}

func TestAESCrypto_DifferentKeys(t *testing.T) {
	plaintext := []byte("secret password")

	// 使用 key1 加密
	key1 := make([]byte, 32)
	rand.Read(key1)
	crypto1, _ := NewAESCrypto(key1)
	ciphertext, err := crypto1.EncryptBytesAAD(plaintext, testAAD)
	if err != nil {
		t.Fatalf("EncryptBytesAAD: %v", err)
	}

	// 使用 key2 解密應該失敗
	key2 := make([]byte, 32)
	rand.Read(key2)
	crypto2, _ := NewAESCrypto(key2)
	decrypted, err := crypto2.DecryptBytesAAD(ciphertext, testAAD)

	if err == nil && bytes.Equal(decrypted, plaintext) {
		t.Error("使用不同金鑰解密應該失敗")
	}
}
