package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	// ErrInvalidKey 金鑰無效
	ErrInvalidKey = errors.New("加密金鑰長度必須為 32 bytes (AES-256)")
	// ErrInvalidCiphertext 密文無效
	ErrInvalidCiphertext = errors.New("密文格式無效")
	// ErrAADRequired 未帶 AAD 綁定的加解密請求（release-transitional-cleanup P2 M1）。
	//
	// 無 AAD 的寫出／讀取入口（Encrypt／Decrypt／EncryptBytes／DecryptBytes）已整組
	// 刪除；本錯誤封住最後一條退化路徑——「帶 AAD 的方法但傳 nil 進去」。兩者合起來
	// 使「寫入端不可能產出無 AAD 密文」成為**原語層的建構事實**，而非靠守衛測試
	// 或呼叫端自律維持的承諾。
	ErrAADRequired = errors.New("AES-GCM 加解密一律須帶 AAD 綁定：空 AAD 無寫出與讀取路徑")
)

// AESCrypto AES-256-GCM 加密服務。
//
// **本型別只有帶 AAD 的入口**：無 AAD 的 Encrypt／Decrypt／EncryptBytes／
// DecryptBytes 已於 release-transitional-cleanup P2 M1 刪除。需要製造無 AAD
// 密文的負向測試 fixture 一律由測試層以 stdlib（crypto/aes＋cipher.NewGCM）
// 自備，故該能力不存在於任何生產可達的路徑上。
type AESCrypto struct {
	key []byte
}

// NewAESCrypto 創建 AES 加密服務
// key 必須為 32 bytes (AES-256)
func NewAESCrypto(key []byte) (*AESCrypto, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	return &AESCrypto{key: key}, nil
}

// EncryptBytesAAD 加密位元組並綁定 additional authenticated data，
// 回傳 nonce + ciphertext（無編碼）。
//
// **len(aad)==0（nil 或空切片）一律回 ErrAADRequired、不執行加密**——
// 否則「傳 nil 進來」就等同復活已刪除的無 AAD 寫出能力。
// aad 不入密文——解密端須自行重建同一份 aad。
func (c *AESCrypto) EncryptBytesAAD(plaintext, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 生成隨機 nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// 加密 (nonce 會被自動 prepend)
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// DecryptBytesAAD 解密並驗證 aad；aad 不符即 GCM 驗證失敗（不回明文）。
//
// **len(aad)==0 一律回 ErrAADRequired、不執行解密**：無 AAD 密文在終態下不存在，
// 讀端亦不得保留「以空 AAD 試一次」的路徑（那正是 fallback 的入口形狀）。
func (c *AESCrypto) DecryptBytesAAD(data, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, encryptedData := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, encryptedData, aad)
}
