package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
)

// aadTestCodec 測試用 ColumnCodec：以固定金鑰的 AESCrypto 實作帶欄位身分的
// 加解密。AAD 取自 ref.AAD()，與生產路徑（KeyManagerService.EncryptFor）同源，
// 故「跨表／跨欄搬移解不開」在測試替身上同樣成立。
//
// **刻意不提供 Encrypt(plaintext)**：與 crypto.ColumnCodec 的建構保證一致
// ——持有本型別者不可能在測試中寫出無 AAD 密文而讓生產不變式失真。
type aadTestCodec struct{ c *crypto.AESCrypto }

func (a aadTestCodec) EncryptFor(_ context.Context, ref crypto.CipherRef, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if !ref.Valid() {
		return "", fmt.Errorf("測試 codec：列身分不完整 %+v", ref)
	}
	raw, err := a.c.EncryptBytesAAD([]byte(plaintext), ref.AAD())
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func (a aadTestCodec) DecryptFor(_ context.Context, ref crypto.CipherRef, ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if !ref.Valid() {
		return "", fmt.Errorf("測試 codec：列身分不完整 %+v", ref)
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", crypto.ErrInvalidCiphertext
	}
	plain, err := a.c.DecryptBytesAAD(data, ref.AAD())
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// aesColumnCodec 測試用 ColumnCodec（kek-provider-modularization D5 AAD cutover 後
// NewAssetService 改收 crypto.ColumnCodec；生產路徑注入的是信封 key manager）
func aesColumnCodec(t *testing.T, key []byte) crypto.ColumnCodec {
	t.Helper()
	c, err := crypto.NewAESCrypto(key)
	if err != nil {
		t.Fatalf("建立測試 column codec 失敗: %v", err)
	}
	return aadTestCodec{c: c}
}
