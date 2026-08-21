package asset

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
)

// sealNoAAD **測試層 stdlib 助手**：以 crypto/aes＋cipher.NewGCM 直接封出
// 無 AAD 的 nonce+ciphertext。
//
// 為何在測試裡手工封：無 AAD 的寫出能力已於 release-transitional-cleanup 整組
// 刪除（先是 encryptNoAADForRollback／EncodeEnvelope，P2 M1 再刪
// AESCrypto.Encrypt／EncryptBytes 並使 EncryptBytesAAD 對空 aad 回
// crypto.ErrAADRequired）——那正是被驗收的事實。負向測試仍需要這種值來模擬
// 「拆除前建立的資料庫」或「繞過 API 的資料庫直寫」，故由測試自行構造。
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

// sealNoAADBase64 發佈前的 **legacy 無前綴密文**（純 base64、單鑰直加密、零綁定）
func sealNoAADBase64(t *testing.T, key []byte, plaintext string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(sealNoAAD(t, key, []byte(plaintext)))
}

// 註：crypto.Codec 已於 D5 cutover（tasks 1.7）自 pkg/crypto 刪除，
// 原 aesCodec 測試替身隨之移除——服務層一律以 aesColumnCodec 注入。

// aadTestCodec 測試用 ColumnCodec：以固定金鑰的 AESCrypto 實作帶欄位身分的
// 加解密。AAD 取自 ref.AAD()，與生產路徑（keyvault.KeyManagerService.EncryptFor）同源，
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

// aesColumnCodec 測試用 ColumnCodec（D5 AAD cutover 後 NewAssetService 的必要參數）
func aesColumnCodec(t *testing.T, key []byte) crypto.ColumnCodec {
	t.Helper()
	c, err := crypto.NewAESCrypto(key)
	if err != nil {
		t.Fatalf("建立測試 column codec 失敗: %v", err)
	}
	return aadTestCodec{c: c}
}

// decryptColumn 測試用：以欄位身分（table|column）解密。
//
// D5 cutover（tasks 1.7）後，遷移／輪替／服務層寫出的一律是帶 AAD 的 `enc:a1`，
// 而 ref-less 的 keyvault.KeyManagerService.Decrypt **會（正確地）拒收帶 AAD 密文**
// （keyvault.ErrCipherRefIncomplete）——測試要驗「migrate/rotate 之後仍解得回原值」時
// 必須經此入口，與生產讀取路徑同源。
func decryptColumn(km *keyvault.KeyManagerService, table, column, ciphertext string) (string, error) {
	return km.DecryptFor(context.Background(),
		crypto.CipherRef{Table: table, Column: column}, ciphertext)
}

// encryptColumn 測試用：以欄位身分（table|column）加密為終態格式（`enc:a1`）。
//
// 取代已刪除的 `encryptNoAADForRollback`（release-transitional-cleanup 3.2）——
// 那是全專案唯一的無 AAD 寫出方法，被大量測試借用為「取得一個合法密文」的捷徑。
// 拆除後測試改走與生產同源的 EncryptFor；**刻意要求列身分**，使測試不可能繞過
// AAD 綁定。真正需要過渡格式值的負向測試另用 preReleaseEnvelope 手工構造。
func encryptColumn(t *testing.T, km *keyvault.KeyManagerService, table, column, plaintext string) string {
	t.Helper()
	out, err := km.EncryptFor(context.Background(),
		crypto.CipherRef{Table: table, Column: column}, plaintext)
	if err != nil {
		t.Fatalf("以 %s.%s 身分加密失敗: %v", table, column, err)
	}
	return out
}

// refAssetPassword 測試預設列身分（不關心身分的測試一律取此）
var refAssetPassword = crypto.CipherRef{Table: "assets", Column: "password_enc"}
