package keyvault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
)

// keyvault 包內測試助手。
//
// **為何是複本而非共用**：本包的包內測試（`package keyvault`）SHALL NOT import
// `internal/service`——後者 import 本包，測試內 import 會構成 Go 的
// 「import cycle not allowed in test」。原本住 `internal/service` 的
// `aes_codec_testhelper_test.go`／`aad_write_guard_test.go` 已遷入本目錄的
// 外部測試包 `package keyvault_test`（該包同樣看不見本檔），本檔仍為 keyvault
// 側的等價複本，實作逐行相同、只調整型別限定。兩份都只存在於 `_test.go`，
// 不構成新的無 AAD 寫出入口。

// sealNoAAD **測試層 stdlib 助手**：以 crypto/aes＋cipher.NewGCM 直接封出
// 無 AAD 的 nonce+ciphertext。
//
// 為何在測試裡手工封：無 AAD 的寫出能力已在過渡格式收尾時整組
// 刪除（先是 encryptNoAADForRollback／EncodeEnvelope，P2 再刪
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

// aesColumnCodec 測試用 ColumnCodec
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
// AAD cutover 後，遷移／輪替／服務層寫出的一律是帶 AAD 的 `enc:a1`，
// 而 ref-less 的 KeyManagerService.Decrypt **會（正確地）拒收帶 AAD 密文**
// （ErrCipherRefIncomplete）——測試要驗「migrate/rotate 之後仍解得回原值」時
// 必須經此入口，與生產讀取路徑同源。
func decryptColumn(km *KeyManagerService, table, column, ciphertext string) (string, error) {
	return km.DecryptFor(context.Background(),
		crypto.CipherRef{Table: table, Column: column}, ciphertext)
}

// encryptColumn 測試用：以欄位身分（table|column）加密為終態格式（`enc:a1`）。
//
// 取代已刪除的 `encryptNoAADForRollback`——
// 那是全專案唯一的無 AAD 寫出方法，被大量測試借用為「取得一個合法密文」的捷徑。
// 拆除後測試改走與生產同源的 EncryptFor；**刻意要求列身分**，使測試不可能繞過
// AAD 綁定。真正需要過渡格式值的負向測試另用 preReleaseEnvelope 手工構造。
func encryptColumn(t *testing.T, km *KeyManagerService, table, column, plaintext string) string {
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

// keyvaultGuardModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const keyvaultGuardModulePath = "github.com/custodexa/backend"

// repoRoot 定位 backend module 根（本套件守衛的共用掃描根）。
//
// **不用 cwd 相對、也不用固定層數 `..`**：
// 兩者都與「本 package 目前住在樹的第幾層」綁死，package 一下移就指向錯誤位置，
// 而 WalkDir 對不存在／空目錄多半只回零命中
// ——守衛於是在掃空的情況下照樣綠。改以「自本測試檔位置向上找 go.mod，並核對
// module 行」為身分錨點：檔案搬到 module 內任何深度都仍指向同一個根，
// 錨點若失效則 Fatal 而非靜默掃錯樹。
func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if body, err := os.ReadFile(gomod); err == nil {
			want := "module " + keyvaultGuardModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				gomod, keyvaultGuardModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位",
				filepath.Dir(self), keyvaultGuardModulePath)
		}
		dir = parent
	}
}
