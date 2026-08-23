package audit

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// audit 模組的測試夾具複本。
//
// **為何是複本**：這幾個 helper 原本與 audit 的 15 個生產檔同住 `internal/service`；
// 生產檔與其測試遷入本包後，本包的**包內**測試 SHALL NOT import
// `internal/service`——後者反過來消費本包（`AuditLogService`／`AlertNotifier`），
// 會構成 import cycle。比照 keyvault 與 policy 的作法，兩側各留一份，
// 複本一律只呼叫 keyvault 的匯出面，逐行實作與 `internal/service/keyvault_fixture_test.go`
// 的原件相同。

// kmTestKey 32 位元組的測試 KEK 材料。
func kmTestKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

// newTestKeyManager 以 env KEK provider 建一個測試用 key manager。
func newTestKeyManager(t *testing.T, db *gorm.DB, kekByte byte) *keyvault.KeyManagerService {
	t.Helper()
	kek, err := crypto.NewEnvKEKProvider(kmTestKey(kekByte))
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	km, err := keyvault.InitKeyManager(db, kek)
	if err != nil {
		t.Fatalf("keyvault.InitKeyManager: %v", err)
	}
	return km
}

// decryptColumn 以欄位身分（table|column）解密——與生產讀取路徑同源。
func decryptColumn(km *keyvault.KeyManagerService, table, column, ciphertext string) (string, error) {
	return km.DecryptFor(context.Background(),
		crypto.CipherRef{Table: table, Column: column}, ciphertext)
}

// strPtr 取字串指標（測試表述用）。
func strPtr(s string) *string { return &s }
