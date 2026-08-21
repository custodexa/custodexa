package identity_test

// 跨包測試包（`package identity_test`）自用的夾具複本
// （modular-architecture W8 獨立驗收：export budget 收斂）。
//
// **為何是複本**：本目錄有三個包——`identity`（生產）、`identity`（包內測試）、
// `identity_test`（本外部測試包）。前兩者的 `_test.go` 夾具對本包不可見，
// 而本包的來源 `internal/service` 側夾具仍被那邊其餘測試使用，不能整批搬走。
// 故只複製本包實際用到的五項，逐行與來源相同（`internal/service/keyvault_fixture_test.go`
// 與 `aes_codec_testhelper_test.go`）。
//
// 一律只呼叫被複製方的匯出面，**不含任何判定**。

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ── [internal/service/aes_codec_testhelper_test.go] 的複本 ──────────

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

// aesColumnCodec 測試用 ColumnCodec（D5 AAD cutover 後的必要參數）
func aesColumnCodec(t *testing.T, key []byte) crypto.ColumnCodec {
	t.Helper()
	c, err := crypto.NewAESCrypto(key)
	if err != nil {
		t.Fatalf("建立測試 column codec 失敗: %v", err)
	}
	return aadTestCodec{c: c}
}

// ── [internal/service/keyvault_fixture_test.go] 的複本 ──────────────

func kmTestKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

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

func newMigrationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// 單連線：sqlite :memory: 每條連線是各自獨立的庫，連線池會讓「寫在 A 連線、
	// 讀在 B 連線」偶發查無資料（本專案既有 flaky 真因，ff51836）
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.User{}, &model.ExportSigningKey{}, &model.CheckpointSigningKey{}, &model.OIDCProvider{},
		&model.LDAPDirectory{}, &model.NotificationChannel{}, &model.AuditLog{}, &model.DataKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// schema_migrations 屬 repository 層，測試以等價表建立
	if err := db.Exec("CREATE TABLE schema_migrations (version varchar(50) PRIMARY KEY, applied_at datetime NOT NULL)").Error; err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	// 生產等價索引語義（migration 20260801_kek_soft_retire）：唯一索引轉 partial，
	// 退役列保留指紋史不阻擋同 KEK 重試
	for _, stmt := range []string{
		"DROP INDEX IF EXISTS idx_data_keys_purpose_version_kek",
		"CREATE UNIQUE INDEX idx_data_keys_purpose_version_kek ON data_keys (purpose, version, kek_id) WHERE kek_retired_at IS NULL",
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("partial index: %v", err)
		}
	}
	return db
}

// pgLockTestDSN 回傳帶隔離 schema 的 DSN；未設 TEST_PG_DSN 則跳過。
func pgLockTestDSN(t *testing.T) string {
	t.Helper()
	// gating 語義集中於 internal/testgate（REQUIRE_INTEGRATION=1 時 skip 轉 fail）
	return testgate.Value(t, testgate.EnvPGDSN)
}

// openPGLockDB 以獨立連線池開啟 DB——一個 *gorm.DB ＝ 模擬一個後端實例。
func openPGLockDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Discard,
		// 本測試只需 data_keys 與遷移守衛掃描的欄位；不建外鍵約束以免
		// AutoMigrate 連帶拉入關聯表
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("postgres 連線失敗（TEST_PG_DSN 是否正確？）: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}
