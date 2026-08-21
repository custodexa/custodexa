package keyvault_test

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var testEncryptionKey = []byte("dev-key-for-testing-only-ok32bts")

// testSigningCodec 簽章服務改收 crypto.ColumnCodec（D5 cutover，tasks 1.7）；
// 測試以固定金鑰的 aadTestCodec 滿足介面——與生產路徑同樣**沒有**無 AAD 寫入方法
func testSigningCodec(t *testing.T, key []byte) crypto.ColumnCodec {
	t.Helper()
	return aesColumnCodec(t, key)
}

func setupSigningDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.ExportSigningKey{}, &model.OIDCProvider{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// TestExportSigningRoundTrip 首啟生成 → 簽驗往返 → manifest 位元組變動驗證失敗
func TestExportSigningRoundTrip(t *testing.T) {
	db := setupSigningDB(t)
	svc, err := keyvault.NewExportSigningService(db, testSigningCodec(t, testEncryptionKey))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	manifest := []byte(`{"files":[{"name":"audit_logs.json","sha256":"abc"}]}` + "\n")
	sig := svc.Sign(manifest)
	if !svc.VerifySignature(manifest, sig) {
		t.Error("原始 manifest 驗簽應通過")
	}
	tampered := append([]byte{}, manifest...)
	tampered[10] ^= 1
	if svc.VerifySignature(tampered, sig) {
		t.Error("manifest 位元組變動後驗簽應失敗")
	}
}

// TestExportSigningPersistence 金鑰落 DB：重建 service 載入同一把鑰，
// 舊簽章仍可驗；私鑰加密存放（DB 內容非有效 base64 私鑰明文）
func TestExportSigningPersistence(t *testing.T) {
	db := setupSigningDB(t)
	first, err := keyvault.NewExportSigningService(db, testSigningCodec(t, testEncryptionKey))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	data := []byte("manifest-bytes")
	sig := first.Sign(data)

	second, err := keyvault.NewExportSigningService(db, testSigningCodec(t, testEncryptionKey))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second.PublicKeyBase64() != first.PublicKeyBase64() {
		t.Error("重載後應為同一把公鑰")
	}
	if !second.VerifySignature(data, sig) {
		t.Error("重載後應可驗第一代簽章")
	}

	var row model.ExportSigningKey
	if err := db.First(&row, 1).Error; err != nil {
		t.Fatalf("read row: %v", err)
	}
	if row.PrivateKeyEnc == "" || len(row.PrivateKeyEnc) < 64 {
		t.Error("私鑰應加密存放")
	}

	// 錯誤的 ENCRYPTION_KEY 應無法載入（金鑰輪替保護：不靜默生成新鑰蓋舊）
	if _, err := keyvault.NewExportSigningService(db, testSigningCodec(t, []byte("wrong-key-wrong-key-wrong-key-32"))); err == nil {
		t.Error("錯誤加密金鑰應回錯誤而非靜默重生金鑰")
	}
}
