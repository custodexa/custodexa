package keyvault

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newKeyManagerDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// OIDCProvider／LDAPDirectory 一併建表：其 client_secret_enc／bind_password_enc
	// 登記於 envelopeMigrationTargets，AAD 殘餘掃描會逐表計數，缺表即整個掃描失敗
	// （非本測試意圖）
	if err := db.AutoMigrate(&model.DataKey{}, &model.OIDCProvider{}, &model.LDAPDirectory{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// schema_migrations 屬 repository 層，測試以等價表建立。
	// 生產上此表恆存在（RunMigrations 建立），post-unseal 佇列項會據以讀寫
	// 執行標記（envelope／ldap_seed）；測試庫缺表會讓佇列項回報基礎設施失敗，
	// 那是測試環境產物而非受測邏輯
	if err := db.Exec(
		"CREATE TABLE schema_migrations (version varchar(50) PRIMARY KEY, applied_at datetime NOT NULL)").Error; err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	// 生產等價索引語義（migration 20260801_kek_soft_retire）：唯一索引轉 partial，
	// 退役列保留指紋史不阻擋同 KEK 重試——放棄後重試重包的行為依賴此語義
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

func kmTestKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func newTestKeyManager(t *testing.T, db *gorm.DB, kekByte byte) *KeyManagerService {
	t.Helper()
	kek, err := crypto.NewEnvKEKProvider(kmTestKey(kekByte))
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	km, err := InitKeyManager(db, kek)
	if err != nil {
		t.Fatalf("InitKeyManager: %v", err)
	}
	return km
}

// TestKeyManagerBootstrapMintsNoV0 全新部署 bootstrap **只鑄 v1 active**
// （release-transitional-cleanup D4）：data v1 與 audit_integrity v1，
// MUST NOT 產生任何 v0 或 retired 列（原 audit v0 legacy 快照已拆除）。
func TestKeyManagerBootstrapMintsNoV0(t *testing.T) {
	db := newKeyManagerDB(t)
	km := newTestKeyManager(t, db, 1)

	var rows []model.DataKey
	if err := db.Order("purpose, version").Find(&rows).Error; err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("bootstrap 應只建 2 列（data v1 + audit_integrity v1），得 %d: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.Version == 0 {
			t.Errorf("bootstrap MUST NOT 鑄造 v0 列: %+v", r)
		}
		if r.Status != model.DataKeyStatusActive {
			t.Errorf("bootstrap MUST NOT 產生 retired 列: %+v", r)
		}
	}
	if km.HMACKeyByVersion(0) != nil {
		t.Error("系統 MUST 無 v0 蓋章鑰（否則偽造 key_version=0 的列反而驗章成功）")
	}
	ver, key := km.ActiveHMACKey()
	if ver != 1 || len(key) != 32 {
		t.Errorf("active 蓋章鑰應為 v1/32bytes，得 v%d/%d", ver, len(key))
	}
}

// TestPreReleaseV0RowRefusesBoot v0 殘列 fail-close（D4）：金鑰表存在**任何用途**
// 之 version 0 列即判為發佈前過渡格式並拒絕啟動，錯誤訊息指明須重建。
//
// 為何是獨立的閘：v0 列既不構成版本斷號也不缺 active，既有完整性檢查會放行它，
// 而放行等於載入 v0 鑰、使 `key_version=0` 的舊列反而驗章成功。
func TestPreReleaseV0RowRefusesBoot(t *testing.T) {
	for _, purpose := range []string{model.DataKeyPurposeAuditIntegrity, model.DataKeyPurposeData} {
		t.Run(purpose, func(t *testing.T) {
			db := newKeyManagerDB(t)
			km := newTestKeyManager(t, db, 1)

			// 手工插入 v0 列（模擬拆除前建立的資料庫）
			raw, err := wrapMaterial(km.kek, purpose, 0, kmTestKey(0xAA))
			if err != nil {
				t.Fatalf("wrap: %v", err)
			}
			row := model.DataKey{Purpose: purpose, Version: 0, WrappedKey: raw,
				KEKID: km.KEKKeyID(), Status: model.DataKeyStatusRetired}
			if err := db.Create(&row).Error; err != nil {
				t.Fatalf("插入 v0 列: %v", err)
			}

			kek, _ := crypto.NewEnvKEKProvider(kmTestKey(1))
			_, err = InitKeyManager(db, kek)
			if !errors.Is(err, ErrPreReleaseKeyTable) {
				t.Fatalf("v0 殘列 MUST 拒絕啟動並回可辨識錯誤，得 %v", err)
			}
			if !strings.Contains(err.Error(), "重建") {
				t.Fatalf("錯誤訊息 MUST 指明須重建資料庫: %v", err)
			}
		})
	}
}

// TestKeyManagerEncryptDecryptRoundtrip 信封格式加解密與空字串語義
func TestKeyManagerEncryptDecryptRoundtrip(t *testing.T) {
	db := newKeyManagerDB(t)
	km := newTestKeyManager(t, db, 1)

	ct := encryptColumn(t, km, "assets", "password_enc", "s3cret-password")
	if !strings.HasPrefix(ct, "enc:a1:v1:") {
		t.Fatalf("新密文 MUST 為帶 AAD 的終態格式，得 %q", ct)
	}
	got, err := decryptColumn(km, "assets", "password_enc", ct)
	if err != nil || got != "s3cret-password" {
		t.Fatalf("DecryptFor: %q err=%v", got, err)
	}

	if e := encryptColumn(t, km, "assets", "password_enc", ""); e != "" {
		t.Error("空字串加密應回空（沿用既有語義）")
	}
	if d, _ := km.Decrypt(""); d != "" {
		t.Error("空字串解密應回空")
	}
}

// TestKeyManagerLegacyDecryptRemoved legacy 純 base64 密文 MUST fail-close
// （release-transitional-cleanup D3：系統無 legacy 單鑰解密路徑）。
// 本測試由「legacy 可解」翻轉為「legacy 不可解」——若日後有人恢復回落分支即轉紅。
func TestKeyManagerLegacyDecryptRemoved(t *testing.T) {
	db := newKeyManagerDB(t)
	km := newTestKeyManager(t, db, 1)

	// 無 AAD 的寫出能力已刪除（P2 M1），legacy fixture 由測試層 stdlib 助手構造
	legacyCT := sealNoAADBase64(t, kmTestKey(1), "old-asset-password")
	plain, err := km.Decrypt(legacyCT)
	if err == nil || plain != "" {
		t.Fatalf("legacy 密文 MUST fail-close，得 plain=%q err=%v", plain, err)
	}
	if !errors.Is(err, ErrNonFinalCiphertext) {
		t.Fatalf("錯誤未可辨識為過渡格式錯: %v", err)
	}
}

// TestKeyManagerReloadIdempotent 重啟載入既有金鑰：不重複 bootstrap、跨實例可解密
func TestKeyManagerReloadIdempotent(t *testing.T) {
	db := newKeyManagerDB(t)
	km1 := newTestKeyManager(t, db, 1)
	ct := encryptColumn(t, km1, "assets", "password_enc", "persist-me")

	km2 := newTestKeyManager(t, db, 1)
	got, err := decryptColumn(km2, "assets", "password_enc", ct)
	if err != nil || got != "persist-me" {
		t.Fatalf("重啟後解密失敗: %q err=%v", got, err)
	}

	var count int64
	db.Model(&model.DataKey{}).Count(&count)
	if count != 2 {
		t.Fatalf("重複 init 不應增列，得 %d", count)
	}
	if !bytes.Equal(km1.HMACKeyByVersion(1), km2.HMACKeyByVersion(1)) {
		t.Error("重啟後蓋章鑰應一致")
	}
}

// TestKeyManagerWrongKEKRefusesBoot 錯誤 KEK 開機拒絕啟動（D8）
func TestKeyManagerWrongKEKRefusesBoot(t *testing.T) {
	db := newKeyManagerDB(t)
	newTestKeyManager(t, db, 1)

	wrongKEK, _ := crypto.NewEnvKEKProvider(kmTestKey(2))
	_, err := InitKeyManager(db, wrongKEK)
	if !errors.Is(err, ErrKEKMismatch) {
		t.Fatalf("錯誤 KEK 應回 ErrKEKMismatch，得 %v", err)
	}
}

// TestKeyManagerUnknownVersionDecryptFails 引用不存在版本的密文回明確錯誤
func TestKeyManagerUnknownVersionDecryptFails(t *testing.T) {
	db := newKeyManagerDB(t)
	km := newTestKeyManager(t, db, 1)

	// enc:v 本身已是過渡格式（先於版本判定被拒）；以終態格式引用不存在版本
	if _, err := km.DecryptFor(context.Background(), refAssetPassword, "enc:a1:v99:aGVsbG8="); err == nil {
		t.Fatal("不存在版本應回錯")
	}
	if km.HMACKeyByVersion(99) != nil {
		t.Fatal("不存在版本蓋章鑰應回 nil")
	}
}

// TestPreReleaseWrappedKeyRefusesBoot 拆除前建立之資料庫的機械保證
// （release-transitional-cleanup D5）：本地 wrapped_key 恆為無前綴裸 base64，
// 改碼後首啟即於**金鑰載入**fail-close，且錯誤訊息指明須重建資料庫。
//
// 這是「舊庫不能誤用」的唯一機械保證（哨兵只 fail-visible、不擋啟動），
// 故三種過渡形態（無前綴、`wk:1`、空字串以外的損毀）皆須於解包前被辨識。
func TestPreReleaseWrappedKeyRefusesBoot(t *testing.T) {
	forge := func(t *testing.T, km *KeyManagerService, transform func(string) string) error {
		t.Helper()
		var row model.DataKey
		if err := km.db.Where("purpose = ? AND version = 1", model.DataKeyPurposeData).
			First(&row).Error; err != nil {
			t.Fatalf("讀取 v1 列: %v", err)
		}
		if err := km.db.Model(&model.DataKey{}).Where("id = ?", row.ID).
			Update("wrapped_key", transform(row.WrappedKey)).Error; err != nil {
			t.Fatalf("植入過渡格式: %v", err)
		}
		kek, _ := crypto.NewEnvKEKProvider(kmTestKey(1))
		_, err := InitKeyManager(km.db, kek)
		return err
	}

	cases := map[string]func(string) string{
		// 拆除前的本地形式：`wk:2:local:<b64>` → `<b64>`
		"無前綴裸 base64": func(v string) string {
			return strings.TrimPrefix(v, "wk:2:"+crypto.WrappedFormatLocal+":")
		},
		// 前綴遷移中繼態：判別子 1（無 AAD 包裹）
		"判別子 1": func(v string) string {
			return "wk:1:" + strings.TrimPrefix(v, "wk:2:")
		},
	}
	for name, transform := range cases {
		t.Run(name, func(t *testing.T) {
			db := newKeyManagerDB(t)
			km := newTestKeyManager(t, db, 1)
			err := forge(t, km, transform)
			if err == nil {
				t.Fatal("發佈前過渡格式的 wrapped_key MUST 於金鑰載入 fail-close")
			}
			if !errors.Is(err, crypto.ErrWrappedKeyPreRelease) {
				t.Fatalf("錯誤未可辨識為發佈前過渡格式: %v", err)
			}
			if !strings.Contains(err.Error(), "重建") {
				t.Fatalf("錯誤訊息 MUST 指明須重建資料庫: %v", err)
			}
		})
	}
}
