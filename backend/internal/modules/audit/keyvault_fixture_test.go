package audit

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// keyvault fixture 的 audit 側複本（modular-architecture W4 4.11）。
//
// **為何又一份複本**：`audit_failure_kek_degraded_test.go` 驗的是「KEK 退役積壓
// → 失效事件狀態機」這條 keyvault→audit 的整合鏈，它同時需要 keyvault 的金鑰表
// 夾具與 audit 的未匯出狀態（`notify` 注入口、`failing` map）。該檔原住
// `internal/service`，W4 搬包後那裡再也取不到 audit 的未匯出面；把它留在原處
// 的代價是**為測試而在生產碼開匯出的注入口**（`SetNotifyForTest` 之類），
// 那正是 W2/W3 一路拒絕的形態。故改為測試隨主題走、夾具複製一份。
// 複本一律只呼叫 keyvault 的匯出面，逐行實作與
// `internal/service/keyvault_fixture_test.go` 的原件相同。

var testKEKMaterialSeq uint64

func newMigrationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// 單連線：sqlite :memory: 每條連線是各自獨立的庫，連線池會讓「寫在 A 連線、
	// 讀在 B 連線」偶發查無資料（本專案既有 flaky 真因，ff51836）。
	// TestRetiredKeyNotPurgedWhileAssetAccountReferences 在整包跑時穩定紅——
	// 引用掃描落到空表而誤判零引用——即此類，非受測邏輯問題
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	// asset_accounts 亦為信封目標表（asset-multi-account D1a），空表即 pending 0。
	// ldap_directories 同理（ldap-settings-migration D1）——**測試庫例外**：生產
	// 由 versioned migration 建表（CHECK 約束需求），此處僅需一張形狀等價的空表
	// 供 EnvelopePendingCount 逐表掃描，缺表即整個掃描 error 並擋住 KEK 輪替
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.User{}, &model.ExportSigningKey{}, &model.CheckpointSigningKey{}, &model.OIDCProvider{},
		&model.LDAPDirectory{}, &model.NotificationChannel{}, &model.AuditLog{}, &model.DataKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// schema_migrations 屬 repository 層，測試以等價表建立
	if err := db.Exec("CREATE TABLE schema_migrations (version varchar(50) PRIMARY KEY, applied_at datetime NOT NULL)").Error; err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	// 生產等價索引語義（migration 20260801_kek_soft_retire）：唯一索引轉 partial，
	// 退役列保留指紋史不阻擋同 KEK 重試。
	//
	// **必須與 newKeyManagerDB 一致**：AutoMigrate 由 struct tag 生出的是**全表**
	// 唯一索引，與生產不符——委託目標的「abandon 過的 ARN 可再次指定」正是靠
	// partial 語義成立，若測試庫留著全表唯一索引，該行為會在 DB 層被擋下而讓
	// 測試看見一個生產不存在的失敗（反之亦然：日後有人把 partial 改回全表，
	// 也該由這裡的測試轉紅）。
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

// seedEnvelopeData 佈建**終態格式**存量（enc:a1）：資產密碼、使用者 TOTP、
// 兩個通知通道。取代已刪除的 seedLegacyData＋RunEnvelopeDataMigration 前置
// （release-transitional-cleanup 3.3）——終態下不存在需要一次性信封化的存量。
func seedEnvelopeData(t *testing.T, db *gorm.DB, km *keyvault.KeyManagerService) {
	t.Helper()
	pw := encryptColumn(t, km, "assets", "password_enc", "asset-password")
	mfa := encryptColumn(t, km, "users", "totp_secret_enc", "totp-secret")
	if err := db.Exec("INSERT INTO assets (name, host, port, protocol, username, password_enc, private_key_enc, sftp_password_enc, created_by) VALUES ('a1','h',22,'ssh','root',?, '', '', 1)", pw).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := db.Exec("INSERT INTO users (username, password, totp_secret_enc) VALUES ('u1','x',?)", mfa).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	for _, ch := range []model.NotificationChannel{
		{Name: "slack", Type: "slack",
			URL:     encryptColumn(t, km, "notification_channels", "url", "https://hooks.slack.com/services/T0/B0/secretpart"),
			Enabled: true},
		{Name: "hook", Type: "webhook",
			URL:     encryptColumn(t, km, "notification_channels", "url", "https://example.com/hook"),
			Secret:  encryptColumn(t, km, "notification_channels", "secret", "hmac-secret"),
			Enabled: true},
	} {
		c := ch
		if err := db.Create(&c).Error; err != nil {
			t.Fatalf("seed channel %s: %v", c.Name, err)
		}
	}
}

// setupKM 建立含 data v1 + audit v0/v1 的金鑰表（KEK=kmTestKey(1)）
func setupKM(t *testing.T) (*gorm.DB, *keyvault.KeyManagerService) {
	t.Helper()
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	seedEnvelopeData(t, db, km)
	return db, km
}

// rewrapAndReinit 執行重包並以新 KEK 重啟（模擬改 env 重啟切換），回新 km 與新舊指紋。
// 切換那次 keyvault.InitKeyManager 不應 fail-close——這是 codex 第五輪 HIGH-1 的回歸點：
// 切換後舊列 live 且 kek_id<>env 是合法的「待退役 predecessor」角色，不得誤判非法。
func rewrapAndReinit(t *testing.T, db *gorm.DB, km *keyvault.KeyManagerService) (*keyvault.KeyManagerService, string, string) {
	t.Helper()
	oldKEK := km.KEKKeyID()
	resMaterial, res := mustRewrapKEK(t, km)
	p, err := crypto.NewEnvKEKProvider([]byte(resMaterial))
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	km2, err := keyvault.InitKeyManager(db, p)
	if err != nil {
		t.Fatalf("切換那次 keyvault.InitKeyManager 不應 fail-close（HIGH-1）: %v", err)
	}
	return km2, oldKEK, res.NewKEKID
}

// newTestKEKMaterial 產生一把合格且互不相同的測試材料（32 字元、KEKAlphabet 值域）。
// 刻意**不使用 CSPRNG**：測試需要的是可重現與唯一性，而非熵；伺服端已無生成器可用。
func newTestKEKMaterial(t *testing.T) string {
	t.Helper()
	m := fmt.Sprintf("TestKEKMaterial%017d", atomic.AddUint64(&testKEKMaterialSeq, 1))
	if len(m) != crypto.KEKMaterialLength {
		t.Fatalf("測試材料長度 %d，應為 %d", len(m), crypto.KEKMaterialLength)
	}
	if v := crypto.ValidateKEKMaterialFormat(m); v != "" {
		t.Fatalf("測試材料不合格式：%s", v)
	}
	return m
}

// localTargetForTest 由材料建構本地重包目標（建構失敗即測試失敗）
func localTargetForTest(t *testing.T, material string) *keyvault.RewrapTarget {
	t.Helper()
	target, err := keyvault.NewLocalRewrapTarget(material)
	if err != nil {
		t.Fatalf("keyvault.NewLocalRewrapTarget(%d 字元): %v", len(material), err)
	}
	return target
}

// rewrapKEKWith 以指定材料重包，錯誤原樣回傳（供守衛測試斷言）
func rewrapKEKWith(t *testing.T, km *keyvault.KeyManagerService, material string) (*keyvault.KEKRewrapResult, error) {
	t.Helper()
	return km.RewrapKEK(context.Background(), localTargetForTest(t, material))
}

// mustRewrapKEK 以一把新材料重包，回傳（材料, 結果）。材料即管理員手上那一份
func mustRewrapKEK(t *testing.T, km *keyvault.KeyManagerService) (string, *keyvault.KEKRewrapResult) {
	t.Helper()
	material := newTestKEKMaterial(t)
	res, err := rewrapKEKWith(t, km, material)
	if err != nil {
		t.Fatalf("RewrapKEK: %v", err)
	}
	return material, res
}

// makeBacklog 模擬退役收尾失敗殘留：把某舊 KEK 的退役列改回 live（未退役）
func makeBacklog(db *gorm.DB, oldKEK string) {
	// 還原為「收尾失敗殘留」的 live 形狀（未退役、無 reason、材料在）
	db.Model(&model.DataKey{}).Where("kek_id = ?", oldKEK).
		Updates(map[string]interface{}{"kek_retired_at": nil, "kek_retired_by": "",
			"kek_retired_reason": "", "wrapped_key": "restored-placeholder"})
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
