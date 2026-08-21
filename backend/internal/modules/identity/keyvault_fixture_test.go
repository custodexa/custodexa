package identity

import (
	"context"
	"fmt"
	"sync/atomic"
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

// keyvault fixture 的 internal/service 側複本（modular-architecture W2 2.5）。
//
// **為何是複本**：這些 fixture 原本與 keyvault 的 13 個生產檔同住 `internal/service`；
// W2 把生產檔與需要 keyvault 未匯出內部的測試一併遷入 `internal/modules/keyvault`，
// 而 keyvault 的**包內**測試 SHALL NOT import `internal/service`（會構成
// 「import cycle not allowed in test」）。故兩側各留一份：keyvault 側是原件，
// 本檔是服務側複本。複本一律只呼叫 keyvault 的匯出面，逐行實作與原件相同。
//
// **唯一的刻意差異**：`aadFixture` 的殘值播種。原件用 `preReleaseEnvelope`
// （取 active data DEK 直封，需 `km.mu`／`km.active`／`km.keys` 三個未匯出欄位），
// 服務側取不到、也 SHALL NOT 為此開匯出面——那等於重新開一個無 AAD 寫出入口，
// 正是 release-transitional-cleanup 拆掉的東西。改以**格式等價**的過渡格式值
// （`enc:v1:<GCM 輸出>`，以測試自有金鑰封裝）播種。留在服務側的四項斷言
// （`aad_residue_alert_test.go`）只判「是否為終態格式」與「值有沒有被改寫」，
// **不解密殘值**，故格式等價已足；真正需要「可用 active DEK 解開的過渡值」的
// 測試（TestPreReleaseCiphertextFailsClose 等）留在 keyvault 包內，用原件。

// preReleaseShapedValue 產出**格式等價**的發佈前過渡格式值（`enc:v1:...`）。
// 內容以測試自有金鑰封裝，不可由 active DEK 解開——服務側殘值斷言不解密，
// 只看格式與是否被改寫（見本檔檔頭）。
func preReleaseShapedValue(t *testing.T, plaintext string) string {
	t.Helper()
	return fmt.Sprintf("enc:v1:%s", sealNoAADBase64(t, kmTestKey(7), plaintext))
}

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

func newAADTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newKeyManagerDB(t)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	return db
}

// aadFixture 建一張最小的登記表存量（assets 與 asset_accounts），回傳 id
func aadFixture(t *testing.T, db *gorm.DB, km *keyvault.KeyManagerService) (assetID, accountID uint) {
	t.Helper()
	for _, ddl := range []string{
		`CREATE TABLE assets (id INTEGER PRIMARY KEY AUTOINCREMENT, password_enc TEXT NOT NULL DEFAULT '',
			private_key_enc TEXT NOT NULL DEFAULT '', sftp_password_enc TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE asset_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, password_enc TEXT NOT NULL DEFAULT '',
			private_key_enc TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, totp_secret_enc TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE export_signing_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, private_key_enc TEXT NOT NULL DEFAULT '')`,
		// audit-checkpoint-chain D5：登記於 envelopeMigrationTargets，缺表即整個殘值掃描失敗
		`CREATE TABLE checkpoint_signing_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, private_key_enc TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE notification_channels (id INTEGER PRIMARY KEY AUTOINCREMENT, secret TEXT NOT NULL DEFAULT '',
			url TEXT NOT NULL DEFAULT '')`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatalf("建表失敗: %v", err)
		}
	}
	// 以**發佈前過渡格式**播種：本 fixture 的用途是餵殘值偵測（哨兵與清理閘），
	// 那正是終態下不應存在、但必須被看見的一類值
	assetPwd := preReleaseShapedValue(t, "asset-secret")
	acctPwd := preReleaseShapedValue(t, "account-secret")
	acctKey := preReleaseShapedValue(t, "account-privkey")
	if err := db.Exec("INSERT INTO assets (password_enc) VALUES (?)", assetPwd).Error; err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	if err := db.Exec("INSERT INTO asset_accounts (password_enc, private_key_enc) VALUES (?, ?)",
		acctPwd, acctKey).Error; err != nil {
		t.Fatalf("insert account: %v", err)
	}
	return 1, 1
}

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

var testKEKMaterialSeq uint64

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

// makeBacklog 模擬退役收尾失敗殘留：把某舊 KEK 的退役列改回 live（未退役）
func makeBacklog(db *gorm.DB, oldKEK string) {
	// 還原為「收尾失敗殘留」的 live 形狀（未退役、無 reason、材料在）
	db.Model(&model.DataKey{}).Where("kek_id = ?", oldKEK).
		Updates(map[string]interface{}{"kek_retired_at": nil, "kek_retired_by": "",
			"kek_retired_reason": "", "wrapped_key": "restored-placeholder"})
}
