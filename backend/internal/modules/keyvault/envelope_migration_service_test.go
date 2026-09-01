package keyvault

import (
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

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
	// asset_accounts 亦為信封目標表，空表即 pending 0。
	// ldap_directories 同理——**測試庫例外**：生產
	// 由 versioned migration 建表（CHECK 約束需求），此處僅需一張形狀等價的空表
	// 供 EnvelopePendingCount 逐表掃描，缺表即整個掃描 error 並擋住 KEK 輪替
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.User{}, &model.ExportSigningKey{}, &model.CheckpointSigningKey{}, &model.OIDCProvider{},
		&model.LDAPDirectory{}, &model.NotificationChannel{}, &model.AuditLog{}, &model.DataKey{},
		&model.ChangeSecretCandidate{}, &model.ClipboardEvent{}, &model.OffsiteProfile{}); err != nil {
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

// TestReencryptColumnCASNotClobbered CAS 寫回（lost-update 情境）：
// SELECT 與 UPDATE 之間該列被並發改寫（如改密 live 輪換）時，不得以舊快照覆蓋
// 新值、不計 Migrated。
//
// 原測試以 legacy 信封化遷移為載體，該遷移已於過渡格式收尾時
// 拆除；CAS 語義屬共用重加密原語 reencryptEnvelopeColumn（現由 DEK 輪替使用），
// 故改以該原語直接驅動——被驗證的性質不變。
func TestReencryptColumnCASNotClobbered(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)

	const original = "https://hooks.slack.com/services/T0/B0/secretpart"
	enc := encryptColumn(t, km, "notification_channels", "url", original)
	if err := db.Create(&model.NotificationChannel{
		Name: "slack", Type: "slack", URL: enc, Enabled: true,
	}).Error; err != nil {
		t.Fatalf("seed channel: %v", err)
	}

	// 攔在第一個 UPDATE 之前，以另一 session 改寫同列——模擬掃描快照後的並發寫入
	const concurrent = "enc:a1:v1:Q09OQ1VSUkVOVA=="
	interposed := false
	if err := db.Callback().Raw().Before("gorm:raw").Register("test:concurrent_write", func(tx *gorm.DB) {
		if interposed || !strings.HasPrefix(tx.Statement.SQL.String(), "UPDATE notification_channels SET url") {
			return
		}
		interposed = true
		if err := db.Session(&gorm.Session{NewDB: true}).
			Exec("UPDATE notification_channels SET url = ? WHERE name = 'slack'", concurrent).Error; err != nil {
			t.Errorf("並發改寫失敗: %v", err)
		}
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	defer db.Callback().Raw().Remove("test:concurrent_write")

	// skip＝「已是 v2」——現況全為 v1，故該列必被選中重加密
	result := &EnvelopeMigrationResult{}
	target := envelopeMigrationColumn{table: "notification_channels", column: "url"}
	reencryptEnvelopeColumn(db, km, target, func(v string) bool {
		ver, ok := envelopeVersionOf(v)
		return ok && ver == 2
	}, result)

	if !interposed {
		t.Fatal("攔截未觸發，本測試未覆蓋 CAS 路徑")
	}
	var urlVal string
	db.Raw("SELECT url FROM notification_channels WHERE name = 'slack'").Scan(&urlVal)
	if urlVal != concurrent {
		t.Fatalf("並發新值被舊快照覆蓋（lost update）: %q", urlVal)
	}
	if result.Migrated != 0 {
		t.Fatalf("CAS 放棄列不得計入 Migrated：want 0, got %d", result.Migrated)
	}
	if result.CASConflicts != 1 {
		t.Fatalf("CAS 放棄應被計數：want 1, got %d", result.CASConflicts)
	}
}

// TestReencryptColumnFailsOnPreReleaseValue 明文收編分支已於過渡格式收尾時移除：
// 非終態格式值 MUST 於解密階段記為失敗，
// SHALL NOT 被當作明文重新加密而靜默洗白（那會使哨兵永遠看不到不可能態）。
func TestReencryptColumnFailsOnPreReleaseValue(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)

	if err := db.Create(&model.NotificationChannel{
		Name: "plain", Type: "webhook", URL: "https://example.com/hook", Secret: "plain-secret", Enabled: true,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	result := &EnvelopeMigrationResult{}
	target := envelopeMigrationColumn{table: "notification_channels", column: "secret"}
	reencryptEnvelopeColumn(db, km, target, func(string) bool { return false }, result)

	if result.Failed != 1 || result.Migrated != 0 {
		t.Fatalf("明文殘值 MUST 記為失敗而非被收編：%+v", result)
	}
	var stored string
	db.Raw("SELECT secret FROM notification_channels WHERE name = 'plain'").Scan(&stored)
	if stored != "plain-secret" {
		t.Fatalf("失敗列 MUST 原樣不動（fail-visible）: %q", stored)
	}
}
