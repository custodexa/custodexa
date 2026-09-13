package main

import (
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
)

// 委託設定自 `.env` 一次性讀入資料庫的守衛（升級路徑）。
//
// 四件事，每一件失效的後果都不同：
//
//	(1) 空表＋有 env → 讀入成功（否則一個原本運作正常的部署會在升級後停在
//	    「拓撲尚未設定」，而管理者手上唯一的線索是一份已經不生效的 `.env`）；
//	(2) 已有列＋有 env → **不覆寫**（冪等），但提示照印；
//	(3) env 含秘密鍵時該值**不入庫**——本次改動的整個要點就是秘密不落任何持久化位置；
//	(4) 無 env 無列 → 不建列，委託模式停在已封存等待介面設定。

func withImportDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.KEKTopology{}, &model.DataKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	prev := database.DB
	database.DB = db
	t.Cleanup(func() {
		database.DB = prev
		_ = sqlDB.Close()
	})
	return db
}

func vaultImportDecision() *config.KEKDecision {
	d := &config.KEKDecision{Mode: config.KEKModeKMS}
	d.KMS.Provider = vaulttransit.ProviderVault
	return d
}

// TestKEKTopologyEnvImportPopulatesEmptyTable 空表＋有 env → 讀入成功。
func TestKEKTopologyEnvImportPopulatesEmptyTable(t *testing.T) {
	db := withImportDB(t)
	t.Setenv("KEK_VAULT_ADDR", "https://vault.example:8200")
	t.Setenv("KEK_VAULT_ROLE_ID", "role-from-env")
	t.Setenv("KEK_KMS_KEY_ID", "custodexa-kek")

	imported := importDelegatedTopologyFromEnv(vaultImportDecision())
	if len(imported) != 3 {
		t.Fatalf("應讀入三個非秘密欄位，得 %v", imported)
	}
	row, err := keyvault.LoadKEKTopology(db)
	if err != nil {
		t.Fatalf("讀入後應有列: %v", err)
	}
	if row.Address != "https://vault.example:8200" || row.RoleID != "role-from-env" ||
		row.TransitKeyName != "custodexa-kek" {
		t.Fatalf("讀入的值不符: %+v", row)
	}
	if row.UpdatedBy != "system:env-import" {
		t.Fatalf("課責欄應標明來源，得 %q", row.UpdatedBy)
	}
}

// TestKEKTopologyEnvImportIsIdempotent 已有列＋有 env → 不覆寫。
func TestKEKTopologyEnvImportIsIdempotent(t *testing.T) {
	db := withImportDB(t)
	if _, _, err := keyvault.SaveKEKTopology(db, keyvault.KEKTopologyInput{
		Provider: vaulttransit.ProviderVault, Address: "https://ui-configured.example:8200",
		TransitKeyName: "ui-key", RoleID: "ui-role", UpdatedBy: "admin"}); err != nil {
		t.Fatalf("前置設定失敗: %v", err)
	}
	t.Setenv("KEK_VAULT_ADDR", "https://stale-env.example:8200")
	t.Setenv("KEK_VAULT_ROLE_ID", "stale-role")

	if imported := importDelegatedTopologyFromEnv(vaultImportDecision()); imported != nil {
		t.Fatalf("已有列時不得讀入，得 %v", imported)
	}
	row, err := keyvault.LoadKEKTopology(db)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if row.Address != "https://ui-configured.example:8200" || row.RoleID != "ui-role" {
		t.Fatalf("既有列被 `.env` 覆寫了: %+v", row)
	}
	// 重跑同樣不改變任何值。
	importDelegatedTopologyFromEnv(vaultImportDecision())
	again, _ := keyvault.LoadKEKTopology(db)
	if again.Address != row.Address || again.RoleID != row.RoleID || again.UpdatedAt != row.UpdatedAt {
		t.Fatalf("重跑改動了既有列: %+v → %+v", row, again)
	}
}

// TestKEKTopologyEnvImportNeverStoresSecrets env 含秘密鍵時該值不入庫。
//
// **掃全欄零命中**：不是只檢查某一個欄位——秘密被寫進任何一欄都是同一個缺陷。
func TestKEKTopologyEnvImportNeverStoresSecrets(t *testing.T) {
	db := withImportDB(t)
	const secret = "secret-id-must-never-be-stored"
	t.Setenv("KEK_VAULT_ADDR", "https://vault.example:8200")
	t.Setenv("KEK_VAULT_ROLE_ID", "role-from-env")
	t.Setenv("KEK_KMS_KEY_ID", "custodexa-kek")
	t.Setenv("KEK_VAULT_SECRET_ID", secret)

	importDelegatedTopologyFromEnv(vaultImportDecision())

	var rows []model.KEKTopology
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, r := range rows {
		for name, v := range map[string]string{
			"provider": r.Provider, "address": r.Address, "transit_key_name": r.TransitKeyName,
			"role_id": r.RoleID, "region": r.Region, "updated_by": r.UpdatedBy,
		} {
			if v == secret {
				t.Fatalf("秘密鍵的值被寫進 %s 欄", name)
			}
		}
	}
}

// TestKEKTopologyEnvImportSkipsWhenNothingToImport 無 env 無列 → 不建列。
//
// 此時委託模式停在已封存等待介面設定，那是本版刻意的語義（不是組態錯誤）。
func TestKEKTopologyEnvImportSkipsWhenNothingToImport(t *testing.T) {
	db := withImportDB(t)
	t.Setenv("KEK_VAULT_ADDR", "")
	t.Setenv("KEK_VAULT_ROLE_ID", "")
	t.Setenv("KEK_KMS_KEY_ID", "")

	if imported := importDelegatedTopologyFromEnv(vaultImportDecision()); imported != nil {
		t.Fatalf("無可讀入的值時不得建列，得 %v", imported)
	}
	if _, err := keyvault.LoadKEKTopology(db); !errors.Is(err, keyvault.ErrKEKTopologyNotConfigured) {
		t.Fatalf("不得建出空列，得 %v", err)
	}
}

// TestKEKTopologyEnvImportRejectsInvalidEnv 舊 `.env` 的值不合新驗證規則時不寫半套。
//
// 例如位址不是 HTTPS：**不降格放行**——那條連線上走的是資料金鑰材料。
func TestKEKTopologyEnvImportRejectsInvalidEnv(t *testing.T) {
	db := withImportDB(t)
	t.Setenv("KEK_VAULT_ADDR", "http://legacy-plaintext.example:8200")
	t.Setenv("KEK_VAULT_ROLE_ID", "role-from-env")
	t.Setenv("KEK_KMS_KEY_ID", "custodexa-kek")

	if imported := importDelegatedTopologyFromEnv(vaultImportDecision()); imported != nil {
		t.Fatalf("不合驗證規則的值不得讀入，得 %v", imported)
	}
	if _, err := keyvault.LoadKEKTopology(db); !errors.Is(err, keyvault.ErrKEKTopologyNotConfigured) {
		t.Fatalf("被拒之後不得留下任何列，得 %v", err)
	}
}

// TestKEKTopologyEnvImportSkipsNonDelegatedModes 非委託模式不讀入。
func TestKEKTopologyEnvImportSkipsNonDelegatedModes(t *testing.T) {
	db := withImportDB(t)
	t.Setenv("KEK_VAULT_ADDR", "https://vault.example:8200")
	t.Setenv("KEK_VAULT_ROLE_ID", "role-from-env")

	for _, mode := range []string{config.KEKModeEnv, config.KEKModeUI, config.KEKModeHSM} {
		if imported := importDelegatedTopologyFromEnv(&config.KEKDecision{Mode: mode}); imported != nil {
			t.Fatalf("模式 %s 不應讀入，得 %v", mode, imported)
		}
	}
	if _, err := keyvault.LoadKEKTopology(db); !errors.Is(err, keyvault.ErrKEKTopologyNotConfigured) {
		t.Fatalf("非委託模式不得建列，得 %v", err)
	}
}

// TestKEKTopologyEnvImportGCPHasNoEditableFields GCP 無可設定的拓撲欄位，故不讀入。
func TestKEKTopologyEnvImportGCPHasNoEditableFields(t *testing.T) {
	db := withImportDB(t)
	t.Setenv("KEK_KMS_REGION", "asia-east1")
	t.Setenv("KEK_KMS_KEY_ID", "projects/p/locations/l/keyRings/r/cryptoKeys/k")

	d := &config.KEKDecision{Mode: config.KEKModeKMS}
	d.KMS.Provider = keyvault.TopologyProviderGCP
	if imported := importDelegatedTopologyFromEnv(d); imported != nil {
		t.Fatalf("GCP 不應讀入，得 %v", imported)
	}
	if _, err := keyvault.LoadKEKTopology(db); !errors.Is(err, keyvault.ErrKEKTopologyNotConfigured) {
		t.Fatalf("GCP 不得建列，得 %v", err)
	}
}
