package database

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/testgate"
)

// TestCredentialSecretConversionMergedSharedOwnership 尚未跑過解封後轉換的舊資料：
// 歸屬遷移先回填（此時還沒有共用憑證），轉換之後才把一致的群組合併成共用憑證。
// 合併建立的共用憑證必須帶全域歸屬（與回填規則「共用 → global」同義），不得留下
// owner_kind 為 NULL 的列；否則範圍化主體依歸屬判定時看不到它，且沒有任何步驟會再補。
func TestCredentialSecretConversionMergedSharedOwnership(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		db := newCredentialLibraryDB(t)
		km := newCredentialLibraryKM(t, db)
		assetA := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
		assetB := seedAsset(t, db, "ssh-b", model.ProtocolSSH)
		seedAccount(t, db, km, assetA, "ops", "same-secret", "group-own")
		seedAccount(t, db, km, assetB, "ops", "same-secret", "group-own")
		if _, err := convertAccountsToDedicatedCredentials(db); err != nil {
			t.Fatalf("存量搬移失敗: %v", err)
		}
		if err := db.Transaction(func(tx *gorm.DB) error {
			_, err := BackfillCredentialOwnership(tx)
			return err
		}); err != nil {
			t.Fatalf("歸屬回填失敗: %v", err)
		}
		assertConversionLeavesGlobalShared(t, db, km)
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		db := freshSchema(t, dsn, fmt.Sprintf("cred_conv_owner_%d", time.Now().UnixNano()))
		if db.Dialector.Name() != "postgres" {
			t.Fatalf("dialector = %s, want postgres", db.Dialector.Name())
		}
		t.Log("EVIDENCE dialect=postgres")
		idx := applyMigrationsBeforeCredentialOwnership(t, db)
		if err := db.AutoMigrate(&SchemaMigration{}); err != nil {
			t.Fatalf("建立 schema_migrations: %v", err)
		}
		km := newCredentialLibraryKM(t, db)
		seedPreConversionGroupPG(t, db, km, "group-own")
		if err := db.Transaction(func(tx *gorm.DB) error { return migrations[idx].Up(tx) }); err != nil {
			t.Fatalf("歸屬遷移失敗: %v", err)
		}
		assertConversionLeavesGlobalShared(t, db, km)
	})
}

// assertConversionLeavesGlobalShared 前提：歸屬已回填、尚無共用憑證；
// 跑轉換後應恰合併出一筆共用憑證，歸屬為 global、無節點，且全表沒有未設歸屬的列。
func assertConversionLeavesGlobalShared(t *testing.T, db *gorm.DB, km *keyvault.KeyManagerService) {
	t.Helper()
	sharedSQL := `SELECT count(*) FROM credentials WHERE scope = ? AND deleted_at IS NULL`
	if n := countRows(t, db, sharedSQL, model.CredentialScopeShared); n != 0 {
		t.Fatalf("前提不成立：轉換前已有 %d 筆共用憑證", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE owner_kind IS NULL`); n != 0 {
		t.Fatalf("前提不成立：回填後仍有 %d 筆未設歸屬", n)
	}

	if err := RunCredentialSecretConversion(db, km); err != nil {
		t.Fatalf("轉換失敗: %v", err)
	}

	var rows []struct {
		ID          uint
		OwnerKind   *string
		OwnerNodeID *uint
	}
	if err := db.Raw(`SELECT id, owner_kind, owner_node_id FROM credentials WHERE scope = ? AND deleted_at IS NULL`,
		model.CredentialScopeShared).Scan(&rows).Error; err != nil {
		t.Fatalf("讀取共用憑證歸屬: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("共用憑證 = %d 筆, want 1（一致的群組應合併）", len(rows))
	}
	got := rows[0]
	if got.OwnerKind == nil {
		t.Fatalf("合併出的共用憑證 #%d 未設歸屬（owner_kind 為 NULL）", got.ID)
	}
	if *got.OwnerKind != model.CredentialOwnerGlobal {
		t.Fatalf("合併出的共用憑證 #%d 歸屬 = %q, want %q", got.ID, *got.OwnerKind, model.CredentialOwnerGlobal)
	}
	if got.OwnerNodeID != nil {
		t.Fatalf("合併出的共用憑證 #%d 帶節點 %d：全域歸屬不得有節點", got.ID, *got.OwnerNodeID)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE owner_kind IS NULL`); n != 0 {
		t.Fatalf("轉換後有 %d 筆憑證未設歸屬", n)
	}
}

// seedPreConversionGroupPG 在歸屬遷移之前的 schema 上寫入「已轉專用、尚未解封轉換」的形狀：
// 兩台資產各一筆專用憑證，v1 密文仍是帳號表身分（created_reason=migration），
// 帳號列帶同一個群組識別。id 取高位，避開序列配發的值。
func seedPreConversionGroupPG(t *testing.T, db *gorm.DB, km *keyvault.KeyManagerService, group string) {
	t.Helper()
	const ts = "2026-01-01 00:00:00"
	for i, name := range []string{"ssh-a", "ssh-b"} {
		assetID := seedAsset(t, db, name, model.ProtocolSSH)
		enc, err := km.EncryptFor(context.Background(), keyvault.RefAccountPassword, "same-secret")
		if err != nil {
			t.Fatalf("加密帳號密碼: %v", err)
		}
		credID, verID, accID := 9101+i, 9201+i, 9301+i
		stmts := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO credentials(id,created_at,updated_at,scope,username,secret_type,auth_method,protocol_family,note,rotation_epoch)
				VALUES(?,?,?,?,'ops','password','password','ssh','',0)`, []any{credID, ts, ts, model.CredentialScopeDedicated}},
			{`INSERT INTO credential_secret_versions(id,credential_id,version_no,secret_type,password_enc,created_reason,created_at)
				VALUES(?,?,1,'password',?,?,?)`, []any{verID, credID, enc, model.CredentialVersionReasonMigration, ts}},
			{`UPDATE credentials SET current_version_id = ? WHERE id = ?`, []any{verID, credID}},
			{`INSERT INTO asset_accounts(id,created_at,updated_at,asset_id,username,auth_method,note,credential_id,effective_version_id,credential_group)
				VALUES(?,?,?,?,'ops','password','',?,?,?)`, []any{accID, ts, ts, assetID, credID, verID, group}},
		}
		for _, s := range stmts {
			if err := db.Exec(s.sql, s.args...).Error; err != nil {
				t.Fatalf("seed: %v\n%s", err, s.sql)
			}
		}
	}
}
