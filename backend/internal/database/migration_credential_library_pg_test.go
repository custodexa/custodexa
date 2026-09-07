package database

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
)

// 帳號憑證庫增量的**結構面實測**（PG-gated；未設 TEST_PG_DSN 即 skip，
// REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
//
// 與 migration_credential_library_test.go 不重疊：那一檔問「轉換的語義對不對」
// （誰得到哪一筆憑證、明文一致才合併），本檔問「這條 migration 在真的 postgres 上
// 跑不跑得起來、Down 之後能不能再 Up、回滾後重跑會不會產生第二份轉換」。
// 兩者缺一：只有 sqlite 測會漏掉方言（partial index、DROP DEFAULT、bigserial），
// 只有結構測會漏掉存量搬移的語義。

// credentialLibraryObjects 本 change 產生的資料庫物件計數（Down／Up 的比對基準）。
func credentialLibraryObjects(t *testing.T, db *gorm.DB, pgSchema string) (tables, indexes int64) {
	t.Helper()
	scan := func(sql string, dst *int64, args ...interface{}) {
		if err := db.Raw(sql, args...).Scan(dst).Error; err != nil {
			t.Fatalf("計數失敗（%s）: %v", sql, err)
		}
	}
	scan(`SELECT count(*) FROM information_schema.tables
	      WHERE table_schema = ? AND table_type = 'BASE TABLE'
	      AND table_name IN ('credentials','credential_secret_versions',
	                         'credential_rotations','credential_rotation_members')`,
		&tables, pgSchema)
	scan(`SELECT count(*) FROM pg_indexes WHERE schemaname = ?
	      AND (tablename IN ('credentials','credential_secret_versions',
	                         'credential_rotations','credential_rotation_members')
	           OR indexname = 'idx_asset_accounts_credential')`, &indexes, pgSchema)
	return tables, indexes
}

// TestCredentialLibraryMigrationDownThenUpPostgres Down 之後能再 Up。
//
// **Down 是有損的**（見 migration_credential_library.go 檔頭的 Down 契約）：
// 本測試斷言的是**結構可還原**，不是資料可還原——後者沒有反向，也不該假裝有。
// Down 只供 parity 守衛與開發庫；生產的回退是還原備份。
func TestCredentialLibraryMigrationDownThenUpPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "credential_library_down_up_test"
	db := freshSchema(t, dsn, pgSchema)
	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	if err := applyMigrationsAfterBaseline(db); err != nil {
		t.Fatalf("增量 migration 失敗: %v", err)
	}
	tablesBefore, indexesBefore := credentialLibraryObjects(t, db, pgSchema)
	if tablesBefore != 4 {
		t.Fatalf("Up 之後憑證庫表數 = %d, want 4", tablesBefore)
	}
	if indexesBefore != 12 {
		t.Fatalf("Up 之後憑證庫索引數 = %d, want 12", indexesBefore)
	}

	// 反序：收縮先還原（它卸下的舊欄是存量搬移的讀取對象），再還原本體
	if err := rollbackCredentialLibraryContract(db); err != nil {
		t.Fatalf("收縮 Down 失敗: %v", err)
	}
	if err := rollbackCredentialLibrary(db); err != nil {
		t.Fatalf("Down 失敗: %v", err)
	}
	tablesAfterDown, indexesAfterDown := credentialLibraryObjects(t, db, pgSchema)
	if tablesAfterDown != 0 || indexesAfterDown != 0 {
		t.Fatalf("Down 之後仍有殘留（表 %d、索引 %d）：反序清理不完整，"+
			"殘留物會讓下一次 Up 的無條件 DDL 撞上既有物件",
			tablesAfterDown, indexesAfterDown)
	}
	// 兩個新欄一併消失（Down 契約寫明「刪除後無來源可還原」，故此處只驗結構）
	var cols int64
	if err := db.Raw(`SELECT count(*) FROM information_schema.columns
		WHERE table_schema = ? AND table_name = 'asset_accounts'
		AND column_name IN ('credential_id','effective_version_id')`, pgSchema).
		Scan(&cols).Error; err != nil {
		t.Fatalf("查欄位失敗: %v", err)
	}
	if cols != 0 {
		t.Fatalf("Down 之後 asset_accounts 仍有 %d 個掛載欄", cols)
	}

	if err := applyCredentialLibrary(db); err != nil {
		t.Fatalf("Down 之後再 Up 失敗（無條件 DDL 撞上殘留物即為此形態）: %v", err)
	}
	if err := applyCredentialLibraryContract(db); err != nil {
		t.Fatalf("收縮 Down 之後再 Up 失敗: %v", err)
	}
	tablesAfterUp, indexesAfterUp := credentialLibraryObjects(t, db, pgSchema)
	if tablesAfterUp != tablesBefore || indexesAfterUp != indexesBefore {
		t.Fatalf("再 Up 之後的物件數不同：表 %d→%d、索引 %d→%d",
			tablesBefore, tablesAfterUp, indexesBefore, indexesAfterUp)
	}
}

// TestCredentialLibraryMigrationRerunAfterRollbackPostgres 回滾之後可再執行一次，
// 且已成功的轉換不會被跑第二遍。
//
// 這正是「可重跑」的完整語義：本 migration **不是冪等的**（DDL 無條件），
// 可重跑指的是「失敗即整交易回滾、庫回到升級前的形狀，修正成因後可再執行一次」；
// 成功後由 schema_migrations 的版本標記擋下，不會靜默做出第二份轉換。
func TestCredentialLibraryMigrationRerunAfterRollbackPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "credential_library_rerun_test"
	db := freshSchema(t, dsn, pgSchema)
	withGlobalDB(t, db)

	if err := RunMigrations(); err != nil {
		t.Fatalf("首次 migration 失敗: %v", err)
	}

	// 模擬「轉換失敗後整批回滾」：結構還原、版本標記移除，庫回到升級前的形狀。
	// 反序還原兩條：收縮卸下的舊欄正是存量搬移要讀的來源
	if err := rollbackCredentialLibraryContract(db); err != nil {
		t.Fatalf("收縮回滾失敗: %v", err)
	}
	if err := rollbackCredentialLibrary(db); err != nil {
		t.Fatalf("回滾失敗: %v", err)
	}
	if err := db.Exec(`DELETE FROM schema_migrations WHERE version IN (?, ?)`,
		"20260906_credential_library", "20260906_credential_library_contract").Error; err != nil {
		t.Fatalf("移除版本標記失敗: %v", err)
	}

	// 修正成因後才有存量可轉：造一台資產與兩個帳號（同資產兩個帳號正是
	// (asset_id, credential_id) 唯一索引最容易撞的形狀）
	if err := db.Exec(`INSERT INTO assets (name, host, port, protocol, created_by, created_at, updated_at)
		VALUES ('ssh-rerun', '10.0.0.9', 22, 'ssh', 1, ?, ?)`, time.Now(), time.Now()).Error; err != nil {
		t.Fatalf("造資產失敗: %v", err)
	}
	var assetID uint
	if err := db.Raw(`SELECT id FROM assets WHERE name = 'ssh-rerun'`).Scan(&assetID).Error; err != nil {
		t.Fatalf("讀資產 id 失敗: %v", err)
	}
	for _, u := range []string{"root", "ops"} {
		if err := db.Exec(`INSERT INTO asset_accounts
			(asset_id, username, password_enc, is_default, auth_method, created_at, updated_at)
			VALUES (?, ?, 'enc:a1:v1:placeholder', false, 'sql', ?, ?)`,
			assetID, u, time.Now(), time.Now()).Error; err != nil {
			t.Fatalf("造帳號 %s 失敗: %v", u, err)
		}
	}

	if err := RunMigrations(); err != nil {
		t.Fatalf("回滾後再執行一次失敗: %v", err)
	}
	var credentials, versions, orphanAccounts int64
	count := func(sql string, dst *int64) {
		if err := db.Raw(sql).Scan(dst).Error; err != nil {
			t.Fatalf("計數失敗（%s）: %v", sql, err)
		}
	}
	count(`SELECT count(*) FROM credentials`, &credentials)
	count(`SELECT count(*) FROM credential_secret_versions`, &versions)
	count(`SELECT count(*) FROM asset_accounts WHERE credential_id = 0 AND deleted_at IS NULL`,
		&orphanAccounts)
	if credentials != 2 || versions != 2 {
		t.Fatalf("轉換結果 = %d 憑證／%d 版本, want 2／2", credentials, versions)
	}
	if orphanAccounts != 0 {
		t.Fatalf("仍有 %d 筆帳號沒有憑證", orphanAccounts)
	}

	// 第三次執行：版本標記已在，整條略過——**不得**產生第二批憑證
	if err := RunMigrations(); err != nil {
		t.Fatalf("第三次執行失敗: %v", err)
	}
	var credentialsAgain int64
	count(`SELECT count(*) FROM credentials`, &credentialsAgain)
	if credentialsAgain != credentials {
		t.Fatalf("成功後重跑產生了第二份轉換：憑證 %d → %d", credentials, credentialsAgain)
	}
}
