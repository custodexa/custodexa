package database

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
)

// TestCredentialOwnershipMigration 憑證管理歸屬增量：
// 共用→global、專用→asset（軟刪列同規則）；密文版本、就位版本、掛載列不變；
// 預先設定的歸屬保留；資料步驟與 RunMigrations 重跑不改內容；零掛載專用憑證只入報告；
// 重算不一致整筆回滾。sqlite 驗資料語義，postgres（PG-gated）另驗 DDL 與整段 migration。
func TestCredentialOwnershipMigration(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		db := newCredentialOwnershipSQLite(t)
		seedCredentialOwnershipFixture(t, db)
		assertCredentialOwnershipBackfill(t, db, func() (CredentialOwnershipReport, error) {
			var r CredentialOwnershipReport
			err := db.Transaction(func(tx *gorm.DB) error {
				var e error
				r, e = BackfillCredentialOwnership(tx)
				return e
			})
			return r, err
		})

		rb := newCredentialOwnershipSQLite(t)
		seedCredentialOwnershipFixture(t, rb)
		assertCredentialOwnershipRollback(t, rb, func() error {
			return rb.Transaction(func(tx *gorm.DB) error {
				_, err := BackfillCredentialOwnership(tx)
				return err
			})
		}, false)
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		db := freshSchema(t, dsn, fmt.Sprintf("cred_owner_%d", time.Now().UnixNano()))
		if db.Dialector.Name() != "postgres" {
			t.Fatalf("dialector = %s, want postgres", db.Dialector.Name())
		}
		t.Log("EVIDENCE dialect=postgres")
		idx := applyMigrationsBeforeCredentialOwnership(t, db)
		seedCredentialOwnershipFixture(t, db)
		assertCredentialOwnershipBackfill(t, db, func() (CredentialOwnershipReport, error) {
			out := captureMigrationLog(t, func() error {
				return db.Transaction(func(tx *gorm.DB) error { return migrations[idx].Up(tx) })
			})
			return reportFromLog(t, out, 1)
		})

		rb := freshSchema(t, dsn, fmt.Sprintf("cred_owner_rb_%d", time.Now().UnixNano()))
		rbIdx := applyMigrationsBeforeCredentialOwnership(t, rb)
		seedCredentialOwnershipFixture(t, rb)
		assertCredentialOwnershipRollback(t, rb, func() error {
			return rb.Transaction(func(tx *gorm.DB) error { return migrations[rbIdx].Up(tx) })
		}, true)

		// RunMigrations：第一次印一行報告，第二次不再執行本增量、內容不變。
		run := freshSchema(t, dsn, fmt.Sprintf("cred_owner_run_%d", time.Now().UnixNano()))
		prev := DB
		DB = run
		t.Cleanup(func() { DB = prev })
		first := captureMigrationLog(t, RunMigrations)
		if _, err := reportFromLog(t, first, 1); err != nil {
			t.Fatal(err)
		}
		tables := []string{"schema_migrations", "credentials", "credential_impact_confirmations"}
		a := dumpTables(t, run, tables...)
		second := captureMigrationLog(t, RunMigrations)
		if n := strings.Count(second, credentialOwnershipReportPrefix); n != 0 {
			t.Fatalf("第二次 RunMigrations 又印出 %d 行報告：遷移集合重入應不再執行", n)
		}
		if b := dumpTables(t, run, tables...); b != a {
			t.Fatal("第二次 RunMigrations 改動了內容")
		}
		if run.Exec(`INSERT INTO credential_impact_confirmations(id,credential_id,user_id,operation) VALUES('x',1,1,'other')`).Error == nil {
			t.Fatal("影響確認的動作值域外被接受")
		}
		if err := rollbackCredentialOwnership(run); err == nil {
			t.Fatal("本增量不提供 Down")
		}
	})
}

// assertCredentialOwnershipBackfill 執行一次遷移（apply），逐項核對結果、重跑冪等與預設值保留。
func assertCredentialOwnershipBackfill(t *testing.T, db *gorm.DB, apply func() (CredentialOwnershipReport, error)) {
	t.Helper()
	stableBefore := credentialStableColumns(t, db)
	bindingsBefore := dumpTables(t, db, "asset_accounts", "credential_secret_versions")

	report, err := apply()
	if err != nil {
		t.Fatalf("遷移失敗: %v", err)
	}
	wantReport := CredentialOwnershipReport{SharedToGlobal: 3, DedicatedToAsset: 4, AlreadySet: 0, DedicatedNotSingleBinding: 1}
	if report != wantReport {
		t.Fatalf("報告 = %+v, want %+v（零掛載專用憑證只計入報告）", report, wantReport)
	}
	want := map[uint]string{
		1: "global|", 2: "global|", 6: "global|",
		3: "asset|", 4: "asset|", 5: "asset|", 7: "asset|",
	}
	if got := credentialOwners(t, db); !equalOwners(got, want) {
		t.Fatalf("歸屬 = %v, want %v", got, want)
	}
	if after := credentialStableColumns(t, db); after != stableBefore {
		t.Fatalf("遷移改動了憑證的既有欄位：\n前 %s\n後 %s", stableBefore, after)
	}
	if after := dumpTables(t, db, "asset_accounts", "credential_secret_versions"); after != bindingsBefore {
		t.Fatal("遷移改動了掛載列或密文版本")
	}

	// 預先設成 node 的列：資料步驟重跑保留，報告兩次相同、內容不變。
	if err := db.Exec(`UPDATE credentials SET owner_kind = ?, owner_node_id = ? WHERE id = 2`,
		model.CredentialOwnerNode, 42).Error; err != nil {
		t.Fatal(err)
	}
	want[2] = "node|42"
	snapshot := dumpTables(t, db, "credentials", "asset_accounts", "credential_secret_versions")
	var reports []CredentialOwnershipReport
	for i := 0; i < 2; i++ {
		var r CredentialOwnershipReport
		if err := db.Transaction(func(tx *gorm.DB) error {
			var e error
			r, e = BackfillCredentialOwnership(tx)
			return e
		}); err != nil {
			t.Fatalf("資料步驟第 %d 次重跑失敗: %v", i+1, err)
		}
		reports = append(reports, r)
		if got := dumpTables(t, db, "credentials", "asset_accounts", "credential_secret_versions"); got != snapshot {
			t.Fatalf("資料步驟第 %d 次重跑改動了內容", i+1)
		}
	}
	rerun := CredentialOwnershipReport{AlreadySet: 7, DedicatedNotSingleBinding: 1}
	if reports[0] != rerun || reports[1] != rerun {
		t.Fatalf("重跑報告 = %+v, want 兩次皆 %+v", reports, rerun)
	}
	if got := credentialOwners(t, db); !equalOwners(got, want) {
		t.Fatalf("重跑後歸屬 = %v, want %v（預先設定的 node 應保留）", got, want)
	}
}

// assertCredentialOwnershipRollback 注入「套用後把一列改回 NULL」使重算不一致，整筆交易應回滾。
// ddlInTx 為真時（postgres 整段 migration）兩欄本身應不存在；否則兩欄值全為 NULL。
func assertCredentialOwnershipRollback(t *testing.T, db *gorm.DB, apply func() error, ddlInTx bool) {
	t.Helper()
	credentialOwnershipVerifyHook = func(tx *gorm.DB) error {
		return tx.Exec(`UPDATE credentials SET owner_kind = NULL WHERE id = 1`).Error
	}
	t.Cleanup(func() { credentialOwnershipVerifyHook = nil })
	err := apply()
	credentialOwnershipVerifyHook = nil
	if err == nil || !strings.Contains(err.Error(), "重算不一致") {
		t.Fatalf("注入不一致應回錯誤，實得 %v", err)
	}
	if ddlInTx {
		var n int64
		if err := db.Raw(`SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'credentials' AND column_name IN ('owner_kind','owner_node_id')`).Scan(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("回滾後 credentials 仍有 %d 個歸屬欄", n)
		}
		return
	}
	var n int64
	if err := db.Raw(`SELECT count(*) FROM credentials WHERE owner_kind IS NOT NULL OR owner_node_id IS NOT NULL`).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("回滾後仍有 %d 列帶歸屬值", n)
	}
}

func newCredentialOwnershipSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// :memory: 連線池：多條連線各自是空庫
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.Credential{}, &model.CredentialSecretVersion{}, &model.AssetAccount{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func applyMigrationsBeforeCredentialOwnership(t *testing.T, db *gorm.DB) int {
	t.Helper()
	idx := -1
	for i, m := range migrations {
		if m.Version == "20261029_credential_ownership" {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatal("找不到本增量")
	}
	for _, m := range migrations[:idx] {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}
	return idx
}

// seedCredentialOwnershipFixture 升級前形狀（不寫歸屬欄）：
// 共用 1、2 存活、6 軟刪；專用 3、4 各掛一台，5 零掛載，7 軟刪（其掛載亦軟刪）。
func seedCredentialOwnershipFixture(t *testing.T, db *gorm.DB) {
	t.Helper()
	const ts = "2026-01-01 00:00:00"
	stmts := []string{}
	cred := func(id int, name, scope string, deleted bool) {
		del := "NULL"
		if deleted {
			del = "'" + ts + "'"
		}
		n := "NULL"
		if name != "" {
			n = "'" + name + "'"
		}
		stmts = append(stmts,
			fmt.Sprintf(`INSERT INTO credentials(id,created_at,updated_at,deleted_at,name,scope,username,secret_type,auth_method,protocol_family,note,current_version_id,rotation_epoch)
				VALUES(%d,'%s','%s',%s,%s,'%s','root','password','sql','ssh','',%d,%d)`, id, ts, ts, del, n, scope, id*10, id),
			fmt.Sprintf(`INSERT INTO credential_secret_versions(id,credential_id,version_no,secret_type,password_enc,created_reason,created_at)
				VALUES(%d,%d,1,'password','enc-fixture','manual','%s')`, id*10, id, ts))
	}
	cred(1, "shared-a", model.CredentialScopeShared, false)
	cred(2, "shared-b", model.CredentialScopeShared, false)
	cred(3, "", model.CredentialScopeDedicated, false)
	cred(4, "", model.CredentialScopeDedicated, false)
	cred(5, "", model.CredentialScopeDedicated, false)
	cred(6, "shared-c", model.CredentialScopeShared, true)
	cred(7, "", model.CredentialScopeDedicated, true)
	account := func(id, assetID, credID int, deleted bool) {
		del := "NULL"
		if deleted {
			del = "'" + ts + "'"
		}
		stmts = append(stmts, fmt.Sprintf(`INSERT INTO asset_accounts(id,created_at,updated_at,deleted_at,asset_id,username,auth_method,note,credential_id,effective_version_id)
			VALUES(%d,'%s','%s',%s,%d,'root','sql','',%d,%d)`, id, ts, ts, del, assetID, credID, credID*10))
	}
	account(100, 10, 1, false)
	account(101, 11, 1, false)
	account(102, 12, 3, false)
	account(103, 13, 4, false)
	account(104, 14, 7, true)
	for _, s := range stmts {
		if err := db.Exec(s).Error; err != nil {
			t.Fatalf("fixture: %v\n%s", err, s)
		}
	}
}

func credentialOwners(t *testing.T, db *gorm.DB) map[uint]string {
	t.Helper()
	var rows []struct {
		ID          uint
		OwnerKind   *string
		OwnerNodeID *uint
	}
	if err := db.Raw(`SELECT id, owner_kind, owner_node_id FROM credentials ORDER BY id`).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := map[uint]string{}
	for _, r := range rows {
		k, n := "<nil>", ""
		if r.OwnerKind != nil {
			k = *r.OwnerKind
		}
		if r.OwnerNodeID != nil {
			n = fmt.Sprint(*r.OwnerNodeID)
		}
		out[r.ID] = k + "|" + n
	}
	return out
}

func equalOwners(a, b map[uint]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// credentialStableColumns 歸屬以外、遷移不得改動的憑證欄位快照。
func credentialStableColumns(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var rows []map[string]any
	if err := db.Raw(`SELECT id, name, scope, deleted_at, current_version_id, pending_version_id, active_rotation_id, rotation_epoch FROM credentials ORDER BY id`).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// captureMigrationLog 執行 fn 並回傳期間標準 log 的輸出；fn 失敗即 Fatal。
func captureMigrationLog(t *testing.T, fn func() error) string {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	err := fn()
	log.SetOutput(os.Stderr)
	if err != nil {
		t.Fatalf("執行失敗: %v", err)
	}
	return buf.String()
}

// reportFromLog 自日誌取出固定前綴的報告行，要求恰 want 行並回傳最後一行的報告。
func reportFromLog(t *testing.T, out string, want int) (CredentialOwnershipReport, error) {
	t.Helper()
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if i := strings.Index(l, credentialOwnershipReportPrefix+" "); i >= 0 {
			lines = append(lines, l[i+len(credentialOwnershipReportPrefix)+1:])
		}
	}
	if len(lines) != want {
		return CredentialOwnershipReport{}, fmt.Errorf("報告行數 = %d, want %d；日誌：%s", len(lines), want, out)
	}
	var r CredentialOwnershipReport
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &r); err != nil {
		return CredentialOwnershipReport{}, errors.Join(errors.New("報告行不是 JSON"), err)
	}
	return r, nil
}
