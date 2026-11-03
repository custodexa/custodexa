package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

// TestAssetAccountExecutorSourceMigration 執行身分來源增量（PG-gated）：
// 既有庫套用後既有帳號（登入用與執行身分）的 executor_source 一律為空字串、purpose 不變；
// 新寫入未帶來源時同樣取空字串；重跑本增量必須大聲失敗。
func TestAssetAccountExecutorSourceMigration(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, fmt.Sprintf("acct_exec_source_%d", time.Now().UnixNano()))
	if db.Dialector.Name() != "postgres" {
		t.Fatalf("dialector = %s, want postgres", db.Dialector.Name())
	}
	t.Log("EVIDENCE dialect=postgres")
	idx := -1
	for i, m := range migrations {
		if m.Version == "20261103_asset_account_executor_source" {
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
	const ts = "2026-01-01 00:00:00"
	exec := func(q string) error { return db.Exec(q).Error }
	fixtures := []struct {
		id       int
		assetID  int
		username string
		purpose  string
	}{
		{100, 10, "root", "login"},
		{101, 10, "cx-exec", "executor"},
		{102, 11, "app", "login"},
	}
	for _, f := range fixtures {
		if err := exec(fmt.Sprintf(`INSERT INTO asset_accounts(id,created_at,updated_at,asset_id,username,auth_method,note,credential_id,purpose)
			VALUES(%d,'%s','%s',%d,'%s','sql','',%d,'%s')`, f.id, ts, ts, f.assetID, f.username, f.id, f.purpose)); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	if err := migrations[idx].Up(db); err != nil {
		t.Fatalf("增量失敗: %v", err)
	}

	type row struct {
		ID             int
		Purpose        string
		ExecutorSource string
	}
	t.Run("existing rows have empty source and unchanged purpose", func(t *testing.T) {
		var rows []row
		if err := db.Raw(`SELECT id, purpose, executor_source FROM asset_accounts ORDER BY id`).Scan(&rows).Error; err != nil {
			t.Fatal(err)
		}
		if len(rows) != len(fixtures) {
			t.Fatalf("rows = %d, want %d", len(rows), len(fixtures))
		}
		for i, r := range rows {
			if r.ExecutorSource != "" {
				t.Errorf("id=%d executor_source = %q, want 空字串", r.ID, r.ExecutorSource)
			}
			if r.Purpose != fixtures[i].purpose {
				t.Errorf("id=%d purpose = %q, want %q（增量不得改動）", r.ID, r.Purpose, fixtures[i].purpose)
			}
		}
		t.Logf("EVIDENCE rows=%+v", rows)
	})

	t.Run("new row without source defaults to empty", func(t *testing.T) {
		if err := exec(`INSERT INTO asset_accounts(id,created_at,updated_at,asset_id,username,auth_method,note,credential_id)
			VALUES(200,now(),now(),12,'ops','sql','',20)`); err != nil {
			t.Fatal(err)
		}
		var src string
		if err := db.Raw(`SELECT executor_source FROM asset_accounts WHERE id = 200`).Scan(&src).Error; err != nil {
			t.Fatal(err)
		}
		if src != "" {
			t.Fatalf("executor_source = %q, want 空字串", src)
		}
	})

	if err := migrations[idx].Up(db); err == nil {
		t.Fatal("重跑本增量應大聲失敗（不用 IF NOT EXISTS）")
	}
}
