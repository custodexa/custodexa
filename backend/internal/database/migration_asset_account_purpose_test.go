package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

// TestAssetAccountPurposeMigration 資產帳號用途增量（PG-gated）：
// 既有庫套用後既有帳號一律為 login；同一資產第二筆未刪除執行身分被部分唯一索引拒絕；
// 軟刪後可再設定。
func TestAssetAccountPurposeMigration(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, fmt.Sprintf("acct_purpose_%d", time.Now().UnixNano()))
	if db.Dialector.Name() != "postgres" {
		t.Fatalf("dialector = %s, want postgres", db.Dialector.Name())
	}
	t.Log("EVIDENCE dialect=postgres")
	idx := -1
	for i, m := range migrations {
		if m.Version == "20261102_asset_account_purpose" {
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
	for i, name := range []string{"root", "app", "ops"} {
		def := "true"
		if i == 2 {
			def = "false"
		}
		if err := exec(fmt.Sprintf(`INSERT INTO asset_accounts(id,created_at,updated_at,asset_id,username,is_default,auth_method,note,credential_id)
			VALUES(%d,'%s','%s',%d,'%s',%s,'sql','',%d)`, 100+i, ts, ts, 10+i, name, def, 1+i)); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	if err := migrations[idx].Up(db); err != nil {
		t.Fatalf("增量失敗: %v", err)
	}

	t.Run("existing rows are login", func(t *testing.T) {
		var purposes []string
		if err := db.Raw(`SELECT purpose FROM asset_accounts ORDER BY id`).Scan(&purposes).Error; err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(purposes) != "[login login login]" {
			t.Fatalf("purposes = %v, want 三筆 login", purposes)
		}
	})

	t.Run("second live executor rejected", func(t *testing.T) {
		if err := exec(`INSERT INTO asset_accounts(id,created_at,updated_at,asset_id,username,auth_method,note,credential_id,purpose)
			VALUES(200,now(),now(),10,'cx-exec','sql','',20,'executor')`); err != nil {
			t.Fatalf("第一筆執行身分應成功: %v", err)
		}
		err := exec(`INSERT INTO asset_accounts(id,created_at,updated_at,asset_id,username,auth_method,note,credential_id,purpose)
			VALUES(201,now(),now(),10,'cx-exec2','sql','',21,'executor')`)
		if err == nil {
			t.Fatal("同一資產第二筆未刪除執行身分應被唯一索引拒絕")
		}
		if err := exec(`INSERT INTO asset_accounts(id,created_at,updated_at,asset_id,username,auth_method,note,credential_id,purpose)
			VALUES(202,now(),now(),11,'cx-exec','sql','',22,'executor')`); err != nil {
			t.Fatalf("另一台資產的執行身分不受影響: %v", err)
		}
	})

	t.Run("soft deleted frees the slot", func(t *testing.T) {
		if err := exec(`UPDATE asset_accounts SET deleted_at = now() WHERE id = 200`); err != nil {
			t.Fatal(err)
		}
		if err := exec(`INSERT INTO asset_accounts(id,created_at,updated_at,asset_id,username,auth_method,note,credential_id,purpose)
			VALUES(203,now(),now(),10,'cx-exec3','sql','',23,'executor')`); err != nil {
			t.Fatalf("軟刪後應可再設定執行身分: %v", err)
		}
	})

	if err := migrations[idx].Up(db); err == nil {
		t.Fatal("重跑本增量應大聲失敗（不用 IF NOT EXISTS）")
	}
}
