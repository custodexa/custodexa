package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

// TestAPITokenRoleLevelMigration API token 授權角色層級的增量（PG-gated）：既有列套用後一律為 read_write
// （升級前的 token 行為不變）、levels_recorded 為 false（升級前建立）；新寫入未帶層級同樣取 read_write；帶層級者照存；
// Down 刪欄後 Up 可再套用；重跑本增量必須大聲失敗。
func TestAPITokenRoleLevelMigration(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, fmt.Sprintf("api_token_role_level_%d", time.Now().UnixNano()))
	if db.Dialector.Name() != "postgres" {
		t.Fatalf("dialector = %s, want postgres", db.Dialector.Name())
	}
	t.Log("EVIDENCE dialect=postgres")
	idx := -1
	for i, m := range migrations {
		if m.Version == "20261118_api_token_role_level" {
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
	exec := func(q string) {
		t.Helper()
		if err := db.Exec(q).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO users(id, username, password, kind, active, created_at, updated_at) VALUES (900, 'level-owner', '!', 'human', true, now(), now())`)
	exec(`INSERT INTO roles(id, name, definition_version, created_at, updated_at) VALUES (901, 'level-role-a', 1, now(), now()), (902, 'level-role-b', 1, now(), now())`)
	exec(`INSERT INTO api_tokens(id, user_id, name, token_hash, created_at) VALUES (903, 900, 'pre-upgrade', 'h903', now())`)
	exec(`INSERT INTO api_token_roles(api_token_id, role_id) VALUES (903, 901), (903, 902)`)

	if err := migrations[idx].Up(db); err != nil {
		t.Fatalf("增量失敗: %v", err)
	}
	levels := func(tokenID int) map[int]string {
		t.Helper()
		var rows []struct {
			RoleID int
			Level  string
		}
		if err := db.Raw(`SELECT role_id, level FROM api_token_roles WHERE api_token_id = ? ORDER BY role_id`, tokenID).Scan(&rows).Error; err != nil {
			t.Fatal(err)
		}
		out := map[int]string{}
		for _, r := range rows {
			out[r.RoleID] = r.Level
		}
		return out
	}
	t.Run("existing rows become read_write", func(t *testing.T) {
		got := levels(903)
		if len(got) != 2 || got[901] != "read_write" || got[902] != "read_write" {
			t.Fatalf("既有列的層級 = %v，應皆為 read_write", got)
		}
		t.Logf("EVIDENCE pre-upgrade levels=%v", got)
	})
	recorded := func(tokenID int) bool {
		t.Helper()
		var v bool
		if err := db.Raw(`SELECT levels_recorded FROM api_tokens WHERE id = ?`, tokenID).Scan(&v).Error; err != nil {
			t.Fatal(err)
		}
		return v
	}
	t.Run("existing tokens are marked as created before levels", func(t *testing.T) {
		if recorded(903) {
			t.Fatal("既有 token 的 levels_recorded 應為 false")
		}
		if err := db.Exec(`UPDATE api_tokens SET levels_recorded = NULL WHERE id = 903`).Error; err == nil {
			t.Fatal("levels_recorded 應為 NOT NULL")
		}
		t.Log("EVIDENCE pre-upgrade levels_recorded=false")
	})
	t.Run("new rows default to read_write and keep an explicit level", func(t *testing.T) {
		exec(`INSERT INTO api_tokens(id, user_id, name, token_hash, created_at) VALUES (904, 900, 'post-upgrade', 'h904', now())`)
		exec(`INSERT INTO api_token_roles(api_token_id, role_id) VALUES (904, 901)`)
		exec(`INSERT INTO api_token_roles(api_token_id, role_id, level) VALUES (904, 902, 'read')`)
		got := levels(904)
		if got[901] != "read_write" || got[902] != "read" {
			t.Fatalf("新列的層級 = %v", got)
		}
	})
	t.Run("level is not nullable", func(t *testing.T) {
		if err := db.Exec(`UPDATE api_token_roles SET level = NULL WHERE api_token_id = 904`).Error; err == nil {
			t.Fatal("level 應為 NOT NULL")
		}
	})
	if err := migrations[idx].Up(db); err == nil {
		t.Fatal("重跑本增量應大聲失敗（不用 IF NOT EXISTS）")
	}
	if err := migrations[idx].Down(db); err != nil {
		t.Fatalf("Down 失敗: %v", err)
	}
	if err := migrations[idx].Up(db); err != nil {
		t.Fatalf("Down 後再 Up 失敗: %v", err)
	}
	if got := levels(903); got[901] != "read_write" || got[902] != "read_write" {
		t.Fatalf("Down→Up 後的層級 = %v", got)
	}
	if recorded(903) {
		t.Fatal("Down→Up 後 levels_recorded 應為 false")
	}
}
