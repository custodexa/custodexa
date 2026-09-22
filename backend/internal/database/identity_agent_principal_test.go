package database

import (
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
	"testing"
)

func principalSchema(t *testing.T, name string) *gorm.DB {
	t.Helper()
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), name)
	if err := applyBaseline(db); err != nil {
		t.Fatal(err)
	}
	if err := applyMigrationsAfterBaseline(db); err != nil {
		t.Fatal(err)
	}
	return db
}
func TestBaselineIdentityAgentPrincipal(t *testing.T) {
	db := principalSchema(t, "identity_agent_principal_test")
	if err := db.Exec(`INSERT INTO users (id,username,password) VALUES (9001,'owner','!')`).Error; err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (username,password,kind) VALUES ('bad-kind','!','robot')`,
		`INSERT INTO users (username,password,kind) VALUES ('no-owner','!','agent')`,
		`INSERT INTO users (username,password,kind,owner_user_id) VALUES ('bad-owner','!','agent',999999)`,
	} {
		if err := db.Exec(q).Error; err == nil {
			t.Fatalf("constraint accepted %s", q)
		}
	}
	if err := db.Exec(`INSERT INTO users (id,username,password,kind,owner_user_id) VALUES (9002,'agent','!','agent',9001)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO agent_tokens (user_id,name,token_hash,created_by,expires_at) VALUES (9002,'first','digest',9001,now())`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO agent_tokens (user_id,name,token_hash,created_by,expires_at) VALUES (9002,'duplicate','digest',9001,now())`).Error; err == nil {
		t.Fatal("duplicate token hash accepted")
	}
}
func TestBaselineSessionAgentLinks(t *testing.T) {
	db := principalSchema(t, "session_agent_links_test")
	var cols []struct {
		ColumnName string
		IsNullable string
	}
	if err := db.Raw(`SELECT column_name,is_nullable FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='sessions' AND column_name IN ('agent_token_id','access_request_id')`).Scan(&cols).Error; err != nil {
		t.Fatal(err)
	}
	if len(cols) != 2 {
		t.Fatalf("columns=%v", cols)
	}
	for _, c := range cols {
		if c.IsNullable != "YES" {
			t.Fatalf("%s not nullable", c.ColumnName)
		}
	}
	var n int64
	if err := db.Raw(`SELECT count(*) FROM pg_constraint WHERE conrelid='sessions'::regclass AND conname='fk_sessions_agent_token' AND contype='f'`).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("agent token FK missing")
	}
}
