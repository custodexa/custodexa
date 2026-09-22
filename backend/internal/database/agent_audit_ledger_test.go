package database

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

func TestAgentAuditLedgerMigrationPostgres(t *testing.T) {
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), fmt.Sprintf("w31_ledger_%d", time.Now().UnixNano()))
	for _, m := range migrations {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}
	for _, q := range []string{
		`INSERT INTO users(id,username,password,kind,active) VALUES(801,'ledger-owner','!','human',true)`,
		`INSERT INTO users(id,username,password,kind,owner_user_id,active) VALUES(802,'ledger-agent','!','agent',801,true)`,
		`INSERT INTO agent_tokens(id,user_id,name,token_hash,created_by,expires_at) VALUES(801,802,'fixture','fixture-hash',801,now()+interval '1 hour')`,
	} {
		if err := db.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
	insert := `INSERT INTO agent_tool_calls(seq,user_id,agent_token_id,owner_user_id,tool,args_redacted,decision,denial_code,result_status,result_digest,result_excerpt,masked_count,duration_ms,created_at,integrity_hmac,key_version) VALUES(?,802,801,801,?,'{}',?,'','','',?,0,0,now(),'fixture',1)`
	for i, tool := range []string{"list_assets", "request_access", "check_request"} {
		if err := db.Exec(insert, i+1, tool, "pending", "").Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name                    string
		seq                     int
		tool, decision, excerpt string
	}{
		{"task required", 4, "run_command", "pending", ""},
		{"excerpt byte limit", 4, "list_assets", "pending", strings.Repeat("界", 683)},
		{"decision check", 4, "list_assets", "unknown", ""},
		{"sequence uniqueness", 1, "list_assets", "pending", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if db.Exec(insert, tc.seq, tc.tool, tc.decision, tc.excerpt).Error == nil {
				t.Fatal("constraint accepted invalid row")
			}
		})
	}
	if err := db.Exec(insert, 4, "list_assets", "pending", strings.Repeat("x", 2048)).Error; err != nil {
		t.Fatal(err)
	}
	if db.Exec(`INSERT INTO agent_probe_events(user_id,agent_token_id,asset_ref,endpoint,class,created_at) VALUES(802,801,99,'fixture','invalid',now())`).Error == nil {
		t.Fatal("invalid probe class accepted")
	}
	if err := rollbackAgentAuditLedger(db); err == nil {
		t.Fatal("destructive Down allowed")
	}
	var n int64
	if err := db.Table("agent_tool_calls").Count(&n).Error; err != nil || n != 4 {
		t.Fatal("Down lost evidence", n, err)
	}
	t.Log("PG CHECKs, byte limit, per-principal uniqueness, null task whitelist, and non-destructive Down verified")
}
