package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

func TestSensitiveRevealAlertMigrationPostgres(t *testing.T) {
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), fmt.Sprintf("sensitive_reveal_%d", time.Now().UnixNano()))
	for _, m := range migrations {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}
	insert := `INSERT INTO command_alerts(kind,rule_id,rule_name,reason_code,session_id,user_id,command,severity,triggered_at,disposition,note) VALUES(?,?,'sensitive_reveal','sensitive_reveal',73,9,'','medium',now(),'pending','{"source_type":"clipboard_event","source_id":5}')`
	if err := db.Exec(insert, "sensitive_reveal", nil).Error; err != nil {
		t.Fatalf("new kind rejected: %v", err)
	}
	for _, kind := range []string{"audit_degraded", "new_source_ip", "agent_breaker_tripped"} {
		if err := db.Exec(insert, kind, nil).Error; err != nil {
			t.Fatalf("existing kind %s rejected: %v", kind, err)
		}
	}
	if db.Exec(insert, "sensitive_reveal", 1).Error == nil {
		t.Fatal("policy signal attached to CRUD rule")
	}
	if db.Exec(insert, "not_a_kind", nil).Error == nil {
		t.Fatal("unknown kind accepted")
	}
	if err := rollbackSensitiveRevealAlert(db); err == nil {
		t.Fatal("destructive down allowed")
	}
	var count int64
	if err := db.Table("command_alerts").Where("kind=?", "sensitive_reveal").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("evidence lost: %d %v", count, err)
	}
	t.Log("sensitive_reveal accepted with NULL rule; existing kinds retained; invalid kind/rule rejected; down preserves evidence")
}
