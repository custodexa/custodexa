package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

// TestNotificationChannelMinSeverityMigrationPostgres: a channel that existed before
// the migration comes out with min_severity "low" (push behavior unchanged after the
// upgrade), and the CHECK rejects values outside low/medium/high.
func TestNotificationChannelMinSeverityMigrationPostgres(t *testing.T) {
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), fmt.Sprintf("channel_min_severity_%d", time.Now().UnixNano()))

	var target int = -1
	for i, m := range migrations {
		if m.Version == "20260929_notification_channel_min_severity" {
			target = i
			break
		}
	}
	if target < 0 {
		t.Fatal("migration 20260929_notification_channel_min_severity is not registered")
	}
	for _, m := range migrations[:target] {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}
	if err := db.Exec(`INSERT INTO notification_channels(name,type,url,enabled) VALUES('pre-upgrade','slack','https://hooks.example.com/x',true)`).Error; err != nil {
		t.Fatalf("seed pre-upgrade channel: %v", err)
	}
	for _, m := range migrations[target:] {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}

	var got string
	if err := db.Raw(`SELECT min_severity FROM notification_channels WHERE name='pre-upgrade'`).Scan(&got).Error; err != nil {
		t.Fatalf("read min_severity: %v", err)
	}
	if got != "low" {
		t.Fatalf("pre-upgrade channel min_severity = %q, want low", got)
	}
	for _, ok := range []string{"low", "medium", "high"} {
		if err := db.Exec(`UPDATE notification_channels SET min_severity=? WHERE name='pre-upgrade'`, ok).Error; err != nil {
			t.Errorf("min_severity %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "critical", "HIGH"} {
		if db.Exec(`UPDATE notification_channels SET min_severity=? WHERE name='pre-upgrade'`, bad).Error == nil {
			t.Errorf("min_severity %q accepted by CHECK", bad)
		}
	}
	t.Log("pre-upgrade channel defaults to low; CHECK admits low/medium/high only")
}
