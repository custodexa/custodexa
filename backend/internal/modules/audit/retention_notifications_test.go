package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupNotificationRetentionDB 帶外鍵的精簡結構：告警列 → 通知內容（連帶刪除）→ 待投遞紀錄（連帶刪除），
// 系統安全告警的待投遞紀錄直接指向告警列。外鍵以 sqlite 的 foreign_keys 開啟，與 PostgreSQL 上的語義相同。
func setupNotificationRetentionDB(t *testing.T) (*RetentionService, *gorm.DB, *fakeAuditLogger, *time.Time) {
	t.Helper()
	dsn := fmt.Sprintf("file:ndl_retention_%d?mode=memory&cache=shared&_pragma=foreign_keys(1)", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.AuditLog{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, stmt := range []string{
		"CREATE TABLE session_commands (id INTEGER PRIMARY KEY AUTOINCREMENT, executed_at DATETIME NOT NULL)",
		"CREATE TABLE command_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, triggered_at DATETIME NOT NULL)",
		`CREATE TABLE notification_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, event_key TEXT NOT NULL,
			alert_id INTEGER REFERENCES command_alerts(id) ON DELETE CASCADE, severity TEXT NOT NULL, occurred_at DATETIME NOT NULL,
			actor_user_id INTEGER, actor_name TEXT NOT NULL DEFAULT '', target_kind TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '',
			target_name TEXT NOT NULL DEFAULT '', params TEXT NOT NULL DEFAULT '{}', name_refs TEXT NOT NULL DEFAULT '{}', link_path TEXT NOT NULL DEFAULT '',
			degraded BOOLEAN NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'pending', dispatch_attempts INTEGER NOT NULL DEFAULT 0,
			lease_until DATETIME, fail_reason TEXT NOT NULL DEFAULT '', dispatched_at DATETIME, created_at DATETIME NOT NULL)`,
		`CREATE TABLE system_alert_outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL,
			alert_id INTEGER REFERENCES command_alerts(id) ON DELETE CASCADE,
			message_id INTEGER REFERENCES notification_messages(id) ON DELETE CASCADE,
			state TEXT NOT NULL, created_at DATETIME NOT NULL)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("建表: %v", err)
		}
	}
	audit := &fakeAuditLogger{}
	svc := NewRetentionService(db, newTestPolicyService(db), nil, audit)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	svc.clock = func() time.Time { return now }
	return svc, db, audit, &now
}

// seedMessage 寫一列通知內容與它的待投遞紀錄；回傳內容列識別碼。
func seedMessage(t *testing.T, db *gorm.DB, category, state string, alertID *int64, created time.Time, deliveryStates ...string) int64 {
	t.Helper()
	var id int64
	if err := db.Raw(`INSERT INTO notification_messages(category,event_key,alert_id,severity,occurred_at,state,created_at) VALUES(?,?,?,?,?,?,?) RETURNING id`,
		category, category, alertID, "medium", created, state, created).Scan(&id).Error; err != nil {
		t.Fatal(err)
	}
	for _, st := range deliveryStates {
		if err := db.Exec(`INSERT INTO system_alert_outbox(category,message_id,state,created_at) VALUES(?,?,?,?)`, category, id, st, created).Error; err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func seedRetentionAlert(t *testing.T, db *gorm.DB, triggered time.Time) int64 {
	t.Helper()
	var id int64
	if err := db.Raw(`INSERT INTO command_alerts(triggered_at) VALUES(?) RETURNING id`, triggered).Scan(&id).Error; err != nil {
		t.Fatal(err)
	}
	return id
}

func countWhere(t *testing.T, db *gorm.DB, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.Raw(query, args...).Scan(&n).Error; err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// TestNotificationRetentionIndependentOfAlertRetention (a) 告警記錄永久保留時，建立 31 天且紀錄皆為終態的
// 系統事件內容與指令告警內容都被清除、紀錄為 0，告警列仍在，同期系統安全告警的紀錄仍在；
// (b) 有一筆重試中的內容與紀錄保留、仍待分派的內容保留、29 天的不動；這一步產生一筆清除審計。
func TestNotificationRetentionIndependentOfAlertRetention(t *testing.T) {
	svc, db, audit, now := setupNotificationRetentionDB(t)
	if got := svc.policy.GetInt(policy.PolicyRetentionAlertDays); got != 0 {
		t.Fatalf("前提：告警記錄保留天數應為 0（永久），得 %d", got)
	}
	old := now.Add(-31 * 24 * time.Hour)
	young := now.Add(-29 * 24 * time.Hour)

	alertID := seedRetentionAlert(t, db, old)
	sysEvent := seedMessage(t, db, "system_event", "dispatched", nil, old, "delivered", "abandoned")
	cmdAlert := seedMessage(t, db, "command_alert", "dispatched", &alertID, old, "canceled")
	failed := seedMessage(t, db, "system_event", "failed", nil, old)
	retrying := seedMessage(t, db, "system_event", "dispatched", nil, old, "delivered", "retrying")
	pending := seedMessage(t, db, "system_event", "pending", nil, old)
	recent := seedMessage(t, db, "system_event", "dispatched", nil, young, "delivered")
	// 同期的系統安全告警紀錄：指向告警列，不屬內容表
	secAlert := seedRetentionAlert(t, db, old)
	if err := db.Exec(`INSERT INTO system_alert_outbox(category,alert_id,state,created_at) VALUES('system_security_alert',?,'delivered',?)`, secAlert, old).Error; err != nil {
		t.Fatal(err)
	}

	svc.PurgeAll()

	for name, id := range map[string]int64{"系統事件": sysEvent, "指令告警": cmdAlert, "分派失敗": failed} {
		if n := countWhere(t, db, `SELECT count(*) FROM notification_messages WHERE id = ?`, id); n != 0 {
			t.Errorf("建立 31 天、紀錄皆終態的%s內容應被清除", name)
		}
		if n := countWhere(t, db, `SELECT count(*) FROM system_alert_outbox WHERE message_id = ?`, id); n != 0 {
			t.Errorf("%s內容的待投遞紀錄應一併清除，剩 %d 筆", name, n)
		}
	}
	if n := countWhere(t, db, `SELECT count(*) FROM command_alerts WHERE id = ?`, alertID); n != 1 {
		t.Error("告警記錄永久保留時告警列不應被清除")
	}
	if n := countWhere(t, db, `SELECT count(*) FROM system_alert_outbox WHERE category = 'system_security_alert'`); n != 1 {
		t.Error("系統安全告警的待投遞紀錄不受 30 天清除影響")
	}
	if n := countWhere(t, db, `SELECT count(*) FROM notification_messages WHERE id = ?`, retrying); n != 1 {
		t.Error("仍有重試中紀錄的內容不應被清除")
	}
	if n := countWhere(t, db, `SELECT count(*) FROM system_alert_outbox WHERE message_id = ?`, retrying); n != 2 {
		t.Errorf("仍有重試中紀錄的內容，其紀錄應全數保留，剩 %d 筆", n)
	}
	if n := countWhere(t, db, `SELECT count(*) FROM notification_messages WHERE id IN (?, ?)`, pending, recent); n != 2 {
		t.Error("仍待分派的內容與建立 29 天的內容不應被清除")
	}

	var entries []*AuditLogEntry
	for _, e := range audit.entries {
		if strings.Contains(e.Details, notificationPurgeTarget) {
			entries = append(entries, e)
		}
	}
	if len(entries) != 1 {
		t.Fatalf("清除審計應恰一筆，得 %d", len(entries))
	}
	var res PurgeResult
	if err := json.Unmarshal([]byte(entries[0].Details), &res); err != nil {
		t.Fatal(err)
	}
	if res.Deleted != 3 || res.Days != notificationMessageRetentionDays || entries[0].Resource != model.ResourceRetention {
		t.Errorf("清除審計內容不符: %+v resource=%s", res, entries[0].Resource)
	}

	// 再跑一次沒有東西可清：不產生新的清除審計
	before := len(audit.entries)
	svc.PurgeAll()
	if len(audit.entries) != before {
		t.Errorf("沒有可清除的內容時不應留痕，多了 %d 筆", len(audit.entries)-before)
	}
}

// TestNotificationRetentionFollowsAlertPurge (c) 告警記錄保留天數為 7、告警列過期被清除時，
// 其指令告警內容與紀錄一併消失（如實的連帶刪除）。
func TestNotificationRetentionFollowsAlertPurge(t *testing.T) {
	svc, db, _, now := setupNotificationRetentionDB(t)
	if _, err := svc.policy.Update(policy.PolicyRetentionAlertDays, "7", "test"); err != nil {
		t.Fatal(err)
	}
	// 告警列以實際時間判定過期（保留清除以 time.Now 計算），內容列建立於 3 天前（未達 30 天）
	alertID := seedRetentionAlert(t, db, time.Now().Add(-8*24*time.Hour))
	msg := seedMessage(t, db, "command_alert", "dispatched", &alertID, now.Add(-3*24*time.Hour), "retrying")

	svc.PurgeAll()

	if n := countWhere(t, db, `SELECT count(*) FROM command_alerts WHERE id = ?`, alertID); n != 0 {
		t.Fatal("前提：告警列應已過期被清除")
	}
	if n := countWhere(t, db, `SELECT count(*) FROM notification_messages WHERE id = ?`, msg); n != 0 {
		t.Error("告警列被清除時，其指令告警內容應連帶刪除")
	}
	if n := countWhere(t, db, `SELECT count(*) FROM system_alert_outbox WHERE message_id = ?`, msg); n != 0 {
		t.Error("告警列被清除時，其指令告警內容的待投遞紀錄應連帶刪除")
	}
}
