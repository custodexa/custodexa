package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

// TestSystemAlertSchemaMigration 系統安全告警增量：值域、級聯、升級零副作用、重跑不改內容。
func TestSystemAlertSchemaMigration(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, fmt.Sprintf("sys_alert_%d", time.Now().UnixNano()))

	// 升級前：套用到本增量之前的全部 migration，並放入既有告警與通道列。
	last := -1
	for i, m := range migrations {
		if m.Version == "20261018_system_security_alerts" {
			last = i
		}
	}
	if last < 0 {
		t.Fatal("找不到本增量 20261018_system_security_alerts")
	}
	for _, m := range migrations[:last] {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}
	if err := db.Exec(`INSERT INTO command_alerts(kind,rule_id,rule_name,reason_code,session_id,user_id,command,severity,triggered_at,disposition,note) VALUES('new_source_ip',NULL,'new_source_ip','new_source_ip_session',5,9,'','medium',now(),'pending','')`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO notification_channels(name,type,url,secret,enabled,language,min_severity,created_at,updated_at) VALUES('c1','webhook','https://example.invalid/h','',true,'zh-TW','low',now(),now())`).Error; err != nil {
		t.Fatal(err)
	}
	before := dumpTables(t, db, "command_alerts", "notification_channels")

	if err := migrations[last].Up(db); err != nil {
		t.Fatal(err)
	}
	if after := dumpTables(t, db, "command_alerts", "notification_channels"); after != before {
		t.Fatalf("升級改動了既有告警或通道列\nbefore=%s\nafter=%s", before, after)
	}
	for _, tb := range []string{"system_alert_details", "system_alert_outbox", "system_alert_severity_overrides"} {
		var n int64
		if err := db.Table(tb).Count(&n).Error; err != nil || n != 0 {
			t.Fatalf("%s 升級後應為空: n=%d err=%v", tb, n, err)
		}
	}

	// 值域：system_security 可無會話、無規則；其他無會話的類別仍被拒；值域外類別被拒。
	ins := `INSERT INTO command_alerts(kind,rule_id,rule_name,reason_code,session_id,user_id,command,severity,triggered_at,disposition,note) VALUES(?,?,?,?,?,9,'','high',now(),'pending','') RETURNING id`
	var alertID uint
	if err := db.Raw(ins, "system_security", nil, "notification_channel_changed", "notification_channel_changed", nil).Scan(&alertID).Error; err != nil || alertID == 0 {
		t.Fatalf("system_security 列被拒: %v", err)
	}
	if db.Exec(ins, "system_security", 1, "x", "x", nil).Error == nil {
		t.Fatal("system_security 掛上規則仍被接受")
	}
	if db.Exec(ins, "new_source_ip", nil, "x", "x", nil).Error == nil {
		t.Fatal("無會話的 new_source_ip 被接受（會話參照檢查被放寬過頭）")
	}
	if db.Exec(ins, "not_a_kind", nil, "x", "x", 1).Error == nil {
		t.Fatal("值域外來源類別被接受")
	}

	// 明細與投遞列；CHECK 拒絕非法狀態、目的地類型與語系、分級。
	if err := db.Exec(`INSERT INTO system_alert_details(alert_id,alert_type,target_kind,target_id,params,correlation_id,created_at) VALUES(?,?,?,?,?,?,now())`,
		alertID, "notification_channel_changed", "notification_channel", "1", "{}", "corr-1").Error; err != nil {
		t.Fatal(err)
	}
	outbox := `INSERT INTO system_alert_outbox(alert_id,dest_type,dest_name,dest_language,url_enc,state,next_attempt_at,created_at) VALUES(?,?,?,?,?,?,now(),now())`
	if err := db.Exec(outbox, alertID, "webhook", "c1", "zh-TW", "enc", "pending").Error; err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]any{
		"state":    {alertID, "webhook", "c1", "zh-TW", "enc", "done"},
		"type":     {alertID, "email", "c1", "zh-TW", "enc", "pending"},
		"language": {alertID, "webhook", "c1", "fr-FR", "enc", "pending"},
		"alert":    {alertID + 999, "webhook", "c1", "zh-TW", "enc", "pending"},
	} {
		if db.Exec(outbox, args...).Error == nil {
			t.Fatalf("非法 %s 被接受", name)
		}
	}
	if err := db.Exec(`INSERT INTO system_alert_severity_overrides(alert_type,severity,updated_by,updated_at) VALUES('management_role_granted','low',1,now())`).Error; err != nil {
		t.Fatal(err)
	}
	if db.Exec(`INSERT INTO system_alert_severity_overrides(alert_type,severity,updated_by,updated_at) VALUES('x','off',1,now())`).Error == nil {
		t.Fatal("分級覆寫接受了三值以外的值")
	}

	// 刪除告警列（保留政策清除）級聯刪除明細與投遞列。
	if err := db.Exec(`DELETE FROM command_alerts WHERE id = ?`, alertID).Error; err != nil {
		t.Fatal(err)
	}
	for _, tb := range []string{"system_alert_details", "system_alert_outbox"} {
		var n int64
		if err := db.Table(tb).Count(&n).Error; err != nil || n != 0 {
			t.Fatalf("%s 未隨告警列級聯刪除: n=%d err=%v", tb, n, err)
		}
	}
	if err := rollbackSystemSecurityAlerts(db); err == nil {
		t.Fatal("證據類 migration 不應提供回滾")
	}

	// RunMigrations 第二次不改內容。
	run := freshSchema(t, dsn, fmt.Sprintf("sys_alert_run_%d", time.Now().UnixNano()))
	prev := DB
	DB = run
	t.Cleanup(func() { DB = prev })
	if err := RunMigrations(); err != nil {
		t.Fatalf("第一次 RunMigrations: %v", err)
	}
	tables := []string{"schema_migrations", "command_alerts", "system_alert_details", "system_alert_outbox", "system_alert_severity_overrides", "notification_channels"}
	first := dumpTables(t, run, tables...)
	if err := RunMigrations(); err != nil {
		t.Fatalf("第二次 RunMigrations: %v", err)
	}
	if second := dumpTables(t, run, tables...); second != first {
		t.Fatal("第二次 RunMigrations 改動了內容")
	}
}
