package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
)

// TestNotificationDeliveryLayerMigration 通知投遞層增量：既有待投遞紀錄原地沿用、分級回填、
// 兩類約束的正向與反向、通道新欄位的預設值、不提供回滾。
func TestNotificationDeliveryLayerMigration(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, fmt.Sprintf("ndl_mig_%d", time.Now().UnixNano()))

	idx := -1
	for i, m := range migrations {
		if m.Version == notificationDeliveryLayerVersion {
			idx = i
		}
	}
	upTo := idx
	if idx < 0 {
		upTo = len(migrations)
	}
	for _, m := range migrations[:upTo] {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}

	// 升級前：一筆 high 的系統安全告警、一筆重試中的投遞紀錄、一個通道。
	var alertID uint
	if err := db.Raw(`INSERT INTO command_alerts(kind,rule_id,rule_name,reason_code,session_id,user_id,command,severity,triggered_at,disposition,note) VALUES('system_security',NULL,'notification_channel_changed','notification_channel_changed',NULL,9,'','high',now(),'pending','') RETURNING id`).Scan(&alertID).Error; err != nil || alertID == 0 {
		t.Fatalf("插入告警列失敗: %v", err)
	}
	var channelID uint
	if err := db.Raw(`INSERT INTO notification_channels(name,type,url,secret,enabled,language,min_severity,created_at,updated_at) VALUES('c1','webhook','enc:u','enc:s',true,'zh-TW','low',now(),now()) RETURNING id`).Scan(&channelID).Error; err != nil {
		t.Fatal(err)
	}
	var outboxID uint
	if err := db.Raw(`INSERT INTO system_alert_outbox(alert_id,dest_type,dest_name,dest_language,source_channel_id,url_enc,secret_enc,state,attempts,next_attempt_at,last_error,created_at,delivery_key) VALUES(?,'webhook','c1','zh-TW',?,'enc:url-snap','enc:secret-snap','retrying',3,now(),'HTTP 500',now(),'0123456789abcdef0123456789abcdef') RETURNING id`,
		alertID, channelID).Scan(&outboxID).Error; err != nil {
		t.Fatal(err)
	}
	type snap struct {
		DeliveryKey string
		URLEnc      string
		SecretEnc   string
		Attempts    int
		State       string
	}
	var before snap
	if err := db.Raw(`SELECT delivery_key, url_enc, secret_enc, attempts, state FROM system_alert_outbox WHERE id = ?`, outboxID).Scan(&before).Error; err != nil {
		t.Fatal(err)
	}

	up := applyNotificationDeliveryLayer
	if idx < 0 {
		t.Errorf("本增量 %s 沒有登記在 migrations 清單", notificationDeliveryLayerVersion)
	} else {
		up = migrations[idx].Up
	}
	if err := up(db); err != nil {
		t.Fatalf("升級失敗: %v", err)
	}

	var after snap
	if err := db.Raw(`SELECT delivery_key, url_enc, secret_enc, attempts, state FROM system_alert_outbox WHERE id = ?`, outboxID).Scan(&after).Error; err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("升級改動了既有待投遞紀錄的快照或投遞識別: before=%+v after=%+v", before, after)
	}
	var migrated struct {
		Category    string
		Severity    string
		DestVersion int
		EndReason   string
		MessageID   *uint
	}
	if err := db.Raw(`SELECT category, severity, dest_version, end_reason, message_id FROM system_alert_outbox WHERE id = ?`, outboxID).Scan(&migrated).Error; err != nil {
		t.Fatal(err)
	}
	if migrated.Category != "system_security_alert" || migrated.DestVersion != 0 || migrated.EndReason != "" || migrated.MessageID != nil {
		t.Fatalf("既有紀錄的新欄位不是預期值: %+v", migrated)
	}
	if migrated.Severity != "high" {
		t.Fatalf("既有紀錄的分級 = %q，應等於告警列的 high（回填沒有執行）", migrated.Severity)
	}
	var ch struct {
		Target               string
		DestinationChangedAt *time.Time
		DestinationVersion   int
		AbandonNotifiedAt    *time.Time
	}
	if err := db.Raw(`SELECT target, destination_changed_at, destination_version, abandon_notified_at FROM notification_channels WHERE id = ?`, channelID).Scan(&ch).Error; err != nil {
		t.Fatal(err)
	}
	if ch.Target != "" || ch.DestinationChangedAt != nil || ch.DestinationVersion != 0 || ch.AbandonNotifiedAt != nil {
		t.Fatalf("通道新欄位的預設值不對: %+v", ch)
	}

	assertNotificationDeliveryConstraints(t, db, alertID, channelID)

	if err := rollbackNotificationDeliveryLayer(db); err == nil {
		t.Fatal("本增量不應提供回滾")
	}
}

// assertNotificationDeliveryConstraints 正向插入各自成功、非法組合各自被約束拒絕。
func assertNotificationDeliveryConstraints(t *testing.T, db *gorm.DB, alertID, channelID uint) {
	t.Helper()
	// 指令告警內容需要一筆告警列
	var cmdAlertID uint
	if err := db.Raw(`INSERT INTO command_alerts(kind,rule_id,rule_name,reason_code,session_id,user_id,command,severity,triggered_at,disposition,note) VALUES('new_source_ip',NULL,'new_source_ip','new_source_ip_session',5,9,'','medium',now(),'pending','') RETURNING id`).Scan(&cmdAlertID).Error; err != nil {
		t.Fatal(err)
	}
	msg := `INSERT INTO notification_messages(category,event_key,alert_id,severity,occurred_at,created_at) VALUES(?,?,?,?,now(),now()) RETURNING id`
	var cmdMsgID, sysMsgID uint
	if err := db.Raw(msg, "command_alert", "command_alert", cmdAlertID, "medium").Scan(&cmdMsgID).Error; err != nil || cmdMsgID == 0 {
		t.Fatalf("合法的指令告警內容列被拒: %v", err)
	}
	if err := db.Raw(msg, "system_event", "access_request.created", nil, "medium").Scan(&sysMsgID).Error; err != nil || sysMsgID == 0 {
		t.Fatalf("合法的系統事件內容列被拒: %v", err)
	}
	for name, args := range map[string][]any{
		"內容列類別值域外":    {"system_security_alert", "x", nil, "low"},
		"內容列分級值域外":    {"system_event", "x", nil, "critical"},
		"指令告警內容沒有告警列": {"command_alert", "command_alert", nil, "low"},
	} {
		if db.Exec(msg, args...).Error == nil {
			t.Errorf("%s 被接受", name)
		}
	}
	if db.Exec(`UPDATE notification_messages SET state = 'bogus' WHERE id = ?`, sysMsgID).Error == nil {
		t.Error("內容列狀態值域外被接受")
	}

	cols := `(category,alert_id,message_id,severity,dest_type,dest_name,dest_language,dest_target,source_channel_id,url_enc,secret_enc,state,next_attempt_at,created_at,delivery_key,end_reason)`
	ins := `INSERT INTO system_alert_outbox` + cols + ` VALUES(?,?,?,?,?,?,?,?,?,?,?,?,now(),now(),md5(random()::text),?)`
	row := func(category string, alert, message any, destType, destName, lang, target string, urlEnc, secretEnc, state, endReason string) []any {
		return []any{category, alert, message, "medium", destType, destName, lang, target, channelID, urlEnc, secretEnc, state, endReason}
	}
	positive := map[string][]any{
		"不帶快照的指令告警紀錄":           row("command_alert", nil, cmdMsgID, "", "", "", "", "", "", "pending", ""),
		"不帶快照的系統事件紀錄":           row("system_event", nil, sysMsgID, "", "", "", "", "", "", "pending", ""),
		"帶快照的 slack_app 系統安全告警": row("system_security_alert", alertID, nil, "slack_app", "c1", "ja-JP", "C0123ABCD", "enc:u", "enc:s", "pending", ""),
		"限流放棄的終態原因":             row("system_event", nil, sysMsgID, "", "", "", "", "", "", "abandoned", "rate_limited"),
		"已取消":                   row("system_event", nil, sysMsgID, "", "", "", "", "", "", "canceled", "channel_disabled"),
	}
	for name, args := range positive {
		if err := db.Exec(ins, args...).Error; err != nil {
			t.Errorf("%s 被拒: %v", name, err)
		}
	}
	negative := map[string][]any{
		"指令告警紀錄沒有內容列":   row("command_alert", nil, nil, "", "", "", "", "", "", "pending", ""),
		"系統事件紀錄帶網址快照":   row("system_event", nil, sysMsgID, "", "", "", "", "enc:u", "", "pending", ""),
		"系統事件紀錄帶語系":     row("system_event", nil, sysMsgID, "", "", "zh-TW", "", "", "", "pending", ""),
		"系統安全告警紀錄沒有告警列": row("system_security_alert", nil, nil, "webhook", "c1", "zh-TW", "", "enc:u", "", "pending", ""),
		"系統安全告警紀錄語系為空":  row("system_security_alert", alertID, nil, "webhook", "c1", "", "", "enc:u", "", "pending", ""),
		"語系值域外":         row("system_security_alert", alertID, nil, "webhook", "c1", "fr-FR", "", "enc:u", "", "pending", ""),
		"狀態值域外":         row("system_security_alert", alertID, nil, "webhook", "c1", "zh-TW", "", "enc:u", "", "bogus", ""),
		"終態原因值域外":       row("system_security_alert", alertID, nil, "webhook", "c1", "zh-TW", "", "enc:u", "", "abandoned", "bogus"),
		"型別值域外":         row("system_security_alert", alertID, nil, "teams", "c1", "zh-TW", "", "enc:u", "", "pending", ""),
		"系統安全告警紀錄型別為空":  row("system_security_alert", alertID, nil, "", "c1", "zh-TW", "", "enc:u", "", "pending", ""),
		"類別值域外":         row("other", nil, sysMsgID, "", "", "", "", "", "", "pending", ""),
	}
	for name, args := range negative {
		if db.Exec(ins, args...).Error == nil {
			t.Errorf("%s 被接受", name)
		}
	}
	// 不帶快照的紀錄 dest_version 必為 0；來源通道必填
	if db.Exec(`INSERT INTO system_alert_outbox(category,message_id,severity,dest_type,dest_name,dest_language,source_channel_id,url_enc,secret_enc,state,next_attempt_at,created_at,delivery_key,dest_version) VALUES('system_event',?,'low','','','',?,'','','pending',now(),now(),md5(random()::text),1)`, sysMsgID, channelID).Error == nil {
		t.Error("不帶快照的紀錄 dest_version 非 0 被接受")
	}
	if db.Exec(`INSERT INTO system_alert_outbox(category,message_id,severity,dest_type,dest_name,dest_language,source_channel_id,url_enc,secret_enc,state,next_attempt_at,created_at,delivery_key) VALUES('system_event',?,'low','','','',NULL,'','','pending',now(),now(),md5(random()::text))`, sysMsgID).Error == nil {
		t.Error("不帶快照的紀錄沒有來源通道被接受")
	}

	// 通道型別值域：slack_app 可、teams 不可
	chIns := `INSERT INTO notification_channels(name,type,url,secret,enabled,language,min_severity,target,created_at,updated_at) VALUES('c2',?,'enc:u','',true,'zh-TW','low','C1',now(),now())`
	if err := db.Exec(chIns, "slack_app").Error; err != nil {
		t.Errorf("slack_app 通道被拒: %v", err)
	}
	if db.Exec(chIns, "teams").Error == nil {
		t.Error("teams 通道被接受")
	}

	// 內容列刪除時紀錄連帶刪除；告警列刪除時指令告警內容連帶刪除
	if err := db.Exec(`DELETE FROM command_alerts WHERE id = ?`, cmdAlertID).Error; err != nil {
		t.Fatal(err)
	}
	var n int64
	db.Raw(`SELECT count(*) FROM notification_messages WHERE id = ?`, cmdMsgID).Scan(&n)
	if n != 0 {
		t.Error("告警列刪除後指令告警內容列仍在")
	}
	db.Raw(`SELECT count(*) FROM system_alert_outbox WHERE message_id = ?`, cmdMsgID).Scan(&n)
	if n != 0 {
		t.Error("內容列刪除後其待投遞紀錄仍在")
	}
}
