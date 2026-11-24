package database

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// TestTargetedNotificationMigration 定向通知增量（PostgreSQL）：
// (a) 升級後既有通道皆為假、既有紀錄 audience = channel 且收件人為空、其餘欄位不變；
// (b) 第二個通道開啟對個人派送時資料庫拒絕；
// (c) audience = user 而收件人為空、audience = channel 而收件人非空、audience = user 而類別是系統安全告警，皆被拒；
// (d) 刪除使用者後，他的個人訊息紀錄仍是 audience = user，不會被當成頻道紀錄取出；
// (e) end_reason 寫入新值可、寫入未登錄值被拒；
// (f) 型別不是 slack_app 的通道 direct_message_enabled 為真時資料庫拒絕；
// 另：同一則內容對同一人至多一筆、到期索引含 audience、不提供回滾。
func TestTargetedNotificationMigration(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, fmt.Sprintf("tnl_mig_%d", time.Now().UnixNano()))

	idx := -1
	for i, m := range migrations {
		if m.Version == targetedNotificationVersion {
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

	// 升級前：兩個 slack_app 通道、一個 webhook 通道、一位使用者、一則系統事件內容、
	// 一筆不帶快照的紀錄、一筆帶快照的系統安全告警紀錄（重試中）。
	chIns := `INSERT INTO notification_channels(name,type,url,secret,enabled,language,min_severity,target,created_at,updated_at) VALUES(?,?,'enc:u','enc:s',true,'zh-TW','low',?,now(),now()) RETURNING id`
	var appA, appB, hook uint
	for _, c := range []struct {
		name, typ, target string
		id                *uint
	}{{"app-a", "slack_app", "C1", &appA}, {"app-b", "slack_app", "C2", &appB}, {"hook", "webhook", "", &hook}} {
		if err := db.Raw(chIns, c.name, c.typ, c.target).Scan(c.id).Error; err != nil || *c.id == 0 {
			t.Fatalf("插入通道 %s 失敗: %v", c.name, err)
		}
	}
	if err := db.Exec(`INSERT INTO users(id,username,password,kind,active) VALUES(7701,'tnl-reviewer','!','human',true)`).Error; err != nil {
		t.Fatal(err)
	}
	var msgID uint
	if err := db.Raw(`INSERT INTO notification_messages(category,event_key,severity,occurred_at,created_at) VALUES('system_event','access_request.created','medium',now(),now()) RETURNING id`).Scan(&msgID).Error; err != nil || msgID == 0 {
		t.Fatalf("插入內容列失敗: %v", err)
	}
	liveIns := `INSERT INTO system_alert_outbox(category,message_id,severity,dest_type,dest_name,dest_language,source_channel_id,url_enc,secret_enc,state,attempts,next_attempt_at,last_error,created_at,delivery_key) VALUES('system_event',?,'medium','','','',?,'','','retrying',2,now(),'HTTP 500',now(),md5(random()::text)) RETURNING id`
	var liveID uint
	if err := db.Raw(liveIns, msgID, appA).Scan(&liveID).Error; err != nil || liveID == 0 {
		t.Fatalf("插入不帶快照紀錄失敗: %v", err)
	}
	var alertID uint
	if err := db.Raw(`INSERT INTO command_alerts(kind,rule_id,rule_name,reason_code,session_id,user_id,command,severity,triggered_at,disposition,note) VALUES('system_security',NULL,'notification_channel_changed','notification_channel_changed',NULL,9,'','high',now(),'pending','') RETURNING id`).Scan(&alertID).Error; err != nil || alertID == 0 {
		t.Fatalf("插入告警列失敗: %v", err)
	}
	var snapID uint
	if err := db.Raw(`INSERT INTO system_alert_outbox(category,alert_id,severity,dest_type,dest_name,dest_language,source_channel_id,url_enc,secret_enc,state,attempts,next_attempt_at,last_error,created_at,delivery_key,dest_version) VALUES('system_security_alert',?,'high','webhook','hook','zh-TW',?,'enc:url-snap','enc:secret-snap','retrying',3,now(),'HTTP 502',now(),md5(random()::text),0) RETURNING id`, alertID, hook).Scan(&snapID).Error; err != nil || snapID == 0 {
		t.Fatalf("插入帶快照紀錄失敗: %v", err)
	}

	type outboxSnap struct {
		Category, Severity, DestType, URLEnc, SecretEnc, State, LastError, DeliveryKey, EndReason string
		Attempts, DestVersion                                                                     int
		MessageID, AlertID, SourceChannelID                                                       int64
	}
	readOutbox := func(id uint) outboxSnap {
		var s outboxSnap
		if err := db.Raw(`SELECT category, severity, dest_type, url_enc, secret_enc, state, last_error, delivery_key, end_reason, attempts, dest_version, COALESCE(message_id, 0) AS message_id, COALESCE(alert_id, 0) AS alert_id, COALESCE(source_channel_id, 0) AS source_channel_id FROM system_alert_outbox WHERE id = ?`, id).Scan(&s).Error; err != nil {
			t.Fatal(err)
		}
		return s
	}
	beforeLive, beforeSnap := readOutbox(liveID), readOutbox(snapID)

	up := applyTargetedNotification
	if idx < 0 {
		t.Errorf("本增量 %s 沒有登記在 migrations 清單", targetedNotificationVersion)
	} else {
		up = migrations[idx].Up
	}
	if err := up(db); err != nil {
		t.Fatalf("升級失敗: %v", err)
	}

	// (a) 既有資料
	if got := readOutbox(liveID); got != beforeLive {
		t.Errorf("(a) 升級改動了不帶快照紀錄的既有欄位: before=%+v after=%+v", beforeLive, got)
	}
	if got := readOutbox(snapID); got != beforeSnap {
		t.Errorf("(a) 升級改動了帶快照紀錄的既有欄位: before=%+v after=%+v", beforeSnap, got)
	}
	var audiences []struct {
		Audience        string
		RecipientUserID *uint
	}
	if err := db.Raw(`SELECT audience, recipient_user_id FROM system_alert_outbox`).Scan(&audiences).Error; err != nil {
		t.Fatal(err)
	}
	if len(audiences) != 2 {
		t.Fatalf("(a) 紀錄數 = %d, want 2", len(audiences))
	}
	for _, a := range audiences {
		if a.Audience != "channel" || a.RecipientUserID != nil {
			t.Errorf("(a) 既有紀錄 audience=%q recipient=%v，want channel 與空", a.Audience, a.RecipientUserID)
		}
	}
	var enabledCount, notifiedCount int64
	db.Raw(`SELECT count(*) FROM notification_channels WHERE direct_message_enabled`).Scan(&enabledCount)
	db.Raw(`SELECT count(*) FROM notification_channels WHERE dm_issue_notified_at IS NOT NULL`).Scan(&notifiedCount)
	if enabledCount != 0 || notifiedCount != 0 {
		t.Errorf("(a) 升級後開啟對個人派送的通道 %d、已節流 %d，want 0 與 0", enabledCount, notifiedCount)
	}

	// (b) 至多一個通道開啟
	if err := db.Exec(`UPDATE notification_channels SET direct_message_enabled = true WHERE id = ?`, appA).Error; err != nil {
		t.Fatalf("(b) 第一個 slack_app 通道開啟被拒: %v", err)
	}
	if err := db.Exec(`UPDATE notification_channels SET direct_message_enabled = true WHERE id = ?`, appB).Error; err == nil {
		t.Error("(b) 第二個通道開啟對個人派送被接受")
	} else if !strings.Contains(err.Error(), "idx_notification_channels_direct_message") {
		t.Errorf("(b) 第二個通道被拒的原因不是部分唯一索引: %v", err)
	}
	// 關掉第一個之後第二個可以開
	if err := db.Exec(`UPDATE notification_channels SET direct_message_enabled = false WHERE id = ?`, appA).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`UPDATE notification_channels SET direct_message_enabled = true WHERE id = ?`, appB).Error; err != nil {
		t.Errorf("(b) 關閉第一個後第二個開啟被拒: %v", err)
	}
	if err := db.Exec(`UPDATE notification_channels SET direct_message_enabled = false WHERE id = ?`, appB).Error; err != nil {
		t.Fatal(err)
	}

	// (f) 非 slack_app 型別不可開啟
	if err := db.Exec(`UPDATE notification_channels SET direct_message_enabled = true WHERE id = ?`, hook).Error; err == nil {
		t.Error("(f) webhook 通道開啟對個人派送被接受")
	} else if !strings.Contains(err.Error(), "notification_channels_direct_message_type_check") {
		t.Errorf("(f) 被拒的原因不是型別 CHECK: %v", err)
	}
	if err := db.Exec(`UPDATE notification_channels SET direct_message_enabled = true WHERE id = ?`, appA).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`UPDATE notification_channels SET type = 'webhook' WHERE id = ?`, appA).Error; err == nil {
		t.Error("(f) 開啟中的 slack_app 通道改為 webhook 而旗標未清被接受")
	}
	if err := db.Exec(`UPDATE notification_channels SET direct_message_enabled = false WHERE id = ?`, appA).Error; err != nil {
		t.Fatal(err)
	}

	// (c) 收件對象與收件人的組合
	userIns := `INSERT INTO system_alert_outbox(category,message_id,severity,dest_type,dest_name,dest_language,source_channel_id,url_enc,secret_enc,state,next_attempt_at,created_at,delivery_key,audience,recipient_user_id) VALUES('system_event',?,'medium','','','',?,'','','pending',now(),now(),md5(random()::text),?,?) RETURNING id`
	var userRowID uint
	if err := db.Raw(userIns, msgID, appA, "user", 7701).Scan(&userRowID).Error; err != nil || userRowID == 0 {
		t.Fatalf("(c) 合法的個人訊息紀錄被拒: %v", err)
	}
	for name, args := range map[string][]any{
		"audience=user 而收件人為空":    {msgID, appA, "user", nil},
		"audience=channel 而收件人非空": {msgID, appA, "channel", 7702},
		"audience 值域外":            {msgID, appA, "group", 7703},
	} {
		if err := db.Exec(strings.TrimSuffix(userIns, " RETURNING id"), args...).Error; err == nil {
			t.Errorf("(c) %s 被接受", name)
		}
	}
	if err := db.Exec(`INSERT INTO system_alert_outbox(category,alert_id,severity,dest_type,dest_name,dest_language,source_channel_id,url_enc,secret_enc,state,next_attempt_at,created_at,delivery_key,audience,recipient_user_id) VALUES('system_security_alert',?,'high','webhook','hook','zh-TW',?,'enc:u','enc:s','pending',now(),now(),md5(random()::text),'user',7701)`, alertID, hook).Error; err == nil {
		t.Error("(c) audience=user 而類別是系統安全告警被接受")
	}
	// 同一則內容對同一人至多一筆
	if err := db.Exec(strings.TrimSuffix(userIns, " RETURNING id"), msgID, appA, "user", 7701).Error; err == nil {
		t.Error("同一則內容對同一人的第二筆個人訊息紀錄被接受")
	} else if !strings.Contains(err.Error(), "idx_system_alert_outbox_message_recipient") {
		t.Errorf("第二筆被拒的原因不是部分唯一索引: %v", err)
	}
	// 頻道紀錄不受該索引約束（同一則內容可有多個通道各一筆，收件人皆為空）
	if err := db.Exec(liveIns[:strings.Index(liveIns, " RETURNING")], msgID, appB).Error; err != nil {
		t.Errorf("同一則內容的第二筆頻道紀錄被拒: %v", err)
	}

	// (d) 刪除使用者後仍是個人訊息紀錄，不會被當成頻道紀錄取出
	if err := db.Exec(`DELETE FROM users WHERE id = 7701`).Error; err != nil {
		t.Fatalf("(d) 刪除使用者失敗（收件人不應有外鍵）: %v", err)
	}
	var orphan struct {
		Audience        string
		RecipientUserID *uint
	}
	if err := db.Raw(`SELECT audience, recipient_user_id FROM system_alert_outbox WHERE id = ?`, userRowID).Scan(&orphan).Error; err != nil {
		t.Fatal(err)
	}
	if orphan.Audience != "user" || orphan.RecipientUserID == nil || *orphan.RecipientUserID != 7701 {
		t.Errorf("(d) 刪除使用者後紀錄變成 audience=%q recipient=%v，want user 與 7701", orphan.Audience, orphan.RecipientUserID)
	}
	var channelDue []uint
	if err := db.Raw(`SELECT id FROM system_alert_outbox WHERE state IN ('pending','retrying') AND source_channel_id = ? AND audience = 'channel' ORDER BY id`, appA).Scan(&channelDue).Error; err != nil {
		t.Fatal(err)
	}
	for _, id := range channelDue {
		if id == userRowID {
			t.Errorf("(d) 刪除使用者後的個人訊息紀錄 %d 出現在頻道紀錄的取件結果", id)
		}
	}
	if len(channelDue) != 1 || channelDue[0] != liveID {
		t.Errorf("(d) 通道 A 的頻道到期紀錄 = %v, want [%d]", channelDue, liveID)
	}

	// (e) end_reason 值域
	for _, reason := range []string{"request_resolved", "recipient_ineligible", "direct_message_disabled", "no_email", "email_ambiguous", "recipient_not_found"} {
		if err := db.Exec(`UPDATE system_alert_outbox SET state = 'canceled', end_reason = ? WHERE id = ?`, reason, userRowID).Error; err != nil {
			t.Errorf("(e) end_reason %q 被拒: %v", reason, err)
		}
	}
	if err := db.Exec(`UPDATE system_alert_outbox SET end_reason = 'precheck_canceled' WHERE id = ?`, userRowID).Error; err != nil {
		t.Errorf("(e) 地基既有的 end_reason 被拒: %v", err)
	}
	if err := db.Exec(`UPDATE system_alert_outbox SET end_reason = 'bogus_reason' WHERE id = ?`, userRowID).Error; err == nil {
		t.Error("(e) 未登錄的 end_reason 被接受")
	}

	// 到期索引含 audience
	var dueDef string
	if err := db.Raw(`SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'idx_system_alert_outbox_due'`).Scan(&dueDef).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dueDef, "(source_channel_id, dest_version, audience, next_attempt_at)") {
		t.Errorf("到期索引未含 audience: %s", dueDef)
	}

	// 不提供回滾
	if idx >= 0 && (migrations[idx].Down == nil || migrations[idx].Down(db) == nil) {
		t.Error("本增量應明確拒絕回滾")
	}
}

// TestTargetedNotificationSingleEnabledIndexSQLite 「至多一列為真」的部分唯一索引在 SQLite 上同樣成立
// （SQLite 測試庫以模型建表，不跑本增量；這裡直接執行同一句 DDL 驗證運算式部分索引的行為）。
func TestTargetedNotificationSingleEnabledIndexSQLite(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.Exec(`CREATE TABLE notification_channels (id integer PRIMARY KEY, type text NOT NULL, direct_message_enabled boolean NOT NULL DEFAULT false)`).Error; err != nil {
		t.Fatal(err)
	}
	var stmt string
	for _, s := range targetedNotificationDDL() {
		if strings.HasPrefix(s, "CREATE UNIQUE INDEX idx_notification_channels_direct_message ") {
			stmt = strings.Replace(s, " USING btree", "", 1) // SQLite 沒有 USING 子句
		}
	}
	if stmt == "" {
		t.Fatal("DDL 清單沒有至多一列為真的部分唯一索引")
	}
	if err := db.Exec(stmt).Error; err != nil {
		t.Fatalf("SQLite 不接受該索引: %v", err)
	}
	if err := db.Exec(`INSERT INTO notification_channels(id,type,direct_message_enabled) VALUES(1,'slack_app',false),(2,'slack_app',false),(3,'slack_app',true)`).Error; err != nil {
		t.Fatalf("兩列為假、一列為真被拒: %v", err)
	}
	if err := db.Exec(`UPDATE notification_channels SET direct_message_enabled = true WHERE id = 1`).Error; err == nil {
		t.Error("SQLite 上第二列為真被接受")
	}
}
