package session

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestRecordingFailureNoticeSharesCauseCode 錄影失敗同源：同一次回報的出站通知 cause_code、
// audit_failure_events.cause_code 與 sessions.recording_error 三者相同（稽核失效通知以內容列持久排入）。
func TestRecordingFailureNoticeSharesCauseCode(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Session{}, &model.AuditLog{}, &model.AuditFailureEvent{},
		&model.SecurityPolicy{}, &model.UserRole{}, &model.NotificationMessage{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Create(&model.SecurityPolicy{Key: policy.PolicyFailureAlertEnabled, Value: "true"}).Error; err != nil {
		t.Fatal(err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	audit.InitAuditFailure(db, policy.NewSecurityPolicyService(db))
	n := audit.InitAlertNotifier(db, nil)
	t.Cleanup(func() { audit.StopAlertNotifierForRelease(n) })

	if err := db.Create(&model.User{Username: "u-rec", Email: strPtr("r2@x"), Active: true}).Error; err != nil {
		t.Fatal(err)
	}
	aid := uint(1)
	sess := model.Session{SessionID: "s-rec-2", UserID: 1, AssetID: &aid, Protocol: "ssh", Status: model.SessionStatusActive}
	if err := db.Create(&sess).Error; err != nil {
		t.Fatal(err)
	}
	ReportSessionRecordingFailure(sess.ID, model.MechanismRecordingText, model.CauseRecordingWriteFailed,
		map[string]string{model.CauseParamDetail: "no space left"})
	deadline := time.Now().Add(5 * time.Second)
	for n.BackgroundInFlight() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	var got model.Session
	db.First(&got, sess.ID)
	var ev model.AuditFailureEvent
	if err := db.Where("mechanism = ?", model.MechanismRecordingText).First(&ev).Error; err != nil {
		t.Fatal(err)
	}
	var msgs []model.NotificationMessage
	db.Where("event_key = ?", "audit_failure").Find(&msgs)
	if len(msgs) != 1 {
		t.Fatalf("應有一列稽核失效通知內容，得 %d", len(msgs))
	}
	var params map[string]string
	if err := json.Unmarshal([]byte(msgs[0].Params), &params); err != nil {
		t.Fatal(err)
	}
	if params["cause_code"] != ev.CauseCode || ev.CauseCode != got.RecordingError || got.RecordingError != model.CauseRecordingWriteFailed {
		t.Fatalf("三處的原因碼應相同: 通知 %q、事件 %q、會話 %q", params["cause_code"], ev.CauseCode, got.RecordingError)
	}
	if params["detail"] != "" || params[model.CauseParamDetail] != "" {
		t.Fatalf("通知不得帶鑑識原文: %v", params)
	}
}
