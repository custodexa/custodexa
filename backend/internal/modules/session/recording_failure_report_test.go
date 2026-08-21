package session

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestReportSessionRecordingFailure 三位一體整合（recording-failure-handling D3）：
// sessions 首因標記（不覆蓋）＋逐 session 審計列（不去重）＋失效事件（同機制去重）
func TestReportSessionRecordingFailure(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Session{}, &model.AuditLog{},
		&model.AuditFailureEvent{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	audit.InitAuditFailure(db, policy.NewSecurityPolicyService(db))

	if err := db.Create(&model.User{Username: "u-rec", Email: strPtr("r@x"), Active: true}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	aid := uint(1)
	sess := model.Session{SessionID: "s-rec-1", UserID: 1, AssetID: &aid,
		Protocol: "ssh", Status: model.SessionStatusActive}
	if err := db.Create(&sess).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}

	ReportSessionRecordingFailure(sess.ID, model.MechanismRecordingText,
		model.CauseRecordingWriteFailed, map[string]string{model.CauseParamDetail: "no space left"})
	ReportSessionRecordingFailure(sess.ID, model.MechanismRecordingText,
		model.CauseRecordingStopFailed, map[string]string{model.CauseParamDetail: "不應覆蓋"})

	var got model.Session
	if err := db.First(&got, sess.ID).Error; err != nil {
		t.Fatal(err)
	}
	// M5：recording_error 存機器碼（前端查譯），首因仍不得被覆蓋
	if got.RecordingError != model.CauseRecordingWriteFailed {
		t.Fatalf("首因不得被覆蓋且應為機器碼: %q", got.RecordingError)
	}

	// 逐 session 審計列不去重：兩次失敗兩列（主軌可追溯）
	var auditCount int64
	db.Model(&model.AuditLog{}).
		Where("action = ? AND resource = ?", model.ActionRecordingFailed, model.ResourceSession).
		Count(&auditCount)
	if auditCount != 2 {
		t.Fatalf("audit_logs 應每次失敗一列, got %d", auditCount)
	}
	var entry model.AuditLog
	db.Where("action = ?", model.ActionRecordingFailed).First(&entry)
	if entry.Username != "u-rec" || entry.ResourceID == nil || *entry.ResourceID != sess.ID {
		t.Fatalf("審計列應掛 session 擁有者與 resource_id: %+v", entry)
	}
	// audit_logs.Details 維持 forensic 原文（zh 短語＋底層 err），不碼化（D8 non-goal）
	if !strings.Contains(entry.Details, "no space left") {
		t.Fatalf("審計 Details 應保留 forensic 原文: %q", entry.Details)
	}

	// 失效事件落 cause_code 與 cause_params（含 session_id 與 forensic detail）
	var ev model.AuditFailureEvent
	if err := db.Where("mechanism = ?", model.MechanismRecordingText).First(&ev).Error; err != nil {
		t.Fatalf("讀失效事件: %v", err)
	}
	if ev.CauseCode != model.CauseRecordingWriteFailed {
		t.Fatalf("cause_code 應為機器碼, got %q", ev.CauseCode)
	}
	var params map[string]string
	if err := json.Unmarshal([]byte(ev.CauseParams), &params); err != nil {
		t.Fatalf("cause_params 應為合法 JSON: %q (%v)", ev.CauseParams, err)
	}
	if params["session_id"] == "" || params[model.CauseParamDetail] != "no space left" {
		t.Fatalf("cause_params 應帶 session_id 與 forensic detail: %v", params)
	}
	if ev.Cause == "" {
		t.Error("cause 散文 fallback 不得為空（既有讀取點依賴，PCI 10.7.3）")
	}

	// 失效事件同機制去重：仍只一筆進行中
	var evCount int64
	db.Model(&model.AuditFailureEvent{}).
		Where("mechanism = ? AND ended_at IS NULL", model.MechanismRecordingText).
		Count(&evCount)
	if evCount != 1 {
		t.Fatalf("同機制進行中事件應去重為 1, got %d", evCount)
	}
}
