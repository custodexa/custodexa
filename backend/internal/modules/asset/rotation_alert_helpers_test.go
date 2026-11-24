package asset

import (
	"encoding/json"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// newRotationNotifier 建立排入介面並確保通知內容表存在（改密工作提醒以系統事件排入）。
func newRotationNotifier(t testing.TB, db *gorm.DB) *audit.AlertNotifier {
	t.Helper()
	if err := db.AutoMigrate(&model.NotificationMessage{}); err != nil {
		t.Fatalf("建立通知內容表失敗: %v", err)
	}
	return audit.NewAlertNotifier(db, nil)
}

// rotationAlertCount 已排入的改密工作提醒則數。
func rotationAlertCount(db *gorm.DB) int64 {
	var n int64
	db.Model(&model.NotificationMessage{}).Where("event_key = ?", string(notifycat.EventCredentialRotationAlert)).Count(&n)
	return n
}

// rotationAlertKinds 已排入的改密工作提醒種類（依排入順序）。
func rotationAlertKinds(t testing.TB, db *gorm.DB) []string {
	t.Helper()
	var rows []model.NotificationMessage
	db.Where("event_key = ?", string(notifycat.EventCredentialRotationAlert)).Order("id").Find(&rows)
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		var params map[string]string
		if err := json.Unmarshal([]byte(r.Params), &params); err != nil {
			t.Fatalf("通知參數無法解析: %v", err)
		}
		out = append(out, params["kind"])
	}
	return out
}
