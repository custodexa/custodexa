package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// TestDailyReviewSignAuditDetails 擋：審計列仍是舊形狀或漏欄，稽核者從操作日誌看不出
// 補簽與所屬日。讀的是實際寫入 audit_logs 的列（真審計服務、同步寫入）
func TestDailyReviewSignAuditDetails(t *testing.T) {
	const tz = "Asia/Taipei"
	_, db, _ := setupDailyReviewDB(t)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	auditSvc := NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false})
	svc := NewDailyReviewService(db, policy.NewSecurityPolicyService(db), auditSvc)
	enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
	fixedClock(svc, at(t, tz, "2026-10-11", 10, 42, 0))
	seedAuditLog(t, db, model.ActionLogin, model.ResourceAuth, model.StatusFailure, at(t, tz, "2026-10-07", 12, 0, 0))

	const reason, note = "值班交接漏簽，已改為雙人輪值", "備註全文不進審計"
	row, err := svc.Sign(SignRequest{ReviewDate: "2026-10-07", Note: note, DelayReason: reason, ReviewerID: 5, ReviewerName: "auditor-a"})
	if err != nil {
		t.Fatal(err)
	}
	var entry model.AuditLog
	if err := db.Where("resource = ?", model.ResourceDailyReview).First(&entry).Error; err != nil {
		t.Fatalf("簽核審計列未寫入: %v", err)
	}
	if entry.Action != model.ActionCreate || entry.ResourceID == nil || *entry.ResourceID != row.ID {
		t.Errorf("action=%s resource_id=%v, want create／%d", entry.Action, entry.ResourceID, row.ID)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(entry.Details), &details); err != nil {
		t.Fatalf("details 不是 JSON: %q", entry.Details)
	}
	for _, k := range []string{"review_date", "timezone", "signed_at", "late", "late_days", "snapshot"} {
		if _, ok := details[k]; !ok {
			t.Errorf("details 缺 %s: %s", k, entry.Details)
		}
	}
	if details["review_date"] != "2026-10-07" || details["timezone"] != tz || details["late"] != true || details["late_days"] != float64(3) {
		t.Errorf("details 值錯: %s", entry.Details)
	}
	snap, _ := details["snapshot"].(map[string]any)
	if snap["login_failures"] != float64(1) {
		t.Errorf("details.snapshot = %v", details["snapshot"])
	}
	if strings.Contains(entry.Details, reason) || strings.Contains(entry.Details, note) {
		t.Errorf("延遲原因或備註全文進了審計: %s", entry.Details)
	}
}
