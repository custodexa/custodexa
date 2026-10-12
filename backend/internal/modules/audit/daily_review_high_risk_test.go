package audit

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// TestDailyReviewHighRiskExcludesReadsAndPreviews 擋：安全政策、syslog 設定、稽核證據匯出
// 三類資源的讀取與預覽被算進高危操作，例行瀏覽灌大簽核者要看的數字。
// 寫入類動作（建立、更新、刪除）與同步匯出仍須計入
func TestDailyReviewHighRiskExcludesReadsAndPreviews(t *testing.T) {
	svc, db, _ := setupDailyReviewDB(t)
	date, start, end := utcDay(time.Now())
	now := start.Add(12 * time.Hour)

	seed := func(action model.AuditAction, resource model.AuditResource, path string) {
		t.Helper()
		if err := db.Exec(
			"INSERT INTO audit_logs (created_at, action, resource, status, user_id, username, path) VALUES (?, ?, ?, ?, 1, 'u', ?)",
			now.UTC(), action, resource, model.StatusSuccess, path).Error; err != nil {
			t.Fatalf("seed audit_log: %v", err)
		}
	}
	// 不計入：讀取、預覽（現行記為 read；升級前記為 create）、連線測試
	seed(model.ActionRead, model.ResourceSecurityPolicy, "/api/v1/security-policies")
	seed(model.ActionRead, model.ResourceSecurityPolicy, "/api/v1/security-policies/defs/password_min_length")
	seed(model.ActionRead, model.ResourceSecurityPolicy, "/api/v1/security-policies/apply-preview")
	seed(model.ActionCreate, model.ResourceSecurityPolicy, "/api/v1/security-policies/apply-preview")
	seed(model.ActionCreate, model.ResourceSecurityPolicy, "/api/v1/security-policies/compliance/preview")
	seed(model.ActionRead, model.ResourceSyslogSetting, "/api/v1/syslog-settings")
	seed(model.ActionExecute, model.ResourceSyslogSetting, "/api/v1/syslog-settings/test")
	seed(model.ActionRead, model.ResourceAuditExport, "/api/v1/audit-export/jobs")
	seed(model.ActionRead, model.ResourceAuditExport, "/api/v1/audit-export/public-key")
	seed(model.ActionRead, model.ResourceAuditExport, "/api/v1/audit-export/jobs/3/download")
	// 計入：政策變更、syslog 變更、發起證據包、同步匯出
	seed(model.ActionUpdate, model.ResourceSecurityPolicy, "/api/v1/security-policies")
	seed(model.ActionUpdate, model.ResourceSyslogSetting, "/api/v1/syslog-settings")
	seed(model.ActionCreate, model.ResourceAuditExport, "/api/v1/audit-export/jobs")
	seed(model.ActionRead, model.ResourceAuditExport, "/api/v1/audit-export")
	const wantPaths = 4

	snap, err := svc.Snapshot(date, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if val(snap.HighRiskOps) != wantPaths {
		t.Errorf("高危操作 = %d, want %d（讀取與預覽不計、寫入與同步匯出要計）", val(snap.HighRiskOps), wantPaths)
	}
	scope, err := highRiskScope(db, start, end)
	if err != nil {
		t.Fatal(err)
	}
	list, err := eventList(scope, model.DailyReviewSourceComplete)
	if err != nil {
		t.Fatal(err)
	}
	if list.Total != wantPaths {
		t.Fatalf("明細總數 = %d, want %d（計數與明細須同一範圍）", list.Total, wantPaths)
	}
	for _, it := range list.Items {
		switch it.Path {
		case "/api/v1/security-policies", "/api/v1/syslog-settings", "/api/v1/audit-export/jobs", "/api/v1/audit-export":
		default:
			t.Errorf("明細列出不該計入的 %s %s", it.Action, it.Path)
		}
		if it.Action == model.ActionRead && it.Path != "/api/v1/audit-export" {
			t.Errorf("明細列出讀取 %s", it.Path)
		}
	}
}
