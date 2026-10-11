package audit

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// TestDailyReviewAlertsAfterSignOnlyFullDay 擋：升級前的簽核（until_signed）不檢查告警
// 處置，此刻仍未審閱的告警可能早在簽核時就存在，不得說成「簽核後才寫入」。
// 舊制列的 alerts_after_sign 在單日明細與逐日清單都必須是 null；整日制列照舊計數。
func TestDailyReviewAlertsAfterSignOnlyFullDay(t *testing.T) {
	const tz = "Asia/Taipei"
	svc, db, _ := setupDailyReviewDB(t)
	enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
	fixedClock(svc, at(t, tz, "2026-10-11", 12, 0, 0))

	signedRow(t, db, tz, "2026-10-08", false, "")
	signedRow(t, db, tz, "2026-10-09", false, "")
	if err := db.Model(&model.DailyReviewLog{}).Where("review_date = ?", "2026-10-09").
		Update("coverage", model.DailyReviewCoverageUntilSigned).Error; err != nil {
		t.Fatal(err)
	}
	seedAlertAt(t, db, at(t, tz, "2026-10-08", 15, 0, 0), nil, model.AlertDispositionPending)
	seedAlertAt(t, db, at(t, tz, "2026-10-09", 15, 0, 0), nil, model.AlertDispositionPending)

	full, err := svc.Day("2026-10-08")
	if err != nil {
		t.Fatal(err)
	}
	if val(full.AlertsAfterSign) != 1 {
		t.Errorf("整日制明細 alerts_after_sign = %d, want 1", val(full.AlertsAfterSign))
	}
	legacy, err := svc.Day("2026-10-09")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.AlertsAfterSign != nil {
		t.Errorf("舊制明細 alerts_after_sign = %d, want null", *legacy.AlertsAfterSign)
	}
	if len(legacy.UnreviewedAlerts) != 1 {
		t.Errorf("舊制明細仍須列出未審閱告警，got %d", len(legacy.UnreviewedAlerts))
	}

	days, _, _, err := svc.DailyReviewLedger(nil, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, d := range days {
		switch d.Date {
		case "2026-10-08":
			seen++
			if val(d.AlertsAfterSign) != 1 {
				t.Errorf("整日制清單列 alerts_after_sign = %d, want 1", val(d.AlertsAfterSign))
			}
		case "2026-10-09":
			seen++
			if d.Coverage != model.DailyReviewCoverageUntilSigned || d.AlertsAfterSign != nil {
				t.Errorf("舊制清單列 coverage=%s alerts_after_sign=%d, want until_signed／null", d.Coverage, val(d.AlertsAfterSign))
			}
		}
	}
	if seen != 2 {
		t.Fatalf("逐日清單缺列：只看到 %d 列", seen)
	}
}
