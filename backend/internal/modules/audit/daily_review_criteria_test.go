package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDailyReviewSnapshotRecordsCriteriaVersion 擋：已簽日無法分辨高危數依據哪一版判準，
// 判準調整造成的差異被呈現成資料被改動
func TestDailyReviewSnapshotRecordsCriteriaVersion(t *testing.T) {
	svc, db, _ := setupDailyReviewDB(t)
	const tz = "UTC"
	enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
	fixedClock(svc, at(t, tz, "2026-10-11", 9, 0, 0))

	row, err := svc.Sign(SignRequest{ReviewDate: "2026-10-10", ReviewerID: 5, ReviewerName: "auditor"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(row.SnapshotJSON, `"high_risk_criteria":2`) {
		t.Errorf("簽核快照沒有記錄判準版本 2: %s", row.SnapshotJSON)
	}

	// 升級前的快照沒有這個鍵：視為第一版
	legacy := `{"date":"2026-09-01","login_failures":2,"login_failures_source":"complete","high_risk_ops":5,"high_risk_ops_source":"complete","unreviewed_alerts":0,"alerts_source":"complete"}`
	var snap DailyReviewSnapshot
	if err := jsonUnmarshalSnapshot(legacy, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.HighRiskCriteria != 1 {
		t.Errorf("舊快照的判準版本 = %d, want 1", snap.HighRiskCriteria)
	}

	detail, err := svc.Day("2026-10-09")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(detail.Counts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"high_risk_criteria":2`) {
		t.Errorf("單日明細的 counts 沒有現行判準版本: %s", raw)
	}
}
