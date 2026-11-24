package audit

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// TestDailyReviewPendingUnreviewedAlertTypes 待簽日寫出未審閱告警分屬幾種類型。
//
// 擋的威脅：類型數把已審閱的告警也算進去，清單寫的「k 類」比抽屜裡實際要處置的多；
// 來源已清除的日子寫成 0 類（未知被當成沒有）；或把類型數塞進會固化進簽核紀錄的計數結構，
// 改到簽核快照的形狀。
func TestDailyReviewPendingUnreviewedAlertTypes(t *testing.T) {
	svc, db, _ := setupDailyReviewDB(t)
	const tz = "UTC"
	enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
	fixedClock(svc, at(t, tz, "2026-10-11", 9, 0, 0))

	seed := func(rule string, h int, reviewed bool) {
		t.Helper()
		ts := at(t, tz, "2026-10-10", h, 0, 0).UTC()
		if reviewed {
			if err := db.Exec(`INSERT INTO command_alerts (rule_name, triggered_at, reviewed_by, reviewed_at, disposition)
				VALUES (?, ?, 9, ?, 'benign')`, rule, ts, ts).Error; err != nil {
				t.Fatal(err)
			}
			return
		}
		if err := db.Exec(`INSERT INTO command_alerts (rule_name, triggered_at) VALUES (?, ?)`, rule, ts).Error; err != nil {
			t.Fatal(err)
		}
	}
	// 3 筆分屬 2 種類型；類型 b 的唯一一筆已審閱 → 未審閱的只剩 1 類
	seed("type-a", 1, false)
	seed("type-a", 2, false)
	seed("type-b", 3, true)
	// 隔天 2 類都未審閱
	for i, rule := range []string{"type-a", "type-b"} {
		ts := at(t, tz, "2026-10-09", i+1, 0, 0).UTC()
		if err := db.Exec(`INSERT INTO command_alerts (rule_name, triggered_at) VALUES (?, ?)`, rule, ts).Error; err != nil {
			t.Fatal(err)
		}
	}

	byDate := func() map[string]DailyReviewPendingDay {
		t.Helper()
		items, _, err := svc.Pending(1, 31)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]DailyReviewPendingDay{}
		for _, it := range items {
			out[it.Date] = it
		}
		return out
	}
	days := byDate()
	d10, ok := days["2026-10-10"]
	if !ok || d10.UnreviewedAlertTypes == nil || *d10.UnreviewedAlertTypes != 1 {
		t.Fatalf("2026-10-10 未審閱類型數 = %v, want 1（已審閱的類型不計）", d10.UnreviewedAlertTypes)
	}
	if d09 := days["2026-10-09"]; d09.UnreviewedAlertTypes == nil || *d09.UnreviewedAlertTypes != 2 {
		t.Fatalf("2026-10-09 未審閱類型數 = %v, want 2", d09.UnreviewedAlertTypes)
	}
	if d08 := days["2026-10-08"]; d08.UnreviewedAlertTypes == nil || *d08.UnreviewedAlertTypes != 0 {
		t.Fatalf("沒有告警的日子類型數 = %v, want 0", d08.UnreviewedAlertTypes)
	}
	raw, _ := json.Marshal(d10)
	if !strings.Contains(string(raw), `"unreviewed_alert_types":1`) {
		t.Fatalf("待簽日線上形狀缺 unreviewed_alert_types: %s", raw)
	}

	// 告警來源清除到 10-09 結束：該日為 null（未知），10-10 不受影響
	setWatermark(t, db, model.RetentionClassCommandAlert, at(t, tz, "2026-10-10", 0, 0, 0))
	days = byDate()
	if d09 := days["2026-10-09"]; d09.UnreviewedAlertTypes != nil {
		t.Fatalf("來源已清除的日子類型數 = %v, want null", *d09.UnreviewedAlertTypes)
	}
	raw, _ = json.Marshal(days["2026-10-09"])
	if !strings.Contains(string(raw), `"unreviewed_alert_types":null`) {
		t.Fatalf("來源已清除的日子線上應為 null: %s", raw)
	}
	if d10 := days["2026-10-10"]; d10.UnreviewedAlertTypes == nil || *d10.UnreviewedAlertTypes != 1 {
		t.Fatalf("清除水位外的日子類型數 = %v, want 1", d10.UnreviewedAlertTypes)
	}
}

// TestDailyReviewSnapshotKeySetUnchanged 簽核快照（counts）的鍵集合不因待簽日新增欄位而改變。
//
// 擋的威脅：把讀取用的欄位加進會固化進簽核紀錄的結構，使新舊簽核紀錄的快照形狀不同。
func TestDailyReviewSnapshotKeySetUnchanged(t *testing.T) {
	raw, err := json.Marshal(DailyReviewSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(m))
	for k := range m {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"alerts_benign", "alerts_escalated", "alerts_source", "alerts_total", "date",
		"high_risk_criteria", "high_risk_ops", "high_risk_ops_source", "login_failures", "login_failures_source",
		"unreviewed_alerts"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("簽核快照鍵集合 = %v, want %v", got, want)
	}
}
