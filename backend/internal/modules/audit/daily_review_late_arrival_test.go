package audit

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sensitivescan"
)

// TestDailyReviewLateArrivalAcrossMidnight 擋：日終剛過就簽，漏掉 23:59:59 命中、
// 數秒後才落庫的告警，該日被固化為零未審閱
func TestDailyReviewLateArrivalAcrossMidnight(t *testing.T) {
	const tz = "Asia/Taipei"
	svc, db, _ := setupDailyReviewDB(t)
	enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
	setClock := fixedClock(svc, at(t, tz, "2026-10-11", 0, 0, 10))

	rules := []model.AlertRule{{ID: 1, Name: "card", Pattern: sensitivescan.CardPattern, Direction: "output", Enabled: true, Severity: "high"}}
	compiled, err := sensitivescan.Compile(rules, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	// 輸出告警於 23:59:59 命中，經 5 秒聚合窗於 00:00:04 才寫入。
	// 時刻以 UTC 傳入：sqlite 以字串比較時間，生產的 pg 比較的是時刻本身
	out := NewOutputAlerts(model.Session{ID: 9, UserID: 3}, rules, NewAlertRecorder(db))
	if err := out.Add(compiled.Scan("4111111111111111\n"), at(t, tz, "2026-10-10", 23, 59, 59).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := out.Flush(at(t, tz, "2026-10-11", 0, 0, 4).UTC(), false); err != nil {
		t.Fatal(err)
	}
	var alert model.CommandAlert
	if err := db.Select("id, reviewed_at").First(&alert).Error; err != nil {
		t.Fatalf("聚合告警未落庫: %v", err)
	}

	var settling *DailyReviewSettlingError
	if _, err := svc.Sign(SignRequest{ReviewDate: "2026-10-10", ReviewerID: 5, ReviewerName: "a"}); !errors.As(err, &settling) {
		t.Fatalf("00:00:10 簽核 err=%v, want Settling", err)
	}
	setClock(at(t, tz, "2026-10-11", 0, 30, 0))
	var pending *DailyReviewAlertsPendingError
	if _, err := svc.Sign(SignRequest{ReviewDate: "2026-10-10", ReviewerID: 5, ReviewerName: "a"}); !errors.As(err, &pending) || pending.Count != 1 {
		t.Fatalf("00:30 簽核 err=%v, want AlertsPending{1}（跨午夜晚到的告警要算在 10-10）", err)
	}
	if err := NewCommandAlertService(db).Review(alert.ID, 5, model.AlertDispositionBenign, ""); err != nil {
		t.Fatal(err)
	}
	row, err := svc.Sign(SignRequest{ReviewDate: "2026-10-10", ReviewerID: 5, ReviewerName: "a"})
	if err != nil {
		t.Fatalf("處置後簽核: %v", err)
	}

	// 簽核後才寫入一筆觸發時刻屬於 10-10 的告警：簽核列不變、明細回報簽核後出現 1 筆
	seedAlertAt(t, db, at(t, tz, "2026-10-10", 22, 0, 0), nil, model.AlertDispositionPending)
	var stored model.DailyReviewLog
	db.First(&stored, row.ID)
	if stored.SnapshotJSON != row.SnapshotJSON {
		t.Errorf("簽核列被改寫")
	}
	detail, err := svc.Day("2026-10-10")
	if err != nil {
		t.Fatal(err)
	}
	if detail.AlertsAfterSign == nil || *detail.AlertsAfterSign != 1 || len(detail.UnreviewedAlerts) != 1 {
		t.Errorf("簽核後出現的未審閱告警 = %v／列 %d, want 1", detail.AlertsAfterSign, len(detail.UnreviewedAlerts))
	}
	var stillPending int64
	db.Model(&model.CommandAlert{}).Where("reviewed_at IS NULL").Count(&stillPending)
	if stillPending != 1 {
		t.Errorf("告警待審閱清單 = %d, want 1（照常留在告警頁）", stillPending)
	}
}
