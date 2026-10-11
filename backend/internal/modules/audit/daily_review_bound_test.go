package audit

import (
	"errors"
	"testing"
	"time"
)

// TestDailyReviewFarFutureDateRejected 擋：簽核、單日明細、期間統計收到遠未來日期時
// 進入行事曆逐日計算而耗盡 CPU（有稽核檢視權限即可觸發）。入口直接拒絕晚於明天的日期
func TestDailyReviewFarFutureDateRejected(t *testing.T) {
	const tz = "Asia/Taipei"
	svc, db, _ := setupDailyReviewDB(t)
	enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
	fixedClock(svc, at(t, tz, "2026-10-11", 12, 0, 0))

	within := func(t *testing.T, name string, f func()) {
		t.Helper()
		start := time.Now()
		f()
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("%s 耗時 %v，應立即回應", name, elapsed)
		}
	}

	for _, date := range []string{"2026-10-13", "9999-12-31"} {
		within(t, "Sign "+date, func() {
			if _, err := svc.Sign(SignRequest{ReviewDate: date, DelayReason: "x", ReviewerID: 5, ReviewerName: "a"}); !errors.Is(err, ErrDailyReviewDayNotEnded) {
				t.Errorf("Sign(%s) err=%v, want ErrDailyReviewDayNotEnded", date, err)
			}
		})
		within(t, "Day "+date, func() {
			if _, err := svc.Day(date); !errors.Is(err, ErrDailyReviewDayNotEnded) {
				t.Errorf("Day(%s) err=%v, want ErrDailyReviewDayNotEnded", date, err)
			}
		})
	}
	if countSigned(t, svc) != 0 {
		t.Fatal("被拒的簽核留下了列")
	}

	// 明天仍可查（狀態為尚未結束），簽核回尚未結束
	if detail, err := svc.Day("2026-10-12"); err != nil || detail.Status != DailyReviewDayNotEnded {
		t.Fatalf("Day(明天) = %+v, %v, want not_ended", detail, err)
	}
	if _, err := svc.Sign(SignRequest{ReviewDate: "2026-10-12", ReviewerID: 5, ReviewerName: "a"}); !errors.Is(err, ErrDailyReviewDayNotEnded) {
		t.Fatalf("Sign(明天) err=%v", err)
	}

	for _, p := range []StatsPeriod{{From: "9999-01-01", To: "9999-12-31"}, {From: "2026-10-01", To: "9999-12-31"}} {
		within(t, "Stats "+p.To, func() {
			if _, err := svc.Stats(p); !errors.Is(err, ErrDailyReviewPeriodInvalid) {
				t.Errorf("Stats(%+v) err=%v, want ErrDailyReviewPeriodInvalid", p, err)
			}
		})
	}
}
