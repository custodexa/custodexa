package audit

import (
	"reflect"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/reviewcal"
)

// overdueCapture 攔截逾期提醒；回傳已送出的參數清單
func overdueCapture(svc *DailyReviewService) *[]map[string]string {
	sent := &[]map[string]string{}
	svc.overdueSink = func(p map[string]string) { *sent = append(*sent, p) }
	return sent
}

// signRange 以簽核列填滿 [from, to]（含頭尾）
func signRange(t *testing.T, svc *DailyReviewService, tz, from, to string) {
	t.Helper()
	for d := from; d <= to; d = reviewcal.AddDays(d, 1) {
		signedRow(t, svc.db, tz, d, false, "")
	}
}

// TestDailyReviewOverdueListsAllPendingDays 擋：只提醒昨天而漏掉更早的未簽日、只有昨天
// 未簽時就發出逾期提醒，或以伺服器時區判 09:00 而提早或延後送出。
// 伺服器時區為 UTC：傳入的時刻一律帶 UTC 位置，業務時區 Asia/Taipei（UTC+8）
func TestDailyReviewOverdueListsAllPendingDays(t *testing.T) {
	const tz = "Asia/Taipei"
	utc := func(tt time.Time) time.Time { return tt.UTC() }

	t.Run("四天未簽三天逾期：08:59 不送、09:00 送一則且參數齊、當天不重送、補齊後不送", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
		signRange(t, svc, tz, "2026-10-01", "2026-10-06")
		sent := overdueCapture(svc)

		if svc.CheckOverdue(utc(at(t, tz, "2026-10-11", 8, 59, 59))) || len(*sent) != 0 {
			t.Fatal("業務時區 08:59:59（UTC 00:59:59）不應送出")
		}
		if !svc.CheckOverdue(utc(at(t, tz, "2026-10-11", 9, 0, 0))) || len(*sent) != 1 {
			t.Fatalf("業務時區 09:00（UTC 01:00）應送出一則，實送 %d", len(*sent))
		}
		want := map[string]string{
			"date": "2026-10-07", "pending_dates": "2026-10-07,2026-10-08,2026-10-09,2026-10-10",
			"pending_count": "4", "overdue_count": "3", "earliest_pending_date": "2026-10-07", "timezone": tz,
		}
		if !reflect.DeepEqual((*sent)[0], want) {
			t.Fatalf("參數 %v, want %v", (*sent)[0], want)
		}
		if svc.CheckOverdue(utc(at(t, tz, "2026-10-11", 9, 15, 0))) || len(*sent) != 1 {
			t.Fatal("當天第二次檢查不應重送")
		}

		signRange(t, svc, tz, "2026-10-07", "2026-10-11")
		if svc.CheckOverdue(utc(at(t, tz, "2026-10-12", 9, 0, 0))) || len(*sent) != 1 {
			t.Fatal("補齊後（只剩昨天未到期）不應送出")
		}
		signRange(t, svc, tz, "2026-10-12", "2026-10-12")
		if svc.CheckOverdue(utc(at(t, tz, "2026-10-13", 9, 0, 0))) || len(*sent) != 1 {
			t.Fatal("全部補齊不應送出")
		}
	})

	t.Run("只有昨天未簽不送", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
		signRange(t, svc, tz, "2026-10-01", "2026-10-09")
		sent := overdueCapture(svc)
		if svc.CheckOverdue(utc(at(t, tz, "2026-10-11", 9, 30, 0))) || len(*sent) != 0 {
			t.Fatalf("只有昨天未簽不應送出，實送 %v", *sent)
		}
	})

	t.Run("功能關閉不送", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "true", "false", at(t, tz, "2026-10-10", 12, 0, 0), model.PolicyHistorySourcePolicyUpdate)
		setPolicyRow(t, db, policy.PolicyDailyReviewEnabled, "false")
		sent := overdueCapture(svc)
		if svc.CheckOverdue(utc(at(t, tz, "2026-10-11", 9, 0, 0))) || len(*sent) != 0 {
			t.Fatalf("功能關閉不應送出，實送 %v", *sent)
		}
	})

	t.Run("有待生效的時區變更時仍以目前生效時區判定", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
		signRange(t, svc, tz, "2026-10-01", "2026-10-07")
		// 今天 08:30（Taipei）改為 UTC：自明天起生效，今天仍以 Taipei 判 09:00
		historyRow(t, db, policy.PolicyDailyReviewTimezone, tz, "UTC", at(t, tz, "2026-10-11", 8, 30, 0), model.PolicyHistorySourcePolicyUpdate)
		setPolicyRow(t, db, policy.PolicyDailyReviewTimezone, "UTC")
		sent := overdueCapture(svc)
		if svc.CheckOverdue(utc(at(t, tz, "2026-10-11", 8, 59, 0))) || len(*sent) != 0 {
			t.Fatal("Taipei 08:59 不應送出")
		}
		if !svc.CheckOverdue(utc(at(t, tz, "2026-10-11", 9, 0, 0))) || len(*sent) != 1 {
			t.Fatal("Taipei 09:00（待生效值 UTC 的 01:00）應送出")
		}
		if got := (*sent)[0]; got["timezone"] != tz || got["pending_dates"] != "2026-10-08,2026-10-09,2026-10-10" || got["overdue_count"] != "2" {
			t.Fatalf("參數 %v，應以目前生效的 %s 判定", got, tz)
		}
	})

	t.Run("逾期日含推定啟用的日子照樣送出並列入", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		historyRow(t, db, policy.PolicyDailyReviewTimezone, "", tz, at(t, tz, "2026-10-01", 0, 0, 0), model.PolicyHistorySourceMigrationUpgrade)
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "false", "true", at(t, tz, "2026-10-05", 0, 0, 0), model.PolicyHistorySourceMigrationPresumedPurged)
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "true", "true", at(t, tz, "2026-10-08", 0, 0, 0), model.PolicyHistorySourceMigrationAuditLog)
		setPolicyRow(t, db, policy.PolicyDailyReviewTimezone, tz)
		setPolicyRow(t, db, policy.PolicyDailyReviewEnabled, "true")
		signRange(t, svc, tz, "2026-10-08", "2026-10-10")
		svc.SetClock(func() time.Time { return at(t, tz, "2026-10-11", 9, 0, 0) })
		detail, err := svc.Day("2026-10-05")
		if err != nil || detail.EnabledBasis != model.DailyReviewBasisPresumedPurged {
			t.Fatalf("前提：10-05 應為推定啟用，實得 %+v %v", detail, err)
		}
		sent := overdueCapture(svc)
		if !svc.CheckOverdue(utc(at(t, tz, "2026-10-11", 9, 0, 0))) || len(*sent) != 1 {
			t.Fatal("推定日逾期應送出")
		}
		if got := (*sent)[0]; got["pending_dates"] != "2026-10-05,2026-10-06,2026-10-07" || got["overdue_count"] != "3" || got["date"] != "2026-10-05" {
			t.Fatalf("參數 %v", got)
		}
	})
}
