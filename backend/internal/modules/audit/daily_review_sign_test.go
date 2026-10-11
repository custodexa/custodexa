package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

func countSigned(t *testing.T, svc *DailyReviewService) int64 {
	t.Helper()
	var n int64
	svc.db.Model(&model.DailyReviewLog{}).Count(&n)
	return n
}

// TestDailyReviewSignPastDayLateNeedsReason 擋：補簽被當成準時、或遲簽可以不留原因
func TestDailyReviewSignPastDayLateNeedsReason(t *testing.T) {
	const tz = "Asia/Taipei"
	setup := func(t *testing.T, signAt time.Time) *DailyReviewService {
		svc, db, _ := setupDailyReviewDB(t)
		enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
		fixedClock(svc, signAt)
		return svc
	}
	t.Run("10-08 23:59:59.999 為準時且不存延遲原因", func(t *testing.T) {
		signAt := at(t, tz, "2026-10-08", 23, 59, 59).Add(999 * time.Millisecond)
		svc := setup(t, signAt)
		row, err := svc.Sign(SignRequest{ReviewDate: "2026-10-07", DelayReason: "不該被存", ReviewerID: 5, ReviewerName: "a"})
		if err != nil {
			t.Fatal(err)
		}
		if row.Late || row.DelayReason != nil || !row.SignedAt.Equal(signAt) {
			t.Errorf("late=%v delay_reason=%v signed_at=%v, want 準時、無原因、%v", row.Late, row.DelayReason, row.SignedAt, signAt)
		}
		if want := at(t, tz, "2026-10-09", 0, 0, 0); !row.DueAt.Equal(want) {
			t.Errorf("due_at=%v, want %v", row.DueAt, want)
		}
	})
	t.Run("10-09 00:00:00 為遲簽晚 1 天且須填原因", func(t *testing.T) {
		svc := setup(t, at(t, tz, "2026-10-09", 0, 0, 0))
		if _, err := svc.Sign(SignRequest{ReviewDate: "2026-10-07", DelayReason: "  ", ReviewerID: 5, ReviewerName: "a"}); !errors.Is(err, ErrDailyReviewDelayReasonRequired) {
			t.Fatalf("空白原因 err=%v, want ErrDailyReviewDelayReasonRequired", err)
		}
		if countSigned(t, svc) != 0 {
			t.Fatal("被拒的簽核留下了列")
		}
		row, err := svc.Sign(SignRequest{ReviewDate: "2026-10-07", DelayReason: "值班交接漏簽", ReviewerID: 5, ReviewerName: "a"})
		if err != nil {
			t.Fatal(err)
		}
		if rec := toRecord(*row); !row.Late || rec.LateDays != 1 || row.DelayReason == nil || *row.DelayReason != "值班交接漏簽" {
			t.Errorf("late=%v late_days=%d reason=%v", row.Late, rec.LateDays, row.DelayReason)
		}
	})
	t.Run("10-11 10:42 為晚 3 天", func(t *testing.T) {
		svc := setup(t, at(t, tz, "2026-10-11", 10, 42, 0))
		row, err := svc.Sign(SignRequest{ReviewDate: "2026-10-07", DelayReason: "補簽", ReviewerID: 5, ReviewerName: "a"})
		if err != nil {
			t.Fatal(err)
		}
		if rec := toRecord(*row); rec.LateDays != 3 || row.ReviewDate != "2026-10-07" {
			t.Errorf("late_days=%d review_date=%s, want 3／2026-10-07（所屬日不因簽核時刻而改變）", rec.LateDays, row.ReviewDate)
		}
	})
	t.Run("America/New_York DST 日的準時期限是日曆加兩日", func(t *testing.T) {
		const ny = "America/New_York"
		svc, db, _ := setupDailyReviewDB(t)
		enableFrom(t, db, ny, at(t, ny, "2026-03-01", 0, 0, 0))
		fixedClock(svc, at(t, ny, "2026-03-08", 12, 0, 0))
		row, err := svc.Sign(SignRequest{ReviewDate: "2026-03-07", ReviewerID: 5, ReviewerName: "a"})
		if err != nil {
			t.Fatal(err)
		}
		want := at(t, ny, "2026-03-09", 0, 0, 0)
		if !row.DueAt.Equal(want) || row.DueAt.Equal(row.WindowStart.Add(48*time.Hour)) {
			t.Errorf("due_at=%v, want %v（不是起點 +48h %v）", row.DueAt, want, row.WindowStart.Add(48*time.Hour))
		}
	})
	t.Run("備註與延遲原因以 code point 計 500 字", func(t *testing.T) {
		svc := setup(t, at(t, tz, "2026-10-11", 10, 0, 0))
		long := strings.Repeat("審", 501)
		var tooLong *DailyReviewTextTooLongError
		if _, err := svc.Sign(SignRequest{ReviewDate: "2026-10-09", Note: long, DelayReason: "x", ReviewerID: 5, ReviewerName: "a"}); !errors.As(err, &tooLong) || tooLong.Field != "note" {
			t.Errorf("501 字備註 err=%v, want field=note", err)
		}
		if _, err := svc.Sign(SignRequest{ReviewDate: "2026-10-09", DelayReason: long, ReviewerID: 5, ReviewerName: "a"}); !errors.As(err, &tooLong) || tooLong.Field != "delay_reason" {
			t.Errorf("501 字延遲原因 err=%v, want field=delay_reason", err)
		}
		if countSigned(t, svc) != 0 {
			t.Fatal("被拒的簽核留下了列")
		}
		if _, err := svc.Sign(SignRequest{ReviewDate: "2026-10-09", Note: strings.Repeat("審", 500), DelayReason: strings.Repeat("因", 500), ReviewerID: 5, ReviewerName: "a"}); err != nil {
			t.Errorf("500 字被拒: %v", err)
		}
	})
}

// TestDailyReviewSignRejections 擋：繞過介面即可簽未結束、寬限內、範圍外或格式錯的日子；
// 推定日被拒簽而永遠清不掉，或簽了之後推定標示消失
func TestDailyReviewSignRejections(t *testing.T) {
	const tz = "Asia/Taipei"
	svc, db, _ := setupDailyReviewDB(t)
	historyRow(t, db, policy.PolicyDailyReviewTimezone, "", tz, at(t, tz, "2026-08-01", 0, 0, 0), model.PolicyHistorySourceMigrationUpgrade)
	historyRow(t, db, policy.PolicyDailyReviewEnabled, "false", "true", at(t, tz, "2026-09-01", 0, 0, 0), model.PolicyHistorySourceMigrationPresumedPurged)
	historyRow(t, db, policy.PolicyDailyReviewEnabled, "true", "true", at(t, tz, "2026-10-01", 0, 0, 0), model.PolicyHistorySourceMigrationAuditLog)
	setPolicyRow(t, db, policy.PolicyDailyReviewTimezone, tz)
	setPolicyRow(t, db, policy.PolicyDailyReviewEnabled, "true")
	setClock := fixedClock(svc, at(t, tz, "2026-10-11", 0, 10, 0))

	req := func(date string) SignRequest {
		return SignRequest{ReviewDate: date, DelayReason: "補簽", ReviewerID: 5, ReviewerName: "a"}
	}
	if _, err := svc.Sign(req("2026-10-11")); !errors.Is(err, ErrDailyReviewDayNotEnded) {
		t.Errorf("今天 err=%v, want NotEnded", err)
	}
	var settling *DailyReviewSettlingError
	if _, err := svc.Sign(req("2026-10-10")); !errors.As(err, &settling) || !settling.SignableAt.Equal(at(t, tz, "2026-10-11", 0, 30, 0)) {
		t.Errorf("寬限內 err=%v, want Settling 於 00:30", err)
	}
	if _, err := svc.Sign(req("2026-08-31")); !errors.Is(err, ErrDailyReviewOutOfScope) {
		t.Errorf("啟用前 err=%v, want OutOfScope", err)
	}
	if _, err := svc.Sign(req("2026-13-01")); !errors.Is(err, ErrDailyReviewDateInvalid) {
		t.Errorf("格式錯 err=%v, want DateInvalid", err)
	}
	if countSigned(t, svc) != 0 {
		t.Fatal("被拒的簽核留下了列")
	}
	// 寬限內的昨日仍列入待簽
	if days, total, _ := svc.Pending(2, 31); total != 40 || len(days) == 0 || days[len(days)-1].Date != "2026-10-10" {
		t.Errorf("待簽 %d 天，第 2 頁 %v；寬限內的 10-10 應列入待簽（09-01 至 10-10 共 40 天）", total, days)
	}

	setClock(at(t, tz, "2026-10-11", 10, 0, 0))
	row, err := svc.Sign(req("2026-09-16"))
	if err != nil {
		t.Fatalf("推定日補簽: %v", err)
	}
	if row.EnabledBasis != model.DailyReviewBasisPresumedPurged {
		t.Errorf("簽核列 enabled_basis=%q, want presumed_purged", row.EnabledBasis)
	}
	detail, err := svc.Day("2026-09-16")
	if err != nil || detail.EnabledBasis != model.DailyReviewBasisPresumedPurged {
		t.Errorf("單日明細 enabled_basis=%q err=%v", detail.EnabledBasis, err)
	}
	list, _, err := svc.List(1, 20, false)
	if err != nil || len(list) != 1 || list[0].EnabledBasis != model.DailyReviewBasisPresumedPurged {
		t.Errorf("已簽紀錄 = %+v err=%v", list, err)
	}
}

// TestDailyReviewSignBlockedByUnreviewedAlerts 擋：繞過介面直接呼叫 API 即可在告警未處置時簽核
func TestDailyReviewSignBlockedByUnreviewedAlerts(t *testing.T) {
	const tz = "Asia/Taipei"
	svc, db, _ := setupDailyReviewDB(t)
	enableFrom(t, db, tz, at(t, tz, "2026-10-01", 0, 0, 0))
	fixedClock(svc, at(t, tz, "2026-10-11", 9, 0, 0))
	alerts := NewCommandAlertService(db)
	var ids []uint
	for i := 0; i < 4; i++ {
		ids = append(ids, seedAlertAt(t, db, at(t, tz, "2026-10-10", 8+i, 0, 0), nil, model.AlertDispositionPending))
	}
	// 他日的告警不影響
	seedAlertAt(t, db, at(t, tz, "2026-10-11", 0, 0, 1), nil, model.AlertDispositionPending)
	if err := alerts.Review(ids[0], 5, model.AlertDispositionBenign, ""); err != nil {
		t.Fatal(err)
	}
	if err := alerts.Review(ids[1], 5, model.AlertDispositionBenign, ""); err != nil {
		t.Fatal(err)
	}

	var pending *DailyReviewAlertsPendingError
	if _, err := svc.Sign(SignRequest{ReviewDate: "2026-10-10", ReviewerID: 5, ReviewerName: "a"}); !errors.As(err, &pending) || pending.Count != 2 {
		t.Fatalf("err=%v, want AlertsPending{2}", err)
	}
	if countSigned(t, svc) != 0 {
		t.Fatal("被拒的簽核留下了列")
	}
	_ = alerts.Review(ids[2], 5, model.AlertDispositionBenign, "")
	_ = alerts.Review(ids[3], 5, model.AlertDispositionEscalated, "轉資安")
	row, err := svc.Sign(SignRequest{ReviewDate: "2026-10-10", ReviewerID: 5, ReviewerName: "a"})
	if err != nil {
		t.Fatalf("處置後簽核: %v", err)
	}
	var snap DailyReviewSnapshot
	_ = json.Unmarshal([]byte(row.SnapshotJSON), &snap)
	if val(snap.AlertsTotal) != 4 || val(snap.AlertsBenign) != 3 || val(snap.AlertsEscalated) != 1 || val(snap.UnreviewedAlerts) != 0 {
		t.Errorf("快照告警分布 %s, want 總數 4、無害 3、升級 1、未審閱 0", row.SnapshotJSON)
	}
}
