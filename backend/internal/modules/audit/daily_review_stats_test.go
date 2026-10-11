package audit

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/reviewcal"
	"gorm.io/gorm"
)

// signedRow 直接寫一筆簽核列（統計 fixture 只需要所屬日、遲簽與準時期限）
func signedRow(t *testing.T, db *gorm.DB, tz, date string, late bool, basis string) {
	t.Helper()
	start, end := reviewcal.DayWindow(date, tz)
	due := reviewcal.DueAt(date, tz)
	signedAt := end.Add(9 * time.Hour)
	if late {
		signedAt = due.Add(2 * time.Hour)
	}
	if basis == "" {
		basis = model.DailyReviewBasisRecorded
	}
	row := model.DailyReviewLog{ReviewDate: date, ReviewerID: 5, ReviewerName: "a", SnapshotJSON: "{}",
		SignedAt: signedAt.UTC(), Timezone: tz, WindowStart: start.UTC(), WindowEnd: end.UTC(), DueAt: due.UTC(), Late: late,
		Coverage: model.DailyReviewCoverageFullDay, SourceStatus: model.DailyReviewSourceComplete, EnabledBasis: basis}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
}

// statsFixture 業務時區 Taipei，現在 2026-10-11 12:00；09-20 至 09-22 整日關閉；
// 10-01、10-02 遲簽、10-05 未簽，其餘到 10-09 準時；presumedUntil 非空時，
// 08-01 至 presumedUntil 前一日的啟用由遷移推定
func statsFixture(t *testing.T, presumedUntil string, signTenth bool) (*DailyReviewService, *gorm.DB) {
	t.Helper()
	const tz = "Asia/Taipei"
	svc, db, _ := setupDailyReviewDB(t)
	historyRow(t, db, policy.PolicyDailyReviewTimezone, "", tz, at(t, tz, "2026-07-01", 0, 0, 0), model.PolicyHistorySourceMigrationUpgrade)
	if presumedUntil != "" {
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "false", "true", at(t, tz, "2026-08-01", 0, 0, 0), model.PolicyHistorySourceMigrationPresumedPurged)
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "true", "true", at(t, tz, presumedUntil, 0, 0, 0), model.PolicyHistorySourceMigrationAuditLog)
	} else {
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "false", "true", at(t, tz, "2026-08-01", 0, 0, 0), model.PolicyHistorySourcePolicyUpdate)
	}
	historyRow(t, db, policy.PolicyDailyReviewEnabled, "true", "false", at(t, tz, "2026-09-20", 0, 0, 0), model.PolicyHistorySourcePolicyUpdate)
	historyRow(t, db, policy.PolicyDailyReviewEnabled, "false", "true", at(t, tz, "2026-09-23", 0, 0, 0), model.PolicyHistorySourcePolicyUpdate)
	setPolicyRow(t, db, policy.PolicyDailyReviewTimezone, tz)
	setPolicyRow(t, db, policy.PolicyDailyReviewEnabled, "true")
	fixedClock(svc, at(t, tz, "2026-10-11", 12, 0, 0))
	for d := "2026-09-11"; d <= "2026-10-09"; d = reviewcal.AddDays(d, 1) {
		switch {
		case d >= "2026-09-20" && d <= "2026-09-22", d == "2026-10-05":
		case presumedUntil != "" && d < presumedUntil:
			if d == "2026-09-12" {
				signedRow(t, db, tz, d, true, model.DailyReviewBasisPresumedPurged)
			}
		case d == "2026-10-01" || d == "2026-10-02":
			signedRow(t, db, tz, d, true, "")
		default:
			signedRow(t, db, tz, d, false, "")
		}
	}
	if signTenth {
		signedRow(t, db, tz, "2026-10-10", false, "")
	}
	return svc, db
}

type statsWant struct{ required, onTime, late, unsigned, inferred int }

func assertStats(t *testing.T, s *DailyReviewStats, w statsWant) {
	t.Helper()
	if s.Required != w.required || s.OnTime != w.onTime || s.Late != w.late || s.Unsigned != w.unsigned || s.InferredDays != w.inferred {
		t.Errorf("應簽 %d 準時 %d 遲簽 %d 未簽 %d 推定 %d, want %+v", s.Required, s.OnTime, s.Late, s.Unsigned, s.InferredDays, w)
	}
}

// TestDailyReviewStatsDenominator 擋：把未到期或關閉期間的日子算進分母，簽核率被壓低
// 而誤判偏離；把今天算進期間使分母與報告對不上；推定日被排除在分母外而把未簽藏起來
func TestDailyReviewStatsDenominator(t *testing.T) {
	for _, signTenth := range []bool{false, true} {
		svc, _ := statsFixture(t, "", signTenth)
		s, err := svc.Stats(StatsPeriod{Period: "30d"})
		if err != nil {
			t.Fatal(err)
		}
		if s.From != "2026-09-11" || s.To != "2026-10-10" || s.Timezone != "Asia/Taipei" {
			t.Errorf("期間 %s～%s tz=%s", s.From, s.To, s.Timezone)
		}
		assertStats(t, s, statsWant{26, 23, 2, 1, 0})
		if s.SignRatePercent == nil || *s.SignRatePercent != 96 {
			t.Errorf("簽核率 = %v, want 96（25/26 無條件捨去）", s.SignRatePercent)
		}
		for _, d := range s.Days {
			if d.Date == "2026-10-10" && d.CountsTowardStats {
				t.Errorf("10-10 未到期卻計入（signTenth=%v）", signTenth)
			}
		}
		if s.EnabledSince == nil || s.EnabledSinceInferred || s.EnabledDays != 18 {
			t.Errorf("enabled_since=%v inferred=%v days=%d, want 09-23 起、非推定、18 天", s.EnabledSince, s.EnabledSinceInferred, s.EnabledDays)
		}
	}

	svc, _ := statsFixture(t, "", false)
	for _, bad := range []StatsPeriod{{From: "2025-10-09", To: "2026-10-10"}, {From: "2026-10-01", To: "2026-10-12"}, {From: "2026-10-05", To: "2026-10-01"}, {Period: "7d"}} {
		if _, err := svc.Stats(bad); !errors.Is(err, ErrDailyReviewPeriodInvalid) {
			t.Errorf("%+v err=%v, want PeriodInvalid", bad, err)
		}
	}
	if s, err := svc.Stats(StatsPeriod{From: "2026-10-01", To: "2026-10-11"}); err != nil || s.Required != 9 {
		t.Errorf("迄日為今天：err=%v 應簽=%v, want 9（10-10、10-11 未到期）", err, s)
	}
	if s, err := svc.Stats(StatsPeriod{From: "2025-10-10", To: "2026-10-10"}); err != nil {
		t.Errorf("366 天被拒: %v", err)
	} else if s.From != "2025-10-10" {
		t.Errorf("from = %s", s.From)
	}

	t.Run("推定日計入分母", func(t *testing.T) {
		svc, _ := statsFixture(t, "2026-09-15", false)
		s, err := svc.Stats(StatsPeriod{Period: "30d"})
		if err != nil {
			t.Fatal(err)
		}
		assertStats(t, s, statsWant{26, 19, 3, 4, 4})
	})
	t.Run("10-04 開啟時連續啟用 7 天", func(t *testing.T) {
		const tz = "Asia/Taipei"
		svc, db, _ := setupDailyReviewDB(t)
		enableFrom(t, db, tz, at(t, tz, "2026-10-04", 15, 0, 0))
		fixedClock(svc, at(t, tz, "2026-10-11", 12, 0, 0))
		s, err := svc.Stats(StatsPeriod{})
		if err != nil {
			t.Fatal(err)
		}
		if s.EnabledDays != 7 {
			t.Errorf("enabled_days = %d, want 7", s.EnabledDays)
		}
	})
	t.Run("連續啟用起點落在推定區段", func(t *testing.T) {
		const tz = "Asia/Taipei"
		svc, db, _ := setupDailyReviewDB(t)
		historyRow(t, db, policy.PolicyDailyReviewTimezone, "", tz, at(t, tz, "2026-07-01", 0, 0, 0), model.PolicyHistorySourceMigrationUpgrade)
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "false", "true", at(t, tz, "2026-08-01", 0, 0, 0), model.PolicyHistorySourceMigrationPresumedPurged)
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "true", "true", at(t, tz, "2026-09-15", 0, 0, 0), model.PolicyHistorySourceMigrationAuditLog)
		setPolicyRow(t, db, policy.PolicyDailyReviewEnabled, "true")
		fixedClock(svc, at(t, tz, "2026-10-11", 12, 0, 0))
		s, err := svc.Stats(StatsPeriod{})
		if err != nil {
			t.Fatal(err)
		}
		if s.EnabledSince == nil || !s.EnabledSince.Equal(at(t, tz, "2026-08-01", 0, 0, 0)) || !s.EnabledSinceInferred {
			t.Errorf("enabled_since=%v inferred=%v, want 08-01 推定", s.EnabledSince, s.EnabledSinceInferred)
		}
	})
}
