package audit

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/reviewcal"
	"gorm.io/gorm"
)

func tzHistory(t *testing.T, db *gorm.DB, initial string, initialAt time.Time, changes ...any) {
	t.Helper()
	historyRow(t, db, policy.PolicyDailyReviewTimezone, "", initial, initialAt, model.PolicyHistorySourceMigrationUpgrade)
	prev := initial
	for i := 0; i+1 < len(changes); i += 2 {
		v, when := changes[i].(string), changes[i+1].(time.Time)
		historyRow(t, db, policy.PolicyDailyReviewTimezone, prev, v, when, model.PolicyHistorySourcePolicyUpdate)
		prev = v
	}
	setPolicyRow(t, db, policy.PolicyDailyReviewTimezone, prev)
}

func lookupDay(t *testing.T, cal *reviewcal.Calendar, date string) reviewcal.Day {
	t.Helper()
	d, ok := cal.Lookup(date)
	if !ok {
		t.Fatalf("%s 查無所屬日", date)
	}
	return d
}

func assertContiguous(t *testing.T, cal *reviewcal.Calendar) {
	t.Helper()
	days := cal.Days()
	for i := 1; i < len(days); i++ {
		if !days[i-1].End.Equal(days[i].Start) {
			t.Errorf("%s 結束 %v ≠ %s 開始 %v（重疊或空檔）", days[i-1].Date, days[i-1].End, days[i].Date, days[i].Start)
		}
	}
}

func assertHours(t *testing.T, d reviewcal.Day, want float64) {
	t.Helper()
	if got := d.End.Sub(d.Start).Hours(); got != want {
		t.Errorf("%s 長度 %.0f 小時, want %.0f（%v → %v）", d.Date, got, want, d.Start, d.End)
	}
}

func utc(date string, hh int) time.Time {
	d, _ := reviewcal.ParseDate(date)
	return d.Add(time.Duration(hh) * time.Hour)
}

// TestDailyReviewCalendarTimezoneTransition 擋：改時區當天出現重疊或空檔，導致某段時間
// 的事件被兩天重複計或完全沒被審；或生效前連改時把仍應生效的舊時區提早切掉
func TestDailyReviewCalendarTimezoneTransition(t *testing.T) {
	t.Run("Taipei 改 UTC：轉換日 32 小時", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		tzHistory(t, db, "Asia/Taipei", utc("2026-09-01", 0), "UTC", utc("2026-10-11", 5))
		cal, err := svc.Calendar(utc("2026-10-14", 12))
		if err != nil {
			t.Fatal(err)
		}
		assertContiguous(t, cal)
		d11, d12, d13 := lookupDay(t, cal, "2026-10-11"), lookupDay(t, cal, "2026-10-12"), lookupDay(t, cal, "2026-10-13")
		if d11.TZ != "Asia/Taipei" || !d11.Start.Equal(utc("2026-10-10", 16)) || !d11.End.Equal(utc("2026-10-11", 16)) {
			t.Errorf("10-11 = %s [%v,%v), want 仍以 Taipei 切", d11.TZ, d11.Start, d11.End)
		}
		if d12.TZ != "UTC" || !d12.Start.Equal(utc("2026-10-11", 16)) || !d12.End.Equal(utc("2026-10-13", 0)) {
			t.Errorf("10-12 = %s [%v,%v)", d12.TZ, d12.Start, d12.End)
		}
		assertHours(t, d12, 32)
		assertHours(t, d13, 24)
	})
	t.Run("UTC 改 Taipei：轉換日 16 小時", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		tzHistory(t, db, "UTC", utc("2026-09-01", 0), "Asia/Taipei", utc("2026-10-11", 12))
		cal, _ := svc.Calendar(utc("2026-10-14", 12))
		assertContiguous(t, cal)
		d12 := lookupDay(t, cal, "2026-10-12")
		if d12.TZ != "Asia/Taipei" || !d12.Start.Equal(utc("2026-10-12", 0)) || !d12.End.Equal(utc("2026-10-12", 16)) {
			t.Errorf("10-12 = %s [%v,%v)", d12.TZ, d12.Start, d12.End)
		}
		assertHours(t, d12, 16)
		assertHours(t, lookupDay(t, cal, "2026-10-11"), 24)
	})
	t.Run("同日改回原時區不產生轉換", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		tzHistory(t, db, "UTC", utc("2026-09-01", 0), "Asia/Taipei", utc("2026-10-11", 12), "UTC", utc("2026-10-11", 13))
		mid, _ := svc.Calendar(utc("2026-10-11", 12).Add(30 * time.Minute))
		if p := mid.Pending(); p == nil || p.Value != "Asia/Taipei" || p.EffectiveDate != "2026-10-12" || !p.EffectiveAt.Equal(utc("2026-10-12", 0)) {
			t.Errorf("改為 Taipei 後的待生效 = %+v, want Taipei 自 10-12（10-12 00:00Z）", p)
		}
		after, _ := svc.Calendar(utc("2026-10-11", 14))
		if p := after.Pending(); p != nil {
			t.Errorf("改回 UTC 後仍有待生效 %+v", p)
		}
		later, _ := svc.Calendar(utc("2026-10-13", 1))
		d12 := lookupDay(t, later, "2026-10-12")
		if d12.TZ != "UTC" {
			t.Errorf("10-12 時區 = %s, want UTC", d12.TZ)
		}
		assertHours(t, d12, 24)
		hist, _ := svc.policy.History(policy.PolicyDailyReviewTimezone)
		if len(hist) != 3 {
			t.Errorf("時區歷史 %d 列, want 3（初值＋兩次變更）", len(hist))
		}
	})
	t.Run("生效前連改兩次只有最後值生效", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		tzHistory(t, db, "UTC", utc("2026-09-01", 0), "Asia/Taipei", utc("2026-10-11", 10), "Asia/Tokyo", utc("2026-10-11", 11))
		cal, _ := svc.Calendar(utc("2026-10-13", 12))
		assertContiguous(t, cal)
		if d := lookupDay(t, cal, "2026-10-12"); d.TZ != "Asia/Tokyo" {
			t.Errorf("10-12 時區 = %s, want Asia/Tokyo", d.TZ)
		}
		if d := lookupDay(t, cal, "2026-10-11"); d.TZ != "UTC" {
			t.Errorf("10-11 時區 = %s, want UTC（當天仍以舊時區切）", d.TZ)
		}
	})
	t.Run("轉換日當天再改自轉換日下一日生效", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		tzHistory(t, db, "UTC", utc("2026-09-01", 0), "Asia/Taipei", utc("2026-10-11", 10), "UTC", utc("2026-10-12", 10))
		cal, _ := svc.Calendar(utc("2026-10-15", 12))
		assertContiguous(t, cal)
		d12, d13 := lookupDay(t, cal, "2026-10-12"), lookupDay(t, cal, "2026-10-13")
		if d12.TZ != "Asia/Taipei" {
			t.Errorf("10-12 = %s, want Taipei（轉換日本身不變）", d12.TZ)
		}
		if d13.TZ != "UTC" || !d13.Start.Equal(utc("2026-10-12", 16)) || !d13.End.Equal(utc("2026-10-14", 0)) {
			t.Errorf("10-13 = %s [%v,%v)", d13.TZ, d13.Start, d13.End)
		}
	})
	t.Run("UTC−12 改 UTC+14：轉換日順延、被跳過的日期不列入", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		tzHistory(t, db, "Etc/GMT+12", utc("2026-09-01", 12), "Pacific/Kiritimati", utc("2026-10-11", 13))
		cal, _ := svc.Calendar(utc("2026-10-15", 12))
		assertContiguous(t, cal)
		if _, ok := cal.Lookup("2026-10-12"); ok {
			t.Error("10-12 應被跳過")
		}
		d13 := lookupDay(t, cal, "2026-10-13")
		if d13.TZ != "Pacific/Kiritimati" || !d13.Start.Equal(utc("2026-10-12", 12)) || !d13.End.Equal(utc("2026-10-13", 10)) {
			t.Errorf("10-13 = %s [%v,%v)", d13.TZ, d13.Start, d13.End)
		}
		for _, d := range cal.Days() {
			if d.Date == "2026-10-12" {
				t.Error("行事曆含被跳過的 10-12")
			}
		}
	})
	t.Run("America/New_York 的 DST 日長 23／25 小時", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		tzHistory(t, db, "America/New_York", utc("2026-03-01", 12))
		cal, _ := svc.Calendar(utc("2026-11-05", 12))
		assertContiguous(t, cal)
		assertHours(t, lookupDay(t, cal, "2026-03-08"), 23)
		assertHours(t, lookupDay(t, cal, "2026-11-01"), 25)
		assertHours(t, lookupDay(t, cal, "2026-07-01"), 24)
	})
	t.Run("啟用當天下午開啟仍列入、整日關閉不列入", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		const tz = "Asia/Taipei"
		tzHistory(t, db, tz, utc("2026-09-01", 0))
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "false", "true", at(t, tz, "2026-10-08", 15, 0, 0), model.PolicyHistorySourcePolicyUpdate)
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "true", "false", at(t, tz, "2026-10-09", 0, 0, 0), model.PolicyHistorySourcePolicyUpdate)
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "false", "true", at(t, tz, "2026-10-11", 0, 0, 0), model.PolicyHistorySourcePolicyUpdate)
		cal, _ := svc.Calendar(at(t, tz, "2026-10-12", 10, 0, 0))
		for date, want := range map[string]bool{"2026-10-07": false, "2026-10-08": true, "2026-10-09": false, "2026-10-10": false, "2026-10-11": true} {
			if d := lookupDay(t, cal, date); d.InScope != want {
				t.Errorf("%s in_scope=%v, want %v", date, d.InScope, want)
			}
		}
	})
	t.Run("推定與有證據區段同日為 recorded、只有推定為其成因", func(t *testing.T) {
		svc, db, _ := setupDailyReviewDB(t)
		tzHistory(t, db, "UTC", utc("2026-09-01", 0))
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "false", "true", utc("2026-09-05", 8), model.PolicyHistorySourceMigrationPresumedPurged)
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "true", "true", utc("2026-09-10", 12), model.PolicyHistorySourceMigrationAuditLog)
		cal, _ := svc.Calendar(utc("2026-09-20", 0))
		if d := lookupDay(t, cal, "2026-09-07"); d.Basis != model.DailyReviewBasisPresumedPurged {
			t.Errorf("09-07 basis=%q, want presumed_purged", d.Basis)
		}
		if d := lookupDay(t, cal, "2026-09-10"); d.Basis != model.DailyReviewBasisRecorded {
			t.Errorf("09-10 basis=%q, want recorded（同日兼有證據區段）", d.Basis)
		}
		if d := lookupDay(t, cal, "2026-09-11"); d.Basis != model.DailyReviewBasisRecorded {
			t.Errorf("09-11 basis=%q, want recorded", d.Basis)
		}
	})
}
