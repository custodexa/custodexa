package reviewcal

import (
	"testing"
	"time"
)

// lookupByStepping 舊做法的參考實作：自今天逐日推進到目標日期（只用於比對小範圍）
func lookupByStepping(c *Calendar, date string) (Day, bool) {
	d := c.Today()
	for d.Date < date {
		d = nextDay(d, c.latest)
	}
	return d, d.Date == date
}

// TestCalendarLookupFarFutureIsBounded 擋：請求帶來的遠未來日期（9999-12-31）讓行事曆
// 逐日推進數百萬次，持有稽核檢視權限的帳號一個請求就能吃滿 CPU
func TestCalendarLookupFarFutureIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 11, 4, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		tz   []Change
	}{
		{"單一時區", []Change{{At: now.AddDate(0, -3, 0), New: "Asia/Taipei", Source: sourceMigrationUpgrade}}},
		{"今天改時區待生效", []Change{
			{At: now.AddDate(0, -3, 0), New: "UTC", Source: sourceMigrationUpgrade},
			{At: now.Add(-time.Hour), Old: "UTC", New: "Asia/Taipei", Source: "policy_update"},
		}},
		{"待生效跨越日期線（明天被跳過）", []Change{
			{At: now.AddDate(0, -3, 0), New: "Etc/GMT+12", Source: sourceMigrationUpgrade},
			{At: now.Add(-time.Hour), Old: "Etc/GMT+12", New: "Pacific/Kiritimati", Source: "policy_update"},
		}},
		{"DST 時區", []Change{{At: now.AddDate(0, -3, 0), New: "America/New_York", Source: sourceMigrationUpgrade}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cal := Build(Inputs{TZ: tc.tz, Enabled: []Change{{At: now.AddDate(0, -2, 0), Old: "false", New: "true", Source: "policy_update"}}}, now)

			// 直接計算與逐日推進在近 400 天逐日一致（含轉換日、被跳過的日期、DST 日）
			for i := 1; i <= 400; i++ {
				date := AddDays(cal.Today().Date, i)
				got, okGot := cal.Lookup(date)
				want, okWant := lookupByStepping(cal, date)
				if okGot != okWant {
					t.Fatalf("%s ok=%v，逐日推進 ok=%v", date, okGot, okWant)
				}
				if !okGot {
					continue
				}
				if got.TZ != want.TZ || !got.Start.Equal(want.Start) || !got.End.Equal(want.End) {
					t.Fatalf("%s 直接計算 %s [%v, %v)，逐日推進 %s [%v, %v)", date, got.TZ, got.Start, got.End, want.TZ, want.Start, want.End)
				}
				if !got.DueAt.Equal(DueAt(date, got.TZ)) || !got.SignableAt.Equal(got.End.Add(SettleGrace)) || !got.InScope {
					t.Fatalf("%s due=%v signable=%v in_scope=%v", date, got.DueAt, got.SignableAt, got.InScope)
				}
			}

			// 遠未來：常數時間回應（舊做法逐日推進約 290 萬次，需數秒以上）
			start := time.Now()
			for i := 0; i < 100; i++ {
				if _, ok := cal.Lookup("9999-12-31"); !ok {
					t.Fatal("9999-12-31 應可計算")
				}
			}
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("100 次遠未來查詢耗時 %v，應為常數時間", elapsed)
			}
			d, _ := cal.Lookup("9999-12-31")
			if d.Date != "9999-12-31" || d.Ended(now) {
				t.Fatalf("遠未來日 %+v 應未結束", d)
			}
		})
	}
}
