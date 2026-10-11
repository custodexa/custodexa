package reviewcal

import "time"

// 期間統計的純計算：行事曆＋已簽列＋現在時刻 → 逐日結果與彙總。
//
// **三處共用同一支**：每日簽核分頁的統計端點、合規判定（PCI 10.4.1 的運作紀錄）
// 與證據包／合規報告的逐日清單都由這裡算出「哪一天算不算、算成什麼」。各算
// 一份的話，同一時點的簽核率會在畫面、判定與報告三處出現三個數字，而沒有任何
// 一處會報錯。這裡不碰資料庫，已簽列由呼叫端查好帶進來。

// 逐日結果
const (
	ResultOnTime   = "on_time"
	ResultLate     = "late"
	ResultUnsigned = "unsigned"
	ResultNotDue   = "not_due"
)

// SignedDay 一個已簽所屬日在統計上需要的固化值（取自簽核列）
type SignedDay struct {
	DueAt        time.Time
	Late         bool
	EnabledBasis string
	LateDays     int
}

// StatsDay 期間統計的逐日列
type StatsDay struct {
	Date              string `json:"date"`
	Result            string `json:"result"` // on_time｜late｜unsigned｜not_due
	CountsTowardStats bool   `json:"counts_toward_stats"`
	EnabledBasis      string `json:"enabled_basis"`
	LateDays          int    `json:"late_days"`
}

// Stats 期間統計（三個畫面與報告唯一的期間定義）
type Stats struct {
	From                 string     `json:"from"`
	To                   string     `json:"to"`
	AsOf                 time.Time  `json:"as_of"`
	Timezone             string     `json:"timezone"`
	Required             int        `json:"required"`
	OnTime               int        `json:"on_time"`
	Late                 int        `json:"late"`
	Unsigned             int        `json:"unsigned"`
	SignRate             *float64   `json:"sign_rate"`
	SignRatePercent      *int       `json:"sign_rate_percent"`
	InferredDays         int        `json:"inferred_days"`
	EnabledSince         *time.Time `json:"enabled_since"`
	EnabledSinceInferred bool       `json:"enabled_since_inferred"`
	EnabledDays          int        `json:"enabled_days"`
	Days                 []StatsDay `json:"days"`
}

// Last30 近 30 天的起訖：截至昨日的 30 個所屬日，今天不屬於期間
func (c *Calendar) Last30() (from, to string) {
	to = AddDays(c.Today().Date, -1)
	return AddDays(to, -29), to
}

// PeriodStats 期間 [from, to]（業務時區日期，含頭尾）的逐日結果與彙總。
//
// 收錄：在啟用範圍內的日子，以及有簽核紀錄的日子（即使不在範圍內）。
// 應簽＝其中準時期限已過者（推定為啟用的日子照樣計入，另回天數）；
// 準時期限未過的日子即使已簽也列為 not_due、不計入。
// enabledNow 為功能開關現值：關閉時沒有「目前這段連續啟用」，起點與累計天數為空。
func (c *Calendar) PeriodStats(from, to string, now time.Time, signed map[string]SignedDay, enabledNow bool) *Stats {
	out := &Stats{From: from, To: to, AsOf: now, Days: []StatsDay{}}
	if toDay, ok := c.Lookup(to); ok {
		out.Timezone = toDay.TZ
	} else {
		out.Timezone = c.Active()
	}
	for date := from; date <= to; date = AddDays(date, 1) {
		day, ok := c.Lookup(date)
		row, isSigned := signed[date]
		if !isSigned && (!ok || !day.InScope) {
			continue
		}
		entry := StatsDay{Date: date, EnabledBasis: day.Basis}
		due := day.DueAt
		if isSigned {
			due = row.DueAt
			entry.EnabledBasis = row.EnabledBasis
		}
		switch {
		case due.After(now):
			entry.Result = ResultNotDue
		case isSigned && row.Late:
			entry.Result = ResultLate
			entry.LateDays = row.LateDays
		case isSigned:
			entry.Result = ResultOnTime
		default:
			entry.Result = ResultUnsigned
		}
		entry.CountsTowardStats = entry.Result != ResultNotDue
		if entry.CountsTowardStats {
			out.Required++
			if IsPresumedBasis(entry.EnabledBasis) {
				out.InferredDays++
			}
			switch entry.Result {
			case ResultOnTime:
				out.OnTime++
			case ResultLate:
				out.Late++
			default:
				out.Unsigned++
			}
		}
		out.Days = append(out.Days, entry)
	}
	if out.Required > 0 {
		rate := float64(out.OnTime+out.Late) / float64(out.Required)
		// 無條件捨去：四捨五入會把 365/366 顯示成 100%，合規語境寧可低報
		pct := (out.OnTime + out.Late) * 100 / out.Required
		out.SignRate, out.SignRatePercent = &rate, &pct
	}
	if since, inferred, ok := c.EnabledSince(); ok && enabledNow {
		out.EnabledSince = &since
		out.EnabledSinceInferred = inferred
		if startDay, ok := c.DayOf(since); ok {
			if y, ok := c.Yesterday(); ok && y.Date >= startDay.Date {
				for d := startDay.Date; d <= y.Date; d = AddDays(d, 1) {
					if _, ok := c.Lookup(d); ok {
						out.EnabledDays++
					}
				}
			}
		}
	}
	return out
}

// EarliestUnsigned 計入統計且未簽的最早日期；沒有則空字串
func (s *Stats) EarliestUnsigned() string {
	for _, d := range s.Days {
		if d.CountsTowardStats && d.Result == ResultUnsigned {
			return d.Date
		}
	}
	return ""
}
