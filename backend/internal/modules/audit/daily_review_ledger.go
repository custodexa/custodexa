package audit

import (
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/reviewcal"
)

// 每日簽核的運作紀錄與逐日清單：合規判定（PCI 10.4.1）、合規報告與證據包的
// daily_reviews.csv 都從這裡取。
//
// **不另寫一套期間計算**：哪些日子收錄、算成什麼、計不計入統計，全部取自期間
// 統計（reviewcal.PeriodStats）的逐日列；這裡只補上簽核者、原因與計數。

// 編譯期確認：每日簽核服務滿足合規判定的運作紀錄來源介面
var _ policy.SignoffRecordSource = (*DailyReviewService)(nil)

// SignoffRecord 近 30 天（截至昨日）的運作紀錄；withDays 時連同逐日清單（含計數）。
func (s *DailyReviewService) SignoffRecord(withDays bool) (*policy.SignoffRecord, error) {
	now := s.now()
	cal, err := s.Calendar(now)
	if err != nil {
		return nil, err
	}
	from, to := cal.Last30()
	st, signed, err := s.periodStats(cal, now, from, to)
	if err != nil {
		return nil, err
	}
	rec := policy.NewSignoffRecord(st)
	if withDays {
		if rec.Days, err = s.signoffDays(cal, st.Days, signed); err != nil {
			return nil, err
		}
	}
	return rec, nil
}

// DailyReviewLedger 證據包時間窗內的逐日清單：收錄的列（至多 limit）、範圍內真實列數
// 與是否截斷。範圍＝起訖與時間窗 [start, end) 有交集、且已結束的所屬日（今天尚未
// 結束，不在任何清單內）；start／end 為 nil 表示不設該端。
func (s *DailyReviewService) DailyReviewLedger(start, end *time.Time, limit int) ([]policy.SignoffDay, int, bool, error) {
	now := s.now()
	cal, err := s.Calendar(now)
	if err != nil {
		return nil, 0, false, err
	}
	yesterday, ok := cal.Yesterday()
	if !ok {
		return []policy.SignoffDay{}, 0, false, nil
	}
	from, err := s.ledgerFrom(cal)
	if err != nil {
		return nil, 0, false, err
	}
	st, signed, err := s.periodStats(cal, now, from, yesterday.Date)
	if err != nil {
		return nil, 0, false, err
	}
	var inRange []reviewcal.StatsDay
	for _, d := range st.Days {
		ws, we := dayWindow(cal, d.Date, signed)
		if (start != nil && !we.After(*start)) || (end != nil && !ws.Before(*end)) {
			continue
		}
		inRange = append(inRange, d)
	}
	total := len(inRange)
	truncated := total > limit
	if truncated {
		inRange = inRange[:limit]
	}
	days, err := s.signoffDays(cal, inRange, signed)
	if err != nil {
		return nil, 0, false, err
	}
	return days, total, truncated, nil
}

// ledgerFrom 逐日清單的起點：行事曆起點與最早簽核列兩者取早（有簽核紀錄的日子一律收錄）
func (s *DailyReviewService) ledgerFrom(cal *reviewcal.Calendar) (string, error) {
	from := cal.Days()[0].Date
	var earliest []string
	if err := s.db.Model(&model.DailyReviewLog{}).Order("review_date ASC").Limit(1).
		Pluck("review_date", &earliest).Error; err != nil {
		return "", fmt.Errorf("查詢最早簽核日: %w", err)
	}
	if len(earliest) > 0 && earliest[0] < from {
		from = earliest[0]
	}
	return from, nil
}

// dayWindow 所屬日起訖：已簽者取簽核列固化的值，其餘取行事曆
func dayWindow(cal *reviewcal.Calendar, date string, signed map[string]model.DailyReviewLog) (time.Time, time.Time) {
	if r, ok := signed[date]; ok {
		return r.WindowStart, r.WindowEnd
	}
	d, _ := cal.Lookup(date)
	return d.Start, d.End
}

// signoffDays 期間統計的逐日列補上簽核與計數。已簽列取簽核時固化的計數；未簽列
// 取此刻的即時計數；來源已清除的計數為 nil（輸出空白，不是 0）。
func (s *DailyReviewService) signoffDays(cal *reviewcal.Calendar, stats []reviewcal.StatsDay,
	signed map[string]model.DailyReviewLog) ([]policy.SignoffDay, error) {

	watermarks, err := NewRetentionWatermarkService(s.db).Load()
	if err != nil {
		return nil, fmt.Errorf("讀取保留水位: %w", err)
	}
	out := make([]policy.SignoffDay, 0, len(stats))
	for _, sd := range stats {
		day, _ := cal.Lookup(sd.Date)
		row := policy.SignoffDay{
			Date: sd.Date, Timezone: day.TZ, TimezoneInferred: day.TZInferred, EnabledBasis: sd.EnabledBasis,
			WindowStart: day.Start, WindowEnd: day.End, DueAt: day.DueAt,
			Status: sd.Result, CountsTowardStats: sd.CountsTowardStats,
			Coverage: model.DailyReviewCoverageFullDay,
		}
		if r, ok := signed[sd.Date]; ok {
			if err := s.fillSigned(&row, r, watermarks); err != nil {
				return nil, err
			}
		} else {
			snap, err := computeSnapshot(s.db, sd.Date, day.Start, day.End, watermarks)
			if err != nil {
				return nil, err
			}
			fillCounts(&row, snap)
		}
		out = append(out, row)
	}
	return out, nil
}

// fillSigned 已簽列：時區、起訖、啟用依據與計數一律取簽核時固化的值，
// 另補簽核後才出現的未審閱告警數（升級前的簽核、或告警來源此刻已整日清除時為 nil）
func (s *DailyReviewService) fillSigned(row *policy.SignoffDay, r model.DailyReviewLog,
	watermarks map[model.RetentionClass]model.AuditRetentionWatermark) error {

	signedAt := r.SignedAt
	row.Timezone, row.TimezoneInferred = r.Timezone, r.TimezoneInferred
	row.WindowStart, row.WindowEnd, row.DueAt = r.WindowStart, r.WindowEnd, r.DueAt
	row.EnabledBasis = r.EnabledBasis
	row.Status = policy.SignoffStatusOnTime
	if r.Late {
		row.Status = policy.SignoffStatusLate
		row.LateDays = lateDaysOf(&r)
	}
	row.SignedAt, row.Signer, row.ReviewNote, row.ReviewID = &signedAt, r.ReviewerName, r.Note, r.ID
	if r.DelayReason != nil {
		row.DelayReason = *r.DelayReason
	}
	if r.Coverage != "" {
		row.Coverage = r.Coverage
	}
	var snap DailyReviewSnapshot
	if err := jsonUnmarshalSnapshot(r.SnapshotJSON, &snap); err != nil {
		return fmt.Errorf("解析 %s 的簽核快照: %w", r.ReviewDate, err)
	}
	// 升級前的舊快照沒有逐項來源狀態：以簽核列記下的最差狀態代之
	for _, p := range []*string{&snap.LoginFailuresSource, &snap.HighRiskOpsSource, &snap.AlertsSource} {
		if *p == "" {
			*p = r.SourceStatus
		}
	}
	fillCounts(row, &snap)
	// 升級前的簽核不檢查告警處置：此刻仍未審閱的告警無法區分簽核前後，維持 nil
	if r.Coverage != model.DailyReviewCoverageFullDay {
		return nil
	}
	if sourceStatus(watermarks, model.RetentionClassCommandAlert, r.WindowStart, r.WindowEnd) == model.DailyReviewSourcePurged {
		return nil
	}
	var n int64
	if err := alertScope(s.db, r.WindowStart, r.WindowEnd).Where("reviewed_at IS NULL").Count(&n).Error; err != nil {
		return fmt.Errorf("統計簽核後的未審閱告警: %w", err)
	}
	row.AlertsAfterSign = &n
	return nil
}

func fillCounts(row *policy.SignoffDay, snap *DailyReviewSnapshot) {
	row.AuditLogSource = snap.LoginFailuresSource
	row.CommandAlertSource = snap.AlertsSource
	row.LoginFailures, row.HighRiskOps = snap.LoginFailures, snap.HighRiskOps
	row.HighRiskCriteria = snap.HighRiskCriteria
	row.AlertsTotal, row.AlertsBenign, row.AlertsEscalated = snap.AlertsTotal, snap.AlertsBenign, snap.AlertsEscalated
}
