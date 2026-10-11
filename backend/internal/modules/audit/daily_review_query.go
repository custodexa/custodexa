package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/reviewcal"
)

// 每日簽核的唯讀查詢：卡片摘要、待簽日、單日明細與期間統計。

// DailyReviewPendingPageMax 待簽清單每頁上限
const DailyReviewPendingPageMax = 31

// DailyReviewStatusPendingPreview 卡片摘要列出的待簽日期數
const DailyReviewStatusPendingPreview = 10

// 單日明細的狀態
const (
	DailyReviewDayPending    = "pending"
	DailyReviewDaySettling   = "settling"
	DailyReviewDaySigned     = "signed"
	DailyReviewDayOutOfScope = "out_of_scope"
	DailyReviewDayNotEnded   = "not_ended"
)

// TimezoneToday 目前所屬日
type TimezoneToday struct {
	Date        string    `json:"date"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
}

// TimezonePending 待生效的時區變更
type TimezonePending struct {
	Value         string    `json:"value"`
	EffectiveDate string    `json:"effective_date"`
	EffectiveAt   time.Time `json:"effective_at"`
}

// TimezoneState 業務時區的分界資訊（政策頁確認框、儲存後說明都讀它）
type TimezoneState struct {
	Active  string           `json:"active"`
	Today   TimezoneToday    `json:"today"`
	Pending *TimezonePending `json:"pending"`
}

func timezoneStateOf(cal *reviewcal.Calendar) TimezoneState {
	today := cal.Today()
	st := TimezoneState{Active: today.TZ, Today: TimezoneToday{Date: today.Date, WindowStart: today.Start, WindowEnd: today.End}}
	if p := cal.Pending(); p != nil {
		st.Pending = &TimezonePending{Value: p.Value, EffectiveDate: p.EffectiveDate, EffectiveAt: p.EffectiveAt}
	}
	return st
}

// DailyReviewPendingDay 一個待簽日
type DailyReviewPendingDay struct {
	Date             string               `json:"date"`
	Timezone         string               `json:"timezone"`
	TimezoneInferred bool                 `json:"timezone_inferred"`
	WindowStart      time.Time            `json:"window_start"`
	WindowEnd        time.Time            `json:"window_end"`
	DueAt            time.Time            `json:"due_at"`
	SignableAt       time.Time            `json:"signable_at"`
	Signable         bool                 `json:"signable"`
	Overdue          bool                 `json:"overdue"`
	LateDays         int                  `json:"late_days"`
	EnabledBasis     string               `json:"enabled_basis"`
	Counts           *DailyReviewSnapshot `json:"counts,omitempty"`
}

func pendingDayOf(d reviewcal.Day, now time.Time) DailyReviewPendingDay {
	p := DailyReviewPendingDay{
		Date: d.Date, Timezone: d.TZ, TimezoneInferred: d.TZInferred,
		WindowStart: d.Start, WindowEnd: d.End, DueAt: d.DueAt, SignableAt: d.SignableAt,
		Signable: d.Signable(now), Overdue: d.Overdue(now), EnabledBasis: d.Basis,
	}
	if p.Overdue {
		p.LateDays = reviewcal.LateDays(d.Date, d.TZ, now)
	}
	return p
}

// pendingDays 在範圍內、已結束、未簽的所屬日（由最早排起）；功能關閉時為空
func (s *DailyReviewService) pendingDays(cal *reviewcal.Calendar, now time.Time) ([]reviewcal.Day, error) {
	if !s.Enabled() {
		return nil, nil
	}
	var signed []string
	if err := s.db.Model(&model.DailyReviewLog{}).Pluck("review_date", &signed).Error; err != nil {
		return nil, fmt.Errorf("查詢已簽日: %w", err)
	}
	signedSet := make(map[string]bool, len(signed))
	for _, d := range signed {
		signedSet[d] = true
	}
	var out []reviewcal.Day
	for _, d := range cal.Days() {
		if d.InScope && d.Ended(now) && !signedSet[d.Date] {
			out = append(out, d)
		}
	}
	return out, nil
}

// PendingCount 待簽日數與已逾期數（側欄徽章輪詢，不做計數查詢）
func (s *DailyReviewService) PendingCount() (count, overdue int, err error) {
	now := s.now()
	cal, err := s.Calendar(now)
	if err != nil {
		return 0, 0, err
	}
	days, err := s.pendingDays(cal, now)
	if err != nil {
		return 0, 0, err
	}
	for _, d := range days {
		if d.Overdue(now) {
			overdue++
		}
	}
	return len(days), overdue, nil
}

// Pending 待簽日清單（由最早排起，分頁；每頁至多 31 天，計數只算本頁）
func (s *DailyReviewService) Pending(page, pageSize int) ([]DailyReviewPendingDay, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > DailyReviewPendingPageMax {
		pageSize = DailyReviewPendingPageMax
	}
	now := s.now()
	cal, err := s.Calendar(now)
	if err != nil {
		return nil, 0, err
	}
	days, err := s.pendingDays(cal, now)
	if err != nil {
		return nil, 0, err
	}
	total := len(days)
	from := (page - 1) * pageSize
	if from > total {
		from = total
	}
	to := from + pageSize
	if to > total {
		to = total
	}
	watermarks, err := NewRetentionWatermarkService(s.db).Load()
	if err != nil {
		return nil, 0, fmt.Errorf("讀取保留水位: %w", err)
	}
	items := make([]DailyReviewPendingDay, 0, to-from)
	for _, d := range days[from:to] {
		item := pendingDayOf(d, now)
		if item.Counts, err = computeSnapshot(s.db, d.Date, d.Start, d.End, watermarks); err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, nil
}

// DailyReviewDayDetail 單日明細
type DailyReviewDayDetail struct {
	Date             string                 `json:"date"`
	Status           string                 `json:"status"`
	Timezone         string                 `json:"timezone"`
	TimezoneInferred bool                   `json:"timezone_inferred"`
	WindowStart      time.Time              `json:"window_start"`
	WindowEnd        time.Time              `json:"window_end"`
	DueAt            time.Time              `json:"due_at"`
	SignableAt       time.Time              `json:"signable_at"`
	EnabledBasis     string                 `json:"enabled_basis"`
	Overdue          bool                   `json:"overdue"`
	LateDays         int                    `json:"late_days"`
	Sources          map[string]string      `json:"sources"`
	Counts           *DailyReviewSnapshot   `json:"counts"`
	UnreviewedAlerts []DailyReviewAlertItem `json:"unreviewed_alerts"`
	LoginFailures    DailyReviewEventList   `json:"login_failures"`
	HighRiskOps      DailyReviewEventList   `json:"high_risk_ops"`
	// 已簽日：簽核紀錄、簽核時固化的計數、簽核後出現的未審閱告警數（升級前的簽核為 nil）
	Review          *DailyReviewRecord `json:"review"`
	SignedSnapshot  map[string]any     `json:"signed_snapshot"`
	AlertsAfterSign *int64             `json:"alerts_after_sign"`
}

// Day 單日明細。已簽日的時區、起訖與啟用依據取簽核列固化的值；晚於明天的日期
// 直接回 ErrDailyReviewDayNotEnded（明天本身仍回 status=not_ended）
func (s *DailyReviewService) Day(date string) (*DailyReviewDayDetail, error) {
	if _, ok := reviewcal.ParseDate(date); !ok {
		return nil, ErrDailyReviewDateInvalid
	}
	now := s.now()
	cal, err := s.Calendar(now)
	if err != nil {
		return nil, err
	}
	if beyondTomorrow(cal, date) {
		return nil, ErrDailyReviewDayNotEnded
	}
	signed, err := s.findSigned(s.db, date)
	if err != nil {
		return nil, err
	}
	day, known := cal.Lookup(date)
	if !known && signed == nil {
		// 改時區時被跳過的日期：不在行事曆上
		return &DailyReviewDayDetail{Date: date, Status: DailyReviewDayOutOfScope, Sources: map[string]string{},
			UnreviewedAlerts: []DailyReviewAlertItem{},
			LoginFailures:    DailyReviewEventList{Items: []DailyReviewEventItem{}},
			HighRiskOps:      DailyReviewEventList{Items: []DailyReviewEventItem{}}}, nil
	}
	out := &DailyReviewDayDetail{Date: date, Timezone: day.TZ, TimezoneInferred: day.TZInferred,
		WindowStart: day.Start, WindowEnd: day.End, DueAt: day.DueAt, SignableAt: day.SignableAt, EnabledBasis: day.Basis}
	switch {
	case signed != nil:
		rec := toRecord(*signed)
		out.Status = DailyReviewDaySigned
		out.Review = &rec
		out.Timezone, out.TimezoneInferred = signed.Timezone, signed.TimezoneInferred
		out.WindowStart, out.WindowEnd, out.DueAt = signed.WindowStart, signed.WindowEnd, signed.DueAt
		out.SignableAt = signed.WindowEnd.Add(reviewcal.SettleGrace)
		out.EnabledBasis = signed.EnabledBasis
		out.LateDays = rec.LateDays
		out.Overdue = signed.Late
		if snap, err := parseSnapshot(signed.SnapshotJSON); err == nil {
			out.SignedSnapshot = snap
		}
	case !day.Ended(now):
		out.Status = DailyReviewDayNotEnded
	case !day.InScope || !s.Enabled():
		out.Status = DailyReviewDayOutOfScope
	case !day.Signable(now):
		out.Status = DailyReviewDaySettling
	default:
		out.Status = DailyReviewDayPending
	}
	if out.Status == DailyReviewDayPending || out.Status == DailyReviewDaySettling {
		out.Overdue = day.Overdue(now)
		if out.Overdue {
			out.LateDays = reviewcal.LateDays(date, day.TZ, now)
		}
	}

	watermarks, err := NewRetentionWatermarkService(s.db).Load()
	if err != nil {
		return nil, fmt.Errorf("讀取保留水位: %w", err)
	}
	start, end := out.WindowStart, out.WindowEnd
	logStatus := sourceStatus(watermarks, model.RetentionClassAuditLog, start, end)
	alertStatus := sourceStatus(watermarks, model.RetentionClassCommandAlert, start, end)
	out.Sources = map[string]string{dailyReviewSourceAuditLog: logStatus, dailyReviewSourceCommandAlert: alertStatus}
	if out.Counts, err = computeSnapshot(s.db, date, start, end, watermarks); err != nil {
		return nil, err
	}
	if out.UnreviewedAlerts, err = unreviewedAlerts(s.db, start, end); err != nil {
		return nil, fmt.Errorf("查詢未審閱告警: %w", err)
	}
	if out.LoginFailures, err = eventList(loginFailureScope(s.db, start, end), logStatus); err != nil {
		return nil, fmt.Errorf("查詢登入失敗明細: %w", err)
	}
	if out.HighRiskOps, err = eventList(highRiskScope(s.db, start, end), logStatus); err != nil {
		return nil, fmt.Errorf("查詢高危操作明細: %w", err)
	}
	if signed != nil && signed.Coverage == model.DailyReviewCoverageFullDay {
		// 整日制簽核時該日未審閱告警必為 0 且審閱不可撤銷，所以此刻仍未審閱者必然是簽核後才落庫的。
		// 升級前的簽核（until_signed）不檢查告警處置，無法區分簽核前後，維持 nil
		n := int64(len(out.UnreviewedAlerts))
		out.AlertsAfterSign = &n
	}
	return out, nil
}

// DailyReviewStatsDay 期間統計的逐日列（純計算在 reviewcal，見 PeriodStats）
type DailyReviewStatsDay = reviewcal.StatsDay

// DailyReviewStats 期間統計（三個 change 唯一的期間定義）
type DailyReviewStats = reviewcal.Stats

// 統計逐日列的結果
const (
	DailyReviewResultOnTime   = reviewcal.ResultOnTime
	DailyReviewResultLate     = reviewcal.ResultLate
	DailyReviewResultUnsigned = reviewcal.ResultUnsigned
	DailyReviewResultNotDue   = reviewcal.ResultNotDue
)

// dailyReviewMaxPeriodDays 自訂期間的最長天數
const dailyReviewMaxPeriodDays = 366

// StatsPeriod 統計期間的請求：Period 為 30d／90d，或以 From／To 指定（業務時區日期，含頭尾）
type StatsPeriod struct {
	Period string
	From   string
	To     string
}

// Stats 期間統計。「今天」是計算時刻所屬的所屬日，尚未結束，不屬於任何「近 N 天」；
// 應簽＝期間內在啟用範圍內且準時期限已過的日子（推定日照樣計入並另回天數）
func (s *DailyReviewService) Stats(req StatsPeriod) (*DailyReviewStats, error) {
	now := s.now()
	cal, err := s.Calendar(now)
	if err != nil {
		return nil, err
	}
	return s.statsWith(cal, now, req)
}

func (s *DailyReviewService) statsWith(cal *reviewcal.Calendar, now time.Time, req StatsPeriod) (*DailyReviewStats, error) {
	today := cal.Today().Date
	var from, to string
	switch {
	case req.From != "" || req.To != "":
		if req.Period != "" {
			return nil, ErrDailyReviewPeriodInvalid
		}
		f, okF := reviewcal.ParseDate(req.From)
		t, okT := reviewcal.ParseDate(req.To)
		if !okF || !okT || f.After(t) || req.To > today || int(t.Sub(f).Hours()/24)+1 > dailyReviewMaxPeriodDays {
			return nil, ErrDailyReviewPeriodInvalid
		}
		from, to = req.From, req.To
	default:
		n := 30
		switch strings.TrimSpace(req.Period) {
		case "", "30d":
		case "90d":
			n = 90
		default:
			return nil, ErrDailyReviewPeriodInvalid
		}
		to = reviewcal.AddDays(today, -1)
		from = reviewcal.AddDays(to, -(n - 1))
	}
	stats, _, err := s.periodStats(cal, now, from, to)
	return stats, err
}

// periodStats 期間 [from, to] 的統計與其中已簽的列（不限期間長度；期間驗證由呼叫端負責）。
// 已簽列一併回傳：證據包與合規報告的逐日清單據此補上簽核者、原因與固化計數，
// 判定與清單因此出自同一次讀取
func (s *DailyReviewService) periodStats(cal *reviewcal.Calendar, now time.Time, from, to string) (*DailyReviewStats, map[string]model.DailyReviewLog, error) {
	var dates []string
	for d := from; d <= to; d = reviewcal.AddDays(d, 1) {
		dates = append(dates, d)
	}
	rows, err := s.signedRows(dates)
	if err != nil {
		return nil, nil, err
	}
	signed := make(map[string]reviewcal.SignedDay, len(rows))
	for date, row := range rows {
		r := row
		signed[date] = reviewcal.SignedDay{DueAt: r.DueAt, Late: r.Late, EnabledBasis: r.EnabledBasis, LateDays: lateDaysOf(&r)}
	}
	return cal.PeriodStats(from, to, now, signed, s.Enabled()), rows, nil
}

// DailyReviewYesterday 卡片的昨日摘要
type DailyReviewYesterday struct {
	Date         string               `json:"date"`
	Timezone     string               `json:"timezone"`
	WindowStart  time.Time            `json:"window_start"`
	WindowEnd    time.Time            `json:"window_end"`
	DueAt        time.Time            `json:"due_at"`
	SignableAt   time.Time            `json:"signable_at"`
	Signable     bool                 `json:"signable"`
	InScope      bool                 `json:"in_scope"`
	EnabledBasis string               `json:"enabled_basis"`
	Signed       bool                 `json:"signed"`
	Review       *DailyReviewRecord   `json:"review"`
	Counts       *DailyReviewSnapshot `json:"counts"`
	// CountsFixed 計數是簽核時固化的（true）或即時計算的（false）
	CountsFixed bool `json:"counts_fixed"`
}

// DailyReviewStatus 卡片摘要
type DailyReviewStatus struct {
	Enabled             bool                  `json:"enabled"`
	TimezoneState       TimezoneState         `json:"timezone_state"`
	Yesterday           *DailyReviewYesterday `json:"yesterday"`
	PendingCount        int                   `json:"pending_count"`
	OverdueCount        int                   `json:"overdue_count"`
	EarliestPendingDate *string               `json:"earliest_pending_date"`
	PendingDates        []string              `json:"pending_dates"`
	Stats30d            *DailyReviewStats     `json:"stats_30d"`
}

// Status 卡片摘要：啟用狀態、業務時區分界、昨日、待簽與逾期日數、近 30 天統計。
// 功能關閉時只回啟用狀態與時區分界（政策頁的時區說明仍要讀它）
func (s *DailyReviewService) Status() (*DailyReviewStatus, error) {
	now := s.now()
	cal, err := s.Calendar(now)
	if err != nil {
		return nil, err
	}
	out := &DailyReviewStatus{Enabled: s.Enabled(), TimezoneState: timezoneStateOf(cal), PendingDates: []string{}}
	if !out.Enabled {
		return out, nil
	}
	days, err := s.pendingDays(cal, now)
	if err != nil {
		return nil, err
	}
	out.PendingCount = len(days)
	for i, d := range days {
		if d.Overdue(now) {
			out.OverdueCount++
		}
		if i < DailyReviewStatusPendingPreview {
			out.PendingDates = append(out.PendingDates, d.Date)
		}
	}
	if len(days) > 0 {
		earliest := days[0].Date
		out.EarliestPendingDate = &earliest
	}

	if y, ok := cal.Yesterday(); ok {
		yd := &DailyReviewYesterday{Date: y.Date, Timezone: y.TZ, WindowStart: y.Start, WindowEnd: y.End,
			DueAt: y.DueAt, SignableAt: y.SignableAt, Signable: y.Signable(now), InScope: y.InScope, EnabledBasis: y.Basis}
		signed, err := s.findSigned(s.db, y.Date)
		if err != nil {
			return nil, err
		}
		if signed != nil {
			rec := toRecord(*signed)
			yd.Signed, yd.Review, yd.CountsFixed = true, &rec, true
			yd.Timezone, yd.WindowStart, yd.WindowEnd, yd.DueAt = signed.Timezone, signed.WindowStart, signed.WindowEnd, signed.DueAt
			yd.EnabledBasis = signed.EnabledBasis
			var snap DailyReviewSnapshot
			if err := jsonUnmarshalSnapshot(signed.SnapshotJSON, &snap); err == nil {
				yd.Counts = &snap
			}
		} else if yd.Counts, err = s.Snapshot(y.Date, y.Start, y.End); err != nil {
			return nil, err
		}
		out.Yesterday = yd
	}
	if out.Stats30d, err = s.statsWith(cal, now, StatsPeriod{Period: "30d"}); err != nil {
		return nil, err
	}
	return out, nil
}
