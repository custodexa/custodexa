package policy

import (
	"io"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/csvsafe"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/pdfdoc"
)

// 每日審閱簽核的兩種輸出：合規報告 PDF 的 10.4.1 段，與 daily_reviews.csv。
//
// **daily_reviews.csv 只有這一支寫法**：證據包（audit 模組）與合規報告共用它，
// 兩處的欄位因此不會各自漂移。欄名與值是機器碼（給試算表篩選），人讀的說法
// 只在 PDF。

// DailyReviewsCSVName 逐日清單在證據包與合規報告 ZIP 內的檔名
const DailyReviewsCSVName = "daily_reviews.csv"

// signoffExcerptOnTimeMax PDF 逐日表節錄中準時列的上限（未簽、補簽與未到期全列）
const signoffExcerptOnTimeMax = 5

// dailyReviewsCSVHeader 欄序即契約（每次回新切片）。
func dailyReviewsCSVHeader() []string {
	return []string{
		"review_date", "timezone", "timezone_inferred", "enabled_basis",
		"window_start", "window_end", "due_at", "status", "counts_toward_stats",
		"signed_at", "signer", "late_days", "delay_reason", "note", "coverage",
		"audit_log_source", "command_alert_source",
		"login_failures", "alerts_total", "alerts_benign", "alerts_escalated",
		"high_risk_ops", "alerts_after_sign", "review_ref",
	}
}

// countCell 計數：來源已清除（nil）輸出空白，不輸出 0
func countCell(n *int64) string {
	if n == nil {
		return ""
	}
	return strconv.FormatInt(*n, 10)
}

func signoffTimeCell(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// DailyReviewsCSVRow 一列的儲存格（欄序同表頭）
func DailyReviewsCSVRow(d SignoffDay) []string {
	signedAt, lateDays, ref := "", "", ""
	if d.SignedAt != nil {
		signedAt = d.SignedAt.Format(time.RFC3339)
	}
	if d.Status == SignoffStatusLate {
		lateDays = strconv.Itoa(d.LateDays)
	}
	if d.ReviewID != 0 {
		ref = "daily_review:" + strconv.FormatUint(uint64(d.ReviewID), 10)
	}
	return []string{
		d.Date, d.Timezone, strconv.FormatBool(d.TimezoneInferred), d.EnabledBasis,
		signoffTimeCell(d.WindowStart), signoffTimeCell(d.WindowEnd), signoffTimeCell(d.DueAt),
		d.Status, strconv.FormatBool(d.CountsTowardStats),
		signedAt, d.Signer, lateDays, d.DelayReason, d.ReviewNote, d.Coverage,
		d.AuditLogSource, d.CommandAlertSource,
		countCell(d.LoginFailures), countCell(d.AlertsTotal), countCell(d.AlertsBenign),
		countCell(d.AlertsEscalated), countCell(d.HighRiskOps), countCell(d.AlertsAfterSign), ref,
	}
}

// WriteDailyReviewsCSV 逐日清單（BOM、CRLF、公式注入轉義：延遲原因與備註是自由文字）。
func WriteDailyReviewsCSV(w io.Writer, days []SignoffDay) error {
	cw, err := csvsafe.NewWriter(w, csvsafe.Options{BOM: true, CRLF: true, Escape: true})
	if err != nil {
		return err
	}
	if err := cw.Write(dailyReviewsCSVHeader()); err != nil {
		return err
	}
	for _, d := range days {
		if err := cw.Write(DailyReviewsCSVRow(d)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// signoffLocalTime 某時刻在業務時區的日期時間（PDF 的簽核時間欄）
func signoffLocalTime(t time.Time, tz string) string {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	return t.In(loc).Format("2006-01-02 15:04")
}

// signoffOffset 業務時區在某時刻的 UTC 位移（「UTC+08:00」）
func signoffOffset(tz string, at time.Time) string {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return "UTC"
	}
	return "UTC" + at.In(loc).Format("-07:00")
}

// renderComplianceSignoff 每日審閱簽核段（偏離段之後）：結果與理由、統計範圍、
// 應簽／已簽／補簽／未簽、逐日表節錄、不回寫聲明。數字只彙總計入統計的列。
func renderComplianceSignoff(doc *pdfdoc.Doc, rep *ComplianceReport, ph reportPhraseFn) {
	sec := rep.Signoff
	if sec == nil {
		return
	}
	doc.SectionTitle(fillTemplate(ph("signoff_section"), "{clause}", sec.ClauseNo, "{title}", sec.ClauseTitle))
	doc.Paragraph(fillTemplate(ph("signoff_result"), "{result}", ph("result_"+sec.Result),
		"{reason}", ph("reason_"+sec.Reason)))

	rec := sec.Record
	switch {
	case sec.Reason == ComplianceReasonDailyReviewDisabled:
		doc.Paragraph(ph("signoff_disabled"))
		return
	case rec == nil:
		doc.Paragraph(ph("signoff_unavailable"))
		return
	}

	doc.KeyValues([]pdfdoc.KV{
		{Key: ph("signoff_range"), Value: fillTemplate(ph("signoff_range_value"),
			"{from}", rec.From, "{to}", rec.To, "{tz}", rec.Timezone, "{offset}", signoffOffset(rec.Timezone, rec.AsOf))},
		{Key: ph("as_of"), Value: reportTime(rec.AsOf, rec.Timezone)},
	})
	if sec.Reason == ComplianceReasonSignoffInsufficientData {
		since := ""
		if rec.EnabledSince != nil {
			since = signoffLocalTime(*rec.EnabledSince, rec.Timezone)[:10]
			if rec.EnabledSinceInferred {
				since += ph("signoff_since_inferred")
			}
		}
		doc.Paragraph(fillTemplate(ph("signoff_insufficient"), "{since}", since,
			"{days}", strconv.Itoa(rec.EnabledDays), "{signed}", strconv.Itoa(rec.OnTime+rec.Late)))
	}
	rate := ph("signoff_rate_none")
	if rec.SignRatePercent != nil {
		rate = strconv.Itoa(*rec.SignRatePercent) + "%"
	}
	doc.Paragraph(fillTemplate(ph("signoff_counts"),
		"{required}", strconv.Itoa(rec.Required), "{signed}", strconv.Itoa(rec.OnTime+rec.Late),
		"{rate}", rate, "{late}", strconv.Itoa(rec.Late), "{unsigned}", strconv.Itoa(rec.Unsigned)))
	doc.Paragraph(ph("signoff_counts_note"))
	if rec.InferredDays > 0 {
		doc.Paragraph(fillTemplate(ph("signoff_inferred"), "{n}", strconv.Itoa(rec.InferredDays)))
	}
	if n := purgedSourceDays(rec.Days); n > 0 {
		doc.Paragraph(fillTemplate(ph("signoff_source_purged"), "{n}", strconv.Itoa(n), "{file}", DailyReviewsCSVName))
	}

	rows, omitted := signoffExcerpt(rec.Days, ph)
	doc.Table(pdfdoc.Table{
		Columns: reportColumns(doc, ph, []reportColumn{
			{key: "col_review_date", weight: 1.3, oneLine: []string{"2026-10-10"}},
			{key: "col_signed_at", weight: 1.8, oneLine: []string{"2026-10-10 09:05"}},
			{key: "col_signoff_type", weight: 1}, {key: "col_signer", weight: 1.4},
			{key: "col_counts_toward", weight: 1.2}, {key: "col_enabled_basis", weight: 1.6},
			{key: "col_delay_reason", weight: 3},
		}),
		Rows: rows, Zebra: true, EmptyText: ph("none"), Wrap: true,
	})
	// 準時列全數列出時不印「其餘 0 列未列出」：沒有省略就沒有要交代的
	if omitted > 0 {
		doc.Paragraph(fillTemplate(ph("signoff_excerpt_more"), "{n}", strconv.Itoa(omitted),
			"{total}", strconv.Itoa(len(rec.Days)), "{file}", DailyReviewsCSVName))
	}
	doc.Paragraph(ph("signoff_no_rewrite"))
}

// purgedSourceDays 任一事件來源已依保留政策整日清除的列數（計數在 CSV 留空）
func purgedSourceDays(days []SignoffDay) int {
	n := 0
	for _, d := range days {
		if d.AuditLogSource == model.DailyReviewSourcePurged || d.CommandAlertSource == model.DailyReviewSourcePurged {
			n++
		}
	}
	return n
}

// signoffExcerpt 逐日表節錄（新到舊）：未簽、補簽與未到期全列，準時至多 5 列；
// omitted 為未列出的準時列數。
func signoffExcerpt(days []SignoffDay, ph reportPhraseFn) ([][]string, int) {
	rows := [][]string{}
	onTime, omitted := 0, 0
	for i := len(days) - 1; i >= 0; i-- {
		d := days[i]
		if d.Status == SignoffStatusOnTime && d.CountsTowardStats {
			if onTime >= signoffExcerptOnTimeMax {
				omitted++
				continue
			}
			onTime++
		}
		signedAt := ""
		if d.SignedAt != nil {
			signedAt = signoffLocalTime(*d.SignedAt, d.Timezone)
		}
		counts := ph("counts_yes")
		if !d.CountsTowardStats {
			counts = ph("counts_no_not_due")
		}
		rows = append(rows, []string{d.Date, signedAt, ph("signoff_status_" + d.Status), d.Signer,
			counts, optionalPhrase("basis_", d.EnabledBasis, ph), d.DelayReason})
	}
	return rows, omitted
}
