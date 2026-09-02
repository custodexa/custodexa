package asset

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/pdfdoc"
)

// 把報告資料集轉成 PDF 文件模型。
//
// 這一層只做「轉換」：版面元件由文件模型提供，數字全部取自已建構的資料集，
// **不在此重算任何一個值**——重算即是第二個事實來源。

// timeCell 表格儲存格的時刻：ISO 8601 到分鐘、帶時區位移。
//
// 不印秒：欄寬有限，帶秒的字串在多欄表格裡會被裁成刪節號，而被裁掉的
// 通常正是時區位移——讀者看不出那個時刻屬於哪個時區就無法核對。
// 完整到秒的值在 CSV。
func timeCell(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format("2006-01-02T15:04-07:00")
}

// RenderPDF 產出報告 PDF。reportRef 是頁尾的報告識別（工作單編號）。
func RenderPDF(w io.Writer, rep *RotationReport, reportRef string) error {
	ph := phraseFor(rep.Meta.Language)
	doc, err := pdfdoc.New(pdfdoc.Options{
		Title:   ph("title"),
		Subject: ph("scope") + ": " + scopeLabel(rep, ph),
		Footer: pdfdoc.Footer{
			Left:   reportRef,
			Center: rep.Meta.GeneratedAt.In(rep.Meta.AsOf.Location()).Format(time.RFC3339),
			Page:   ph("page_of"),
			Note:   ph("footer_integrity"),
		},
	})
	if err != nil {
		return err
	}

	renderCover(doc, rep, ph)
	// 封面之後全部橫式：這些表的欄位由規格固定，直式版心裡每欄不到十公釐，
	// 欄名與帶時區位移的時刻會整欄被裁掉——一個讀不出時區的時刻無法核對
	doc.NewLandscapePage()
	renderExceptions(doc, rep, ph)
	renderNoPolicy(doc, rep, ph)
	doc.NewLandscapePage()
	renderAppendixA(doc, rep, ph)
	renderAppendixB(doc, rep, ph)
	return doc.Output(w)
}

// renderCover 封面與摘要。
func renderCover(doc *pdfdoc.Doc, rep *RotationReport, ph phraseFn) {
	m := rep.Meta
	doc.CoverTitle(ph("title"), scopeLabel(rep, ph))
	doc.KeyValues([]pdfdoc.KV{
		{Key: ph("as_of"), Value: m.AsOf.Format(time.RFC3339)},
		{Key: ph("period"), Value: m.PeriodStart.Format(time.RFC3339) + " – " +
			m.PeriodEnd.Format(time.RFC3339)},
		{Key: ph("generated_at"), Value: m.GeneratedAt.In(m.AsOf.Location()).Format(time.RFC3339)},
		{Key: ph("generated_by"), Value: m.GeneratedBy},
		{Key: ph("global_policy"), Value: globalPolicyLine(rep, ph)},
	})

	s := rep.Summary
	doc.SectionTitle(ph("summary"))
	doc.MetricCells(coverMetrics(rep, ph), 6)

	doc.Donuts([]pdfdoc.Donut{
		{Label: ph("rate_excluding_no_record"), Ratio: s.RateExcludingNoRecord,
			Center: percentText(s.RateExcludingNoRecord, ph)},
		{Label: ph("rate_counting_no_record"), Ratio: s.RateCountingNoRecord,
			Center: percentText(s.RateCountingNoRecord, ph)},
	})

	doc.StackedBar(pdfdoc.StackedBar{
		EmptyText: ph("exceptions_empty"),
		Segments: []pdfdoc.Segment{
			{Label: ph("bucket_compliant"), Value: s.Compliant, Shade: 70},
			{Label: ph("bucket_due_soon"), Value: s.DueWithin30, Shade: 115},
			{Label: ph("bucket_overdue"), Value: s.Overdue, Shade: 150},
			{Label: ph("bucket_no_record"), Value: s.NoRecord, Shade: 180},
			{Label: ph("bucket_unverified"), Value: s.Unverified, Shade: 205},
			{Label: ph("bucket_no_policy"), Value: s.NoPolicy, Shade: 230},
		},
	})

	doc.Paragraph(fmt.Sprintf("%s: %s %d, %s %d, %s %d", ph("notes"),
		ph("note_no_policy"), s.NoPolicy,
		ph("note_shared"), s.SharedCredential,
		ph("note_multi_plan"), s.MultiPlan))

	doc.NoteBlock(ph("caliber"), []string{
		ph("caliber_a"),
		ph("caliber_b"),
		ph("caliber_due_soon") + fmt.Sprintf(" (%d)", rep.Meta.DueSoonWindowDays),
		ph("caliber_no_record"),
		ph("caliber_shared"),
		ph("caliber_population"),
		ph("truncation") + ": " + truncationLine(rep, ph),
	})
}

// coverMetrics 封面的六格指標。
//
// 抽成函式而非寫在版面呼叫裡：這六個數字是報告的結論，必須能被測試直接
// 對照 CSV 的分桶列數。
func coverMetrics(rep *RotationReport, ph phraseFn) []pdfdoc.Metric {
	s := rep.Summary
	return []pdfdoc.Metric{
		{Label: ph("metric_total"), Value: strconv.Itoa(s.TotalAccounts)},
		{Label: ph("metric_compliant"), Value: strconv.Itoa(s.Compliant)},
		{Label: ph("metric_overdue"), Value: strconv.Itoa(s.Overdue)},
		{Label: ph("metric_due_soon"), Value: strconv.Itoa(s.DueWithin30)},
		{Label: ph("metric_no_record"), Value: strconv.Itoa(s.NoRecord)},
		{Label: ph("metric_unverified"), Value: strconv.Itoa(s.Unverified)},
	}
}

// renderExceptions 例外清單：只列逾期、即將到期、未驗證，依此順序分組。
//
// 無記錄**不進例外清單**：上線初期它可能佔九成，塞進來會把真正逾期的帳號
// 淹掉，而例外清單的用途正是讓稽核一眼看到要處置的對象。其數量在摘要、
// 明細在附表 A。
func renderExceptions(doc *pdfdoc.Doc, rep *RotationReport, ph phraseFn) {
	doc.SectionTitle(ph("exceptions"))
	cols := exceptionColumns(doc, ph)
	for _, bucket := range exceptionBuckets {
		doc.Paragraph(ph("bucket_" + bucket))
		doc.Table(pdfdoc.Table{Columns: cols, Rows: exceptionRows(rep, bucket, ph),
			Zebra: true, EmptyText: ph("exceptions_empty")})
	}
}

// exceptionBuckets 例外清單涵蓋的桶與其順序。no_record 不在其中。
var exceptionBuckets = []string{BucketOverdue, BucketDueSoon, BucketUnverified}

// exceptionRows 某一桶的例外列。
func exceptionRows(rep *RotationReport, bucket string, ph phraseFn) [][]string {
	rows := [][]string{}
	for i := range rep.Rows {
		if rep.Rows[i].Bucket == bucket {
			rows = append(rows, exceptionValues(&rep.Rows[i], ph))
		}
	}
	return rows
}

// renderNoPolicy 政策未設定的帳號（獨立段）。
func renderNoPolicy(doc *pdfdoc.Doc, rep *RotationReport, ph phraseFn) {
	doc.SectionTitle(ph("no_policy_section"))
	doc.Paragraph(ph("no_policy_lead"))
	widths := doc.FitColumns([]float64{3, 2, 3, 2.4, 2.4, 1.6})
	cols := []pdfdoc.Column{
		{Title: ph("col_asset"), Width: widths[0]},
		{Title: ph("col_account"), Width: widths[1]},
		{Title: ph("col_plans"), Width: widths[2]},
		{Title: ph("col_last_success"), Width: widths[3]},
		{Title: ph("col_next_schedule"), Width: widths[4]},
		{Title: ph("col_marks"), Width: widths[5]},
	}
	doc.Table(pdfdoc.Table{Columns: cols, Rows: noPolicyRows(rep, ph), Zebra: true,
		EmptyText: ph("exceptions_empty")})
}

// noPolicyRows 政策未設定段的列。
func noPolicyRows(rep *RotationReport, ph phraseFn) [][]string {
	rows := [][]string{}
	for i := range rep.Rows {
		r := &rep.Rows[i]
		if r.Bucket != BucketNoPolicy {
			continue
		}
		rows = append(rows, []string{
			r.AssetName, r.Username, strings.Join(r.Plans, " / "),
			timeCell(r.LastSuccessAt), timeCell(r.NextScheduleAt), marksOf(r, ph),
		})
	}
	return rows
}

// appendixAColumns 附表 A 的欄索引（指向 accountColumnKeys 與 accountValues 的同一序）。
//
// **CSV 是超集，PDF 少四欄**：位址與協定（同一台機器整欄重複，資產名已足以指認）、
// 天數來源（適用天數旁的括號註記在封面口徑說明已交代）、最近記錄狀態
// （與最後成功改密時刻並列時，讀者要的是後者）。少掉的四欄在帳號 CSV 裡逐欄俱在，
// 這一份是給人在紙上讀的：欄再窄下去，帶時區位移的時刻會被裁成刪節號，
// 而一個讀不出位移的時刻無法核對。
var appendixAColumns = []int{0, 3, 4, 5, 6, 7, 8, 9, 11, 13, 14, 15, 16, 17}

// appendixAWidths 上列各欄的相對寬（FitColumns 會正規化到版心）。
var appendixAWidths = []float64{2.0, 1.5, 1.6, 0.8, 1.7, 2.6, 1.6, 1.3, 4.2, 1.8, 4.2, 1.8, 1.6, 1.3}

// renderAppendixA 全帳號明細。欄值取自與 CSV 同一支轉換，只是投影掉四欄——
// 兩處各寫一份即等於允許「同一欄放的不是同一件事」。
func renderAppendixA(doc *pdfdoc.Doc, rep *RotationReport, ph phraseFn) {
	doc.SectionTitle(ph("appendix_a"))
	widths := doc.FitColumns(appendixAWidths)
	cols := make([]pdfdoc.Column, len(appendixAColumns))
	for i, idx := range appendixAColumns {
		cols[i] = pdfdoc.Column{Title: ph(accountColumnKeys[idx]), Width: widths[i]}
	}
	rows := make([][]string, 0, len(rep.Rows))
	for i := range rep.Rows {
		full := accountValues(&rep.Rows[i], ph, timeCell)
		row := make([]string, len(appendixAColumns))
		for j, idx := range appendixAColumns {
			row[j] = full[idx]
		}
		rows = append(rows, row)
	}
	doc.Table(pdfdoc.Table{Columns: cols, Rows: rows, Zebra: true,
		EmptyText: ph("exceptions_empty")})
}

// renderAppendixB 區間內的改密記錄。原因碼只有機器碼，不含遠端原文。
func renderAppendixB(doc *pdfdoc.Doc, rep *RotationReport, ph phraseFn) {
	doc.SectionTitle(ph("appendix_b"))
	widths := doc.FitColumns([]float64{1, 4.2, 2, 2.4, 1.8, 1.4, 1.3, 1.2, 2})
	cols := make([]pdfdoc.Column, len(recordColumnKeys))
	for i, k := range recordColumnKeys {
		cols[i] = pdfdoc.Column{Title: ph(k), Width: widths[i]}
	}
	rows := make([][]string, 0, len(rep.Records))
	for i := range rep.Records {
		rows = append(rows, recordValues(&rep.Records[i], ph, timeCell))
	}
	doc.Table(pdfdoc.Table{Columns: cols, Rows: rows, Zebra: true,
		EmptyText: ph("exceptions_empty")})
}

func exceptionColumns(doc *pdfdoc.Doc, ph phraseFn) []pdfdoc.Column {
	widths := doc.FitColumns([]float64{2.6, 1.6, 1.4, 2, 3, 1.4, 3, 1.4, 1.6})
	titles := []string{"col_asset", "col_account", "col_bucket", "col_max_age_days",
		"col_last_success", "col_remaining_a", "col_next_schedule", "col_remaining_b",
		"col_marks"}
	cols := make([]pdfdoc.Column, len(titles))
	for i, k := range titles {
		cols[i] = pdfdoc.Column{Title: ph(k), Width: widths[i]}
	}
	return cols
}

func exceptionValues(row *AccountRow, ph phraseFn) []string {
	days := daysValue(row.MaxAgeDays)
	if src := maxAgeSourceLabel(row.MaxAgeSource, ph); src != "" && days != "" {
		days = days + " (" + src + ")"
	}
	return []string{
		row.AssetName, row.Username, ph("bucket_" + row.Bucket), days,
		timeCell(row.LastSuccessAt), intPtrValue(row.RemainingDaysA),
		timeCell(row.NextScheduleAt), intPtrValue(row.RemainingDaysB),
		marksOf(row, ph),
	}
}

// marksOf 標記欄：共用／多計劃／特權。
func marksOf(row *AccountRow, ph phraseFn) string {
	marks := make([]string, 0, 3)
	if row.SharedCredential {
		marks = append(marks, ph("mark_shared"))
	}
	if row.MultiPlan {
		marks = append(marks, ph("mark_multi_plan"))
	}
	if row.Privileged {
		marks = append(marks, ph("mark_privileged"))
	}
	return strings.Join(marks, " ")
}

// scopeLabel 範圍的可讀呈現。
func scopeLabel(rep *RotationReport, ph phraseFn) string {
	switch rep.Meta.ScopeKind {
	case "", model.RotationScopeAll:
		return ph("scope_all")
	case model.RotationScopeNode:
		return ph("scope_node") + ": " + rep.Meta.ScopeLabel
	case model.RotationScopePlan:
		return ph("scope_plan") + ": " + rep.Meta.ScopeLabel
	default:
		return rep.Meta.ScopeLabel
	}
}

// globalPolicyLine 全域政策：未設定時明說未設定，不印 0。
func globalPolicyLine(rep *RotationReport, ph phraseFn) string {
	if rep.Meta.GlobalMaxAgeDays <= 0 {
		return ph("global_policy_days") + ": " + ph("global_policy_unset")
	}
	return ph("global_policy_days") + ": " + strconv.Itoa(rep.Meta.GlobalMaxAgeDays)
}

// percentText 合規率的呈現；分母為零時是「不適用」，不是 0%。
func percentText(ratio *float64, ph phraseFn) string {
	if ratio == nil {
		return ph("not_applicable")
	}
	return strconv.FormatFloat(*ratio*100, 'f', 1, 64) + "%"
}

// truncationLine 截斷狀態。
func truncationLine(rep *RotationReport, ph phraseFn) string {
	parts := make([]string, 0, 2)
	if rep.Truncation.RowsTruncated {
		parts = append(parts, ph("truncation_rows")+" "+strconv.Itoa(rep.Truncation.RowsCap))
	}
	if rep.Truncation.RecordsTruncated {
		parts = append(parts, ph("truncation_records")+" "+strconv.Itoa(rep.Truncation.RecordsCap))
	}
	if len(parts) == 0 {
		return ph("truncation_none")
	}
	return strings.Join(parts, "; ")
}
