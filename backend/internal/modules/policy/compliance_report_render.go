package policy

import (
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/csvsafe"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/internal/pdfdoc"
)

// 合規報告的兩種輸出：PDF（給人讀）與 CSV（給試算表）。
//
// 這一層只做轉換：每一個數字與每一列都取自資料集，不在此重算。文字一律走
// notifycat 的 compliance_report 詞庫（後端零散文出站）。

// reportPhraseFn 取本報告語言的一則短語。
type reportPhraseFn func(key string) string

func reportPhraseFor(lang string) reportPhraseFn {
	return func(key string) string {
		return notifycat.Phrase(lang, notifycat.LexiconComplianceReport, key)
	}
}

// complianceReportLexicon 某語言的全部詞條（措辭守衛用）。
func complianceReportLexicon(lang string) map[string]string {
	return notifycat.LexiconEntries(lang, notifycat.LexiconComplianceReport)
}

// ComplianceReportCSVAsOfPrefix CSV 首行註解列的前綴，其後接 RFC3339 的資料時點。
// CSV 最常被單獨抽出來丟進試算表，離開資料時點的判定結果無從解釋。
const ComplianceReportCSVAsOfPrefix = "# as_of="

// complianceReportColumns CSV 欄名鍵，順序即欄序（每次回新切片，呼叫端改動不外溢）。
func complianceReportColumns() []string {
	return []string{
		"col_clause_no", "col_clause_title", "col_clause_kind", "col_key", "col_result",
		"col_reason", "col_reason_text", "col_current", "col_zero_meaning", "col_expected",
		"col_comparator", "col_unit", "col_confirmed_by", "col_confirmed_at",
		"col_confirmation_note", "col_note", "col_updated_by", "col_updated_at",
	}
}

// reportTime 封面與表格的時刻：本機時區、到秒、附 UTC 位移。
func reportTime(t time.Time) string {
	local := t.In(time.Local)
	return local.Format("2006-01-02 15:04:05") + " (UTC" + local.Format("-07:00") + ")"
}

func reportTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return reportTime(*t)
}

func csvTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// rowResultText 列的結果說法：設定要求型依判定結果，其餘兩型依條文型別。
func rowResultText(kind, result string, ph reportPhraseFn) string {
	switch kind {
	case model.PolicyClauseKindBuiltinProtection:
		return ph("result_builtin")
	case model.PolicyClauseKindSelfAttested:
		return ph("result_self_attested")
	}
	if result == "" {
		return ph("none")
	}
	return ph("result_" + result)
}

func optionalPhrase(prefix, value string, ph reportPhraseFn) string {
	if value == "" {
		return ""
	}
	return ph(prefix + value)
}

// complianceReportCSVRows 資料集攤成 CSV 列（不含表頭）。設定要求列在前，
// 其後由機構自行確認、由產品承擔兩型各一列。
//
// 目前值與要求值維持原始值（給試算表篩選與比對）；人讀的說法另成兩欄：
// 理由碼的譯文，與 0 在該鍵上的意義——同一個 0 在保留天數是永久保留、在鎖定次數
// 是不啟用限制，只印「0」會被讀成字面上的零。
func complianceReportCSVRows(rep *ComplianceReport, ph reportPhraseFn) [][]string {
	keys := complianceReportColumns()
	row := func(v map[string]string) []string {
		out := make([]string, len(keys))
		for i, k := range keys {
			out[i] = v[k]
		}
		return out
	}
	out := make([][]string, 0, len(rep.Rows)+len(rep.SelfAttested)+len(rep.Builtin))
	for _, r := range rep.Rows {
		out = append(out, row(map[string]string{
			"col_clause_no": r.ClauseNo, "col_clause_title": r.ClauseTitle,
			"col_clause_kind": ph("kind_" + r.Kind), "col_key": r.Key,
			"col_result": rowResultText(r.Kind, r.Result, ph), "col_reason": r.Reason,
			"col_reason_text": reasonText(r, ph), "col_current": r.Current,
			"col_zero_meaning": zeroMeaning(r.Key, r.Current, r.ZeroDisables, ph),
			"col_expected":     r.Expected, "col_comparator": optionalPhrase("comparator_", r.Comparator, ph),
			"col_unit": optionalPhrase("unit_", r.UnitKey, ph), "col_confirmed_by": r.ConfirmedBy,
			"col_confirmed_at": csvTimePtr(r.ConfirmedAt), "col_confirmation_note": r.ConfirmationNote,
			"col_note": r.Note, "col_updated_by": r.UpdatedBy, "col_updated_at": csvTimePtr(r.UpdatedAt),
		}))
	}
	clauseRows := func(list []ComplianceReportClause, kind string) {
		for _, c := range list {
			out = append(out, row(map[string]string{
				"col_clause_no": c.ClauseNo, "col_clause_title": c.Title, "col_clause_kind": ph("kind_" + kind),
				"col_result": rowResultText(kind, "", ph), "col_note": c.Note,
			}))
		}
	}
	clauseRows(rep.SelfAttested, model.PolicyClauseKindSelfAttested)
	clauseRows(rep.Builtin, model.PolicyClauseKindBuiltinProtection)
	return out
}

// WriteComplianceReportCSV 全條文逐鍵明細檔（BOM、CRLF、公式注入轉義）。
func WriteComplianceReportCSV(w io.Writer, rep *ComplianceReport) error {
	ph := reportPhraseFor(rep.Meta.Language)
	cw, err := csvsafe.NewWriter(w, csvsafe.Options{BOM: true, CRLF: true, Escape: true})
	if err != nil {
		return err
	}
	if err := cw.Write([]string{ComplianceReportCSVAsOfPrefix + rep.Meta.AsOf.Format(time.RFC3339)}); err != nil {
		return err
	}
	keys := complianceReportColumns()
	header := make([]string, len(keys))
	for i, k := range keys {
		header[i] = ph(k)
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, row := range complianceReportCSVRows(rep, ph) {
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// complianceReportMetrics 封面摘要六格：前兩格單位是條文，後四格是設定鍵。
func complianceReportMetrics(rep *ComplianceReport, ph reportPhraseFn) []pdfdoc.Metric {
	s := rep.Summary
	return []pdfdoc.Metric{
		{Label: ph("metric_clauses"), Value: strconv.Itoa(rep.ClauseCount)},
		{Label: ph("metric_builtin"), Value: strconv.Itoa(len(rep.Builtin))},
		{Label: ph("metric_compliant"), Value: strconv.Itoa(s.Compliant)},
		{Label: ph("metric_deviating"), Value: strconv.Itoa(s.Deviating)},
		{Label: ph("metric_needs_review"), Value: strconv.Itoa(s.NeedsReview)},
		{Label: ph("metric_audit_review"), Value: strconv.Itoa(s.AuditReview)},
	}
}

// complianceReportCoverFacts 封面的鍵值區：資料時點與產出時刻分列。
func complianceReportCoverFacts(rep *ComplianceReport, ph reportPhraseFn) []pdfdoc.KV {
	m := rep.Meta
	source := ph("source_custom")
	if m.GroupSource == model.PolicyGroupSourceBuiltin {
		source = ph("source_builtin")
	}
	facts := []pdfdoc.KV{
		{Key: ph("group_version"), Value: m.GroupVersion},
		{Key: ph("group_source"), Value: source},
		{Key: ph("as_of"), Value: reportTime(m.AsOf)},
		{Key: ph("generated_at"), Value: reportTime(m.GeneratedAt)},
		{Key: ph("generated_by"), Value: m.GeneratedBy},
		{Key: ph("job_ref"), Value: m.JobRef},
	}
	if m.GroupLocale != "" {
		facts = append(facts, pdfdoc.KV{Key: ph("group_locale"), Value: m.GroupLocale})
	}
	return facts
}

// complianceReportUnmappedLine 「另有 N 項設定不在本組對照範圍內」。封面必印：
// 少了它，「12 項符合」會被讀成全系統。
func complianceReportUnmappedLine(rep *ComplianceReport, ph reportPhraseFn) string {
	return strings.ReplaceAll(ph("unmapped_line"), "{n}", strconv.Itoa(rep.Summary.Unmapped))
}

// complianceReportCoverText 封面上的敘述文字（範圍聲明與未對照數）。
func complianceReportCoverText(rep *ComplianceReport, ph reportPhraseFn) string {
	return ph("scope_statement") + "\n" + complianceReportUnmappedLine(rep, ph)
}

// complianceReportBuiltinSection 由產品承擔的條文段：標題、導言、逐條（條號、標題）。
func complianceReportBuiltinSection(rep *ComplianceReport, ph reportPhraseFn) (string, string, [][]string) {
	rows := make([][]string, 0, len(rep.Builtin))
	for _, c := range rep.Builtin {
		rows = append(rows, []string{c.ClauseNo, c.Title})
	}
	return ph("builtin_section"), ph("builtin_lead"), rows
}

// zeroMeaningVariant 零值語義與政策頁、合規對照頁同一套（逐鍵登記，未登記者為
// 「不啟用這項限制」）：保留天數的 0 是永久保留、鎖定次數的 0 是不啟用限制，
// 用一句話涵蓋全部就會說錯其中一邊。
func zeroMeaningVariant(key string) string {
	switch key {
	case PolicyRetentionAuditLogDays, PolicyRetentionSessionCommandDays, PolicyRetentionAlertDays,
		PolicyRetentionRecordingDays, PolicyRetentionCheckpointDays:
		return "retention"
	case PolicyOffsiteLocalRetentionDays:
		return "local_retention"
	case PolicyKeyCryptoperiodReminderDays:
		return "key_reminder"
	case PolicyTransportConsentTTLDays:
		return "consent_ttl"
	}
	return "disabled"
}

// reasonText 判定理由的人話（CSV 理由欄、PDF 附表與例外表共用）。
//
// 保留天數類設 0 的理由另有一句：那裡的 0 是永久保留而不是停用，偏離的原因是
// 沒有明確的保留期限。哪些鍵屬於保留天數類沿 zeroMeaningVariant 的逐鍵登記；
// 理由碼欄仍印原碼，判定本身不變。
func reasonText(r ComplianceReportRow, ph reportPhraseFn) string {
	if r.Reason == ComplianceReasonDisabled && zeroMeaningVariant(r.Key) == "retention" {
		return ph("reason_" + ComplianceReasonDisabled + "_retention")
	}
	return optionalPhrase("reason_", r.Reason, ph)
}

// zeroMeaning 值為 0 且該鍵的 0 有停用語義時，0 的意義；其餘回空字串。
func zeroMeaning(key, raw string, zeroDisables bool, ph reportPhraseFn) string {
	if !zeroDisables || raw != "0" {
		return ""
	}
	return ph("zero_" + zeroMeaningVariant(key))
}

// fillTemplate 代入詞條裡的 {name} 位置（語序與標點由各語言的詞條決定）。
func fillTemplate(template string, pairs ...string) string {
	return strings.NewReplacer(pairs...).Replace(template)
}

// displayValue 設定值的人話：開關譯成開啟／關閉，數值帶單位，0 有停用語義者
// 附上它的意義（「0 天（永久保留）」而不是「0 天」）。枚舉值原樣。
func displayValue(key, raw, unitKey string, zeroDisables bool, ph reportPhraseFn) string {
	switch raw {
	case "":
		return ""
	case "true":
		return ph("value_on")
	case "false":
		return ph("value_off")
	}
	text := raw
	if unitKey != "" {
		text = raw + " " + ph("unit_"+unitKey)
	}
	if meaning := zeroMeaning(key, raw, zeroDisables, ph); meaning != "" {
		return fillTemplate(ph("zero_value_format"), "{value}", text, "{meaning}", meaning)
	}
	return text
}

func currentText(r ComplianceReportRow, ph reportPhraseFn) string {
	return displayValue(r.Key, r.Current, r.UnitKey, r.ZeroDisables, ph)
}

// expectedText 要求值的人話，語序依語言（中文「至少 730 天」、日文「730 日以上」）。
// 參考值型的要求（待人工確認）標為參考值，不寫成「須為」。
func expectedText(r ComplianceReportRow, ph reportPhraseFn) string {
	if r.Comparator == "" {
		return ""
	}
	if r.Expected == "" {
		return ph("comparator_" + r.Comparator)
	}
	value := displayValue(r.Key, r.Expected, r.UnitKey, r.ZeroDisables, ph)
	template := "expect_" + r.Comparator
	if r.Reason == ComplianceReasonReferenceConfirmed || r.Reason == ComplianceReasonReferenceUnconfirmed {
		template = "expect_reference"
	}
	return fillTemplate(ph(template), "{value}", value)
}

// RenderComplianceReportPDF 產出報告 PDF。
func RenderComplianceReportPDF(w io.Writer, rep *ComplianceReport) error {
	ph := reportPhraseFor(rep.Meta.Language)
	doc, err := pdfdoc.New(pdfdoc.Options{
		Title:   ph("title"),
		Subject: rep.Meta.GroupName,
		Footer: pdfdoc.Footer{
			Left:   rep.Meta.JobRef,
			Center: ph("generated_at") + " " + reportTime(rep.Meta.GeneratedAt),
			Page:   ph("page_of"),
			Note:   ph("footer_integrity"),
		},
		Bullet: ph("note_bullet"),
	})
	if err != nil {
		return err
	}

	renderComplianceCover(doc, rep, ph)
	doc.NewLandscapePage()
	renderComplianceExceptions(doc, rep, ph)
	renderComplianceSelfAttested(doc, rep, ph)
	doc.NoteBlock(ph("caliber"), []string{ph("caliber_body")})
	doc.NewLandscapePage()
	renderComplianceAppendix(doc, rep, ph)
	return doc.Output(w)
}

// renderComplianceCover 第 1 頁：封面、範圍聲明、兩組摘要、由產品承擔的條文。
func renderComplianceCover(doc *pdfdoc.Doc, rep *ComplianceReport, ph reportPhraseFn) {
	doc.CoverTitle(ph("title"), rep.Meta.GroupName)
	doc.KeyValues(complianceReportCoverFacts(rep, ph))
	doc.NoteBlock(ph("scope_title"), []string{ph("scope_statement")})

	metrics := complianceReportMetrics(rep, ph)
	doc.SectionTitle(ph("summary"))
	doc.Paragraph(ph("unit_clauses"))
	doc.MetricCells(metrics[:2], 2)
	doc.Paragraph(ph("unit_settings"))
	doc.MetricCells(metrics[2:], 4)
	doc.Paragraph(complianceReportUnmappedLine(rep, ph))

	title, lead, rows := complianceReportBuiltinSection(rep, ph)
	doc.SectionTitle(title)
	doc.Paragraph(lead)
	doc.Table(pdfdoc.Table{
		Columns:   reportColumns(doc, ph, []reportColumn{{key: "col_clause_no", weight: 1}, {key: "col_clause_title", weight: 5}}),
		Rows:      rows,
		Zebra:     true,
		EmptyText: ph("builtin_empty"),
		Wrap:      true,
	})
}

// reportColumn 報告表格的一欄：欄名詞條、相對寬，以及不宜拆行的內容（設定鍵、
// 時刻）——欄寬至少要讓這些內容單行放下。鍵名是拿去和系統比對的字串，拆成兩行
// 就對不上；時刻拆開則位移會落到下一行。欄名裡最長的一個詞也要放得下（欄名
// 只在詞與詞之間折行，不把「Clause」折成「Claus／e」）。
type reportColumn struct {
	key     string
	weight  float64
	oneLine []string
}

func reportColumns(doc *pdfdoc.Doc, ph reportPhraseFn, spec []reportColumn) []pdfdoc.Column {
	weights := make([]float64, len(spec))
	mins := make([]float64, len(spec))
	for i, c := range spec {
		weights[i] = c.weight
		mins[i] = doc.TableCellWidth(append(strings.Fields(ph(c.key)), c.oneLine...)...)
	}
	widths := doc.FitColumnsMin(weights, mins)
	cols := make([]pdfdoc.Column, len(spec))
	for i, c := range spec {
		cols[i] = pdfdoc.Column{Title: ph(c.key), Width: widths[i]}
	}
	return cols
}

// reportOneLine 某一欄全部列的值（撐欄寬用）。
func reportOneLine(rows []ComplianceReportRow, pick func(ComplianceReportRow) string) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, pick(r))
	}
	return out
}

// renderComplianceExceptions 例外清單：偏離 → 待人工確認 → 待稽核判讀。
//
// 三段各有自己的欄：偏離附理由（「設為 0 等於停用」這類說明只在這裡看得到），
// 待人工確認把確認者、確認時刻、確認說明分欄列出（擠成一格會被截斷），
// 待稽核判讀只附目前值——條文沒有定值，也就沒有要求值可列。
func renderComplianceExceptions(doc *pdfdoc.Doc, rep *ComplianceReport, ph reportPhraseFn) {
	doc.SectionTitle(ph("exceptions"))
	keys := reportOneLine(rep.Rows, func(r ComplianceReportRow) string { return r.Key })
	updated := reportOneLine(rep.Rows, func(r ComplianceReportRow) string { return reportTimePtr(r.UpdatedAt) })
	confirmed := reportOneLine(rep.Rows, func(r ComplianceReportRow) string { return reportTimePtr(r.ConfirmedAt) })

	head := []reportColumn{
		{key: "col_clause_no", weight: 0.8}, {key: "col_clause_title", weight: 2.4},
		{key: "col_key", weight: 2.4, oneLine: keys}, {key: "col_current", weight: 1.6},
	}
	tail := []reportColumn{{key: "col_updated_by", weight: 1.2}, {key: "col_updated_at", weight: 2.2, oneLine: updated}}
	layouts := map[string][]reportColumn{
		ComplianceResultDeviating: append(append(append([]reportColumn{}, head...),
			reportColumn{key: "col_expected", weight: 1.6}, reportColumn{key: "col_reason_text", weight: 2.6}), tail...),
		ComplianceResultNeedsReview: append(append(append([]reportColumn{}, head...),
			reportColumn{key: "col_expected", weight: 1.6}, reportColumn{key: "col_confirmed_by", weight: 1.2},
			reportColumn{key: "col_confirmed_at", weight: 2.2, oneLine: confirmed},
			reportColumn{key: "col_confirmation_note", weight: 2.6}), tail...),
		ComplianceResultAuditReview: append(append([]reportColumn{}, head...), tail...),
	}
	cells := map[string]func(r ComplianceReportRow) string{
		"col_clause_no":         func(r ComplianceReportRow) string { return r.ClauseNo },
		"col_clause_title":      func(r ComplianceReportRow) string { return r.ClauseTitle },
		"col_key":               func(r ComplianceReportRow) string { return r.Key },
		"col_current":           func(r ComplianceReportRow) string { return currentText(r, ph) },
		"col_expected":          func(r ComplianceReportRow) string { return expectedText(r, ph) },
		"col_reason_text":       func(r ComplianceReportRow) string { return reasonText(r, ph) },
		"col_confirmed_by":      confirmedByCell(ph),
		"col_confirmed_at":      func(r ComplianceReportRow) string { return reportTimePtr(r.ConfirmedAt) },
		"col_confirmation_note": func(r ComplianceReportRow) string { return r.ConfirmationNote },
		"col_updated_by":        func(r ComplianceReportRow) string { return r.UpdatedBy },
		"col_updated_at":        func(r ComplianceReportRow) string { return reportTimePtr(r.UpdatedAt) },
	}
	for _, result := range []string{ComplianceResultDeviating, ComplianceResultNeedsReview, ComplianceResultAuditReview} {
		doc.Paragraph(ph("section_" + result))
		layout := layouts[result]
		rows := [][]string{}
		for _, r := range rep.Rows {
			if r.Result != result {
				continue
			}
			row := make([]string, len(layout))
			for i, c := range layout {
				row[i] = cells[c.key](r)
			}
			rows = append(rows, row)
		}
		doc.Table(pdfdoc.Table{Columns: reportColumns(doc, ph, layout), Rows: rows, Zebra: true,
			EmptyText: ph("none"), Wrap: true})
	}
}

// confirmedByCell 確認者欄：未確認者標「尚未確認」。
func confirmedByCell(ph reportPhraseFn) func(r ComplianceReportRow) string {
	return func(r ComplianceReportRow) string {
		if r.ConfirmedBy == "" {
			return ph("not_confirmed")
		}
		return r.ConfirmedBy
	}
}

// renderComplianceSelfAttested 由機構自行確認的條文（只列標題與備註，不判定）。
func renderComplianceSelfAttested(doc *pdfdoc.Doc, rep *ComplianceReport, ph reportPhraseFn) {
	doc.SectionTitle(ph("section_self_attested"))
	doc.Paragraph(ph("self_attested_lead"))
	rows := make([][]string, 0, len(rep.SelfAttested))
	for _, c := range rep.SelfAttested {
		rows = append(rows, []string{c.ClauseNo, c.Title, c.Note})
	}
	doc.Table(pdfdoc.Table{
		Columns: reportColumns(doc, ph, []reportColumn{{key: "col_clause_no", weight: 0.8},
			{key: "col_clause_title", weight: 4}, {key: "col_note", weight: 5}}),
		Rows: rows, Zebra: true, EmptyText: ph("none"), Wrap: true,
	})
}

// renderComplianceAppendix 附表 A：全條文逐鍵明細，列與 CSV 同一序（設定要求列，
// 其後由機構自行確認、由產品承擔各一列）。紙上的目前值與要求值用人話（帶單位與
// 0 的意義），比較方式與單位併入其中；原始值與其餘欄位在 CSV。
func renderComplianceAppendix(doc *pdfdoc.Doc, rep *ComplianceReport, ph reportPhraseFn) {
	doc.SectionTitle(ph("appendix_a"))
	doc.Paragraph(ph("appendix_a_lead"))
	cols := reportColumns(doc, ph, []reportColumn{
		{key: "col_clause_no", weight: 0.7}, {key: "col_clause_title", weight: 2.2},
		{key: "col_clause_kind", weight: 1.3},
		{key: "col_key", weight: 2.4, oneLine: reportOneLine(rep.Rows, func(r ComplianceReportRow) string { return r.Key })},
		{key: "col_result", weight: 1.4}, {key: "col_current", weight: 1.5}, {key: "col_expected", weight: 1.5},
		{key: "col_reason_text", weight: 2.2}, {key: "col_updated_by", weight: 1.1},
		{key: "col_updated_at", weight: 2.2, oneLine: reportOneLine(rep.Rows,
			func(r ComplianceReportRow) string { return reportTimePtr(r.UpdatedAt) })},
	})
	rows := make([][]string, 0, len(rep.Rows)+len(rep.SelfAttested)+len(rep.Builtin))
	for _, r := range rep.Rows {
		rows = append(rows, []string{
			r.ClauseNo, r.ClauseTitle, ph("kind_" + r.Kind), r.Key, rowResultText(r.Kind, r.Result, ph),
			currentText(r, ph), expectedText(r, ph), reasonText(r, ph),
			r.UpdatedBy, reportTimePtr(r.UpdatedAt),
		})
	}
	clauseRows := func(list []ComplianceReportClause, kind string) {
		for _, c := range list {
			rows = append(rows, []string{c.ClauseNo, c.Title, ph("kind_" + kind), "", rowResultText(kind, "", ph),
				"", "", "", "", ""})
		}
	}
	clauseRows(rep.SelfAttested, model.PolicyClauseKindSelfAttested)
	clauseRows(rep.Builtin, model.PolicyClauseKindBuiltinProtection)
	doc.Table(pdfdoc.Table{Columns: cols, Rows: rows, Zebra: true, EmptyText: ph("none"), Wrap: true})
}
