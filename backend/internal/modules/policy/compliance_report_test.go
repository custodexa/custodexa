package policy

import (
	"bytes"
	"compress/zlib"
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/custodexa/backend/internal/model"
)

// 合規報告的資料集與兩種輸出。
//
// 本檔釘兩件事：
//  1. PDF 摘要格與 CSV 明細出自同一份資料集（A 類：摘要說 2 項偏離、明細列 3 項，
//     稽核拿到的是一份自相矛盾的證據，且沒有任何一處會報錯）。
//  2. 封面帶範圍聲明，由產品承擔的條文逐條列出且措辭不宣稱「符合」「已啟用」
//     （B 類：報告把產品機制寫成合規結論，等於替機構做了它沒做的合規認定）。

var reportLanguages = []string{
	model.NotificationChannelLanguageZhTW, "en-US", "ja-JP",
}

// reportFixture 一組涵蓋全部結果型別的判定：偏離、符合、待稽核判讀、待人工確認
// （已確認）、由機構自行確認、兩條由產品承擔（另一條已自規範移除，不得列出），
// 以及一個不在本組對照範圍的鍵。另含一個真實的長設定鍵（指令流保留天數設 0，
// 即永久保留而判偏離），且每個鍵都有最後變更者與時刻——稽核看的例外表上最長的
// 那幾格（鍵名、帶位移的時刻、確認說明）都要在 PDF 上出現。
func reportFixture(t *testing.T, lang string) *ComplianceReport {
	t.Helper()
	group := testGroup("g", true)
	group.Name = "內部基準"
	group.Locale = model.NotificationChannelLanguageZhTW
	clauses := []model.PolicyClause{
		testClause("g", "1", model.PolicyClauseKindSetting, ""),
		testClause("g", "2", model.PolicyClauseKindSetting, ""),
		testClause("g", "3", model.PolicyClauseKindSetting, ""),
		testClause("g", "4", model.PolicyClauseKindSetting, ""),
		testClause("g", "5", model.PolicyClauseKindSelfAttested, ""),
		{GroupCode: "g", ClauseNo: "6", Title: "會話全程錄影", Kind: model.PolicyClauseKindBuiltinProtection},
		{GroupCode: "g", ClauseNo: "7", Title: "指令逐筆稽核", Kind: model.PolicyClauseKindBuiltinProtection},
		{GroupCode: "g", ClauseNo: "8", Title: "已移除的條文", Kind: model.PolicyClauseKindBuiltinProtection,
			RemovedInVersion: "2.0"},
		testClause("g", "9", model.PolicyClauseKindSetting, ""),
	}
	controls := []model.PolicyClauseControl{
		testControl("g", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "14", false),
		testControl("g", "2", testKeyLockout, model.PolicyControlComparatorMax, "10", false),
		testControl("g", "3", testKeyTransport, model.PolicyControlComparatorReview, "", false),
		testControl("g", "4", testKeyClipboard, model.PolicyControlComparatorEquals, "false", true),
		testControl("g", "9", PolicyRetentionSessionCommandDays, model.PolicyControlComparatorMin, "730", false),
	}
	confirmedAt := time.Date(2026, 9, 20, 3, 4, 0, 0, time.UTC)
	annotations := []model.PolicyClauseAnnotation{
		{GroupCode: "g", ClauseNo: "4", ConfirmedBy: "alice", ConfirmedAt: &confirmedAt,
			ConfirmationNote: "剪貼簿依內規放行"},
		{GroupCode: "g", ClauseNo: "5", Note: "由資安室每季檢視"},
	}
	defs := append(testComplianceDefs(), *findDef(PolicyRetentionSessionCommandDays))
	changes := map[string]PolicyKeyChange{}
	for _, d := range defs {
		changes[d.Key] = PolicyKeyChange{UpdatedBy: "bob", UpdatedAt: &reportFixtureChangedAt}
	}
	snap := BuildSnapshot(defs, map[string]string{PolicyRetentionSessionCommandDays: "0"}, changes,
		[]model.PolicyGroup{group}, clauses, controls, annotations)
	return BuildComplianceReport(snap, group, clauses, annotations, ComplianceReportMeta{
		GeneratedBy: "auditor01",
		GeneratedAt: time.Date(2026, 9, 29, 1, 12, 0, 0, time.UTC),
		Language:    lang,
		JobRef:      "job-1042",
	})
}

// reportFixtureChangedAt fixture 裡每個鍵的最後變更時刻。
var reportFixtureChangedAt = time.Date(2026, 9, 18, 5, 6, 0, 0, time.UTC)

func readReportCSV(t *testing.T, raw []byte) [][]string {
	t.Helper()
	body := bytes.TrimPrefix(raw, []byte("\xEF\xBB\xBF"))
	if len(body) == len(raw) {
		t.Fatal("CSV 缺 UTF-8 BOM，試算表直開會亂碼")
	}
	r := csv.NewReader(bytes.NewReader(body))
	r.Comment = '#'
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("解析 CSV: %v", err)
	}
	return rows
}

// TestComplianceReportOutputsSameSource PDF 摘要格＝CSV 依結果欄分組的列數，
// 本組條文數＝CSV 出現的相異條號數；三種語言各跑一次。
func TestComplianceReportOutputsSameSource(t *testing.T) {
	for _, lang := range reportLanguages {
		rep := reportFixture(t, lang)
		ph := reportPhraseFor(lang)

		var csvBuf bytes.Buffer
		if err := WriteComplianceReportCSV(&csvBuf, rep); err != nil {
			t.Fatalf("[%s] 寫 CSV: %v", lang, err)
		}
		rows := readReportCSV(t, csvBuf.Bytes())
		header := rows[0]
		col := map[string]int{}
		for i, h := range header {
			col[h] = i
		}
		resultCol, ok := col[ph("col_result")]
		if !ok {
			t.Fatalf("[%s] CSV 缺結果欄：%v", lang, header)
		}
		clauseCol := col[ph("col_clause_no")]
		byResult := map[string]int{}
		clauseNos := map[string]bool{}
		for _, r := range rows[1:] {
			byResult[r[resultCol]]++
			clauseNos[r[clauseCol]] = true
		}

		want := map[string]string{
			ph("metric_clauses"):      strconv.Itoa(len(clauseNos)),
			ph("metric_builtin"):      strconv.Itoa(byResult[ph("result_builtin")]),
			ph("metric_compliant"):    strconv.Itoa(byResult[ph("result_compliant")]),
			ph("metric_deviating"):    strconv.Itoa(byResult[ph("result_deviating")]),
			ph("metric_needs_review"): strconv.Itoa(byResult[ph("result_needs_review")]),
			ph("metric_audit_review"): strconv.Itoa(byResult[ph("result_review")]),
		}
		metrics := complianceReportMetrics(rep, ph)
		if len(metrics) != len(want) {
			t.Fatalf("[%s] 摘要格數 %d，want %d", lang, len(metrics), len(want))
		}
		for _, m := range metrics {
			if want[m.Label] != m.Value {
				t.Errorf("[%s] 摘要「%s」= %s，CSV 列數 = %s", lang, m.Label, m.Value, want[m.Label])
			}
			if m.Value == "0" {
				t.Errorf("[%s] 摘要「%s」為 0：fixture 未涵蓋該結果，本測試只驗到零", lang, m.Label)
			}
		}
		if rep.Summary.Unmapped == 0 {
			t.Errorf("[%s] fixture 應有不在本組對照範圍的鍵", lang)
		}

		var pdfBuf bytes.Buffer
		if err := RenderComplianceReportPDF(&pdfBuf, rep); err != nil {
			t.Fatalf("[%s] 產 PDF: %v", lang, err)
		}
		if !bytes.HasPrefix(pdfBuf.Bytes(), []byte("%PDF-")) {
			t.Fatalf("[%s] 產物不是 PDF", lang)
		}
	}
}

// allowedZeroMeaningWord 措辭禁詞的逐條例外（語言|詞條 → 允許的那一個詞）。
//
// 這幾條說的是某個設定鍵在 0 時的意義（保留天數 0＝永久保留、金鑰提醒 0＝不提醒），
// 以及保留天數設 0 時的偏離理由，與政策頁、合規對照頁同一句話；不是在說報告本身的
// 保管或完成通知。只放行這幾條的這一個詞，其餘詞條照舊不得出現。
var allowedZeroMeaningWord = map[string]string{
	model.NotificationChannelLanguageZhTW + "|zero_retention": "永久",
	"en-US|zero_retention":    "forever",
	"ja-JP|zero_retention":    "無期限",
	"ja-JP|zero_key_reminder": "通知",
	model.NotificationChannelLanguageZhTW + "|reason_disabled_by_zero_retention": "永久",
	"en-US|reason_disabled_by_zero_retention":                                    "forever",
	"ja-JP|reason_disabled_by_zero_retention":                                    "無期限",
}

// TestComplianceReportCoverAndBuiltinWording 封面有範圍聲明且分開標資料時點與
// 產出時刻；由產品承擔的條文逐條列條號與標題（已移除者不列），該段與 CSV 對應列
// 不出現「符合」「已啟用」；報告詞庫不含回推、完成通知與長期保管的說法。
func TestComplianceReportCoverAndBuiltinWording(t *testing.T) {
	forbiddenInBuiltin := map[string][]string{
		model.NotificationChannelLanguageZhTW: {"符合", "已啟用"},
		"en-US":                               {"complian", "enabled"},
		"ja-JP":                               {"適合", "有効"},
	}
	// 三語覆蓋同一組語義，依序為：期間回推、完成通知、期間、長期／永久保存。
	// 英文以字首比對（notif、retroactiv、perpetu）涵蓋詞形變化。
	forbiddenAnywhere := map[string][]string{
		model.NotificationChannelLanguageZhTW: {
			"回推", "追溯", "通知", "期間", "永久", "長期", "永遠", "無限期",
		},
		"en-US": {
			"backfill", "retroactiv", "notif", "period",
			"permanent", "long-term", "long term", "forever", "indefinite", "perpetu",
		},
		"ja-JP": {
			"遡", "さかのぼ", "通知", "お知らせ", "期間",
			"永続", "永久", "長期", "無期限", "恒久",
		},
	}
	for _, lang := range reportLanguages {
		rep := reportFixture(t, lang)
		ph := reportPhraseFor(lang)

		facts := complianceReportCoverFacts(rep, ph)
		labels := map[string]bool{}
		for _, kv := range facts {
			labels[kv.Key] = true
		}
		for _, k := range []string{"as_of", "generated_at", "generated_by", "job_ref", "group_version", "group_source"} {
			if !labels[ph(k)] {
				t.Errorf("[%s] 封面缺「%s」", lang, ph(k))
			}
		}
		if statement := ph("scope_statement"); statement == "scope_statement" || statement == "" {
			t.Errorf("[%s] 範圍聲明詞條缺漏", lang)
		}
		if !strings.Contains(complianceReportCoverText(rep, ph), ph("scope_statement")) {
			t.Errorf("[%s] 封面未印範圍聲明", lang)
		}

		title, lead, rows := complianceReportBuiltinSection(rep, ph)
		if len(rows) != 2 {
			t.Fatalf("[%s] 產品承擔段應逐條列 2 條（已移除者不列），實得 %v", lang, rows)
		}
		if rows[0][0] != "6" || rows[0][1] != "會話全程錄影" || rows[1][0] != "7" {
			t.Errorf("[%s] 產品承擔段未列條號與標題：%v", lang, rows)
		}
		section := strings.ToLower(title + "\n" + lead + "\n" + ph("result_builtin"))
		for _, word := range forbiddenInBuiltin[lang] {
			if strings.Contains(section, strings.ToLower(word)) {
				t.Errorf("[%s] 產品承擔段出現「%s」：%q", lang, word, section)
			}
		}

		for key, value := range complianceReportLexicon(lang) {
			for _, word := range forbiddenAnywhere[lang] {
				if allowedZeroMeaningWord[lang+"|"+key] == word {
					continue
				}
				if strings.Contains(strings.ToLower(value), strings.ToLower(word)) {
					t.Errorf("[%s] 詞條 %s 出現「%s」：%q", lang, key, word, value)
				}
			}
		}
	}
}

// zeroMeaningOracle 零值語義的預期譯文：與政策頁、合規對照頁同一套說法
// （前端 `policyZero.*` 與 `ZERO_MEANING_KEYS`）。報告若另創一種說法，同一個 0
// 在畫面與紙上就會被說成兩件事。
var zeroMeaningOracle = map[string]map[string]string{
	model.NotificationChannelLanguageZhTW: {
		"retention": "永久保留", "localRetention": "不提前清理", "keyReminder": "不提醒",
		"consentTtl": "永不過期", "disabled": "不啟用這項限制",
	},
	"en-US": {
		"retention": "kept forever", "localRetention": "no early cleanup", "keyReminder": "no reminder",
		"consentTtl": "never expires", "disabled": "this limit is off",
	},
	"ja-JP": {
		"retention": "無期限保存", "localRetention": "早期削除なし", "keyReminder": "通知しない",
		"consentTtl": "失効しない", "disabled": "この制限を使わない",
	},
}

// zeroMeaningVariantOracle 鍵 → 零值語義（未列者為 disabled）。
var zeroMeaningVariantOracle = map[string]string{
	PolicyRetentionAuditLogDays:       "retention",
	PolicyRetentionSessionCommandDays: "retention",
	PolicyRetentionAlertDays:          "retention",
	PolicyRetentionRecordingDays:      "retention",
	PolicyRetentionCheckpointDays:     "retention",
	PolicyOffsiteLocalRetentionDays:   "localRetention",
	PolicyKeyCryptoperiodReminderDays: "keyReminder",
	PolicyTransportConsentTTLDays:     "consentTtl",
}

// disabledByZeroOracle 「設為 0 等於停用」的偏離理由（沿判定理由的既有譯文）。
var disabledByZeroOracle = map[string]string{
	model.NotificationChannelLanguageZhTW: "設為 0 等於停用，未達要求",
	"en-US":                               "0 turns this off, which does not meet the requirement",
	"ja-JP":                               "0 は無効化を意味し、要求を満たしません",
}

// disabledByZeroRetentionOracle 保留天數類設 0 的偏離理由：0 是永久保留、不是停用，
// 偏離的真因是沒有明確的保留期限（與合規對照頁 `verdictReason.disabled_by_zero_retention`
// 同一句）。
var disabledByZeroRetentionOracle = map[string]string{
	model.NotificationChannelLanguageZhTW: "設為 0 表示永久保留，未設定明確的保留期限；這一組要求設定明確期限",
	"en-US":                               "0 means records are kept forever with no set retention limit; this group requires a set limit",
	"ja-JP":                               "0 は無期限保存を意味し、明確な保存期限がありません。このグループは期限の設定を求めています",
}

// TestComplianceReportPdfReadsInFull 稽核看的 PDF 上，規格要求呈現的資訊整格可讀：
//   - 任何一格都不被裁成刪節號（確認說明、帶位移的時刻、長設定鍵）；
//   - 設定鍵整個出現在同一行（鍵名是拿去比對系統的字串，被拆開就對不上）；
//   - 零值有停用語義的鍵印出它的意義與偏離理由，不印成「0 天」了事——
//     讀者會把永久保留讀成只留 0 天；
//   - 標點依報告語言：英文不出現全形標點，日文的要求值依日文語序。
//
// CSV 另有零值意義與理由兩欄，對所有零值有停用語義的鍵一體適用。
func TestComplianceReportPdfReadsInFull(t *testing.T) {
	zeroDisplay := map[string]string{
		model.NotificationChannelLanguageZhTW: "0 天（永久保留）",
		"en-US":                               "0 days (kept forever)",
		"ja-JP":                               "0 日（無期限保存）",
	}
	minDisplay := map[string]string{
		model.NotificationChannelLanguageZhTW: "至少 730 天",
		"en-US":                               "At least 730 days",
		"ja-JP":                               "730 日以上",
	}
	for _, lang := range reportLanguages {
		t.Run("fixture/"+lang, func(t *testing.T) {
			rep := reportFixture(t, lang)
			lines := renderReportPDFLines(t, rep)
			assertNoEllipsis(t, lines)
			joined := stripReportSpace(strings.Join(lines, ""))

			confirmedAt := time.Date(2026, 9, 20, 3, 4, 0, 0, time.UTC)
			for _, want := range []string{"alice", reportTime(confirmedAt), "剪貼簿依內規放行",
				zeroDisplay[lang], disabledByZeroRetentionOracle[lang], minDisplay[lang]} {
				if !strings.Contains(joined, stripReportSpace(want)) {
					t.Errorf("PDF 缺「%s」", want)
				}
			}
			// 保留天數設 0 不得再印成「等於停用」：0 是永久保留，不是停用
			if strings.Contains(joined, stripReportSpace(disabledByZeroOracle[lang])) {
				t.Errorf("保留天數設 0 的理由仍印「%s」", disabledByZeroOracle[lang])
			}
			// 最後變更時刻（帶位移）：附表 A 每列一次，例外表的每一列再一次
			exceptions := 0
			for _, r := range rep.Rows {
				if r.Result == ComplianceResultDeviating || r.Result == ComplianceResultNeedsReview ||
					r.Result == ComplianceResultAuditReview {
					exceptions++
				}
			}
			stamp := stripReportSpace(reportTime(reportFixtureChangedAt))
			if got, want := strings.Count(joined, stamp), len(rep.Rows)+exceptions; got < want {
				t.Errorf("帶位移的最後變更時刻「%s」只出現 %d 次，want ≥ %d", stamp, got, want)
			}
			if !lineContains(lines, PolicyRetentionSessionCommandDays) {
				t.Errorf("設定鍵 %s 沒有整個出現在同一行", PolicyRetentionSessionCommandDays)
			}
			if lang == "en-US" {
				for _, ln := range lines {
					if i := strings.IndexAny(ln, "：（）、，。；"); i >= 0 {
						t.Errorf("英文報告出現全形標點：%q", ln)
					}
				}
			}
		})
	}

	// 所有零值有停用語義的鍵：設 0 而組要求非零時，CSV 的零值意義與理由兩欄、
	// PDF 的目前值都說出它的意義
	var zeroKeys []string
	for _, d := range policyDefs {
		if d.ZeroDisables && d.Type == PolicyTypeInt {
			zeroKeys = append(zeroKeys, d.Key)
		}
	}
	if len(zeroKeys) < 10 {
		t.Fatalf("零值有停用語義的鍵只有 %d 個，前提不成立", len(zeroKeys))
	}
	for _, lang := range reportLanguages {
		t.Run("zero_disables_keys/"+lang, func(t *testing.T) {
			rep := zeroDisablesReport(t, zeroKeys, lang)
			ph := reportPhraseFor(lang)
			var csvBuf bytes.Buffer
			if err := WriteComplianceReportCSV(&csvBuf, rep); err != nil {
				t.Fatalf("寫 CSV: %v", err)
			}
			rows := readReportCSV(t, csvBuf.Bytes())
			col := map[string]int{}
			for i, h := range rows[0] {
				col[h] = i
			}
			keyCol := col[ph("col_key")]
			meaningCol, okMeaning := col[ph("col_zero_meaning")]
			reasonCol, okReason := col[ph("col_reason_text")]
			if !okMeaning || !okReason {
				t.Fatalf("CSV 缺零值意義或理由欄：%v", rows[0])
			}
			seen, retentionSeen, otherSeen := 0, 0, 0
			for _, r := range rows[1:] {
				if r[keyCol] == "" {
					continue
				}
				seen++
				variant := zeroMeaningVariantOracle[r[keyCol]]
				if variant == "" {
					variant = "disabled"
				}
				if want := zeroMeaningOracle[lang][variant]; r[meaningCol] != want {
					t.Errorf("%s 的零值意義 = %q，want %q", r[keyCol], r[meaningCol], want)
				}
				// 保留天數類用專屬理由，其餘零值停用鍵維持原句（雙向各至少一個鍵）
				wantReason := disabledByZeroOracle[lang]
				if variant == "retention" {
					wantReason = disabledByZeroRetentionOracle[lang]
					retentionSeen++
				} else {
					otherSeen++
				}
				if r[reasonCol] != wantReason {
					t.Errorf("%s 的理由 = %q，want %q", r[keyCol], r[reasonCol], wantReason)
				}
			}
			if seen != len(zeroKeys) {
				t.Fatalf("CSV 設定列 %d，want %d", seen, len(zeroKeys))
			}
			if retentionSeen == 0 || otherSeen == 0 {
				t.Fatalf("理由兩型須各至少一鍵：保留天數類 %d、其餘 %d", retentionSeen, otherSeen)
			}

			lines := renderReportPDFLines(t, rep)
			assertNoEllipsis(t, lines)
			joined := stripReportSpace(strings.Join(lines, ""))
			for _, key := range zeroKeys {
				if !lineContains(lines, key) {
					t.Errorf("設定鍵 %s 沒有整個出現在同一行", key)
				}
				variant := zeroMeaningVariantOracle[key]
				if variant == "" {
					variant = "disabled"
				}
				if !strings.Contains(joined, stripReportSpace(zeroMeaningOracle[lang][variant])) {
					t.Errorf("PDF 缺 %s 的零值意義", key)
				}
			}
			for _, want := range []string{disabledByZeroRetentionOracle[lang], disabledByZeroOracle[lang]} {
				if !strings.Contains(joined, stripReportSpace(want)) {
					t.Errorf("PDF 缺理由「%s」", want)
				}
			}
		})
	}
}

// zeroDisablesReport 每個零值有停用語義的鍵各一條條文，現值皆 0、要求皆非零。
func zeroDisablesReport(t *testing.T, keys []string, lang string) *ComplianceReport {
	t.Helper()
	group := testGroup("z", true)
	var clauses []model.PolicyClause
	var controls []model.PolicyClauseControl
	values := map[string]string{}
	defs := make([]PolicyDef, 0, len(keys))
	for i, key := range keys {
		no := strconv.Itoa(i + 1)
		clauses = append(clauses, testClause("z", no, model.PolicyClauseKindSetting, ""))
		comparator := model.PolicyControlComparatorMax
		if findDef(key).Direction == DirectionMin {
			comparator = model.PolicyControlComparatorMin
		}
		controls = append(controls, testControl("z", no, key, comparator, "1", false))
		values[key] = "0"
		defs = append(defs, *findDef(key))
	}
	snap := BuildSnapshot(defs, values, nil, []model.PolicyGroup{group}, clauses, controls, nil)
	rep := BuildComplianceReport(snap, group, clauses, nil, ComplianceReportMeta{
		GeneratedBy: "auditor01", GeneratedAt: time.Date(2026, 9, 29, 1, 12, 0, 0, time.UTC),
		Language: lang, JobRef: "job-1043",
	})
	if rep.Summary.Deviating != len(keys) {
		t.Fatalf("前提：%d 個鍵設 0 應全數偏離，實得 %d", len(keys), rep.Summary.Deviating)
	}
	return rep
}

func renderReportPDFLines(t *testing.T, rep *ComplianceReport) []string {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderComplianceReportPDF(&buf, rep); err != nil {
		t.Fatalf("產 PDF: %v", err)
	}
	lines := pdfTextLines(buf.Bytes())
	if len(lines) < 20 {
		t.Fatalf("PDF 只抽回 %d 行文字，抽取失效", len(lines))
	}
	return lines
}

func assertNoEllipsis(t *testing.T, lines []string) {
	t.Helper()
	for _, ln := range lines {
		if strings.Contains(ln, "…") {
			t.Errorf("PDF 有被裁掉的格：%q", ln)
		}
	}
}

func lineContains(lines []string, s string) bool {
	for _, ln := range lines {
		if strings.Contains(ln, s) {
			return true
		}
	}
	return false
}

func stripReportSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// pdfTextLines 解壓每個內容串流，依序取出 `Td (…)Tj` 的文字並由 UTF-16BE 解回。
// 與 pdfdoc 的測試同一套抽法（跨套件無法共用測試檔）：讀者在頁面上看到的每一行。
func pdfTextLines(pdf []byte) []string {
	var lines []string
	const begin, end = "\nstream\n", "\nendstream"
	for i := 0; ; {
		s := bytes.Index(pdf[i:], []byte(begin))
		if s < 0 {
			return lines
		}
		s += i + len(begin)
		e := bytes.Index(pdf[s:], []byte(end))
		if e < 0 {
			return lines
		}
		e += s
		i = e
		zr, err := zlib.NewReader(bytes.NewReader(pdf[s:e]))
		if err != nil {
			continue
		}
		plain, rerr := io.ReadAll(zr)
		_ = zr.Close()
		if rerr != nil || !bytes.Contains(plain, []byte("BT ")) {
			continue
		}
		lines = append(lines, pdfTextOperands(plain)...)
	}
}

func pdfTextOperands(plain []byte) []string {
	var out []string
	marker := []byte("Td (")
	for p := 0; ; {
		m := bytes.Index(plain[p:], marker)
		if m < 0 {
			return out
		}
		p += m + len(marker)
		var raw []byte
		for p < len(plain) {
			c := plain[p]
			p++
			if c == '\\' && p < len(plain) {
				n := plain[p]
				p++
				if n == 'r' {
					n = '\r'
				}
				raw = append(raw, n)
				continue
			}
			if c == ')' {
				break
			}
			raw = append(raw, c)
		}
		if !bytes.HasPrefix(plain[p:], []byte("Tj")) {
			continue
		}
		u := make([]uint16, 0, len(raw)/2)
		for j := 0; j+1 < len(raw); j += 2 {
			u = append(u, uint16(raw[j])<<8|uint16(raw[j+1]))
		}
		out = append(out, string(utf16.Decode(u)))
	}
}
