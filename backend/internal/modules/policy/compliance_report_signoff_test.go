package policy

import (
	"bytes"
	"encoding/csv"
	"strconv"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// signoffReportScenario spec 的共用情境：09-01 起開啟；09-18、09-25、10-02 補簽；
// 10-06 至 10-09 未簽；其餘到 10-09 準時。signTenth 時 10-10 已準時簽核（未到期）
func signoffReportScenario(t *testing.T, signTenth bool) *SignoffRecord {
	t.Helper()
	signs := signAll("2026-09-11", "2026-10-05")
	signs["2026-09-18"] = signoffSign{late: true, signer: "auditor01", reason: "=HYPERLINK(\"http://x\")"}
	signs["2026-09-25"] = signoffSign{late: true, signer: "auditor01", reason: "系統升級停機，隔日補簽"}
	signs["2026-10-02"] = signoffSign{late: true, signer: "mia", reason: "連假期間無人值守"}
	if signTenth {
		// 10-10 的準時期限是 10-12 00:00；於今天 09:05 簽核，已簽但未到期
		signs["2026-10-10"] = signoffSign{signer: "auditor01"}
	}
	rec := buildSignoffRecord(t, enabledFrom(t, "2026-09-01"), signs, true)
	for i := range rec.Days {
		if rec.Days[i].Date == "2026-09-18" {
			rec.Days[i].ReviewNote = "@SUM(1,1)"
		}
	}
	return rec
}

// signoffReport 以 PCI 組的 10.4.1 要求與同一份運作紀錄建判定與報告
func signoffReport(t *testing.T, rec *SignoffRecord, lang string) *ComplianceReport {
	t.Helper()
	group := testGroup("pci", true)
	group.Source = model.PolicyGroupSourceBuiltin
	clauses := []model.PolicyClause{{GroupCode: "pci", ClauseNo: "10.4.1", Title: "每日審閱簽核", Kind: model.PolicyClauseKindSetting}}
	controls := []model.PolicyClauseControl{testControl("pci", "10.4.1", PolicyDailyReviewEnabled,
		model.PolicyControlComparatorSignoffRecord, "true", false)}
	defs := []PolicyDef{*findDef(PolicyDailyReviewEnabled)}
	values := map[string]string{PolicyDailyReviewEnabled: "true"}
	snap := BuildSnapshotWithSignoff(defs, values, nil, []model.PolicyGroup{group}, clauses, controls, nil, rec)
	return BuildComplianceReportWithSignoff(snap, group, clauses, nil, ComplianceReportMeta{
		GeneratedBy: "auditor01", GeneratedAt: signoffAsOf(t), Language: lang, JobRef: "job-2001",
	}, rec)
}

func dailyReviewsCSVRows(t *testing.T, days []SignoffDay) (map[string]int, [][]string) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteDailyReviewsCSV(&buf, days); err != nil {
		t.Fatal(err)
	}
	body := bytes.TrimPrefix(buf.Bytes(), []byte("\xEF\xBB\xBF"))
	if len(body) == buf.Len() {
		t.Fatal("daily_reviews.csv 缺 BOM")
	}
	rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	return col, rows[1:]
}

// TestComplianceReportSignoffSectionMatchesCSV 擋：PDF 段落數字與 CSV、與合規對照頁三者
// 不一致；或把昨日已簽算進分子而無法對帳。
func TestComplianceReportSignoffSectionMatchesCSV(t *testing.T) {
	for _, lang := range reportLanguages {
		t.Run(lang, func(t *testing.T) {
			ph := reportPhraseFor(lang)
			var pdfTexts []string
			for _, signTenth := range []bool{false, true} {
				rec := signoffReportScenario(t, signTenth)
				rep := signoffReport(t, rec, lang)
				if rep.Signoff == nil || rep.Signoff.Result != ComplianceResultDeviating ||
					rep.Signoff.Reason != ComplianceReasonSignoffUnsignedDays {
					t.Fatalf("判定段 %+v, want 偏離／signoff_unsigned_days", rep.Signoff)
				}
				// 合規對照頁看到的那一份（判定上的運作紀錄）與報告同一份
				for _, r := range rep.Rows {
					if r.Key == PolicyDailyReviewEnabled && r.Result != rep.Signoff.Result {
						t.Errorf("報告列結果 %s 與段落 %s 不同", r.Result, rep.Signoff.Result)
					}
				}

				lines := renderReportPDFLines(t, rep)
				assertNoEllipsis(t, lines)
				joined := stripReportSpace(strings.Join(lines, ""))
				counts := fillTemplate(ph("signoff_counts"), "{required}", "29", "{signed}", "25",
					"{rate}", "86%", "{late}", "3", "{unsigned}", "4")
				for _, want := range []string{"2026-09-11", "2026-10-10", counts, ph("signoff_no_rewrite")} {
					if !strings.Contains(joined, stripReportSpace(want)) {
						t.Errorf("signTenth=%v PDF 缺「%s」", signTenth, want)
					}
				}
				pdfTexts = append(pdfTexts, counts)

				col, rows := dailyReviewsCSVRows(t, rec.Days)
				if len(rows) != 30 {
					t.Fatalf("CSV %d 列, want 30", len(rows))
				}
				byStatus := map[string]int{}
				counted := 0
				for _, r := range rows {
					if r[col["counts_toward_stats"]] != "true" {
						continue
					}
					counted++
					byStatus[r[col["status"]]]++
				}
				if counted != rec.Required || byStatus["on_time"] != rec.OnTime || byStatus["late"] != rec.Late ||
					byStatus["unsigned"] != rec.Unsigned {
					t.Errorf("CSV 計入列 %d（%v）與 PDF 應簽 %d 準時 %d 補簽 %d 未簽 %d 對不上",
						counted, byStatus, rec.Required, rec.OnTime, rec.Late, rec.Unsigned)
				}
				for _, r := range rows {
					if r[col["review_date"]] != "2026-10-10" {
						continue
					}
					wantStatus := "not_due"
					if signTenth {
						wantStatus = "on_time"
					}
					if r[col["status"]] != wantStatus || r[col["counts_toward_stats"]] != "false" {
						t.Errorf("10-10 列 %s／%s, want %s／false", r[col["status"]], r[col["counts_toward_stats"]], wantStatus)
					}
				}
			}
			if pdfTexts[0] != pdfTexts[1] {
				t.Errorf("10-10 已簽與未簽兩案的 PDF 數字不同：%q vs %q", pdfTexts[0], pdfTexts[1])
			}
		})
	}

	t.Run("CSV 公式注入轉義：延遲原因與備註", func(t *testing.T) {
		col, rows := dailyReviewsCSVRows(t, signoffReportScenario(t, false).Days)
		for _, r := range rows {
			if r[col["review_date"]] != "2026-09-18" {
				continue
			}
			if r[col["delay_reason"]] != "'=HYPERLINK(\"http://x\")" || r[col["note"]] != "'@SUM(1,1)" {
				t.Errorf("延遲原因 %q 備註 %q, want 前置單引號", r[col["delay_reason"]], r[col["note"]])
			}
			return
		}
		t.Fatal("CSV 沒有 09-18")
	})

	t.Run("推定日與期間不足的說法", func(t *testing.T) {
		ph := reportPhraseFor(model.NotificationChannelLanguageZhTW)
		rec := buildSignoffRecord(t, enabledFrom(t, "2026-10-08"), signAll("2026-10-08", "2026-10-09"), true)
		lines := renderReportPDFLines(t, signoffReport(t, rec, model.NotificationChannelLanguageZhTW))
		joined := stripReportSpace(strings.Join(lines, ""))
		want := fillTemplate(ph("signoff_insufficient"), "{since}", "2026-10-08", "{days}", "3", "{signed}", "2")
		if !strings.Contains(joined, stripReportSpace(want)) {
			t.Errorf("期間不足時 PDF 缺「%s」", want)
		}
		rec.InferredDays = 4
		lines = renderReportPDFLines(t, signoffReport(t, rec, model.NotificationChannelLanguageZhTW))
		if !strings.Contains(stripReportSpace(strings.Join(lines, "")),
			stripReportSpace(fillTemplate(ph("signoff_inferred"), "{n}", strconv.Itoa(4)))) {
			t.Error("推定日 > 0 時 PDF 未印推定說明")
		}
	})

	// 擋：資料時點與產出時刻以伺服器時區（容器多為 UTC）印出，與同一份報告裡
	// 以業務時區寫的統計範圍、逐日表對不起來；且只印位移不印時區名
	t.Run("資料時點與產出時刻以業務時區標明", func(t *testing.T) {
		rep := signoffReport(t, signoffReportScenario(t, false), model.NotificationChannelLanguageZhTW)
		if rep.Meta.Timezone != "Asia/Taipei" {
			t.Fatalf("Meta.Timezone %q, want 取自運作紀錄的 Asia/Taipei", rep.Meta.Timezone)
		}
		joined := stripReportSpace(strings.Join(renderReportPDFLines(t, rep), ""))
		// signoffAsOf＝台北 2026-10-11 12:00（UTC 04:00）
		want := stripReportSpace("2026-10-11 12:00:00 (Asia/Taipei, UTC+08:00)")
		if n := strings.Count(joined, want); n < 3 {
			t.Errorf("業務時區時刻「%s」出現 %d 次，want ≥ 3（封面資料時點、封面產出時刻、頁尾、段落資料時點）", want, n)
		}
		if strings.Contains(joined, stripReportSpace("04:00:00 (UTC+00:00)")) {
			t.Error("仍有以 UTC 印出的資料時點或產出時刻")
		}
		if got := reportTime(signoffAsOf(t), ""); strings.Contains(got, "Asia/Taipei") {
			t.Errorf("未給時區時不該冒出時區名：%q", got)
		}
		if got := reportTime(signoffAsOf(t), "No/Such_Zone"); strings.Contains(got, "No/Such_Zone") {
			t.Errorf("載不到的時區不該照印：%q", got)
		}
	})

	// 擋：準時列全數列出時仍印「其餘準時 0 列未列出」
	t.Run("準時列沒有省略時不印省略句", func(t *testing.T) {
		for _, lang := range reportLanguages {
			ph := reportPhraseFor(lang)
			// 省略句的固定字面（{n} 與 {total} 之間那段）：只有印了這句才會出現
			tpl := ph("signoff_excerpt_more")
			marker := stripReportSpace(tpl[strings.Index(tpl, "{n}")+len("{n}") : strings.Index(tpl, "{total}")])
			full := stripReportSpace(strings.Join(renderReportPDFLines(t,
				signoffReport(t, signoffReportScenario(t, false), lang)), ""))
			if !strings.Contains(full, marker) {
				t.Errorf("%s 有省略時缺省略句（其餘準時 17 列）", lang)
			}
			rec := buildSignoffRecord(t, enabledFrom(t, "2026-10-08"), signAll("2026-10-08", "2026-10-09"), true)
			short := stripReportSpace(strings.Join(renderReportPDFLines(t, signoffReport(t, rec, lang)), ""))
			if strings.Contains(short, marker) {
				t.Errorf("%s 沒有省略卻印了「其餘 0 列」", lang)
			}
		}
	})

	t.Run("取不到紀錄時不印數字", func(t *testing.T) {
		ph := reportPhraseFor(model.NotificationChannelLanguageZhTW)
		rep := signoffReport(t, nil, model.NotificationChannelLanguageZhTW)
		if rep.Signoff == nil || rep.Signoff.Reason != ComplianceReasonSignoffSourceUnavailable {
			t.Fatalf("段落 %+v", rep.Signoff)
		}
		joined := stripReportSpace(strings.Join(renderReportPDFLines(t, rep), ""))
		if !strings.Contains(joined, stripReportSpace(ph("signoff_unavailable"))) {
			t.Error("PDF 未說明取不到紀錄")
		}
		if strings.Contains(joined, stripReportSpace(ph("signoff_range"))) {
			t.Error("取不到紀錄卻印了統計範圍")
		}
	})
}
