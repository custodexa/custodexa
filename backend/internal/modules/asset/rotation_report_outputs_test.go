package asset

import (
	"bytes"
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 三種輸出同源。稽核最不能接受的是同一份報告的 PDF 與 CSV 對不上數字，
// 而那種錯誤在畫面上完全看不出來。

// mixedReport 六桶俱全的一份報告。
func mixedReport(t *testing.T) *RotationReport {
	t.Helper()
	f := newReportFixture(t)
	f.global = 90
	asOf := mustTime(t, "2026-09-02T00:00:00Z")
	a := f.asset(t, "核心系統-01")

	compliant := f.account(t, a.ID, "compliant")
	f.success(t, compliant, asOf.Add(-10*24*time.Hour))
	due := f.account(t, a.ID, "due-soon")
	f.success(t, due, asOf.Add(-70*24*time.Hour))
	over := f.account(t, a.ID, "overdue")
	f.success(t, over, asOf.Add(-120*24*time.Hour))
	f.account(t, a.ID, "no-record")
	unver := f.account(t, a.ID, "unverified")
	require.NoError(t, f.db.Create(&model.ChangeSecretCandidate{
		AccountID: unver.ID, AssetID: a.ID, SecretType: model.ChangeSecretTypePassword,
	}).Error)

	// 帳號名以公式起頭字元開頭：一併驗 CSV 的轉義（帳號名是使用者可控欄位）
	formula := f.account(t, a.ID, "=cmd")
	require.NotZero(t, formula.ID)

	// 區間內一筆失敗記錄：原因碼只有機器碼
	require.NoError(t, f.db.Create(&model.ChangeSecretRecord{
		PlanID: 1, AssetID: a.ID, AccountID: over.ID, AccountUsername: "overdue",
		SecretType: model.ChangeSecretTypePassword, Status: model.ChangeSecretFailed,
		Error: "remote_exit_nonzero", ExecutedAt: asOf.Add(-2 * 24 * time.Hour),
	}).Error)

	rep, err := f.builder.Build(ReportScope{Kind: model.RotationScopeAll},
		asOf.Add(-30*24*time.Hour), asOf, asOf, "zh-TW")
	require.NoError(t, err)
	rep.Meta.GeneratedBy = "tester"
	return rep
}

// readCSV 解出 CSV（去 BOM）。
func readCSV(t *testing.T, raw []byte) [][]string {
	t.Helper()
	body := bytes.TrimPrefix(raw, []byte("\xEF\xBB\xBF"))
	require.NotEqual(t, len(raw), len(body), "CSV 缺 UTF-8 BOM，試算表直開會亂碼")
	r := csv.NewReader(bytes.NewReader(body))
	// 首行是截止時點註解列（見 csvAsOfPrefix），欄名在其後
	r.Comment = '#'
	rows, err := r.ReadAll()
	require.NoError(t, err)
	return rows
}

// TestRotationReportOutputsSameSource PDF 封面的六格指標＝CSV 帳號檔依狀態桶
// 分組的列數。
func TestRotationReportOutputsSameSource(t *testing.T) {
	rep := mixedReport(t)
	ph := phraseFor(rep.Meta.Language)

	var csvBuf bytes.Buffer
	require.NoError(t, WriteAccountsCSV(&csvBuf, rep))
	rows := readCSV(t, csvBuf.Bytes())
	require.Greater(t, len(rows), 1)

	header := rows[0]
	bucketCol := -1
	for i, h := range header {
		if h == ph("col_bucket") {
			bucketCol = i
		}
	}
	require.NotEqual(t, -1, bucketCol, "帳號檔缺狀態欄")

	counts := map[string]int{}
	for _, r := range rows[1:] {
		counts[r[bucketCol]]++
	}

	metrics := coverMetrics(rep, ph)
	want := map[string]string{
		ph("metric_total"):      strconv.Itoa(len(rows) - 1),
		ph("metric_compliant"):  strconv.Itoa(counts[ph("bucket_compliant")]),
		ph("metric_overdue"):    strconv.Itoa(counts[ph("bucket_overdue")]),
		ph("metric_due_soon"):   strconv.Itoa(counts[ph("bucket_due_soon")]),
		ph("metric_no_record"):  strconv.Itoa(counts[ph("bucket_no_record")]),
		ph("metric_unverified"): strconv.Itoa(counts[ph("bucket_unverified")]),
	}
	require.Len(t, metrics, len(want))
	for _, m := range metrics {
		assert.Equal(t, want[m.Label], m.Value, "封面指標「%s」與 CSV 分桶列數不符", m.Label)
	}
	// 六桶都要有案例，否則這支測試只驗到零
	for _, b := range []string{"compliant", "overdue", "due_soon", "no_record", "unverified"} {
		assert.Greater(t, counts[ph("bucket_"+b)], 0, "桶 %s 無案例，測試涵蓋不足", b)
	}

	// 公式注入轉義：以 = 開頭的帳號名在儲存格中已前置單引號
	assert.Contains(t, csvBuf.String(), "'=cmd", "帳號名的公式起頭未轉義")

	// 記錄檔的原因碼只有機器碼
	var recBuf bytes.Buffer
	require.NoError(t, WriteRecordsCSV(&recBuf, rep))
	recRows := readCSV(t, recBuf.Bytes())
	require.Greater(t, len(recRows), 1, "區間內應有記錄")
	found := false
	for _, r := range recRows[1:] {
		if r[len(r)-1] == "remote_exit_nonzero" {
			found = true
			assert.Equal(t, ph("status_failed"), r[len(r)-2])
		}
	}
	assert.True(t, found, "失敗記錄的原因碼未出現在記錄檔")

	// PDF 產得出來
	var pdfBuf bytes.Buffer
	require.NoError(t, RenderPDF(&pdfBuf, rep, "job-42"))
	assert.Greater(t, pdfBuf.Len(), 1000)
	assert.True(t, bytes.HasPrefix(pdfBuf.Bytes(), []byte("%PDF-")))
}

// TestRotationReportPdfExceptionExcludesNoRecord 例外清單不含無記錄帳號，
// 但該帳號仍出現在附表 A。
//
// 雙向斷言：只驗「不在例外清單」，一個把它整份漏掉的實作也會通過。
func TestRotationReportPdfExceptionExcludesNoRecord(t *testing.T) {
	rep := mixedReport(t)
	ph := phraseFor(rep.Meta.Language)

	assert.Equal(t, []string{BucketOverdue, BucketDueSoon, BucketUnverified}, exceptionBuckets)
	assert.NotContains(t, exceptionBuckets, BucketNoRecord)

	inExceptions := false
	for _, bucket := range exceptionBuckets {
		for _, row := range exceptionRows(rep, bucket, ph) {
			if row[1] == "no-record" {
				inExceptions = true
			}
			assert.NotEqual(t, ph("bucket_no_record"), row[2],
				"例外清單出現無記錄狀態的列")
		}
	}
	assert.False(t, inExceptions, "無記錄帳號不得列入例外清單")

	// 對照：它在附表 A 有自己的列
	var csvBuf bytes.Buffer
	require.NoError(t, WriteAccountsCSV(&csvBuf, rep))
	assert.Contains(t, csvBuf.String(), "no-record", "無記錄帳號必須出現在全帳號明細")

	// 例外清單本身不是空的（否則上面的斷言全部落在空集合上）
	total := 0
	for _, bucket := range exceptionBuckets {
		total += len(exceptionRows(rep, bucket, ph))
	}
	assert.Greater(t, total, 0)
}

// TestRotationReportPdfNoPolicySection 政策未設定的帳號自成一段，段首說明
// 處置對象是政策設定。
func TestRotationReportPdfNoPolicySection(t *testing.T) {
	f := newReportFixture(t)
	f.global = 0 // 全域未設定
	asOf := mustTime(t, "2026-09-02T00:00:00Z")
	a := f.asset(t, "host-a")
	f.account(t, a.ID, "orphan")

	rep, err := f.builder.Build(ReportScope{Kind: model.RotationScopeAll},
		asOf.Add(-30*24*time.Hour), asOf, asOf, "zh-TW")
	require.NoError(t, err)
	ph := phraseFor(rep.Meta.Language)

	rows := noPolicyRows(rep, ph)
	require.Len(t, rows, 1)
	assert.Equal(t, "orphan", rows[0][1])

	// 段首說明三語齊備且非空
	for _, lang := range []string{"zh-TW", "en-US", "ja-JP"} {
		p := phraseFor(lang)
		assert.NotEqual(t, "no_policy_lead", p("no_policy_lead"), "%s 缺段首說明", lang)
		assert.NotEqual(t, "no_policy_section", p("no_policy_section"), "%s 缺段標題", lang)
	}

	// 這些帳號不進例外清單也不進合規率
	for _, bucket := range exceptionBuckets {
		assert.Empty(t, exceptionRows(rep, bucket, ph))
	}
	assert.Nil(t, rep.Summary.RateCountingNoRecord)

	var buf bytes.Buffer
	require.NoError(t, RenderPDF(&buf, rep, "job-1"))
	assert.Greater(t, buf.Len(), 1000)
}

// TestRotationReportOutputsLanguage 報告語言決定欄名與狀態名；日期不隨語言變。
func TestRotationReportOutputsLanguage(t *testing.T) {
	rep := mixedReport(t)
	rep.Meta.Language = "ja-JP"

	var buf bytes.Buffer
	require.NoError(t, WriteAccountsCSV(&buf, rep))
	body := buf.String()
	assert.Contains(t, body, "資産", "日文報告的欄名未依語言呈現")
	assert.Contains(t, body, "アカウント")
	// ISO 8601 帶時區位移，不隨語言變
	assert.True(t, strings.Contains(body, rep.Meta.AsOf.Add(-10*24*time.Hour).Format(time.RFC3339)) ||
		strings.Contains(body, "T00:00:00Z"), "時刻未以 ISO 8601 呈現")

	var pdfBuf bytes.Buffer
	require.NoError(t, RenderPDF(&pdfBuf, rep, "job-42"))
	assert.True(t, bytes.HasPrefix(pdfBuf.Bytes(), []byte("%PDF-")))
}

// TestRotationReportCsvCarriesAsOf 兩個 CSV 的首行載明截止時點與時區位移。
//
// CSV 是最常被單獨抽出來丟進試算表的那一份；「剩餘天數」離開截止時點就不可
// 解釋，也無法重算。註解列以 # 起頭（試算表與解析器可跳過），欄名仍是第一列資料。
func TestRotationReportCsvCarriesAsOf(t *testing.T) {
	rep := mixedReport(t)
	ph := phraseFor(rep.Meta.Language)
	wantLine := "# as_of=" + rep.Meta.AsOf.Format(time.RFC3339)
	assert.Contains(t, wantLine, "T", "截止時點須為 ISO 8601")

	for name, write := range map[string]func(io.Writer, *RotationReport) error{
		"accounts.csv": WriteAccountsCSV,
		"records.csv":  WriteRecordsCSV,
	} {
		var buf bytes.Buffer
		require.NoError(t, write(&buf, rep))
		body := strings.TrimPrefix(buf.String(), "\xEF\xBB\xBF")
		lines := strings.Split(body, "\r\n")
		require.Greater(t, len(lines), 2, "%s 內容過短", name)
		assert.Equal(t, wantLine, lines[0],
			"%s 首行須為截止時點註解列（含時區位移）", name)

		// 欄名沒有被註解列擠掉：解析器跳過 # 之後拿到的仍是表頭
		rows := readCSV(t, buf.Bytes())
		require.NotEmpty(t, rows)
		if name == "accounts.csv" {
			assert.Equal(t, ph("col_asset"), rows[0][0], "%s 的表頭遺失", name)
		} else {
			assert.Equal(t, ph("col_record_id"), rows[0][0], "%s 的表頭遺失", name)
		}
	}
}
