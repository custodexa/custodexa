package asset

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 報告記錄明細的傳輸風險：取自改密紀錄本身（執行當下的判定），
// 空值留白；記錄檔與 PDF 附表 B 的新欄附在最後，既有欄序不變。

// TestRotationReportRecordCarriesTransportRisk 資料集的記錄列逐筆拷貝紀錄的傳輸風險。
func TestRotationReportRecordCarriesTransportRisk(t *testing.T) {
	f := newReportFixture(t)
	f.global = 90
	a := f.asset(t, "orders-db")
	acc := f.account(t, a.ID, "app_user")
	at := time.Now().Add(-24 * time.Hour)
	for _, rec := range []model.ChangeSecretRecord{
		{PlanID: 1, AssetID: a.ID, AccountID: acc.ID, AccountUsername: "app_user",
			SecretType: model.ChangeSecretTypePassword, Status: model.ChangeSecretSuccess,
			TransportRisk: model.RiskDBRotationUnencrypted, ExecutedAt: at},
		{PlanID: 1, AssetID: a.ID, AccountID: acc.ID, AccountUsername: "app_user",
			SecretType: model.ChangeSecretTypePassword, Status: model.ChangeSecretSuccess,
			ExecutedAt: at.Add(time.Minute)},
	} {
		rec := rec
		require.NoError(t, f.db.Create(&rec).Error)
	}

	rep := f.build(t, ReportScope{Kind: model.RotationScopeAll}, time.Now())
	require.Len(t, rep.Records, 2)
	got := map[string]int{}
	for _, r := range rep.Records {
		got[r.TransportRisk]++
	}
	assert.Equal(t, map[string]int{model.RiskDBRotationUnencrypted: 1, "": 1}, got,
		"記錄列的傳輸風險須逐筆取自紀錄本身")
}

// TestRotationReportRecordsCSVTransportRiskColumn 記錄檔末尾多一欄：空值留白、
// 認得的值依報告語言、不認得的非空值原樣輸出；附表 B 的欄寬數與欄數一致。
func TestRotationReportRecordsCSVTransportRiskColumn(t *testing.T) {
	rep := mixedReport(t)
	base := rep.Records[0]
	rows := []RecordRow{base, base, base}
	rows[0].RecordID, rows[0].TransportRisk = 9001, ""
	rows[1].RecordID, rows[1].TransportRisk = 9002, model.RiskDBRotationUnencrypted
	rows[2].RecordID, rows[2].TransportRisk = 9003, "future_risk_key"
	rep.Records = rows
	ph := phraseFor(rep.Meta.Language)

	var buf bytes.Buffer
	require.NoError(t, WriteRecordsCSV(&buf, rep))
	parsed := readCSV(t, buf.Bytes())
	require.Len(t, parsed, 4)
	header := parsed[0]
	require.Len(t, header, 10, "記錄檔欄數＝原 9 欄＋傳輸風險 1 欄")
	assert.Equal(t, ph("col_reason_code"), header[8], "既有欄序不變")
	assert.Equal(t, ph("col_transport_risk"), header[9])
	assert.Equal(t, "傳輸", header[9])

	last := func(i int) string { return parsed[i][len(parsed[i])-1] }
	assert.Equal(t, "", last(1), "空值留白")
	assert.Equal(t, "未加密連線", last(2), "認得的值依報告語言輸出短語")
	assert.Equal(t, "future_risk_key", last(3), "不認得的非空值原樣輸出，不得留白")

	rep.Meta.Language = "en-US"
	buf.Reset()
	require.NoError(t, WriteRecordsCSV(&buf, rep))
	parsed = readCSV(t, buf.Bytes())
	assert.Equal(t, "Transport", parsed[0][9])
	assert.Equal(t, "Unencrypted connection", parsed[2][9])

	var pdfBuf bytes.Buffer
	require.NoError(t, RenderPDF(&pdfBuf, rep, "job-tr"))
	assert.True(t, bytes.HasPrefix(pdfBuf.Bytes(), []byte("%PDF-")))
}
