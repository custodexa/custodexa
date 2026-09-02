package asset

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 輪替證據報告的產物打包者。
//
// 產物是一個 ZIP：報告本體（PDF）、兩個 CSV、清單檔與簽章檔。**清單檔最後寫入**
// ——它含前面每一個檔的 SHA-256，中途中斷的包沒有清單檔，依既有判準即不完整、
// 不可作為證據。

// 產物內的檔名（固定，收包方的解析對象）。
const (
	reportFilePDF      = "report.pdf"
	reportFileAccounts = "accounts.csv"
	reportFileRecords  = "records.csv"
)

// RotationReportPackager 輪替證據報告的打包者（滿足 audit.ReportPackager）。
type RotationReportPackager struct {
	builder *RotationReportBuilder
	signer  audit.ManifestSigner
	version string
}

// NewRotationReportPackager 建立打包者。signer 為 nil＝不簽（清單檔會自述未簽
// 的機器碼，而不是靜默少一個檔）。
func NewRotationReportPackager(builder *RotationReportBuilder,
	signer audit.ManifestSigner, version string) *RotationReportPackager {
	return &RotationReportPackager{builder: builder, signer: signer, version: version}
}

// Kind 分派鍵。
func (p *RotationReportPackager) Kind() string {
	return model.ExportJobKindRotationReport
}

// Package 產出一份報告產物。
//
// 截止時點取記錄區間的結尾：一份報告要能被重算，其所有派生值就必須綁在參數上，
// 而不是綁在「打包當下是幾點」——排隊久一點的報告不該算出不同的剩餘天數。
func (p *RotationReportPackager) Package(w io.Writer, filterJSON string,
	requestedAt time.Time, jobID uint) (*audit.ExportManifest, error) {
	f, err := ParseReportJobFilter(filterJSON)
	if err != nil {
		return nil, err
	}
	if err := ValidateReportScope(f.ScopeKind, f.ScopeID); err != nil {
		return nil, err
	}
	lang := f.Language
	if !model.ValidNotificationChannelLanguage(lang) {
		lang = model.NotificationChannelLanguageDefault
	}

	rep, err := p.builder.Build(ReportScope{Kind: f.ScopeKind, ID: f.ScopeID},
		f.PeriodStart, f.PeriodEnd, f.PeriodEnd, lang)
	if err != nil {
		return nil, err
	}
	rep.Meta.GeneratedBy = f.GeneratedBy
	rep.Meta.ProductVersion = p.version

	zw := zip.NewWriter(w)
	defer zw.Close()

	manifest := &audit.ExportManifest{
		Mode:           model.ExportJobKindRotationReport,
		Kind:           model.ExportJobKindRotationReport,
		JobID:          jobID,
		ExportedBy:     f.GeneratedBy,
		ExportedAt:     rep.Meta.GeneratedAt,
		JobRequestedAt: &requestedAt,
		Filter:         reportManifestFilter(filterJSON, rep),
		Files:          []audit.ExportedFile{},
		Counts: map[string]int{
			"accounts": len(rep.Rows),
			"records":  len(rep.Records),
		},
		Truncated: map[string]bool{
			"accounts": rep.Truncation.RowsTruncated,
			"records":  rep.Truncation.RecordsTruncated,
		},
		NoteCodes: truncationNoteCodes(rep),
		Signed: p.signer != nil,
	}
	if p.signer == nil {
		manifest.SignedReason = audit.SignedReasonServiceUnavailable
	}

	writers := []struct {
		name  string
		write func(io.Writer) error
	}{
		{reportFilePDF, func(dst io.Writer) error { return RenderPDF(dst, rep, reportRef(jobID)) }},
		{reportFileAccounts, func(dst io.Writer) error { return WriteAccountsCSV(dst, rep) }},
		{reportFileRecords, func(dst io.Writer) error { return WriteRecordsCSV(dst, rep) }},
	}
	for _, item := range writers {
		entry, err := zw.Create(item.name)
		if err != nil {
			return nil, fmt.Errorf("建立 %s 失敗: %w", item.name, err)
		}
		hw := &hashingWriter{w: entry, hasher: sha256.New()}
		if err := item.write(hw); err != nil {
			return nil, fmt.Errorf("寫入 %s 失敗: %w", item.name, err)
		}
		manifest.Files = append(manifest.Files, audit.ExportedFile{
			Name: item.name, Size: hw.n, SHA256: fmt.Sprintf("%x", hw.hasher.Sum(nil)),
		})
	}

	if err := audit.WriteManifest(zw, manifest, p.signer); err != nil {
		return nil, err
	}
	return manifest, nil
}

// reportManifestFilter 清單檔的參數段：報告參數加上自參數導出的截止時點。
// 讀者要能只憑清單檔重算出同一份報告。
func reportManifestFilter(filterJSON string, rep *RotationReport) map[string]string {
	m := ReportJobDisplay(filterJSON)
	m["as_of"] = rep.Meta.AsOf.Format(time.RFC3339)
	// 兩個 CSV 的首行是截止時點註解列而非欄名；收包方的解析器要能據此跳過它
	m["csv_as_of_prefix"] = csvAsOfPrefix
	m["scope_label"] = rep.Meta.ScopeLabel
	return m
}

// truncationNoteCodes 截斷的機器碼（未截斷即無鍵——「沒有這個問題」與
// 「有這個問題但值是零」不該長得一樣）。
func truncationNoteCodes(rep *RotationReport) map[string]string {
	codes := map[string]string{}
	if rep.Truncation.RowsTruncated {
		codes["accounts"] = fmt.Sprintf("truncated_at_%d", rep.Truncation.RowsCap)
	}
	if rep.Truncation.RecordsTruncated {
		codes["records"] = fmt.Sprintf("truncated_at_%d", rep.Truncation.RecordsCap)
	}
	return codes
}

// reportRef 報告識別：印在每頁頁尾，供讀者把手上這張紙對回工作單。
//
// 值即工作單識別碼。排程名或產出者名不是識別——同一個排程每期產出的封面
// 逐字相同，收包方拿到兩份紙本只能靠時刻猜是哪一張工作單。
func reportRef(jobID uint) string {
	return fmt.Sprintf("job-%d", jobID)
}

// hashingWriter 邊寫邊算 SHA-256 與位元組數。
type hashingWriter struct {
	w      io.Writer
	hasher hash.Hash
	n      int64
}

func (hw *hashingWriter) Write(p []byte) (int, error) {
	n, err := hw.w.Write(p)
	hw.hasher.Write(p[:n])
	hw.n += int64(n)
	return n, err
}
