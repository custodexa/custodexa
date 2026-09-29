package audit

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 合規對照報告的打包者（滿足 ReportPackager）。
//
// 資料集與版面在 policy 模組（依賴矩陣只允許 audit→policy）；本檔只負責把
// 兩個資料檔寫進 ZIP、逐檔算雜湊，最後寫清單檔與簽章——清單檔最後寫入，中途
// 中斷的包沒有清單檔，依既有判準即不完整。

// 產物內的檔名（固定，收包方的解析對象）。
const (
	complianceReportFilePDF = "report.pdf"
	complianceReportFileCSV = "clauses.csv"
)

// ComplianceReportSource 報告資料集的來源（由 policy.ComplianceService 滿足）。
type ComplianceReportSource interface {
	BuildReport(group string, meta policy.ComplianceReportMeta) (*policy.ComplianceReport, error)
}

// ComplianceReportPackager 合規報告打包者。
type ComplianceReportPackager struct {
	source  ComplianceReportSource
	signer  ManifestSigner
	version string
}

// NewComplianceReportPackager 建立打包者；signer 為 nil＝不簽（清單檔自述未簽的機器碼）。
func NewComplianceReportPackager(source ComplianceReportSource, signer ManifestSigner,
	version string) *ComplianceReportPackager {
	return &ComplianceReportPackager{source: source, signer: signer, version: version}
}

// Kind 分派鍵。
func (p *ComplianceReportPackager) Kind() string {
	return model.ExportJobKindComplianceReport
}

// Package 產出一份報告產物。資料時點＝打包當下（報告只有「截至現在」）。
func (p *ComplianceReportPackager) Package(w io.Writer, filterJSON string,
	requestedAt time.Time, jobID uint) (*ExportManifest, error) {
	f, err := policy.ParseComplianceReportJobFilter(filterJSON)
	if err != nil {
		return nil, err
	}
	lang := f.Language
	if !model.ValidNotificationChannelLanguage(lang) {
		lang = model.NotificationChannelLanguageDefault
	}
	rep, err := p.source.BuildReport(f.Group, policy.ComplianceReportMeta{
		GeneratedAt: time.Now(),
		GeneratedBy: f.GeneratedBy,
		Language:    lang,
		JobRef:      fmt.Sprintf("job-%d", jobID),
	})
	if err != nil {
		return nil, err
	}

	zw := zip.NewWriter(w)
	defer zw.Close()

	manifest := &ExportManifest{
		Mode:           model.ExportJobKindComplianceReport,
		Kind:           model.ExportJobKindComplianceReport,
		JobID:          jobID,
		ExportedBy:     f.GeneratedBy,
		ExportedAt:     rep.Meta.GeneratedAt,
		JobRequestedAt: &requestedAt,
		Filter: map[string]string{
			"group":          rep.Meta.GroupCode,
			"group_version":  rep.Meta.GroupVersion,
			"language":       lang,
			"retention_days": strconv.Itoa(f.RetentionDays),
			"as_of":          rep.Meta.AsOf.Format(time.RFC3339),
			// CSV 首行是資料時點註解列而非欄名；收包方的解析器據此跳過它
			"csv_as_of_prefix": policy.ComplianceReportCSVAsOfPrefix,
			"product_version":  p.version,
		},
		Files: []ExportedFile{},
		Counts: map[string]int{
			"setting_rows":  len(rep.Rows),
			"self_attested": len(rep.SelfAttested),
			"builtin":       len(rep.Builtin),
		},
		Truncated: map[string]bool{},
		Signed:    p.signer != nil,
	}
	if p.signer == nil {
		manifest.SignedReason = SignedReasonServiceUnavailable
	}

	writers := []struct {
		name  string
		write func(io.Writer) error
	}{
		{complianceReportFilePDF, func(dst io.Writer) error { return policy.RenderComplianceReportPDF(dst, rep) }},
		{complianceReportFileCSV, func(dst io.Writer) error { return policy.WriteComplianceReportCSV(dst, rep) }},
	}
	for _, item := range writers {
		entry, err := zw.Create(item.name)
		if err != nil {
			return nil, fmt.Errorf("建立 %s 失敗: %w", item.name, err)
		}
		hw := &reportHashWriter{w: entry, hasher: sha256.New()}
		if err := item.write(hw); err != nil {
			return nil, fmt.Errorf("寫入 %s 失敗: %w", item.name, err)
		}
		manifest.Files = append(manifest.Files, ExportedFile{
			Name: item.name, Size: hw.n, SHA256: fmt.Sprintf("%x", hw.hasher.Sum(nil)),
		})
	}
	if err := WriteManifest(zw, manifest, p.signer); err != nil {
		return nil, err
	}
	return manifest, nil
}

// reportHashWriter 邊寫邊算 SHA-256 與位元組數。
type reportHashWriter struct {
	w      io.Writer
	hasher hash.Hash
	n      int64
}

func (hw *reportHashWriter) Write(b []byte) (int, error) {
	n, err := hw.w.Write(b)
	hw.hasher.Write(b[:n])
	hw.n += int64(n)
	return n, err
}
