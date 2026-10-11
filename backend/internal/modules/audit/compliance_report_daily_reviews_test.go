package audit

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/modules/policy"
)

// signoffReportSource 帶每日審閱段的報告來源替身（PCI 那一型）；signoff 為 nil 時同一般組
type signoffReportSource struct {
	stubReportSource
	signoff *policy.ComplianceReportSignoff
}

func (s *signoffReportSource) BuildReport(group string, meta policy.ComplianceReportMeta) (*policy.ComplianceReport, error) {
	rep, err := s.stubReportSource.BuildReport(group, meta)
	if err != nil {
		return nil, err
	}
	rep.Signoff = s.signoff
	return rep, nil
}

// TestComplianceReportZipIncludesDailyReviews 擋：含每日審閱條文的組少了逐日清單，
// 或清單檔沒記它的雜湊；不含該條文的組被多塞一個檔。
func TestComplianceReportZipIncludesDailyReviews(t *testing.T) {
	signedAt := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	signoff := &policy.ComplianceReportSignoff{ClauseNo: "10.4.1", ClauseTitle: "每日審閱簽核",
		Key: policy.PolicyDailyReviewEnabled, Result: policy.ComplianceResultDeviating,
		Reason: policy.ComplianceReasonSignoffUnsignedDays,
		Record: &policy.SignoffRecord{From: "2026-09-11", To: "2026-10-10", Timezone: "Asia/Taipei",
			AsOf: time.Date(2026, 10, 11, 4, 0, 0, 0, time.UTC), Required: 2, OnTime: 1, Unsigned: 1,
			Days: []policy.SignoffDay{
				{Date: "2026-09-30", Status: policy.SignoffStatusOnTime, CountsTowardStats: true, SignedAt: &signedAt, Signer: "auditor01"},
				{Date: "2026-10-01", Status: policy.SignoffStatusUnsigned, CountsTowardStats: true},
			}}}
	cases := []struct {
		name    string
		signoff *policy.ComplianceReportSignoff
		want    []string
	}{
		{"含每日審閱條文的組", signoff,
			[]string{"report.pdf", "clauses.csv", policy.DailyReviewsCSVName, "manifest.json", "manifest.sig"}},
		{"不含該條文的組結構不變", nil,
			[]string{"report.pdf", "clauses.csv", "manifest.json", "manifest.sig"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := NewComplianceReportPackager(&signoffReportSource{signoff: c.signoff}, &recordingSigner{}, "9.9.9")
			filterJSON, err := policy.ComplianceReportJobFilter{Group: "pci_dss_4_0_1", Language: "zh-TW",
				RetentionDays: 90, GeneratedBy: "auditor01"}.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			manifest, err := p.Package(&buf, filterJSON, time.Now(), 7)
			if err != nil {
				t.Fatalf("Package: %v", err)
			}
			zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			content := map[string][]byte{}
			for _, f := range zr.File {
				names = append(names, f.Name)
				rc, err := f.Open()
				if err != nil {
					t.Fatal(err)
				}
				content[f.Name], _ = io.ReadAll(rc)
				_ = rc.Close()
			}
			if fmt.Sprint(names) != fmt.Sprint(c.want) {
				t.Fatalf("ZIP 檔序 %v, want %v", names, c.want)
			}
			if len(manifest.Files) != len(c.want)-2 {
				t.Errorf("清單檔記了 %d 個資料檔, want %d", len(manifest.Files), len(c.want)-2)
			}
			for _, f := range manifest.Files {
				if got := fmt.Sprintf("%x", sha256.Sum256(content[f.Name])); got != f.SHA256 {
					t.Errorf("%s 雜湊 %s, 清單檔記 %s", f.Name, got, f.SHA256)
				}
			}
			if c.signoff != nil {
				if manifest.Counts["daily_reviews"] != 2 {
					t.Errorf("清單檔每日簽核列數 %d, want 2", manifest.Counts["daily_reviews"])
				}
				if !bytes.Contains(content[policy.DailyReviewsCSVName], []byte("2026-10-01,")) {
					t.Errorf("daily_reviews.csv 缺未簽的那一天：%s", content[policy.DailyReviewsCSVName])
				}
			}
		})
	}
}
