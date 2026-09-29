package audit

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 合規報告的打包與種類規則。
//
//   - 打包：ZIP 四檔、清單檔最後寫入、逐檔雜湊對得上、簽章檔存在（A 類：保管鏈
//     對不上或缺簽章，產物就不能拿來當證據，而它看起來是可以的）。
//   - 種類：合規報告是共用產物（不綁申請者），且這個例外**不溢出**到證據包
//     （B 類：放寬寫成「非證據包即放寬」時，下一個新種類會默默繼承共用下載）。

type stubReportSource struct {
	calls     int
	lastGroup string
	lastMeta  policy.ComplianceReportMeta
}

func (s *stubReportSource) BuildReport(group string, meta policy.ComplianceReportMeta) (*policy.ComplianceReport, error) {
	s.calls++
	s.lastGroup = group
	s.lastMeta = meta
	meta.GroupCode = group
	meta.GroupName = "內部基準"
	meta.GroupVersion = "1.0"
	meta.GroupSource = model.PolicyGroupSourceCustom
	meta.AsOf = time.Date(2026, 9, 29, 1, 12, 4, 0, time.UTC)
	return &policy.ComplianceReport{
		Meta:        meta,
		ClauseCount: 2,
		Summary:     policy.GroupSummary{GroupCode: group, Compliant: 1, Unmapped: 3, BuiltinProtection: 1},
		Rows: []policy.ComplianceReportRow{{
			ClauseNo: "1", ClauseTitle: "密碼長度", Kind: model.PolicyClauseKindSetting,
			Key: "password_min_length", Result: policy.ComplianceResultCompliant,
			Current: "14", Expected: "12", Comparator: model.PolicyControlComparatorMin,
		}},
		Builtin: []policy.ComplianceReportClause{{ClauseNo: "2", Title: "會話全程錄影"}},
	}, nil
}

type recordingSigner struct{ signed int }

func (s *recordingSigner) Sign([]byte) string {
	s.signed++
	return "sig-for-test"
}

func TestComplianceReportPackagerZipSigned(t *testing.T) {
	src := &stubReportSource{}
	signer := &recordingSigner{}
	p := NewComplianceReportPackager(src, signer, "9.9.9")
	if p.Kind() != model.ExportJobKindComplianceReport {
		t.Fatalf("Kind = %q", p.Kind())
	}
	filter := policy.ComplianceReportJobFilter{Group: "inhouse", GroupName: "內規",
		Language: "en-US", RetentionDays: 90, GeneratedBy: "auditor01"}
	filterJSON, err := filter.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	requested := time.Date(2026, 9, 29, 1, 0, 0, 0, time.UTC)
	manifest, err := p.Package(&buf, filterJSON, requested, 1042)
	if err != nil {
		t.Fatalf("Package: %v", err)
	}
	if src.lastGroup != "inhouse" || src.lastMeta.Language != "en-US" ||
		src.lastMeta.GeneratedBy != "auditor01" || src.lastMeta.JobRef != "job-1042" {
		t.Fatalf("資料集參數未取自工作單快照：group=%q meta=%+v", src.lastGroup, src.lastMeta)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("產物不是 ZIP: %v", err)
	}
	names := []string{}
	content := map[string][]byte{}
	for _, f := range zr.File {
		names = append(names, f.Name)
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		content[f.Name] = data
	}
	want := []string{"report.pdf", "clauses.csv", "manifest.json", "manifest.sig"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("ZIP 檔序 = %v，want %v（清單檔須在資料檔之後）", names, want)
	}
	if signer.signed != 1 || len(content["manifest.sig"]) == 0 {
		t.Fatalf("簽章檔缺漏：signed=%d sig=%q", signer.signed, content["manifest.sig"])
	}

	var m map[string]any
	if err := json.Unmarshal(content["manifest.json"], &m); err != nil {
		t.Fatalf("清單檔非 JSON: %v", err)
	}
	if m["kind"] != model.ExportJobKindComplianceReport || m["mode"] != model.ExportJobKindComplianceReport {
		t.Errorf("清單檔種類 = %v/%v", m["kind"], m["mode"])
	}
	if m["job_id"] != float64(1042) || m["signed"] != true {
		t.Errorf("清單檔 job_id／signed = %v／%v", m["job_id"], m["signed"])
	}
	filterOut, _ := m["filter"].(map[string]any)
	if filterOut["group"] != "inhouse" || filterOut["as_of"] == nil {
		t.Errorf("清單檔參數段缺政策組或資料時點：%v", filterOut)
	}
	for _, f := range manifest.Files {
		sum := fmt.Sprintf("%x", sha256.Sum256(content[f.Name]))
		if sum != f.SHA256 {
			t.Errorf("%s 的雜湊與清單檔不符", f.Name)
		}
	}
	if len(manifest.Files) != 2 {
		t.Errorf("清單檔應記兩個資料檔，實得 %d", len(manifest.Files))
	}
}

func TestExportJobComplianceReportIsShared(t *testing.T) {
	svc := NewAuditExportJobService(newJobServiceDB(t))

	bundle := mustCreatePendingJob(t, svc, 1, 100)
	report, created, err := svc.CreateReportJob(model.ExportJobKindComplianceReport,
		`{"group":"inhouse"}`, "", "auditor", 1, nil, nil)
	if err != nil || !created {
		t.Fatalf("建合規報告工作單: created=%v err=%v", created, err)
	}

	// 正向：他人可取、可列
	if _, err := svc.GetForDownload(report.ID, 2); err != nil {
		t.Fatalf("他人取合規報告應成功，實得 %v", err)
	}
	jobs, total, err := svc.List(2, model.ExportJobKindComplianceReport, 1, 20)
	if err != nil || total != 1 || jobs[0].ID != report.ID {
		t.Fatalf("合規報告分頁應對他人列出 %d，實得 total=%d err=%v", report.ID, total, err)
	}

	// 反向：證據包仍綁申請者，且不混進合規報告清單
	if _, err := svc.GetForDownload(bundle.ID, 2); !errors.Is(err, ErrExportJobNotFound) {
		t.Fatalf("他人取證據包應被拒，實得 %v", err)
	}
	if _, total, _ := svc.List(1, "", 1, 20); total != 1 {
		t.Fatalf("缺省清單應只有本人證據包 1 張，實得 %d", total)
	}
	// 反向：未知種類一律綁申請者（白名單反向寫）
	if !bindsRequester("some_future_kind") || bindsRequester(model.ExportJobKindComplianceReport) {
		t.Fatal("共用例外只給明列的報告種類")
	}
}
