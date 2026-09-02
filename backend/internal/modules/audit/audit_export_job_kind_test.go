package audit

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 工作單的種類分支。
//
// 本檔釘四件事，全部是「例外只開在該開的那一側」的雙向斷言：
//  1. 下載授權：報告不綁申請者，證據包**不因種類欄出現而放寬**。
//  2. 系統發起者（RequesterID 0）免申請者重驗，由人發起的仍然要驗。
//  3. 報告的去重鍵是種類加篩選快照，不含申請者。
//  4. 清單的種類缺省為證據包（既有呼叫端行為不變）。

// stubPackager 報告打包替身
type stubPackager struct {
	calls     int
	kind      string
	payload   string
	lastJSON  string
	lastJobID uint
}

func (s *stubPackager) Kind() string { return s.kind }

func (s *stubPackager) Package(w io.Writer, filterJSON string, _ time.Time,
	jobID uint) (*ExportManifest, error) {
	s.calls++
	s.lastJSON = filterJSON
	s.lastJobID = jobID
	if _, err := io.WriteString(w, s.payload); err != nil {
		return nil, err
	}
	return &ExportManifest{Mode: s.kind, Kind: s.kind}, nil
}

func mustCreateReportJob(t *testing.T, svc *AuditExportJobService, requester uint,
	name, filterJSON string) *model.AuditExportJob {
	t.Helper()
	job, created, err := svc.CreateReportJob(model.ExportJobKindRotationReport, filterJSON, "",
		name, requester, nil, nil)
	if err != nil || !created {
		t.Fatalf("建立報告工作單: created=%v err=%v", created, err)
	}
	return job
}

func TestExportJobKindDownloadRules(t *testing.T) {
	svc := NewAuditExportJobService(newJobServiceDB(t))

	bundle := mustCreatePendingJob(t, svc, 1, 100)
	report := mustCreateReportJob(t, svc, 1, "auditor", `{"scope_kind":"all"}`)

	// 證據包：他人取件仍被拒（例外不得溢出到這一側）
	if _, err := svc.GetForDownload(bundle.ID, 2); !errors.Is(err, ErrExportJobNotFound) {
		t.Fatalf("他人取證據包應收斂為 ErrExportJobNotFound，實得 %v", err)
	}
	if _, err := svc.GetForDownload(bundle.ID, 1); err != nil {
		t.Fatalf("申請者本人取證據包應成功，實得 %v", err)
	}

	// 報告：他人可取（例外的正向側）
	got, err := svc.GetForDownload(report.ID, 2)
	if err != nil {
		t.Fatalf("他人取報告應成功（不綁申請者），實得 %v", err)
	}
	if got.Kind != model.ExportJobKindRotationReport {
		t.Fatalf("取回的種類應為 rotation_report，實得 %q", got.Kind)
	}
	if _, err := svc.GetForDownload(99999, 1); !errors.Is(err, ErrExportJobNotFound) {
		t.Fatalf("不存在的工作單應收斂為 ErrExportJobNotFound，實得 %v", err)
	}
}

func TestExportJobSystemRequesterSkipsVerify(t *testing.T) {
	packager := &stubPackager{kind: model.ExportJobKindRotationReport, payload: "report-bytes"}
	// 驗證器一律回「已失權」：走到它就會取消 job，故 job 完成即證明沒走到
	verifier := &countingVerifier{allowed: false}
	w, svc, db, _ := newWorkerEnv(t, &stubJobExporter{mode: "ok", payload: "x"}, verifier)
	w.RegisterPackager(packager)

	sys := mustCreateReportJob(t, svc, 0, "system", `{"scope_kind":"all","schedule_id":1}`)
	w.RunCycle()

	got := reloadJob(t, db, sys.ID)
	if got.Status != model.ExportJobDone {
		t.Fatalf("系統發起的工作單應免重驗並完成打包，實得狀態 %q 摘要 %q",
			got.Status, got.ErrorSummary)
	}
	if verifier.calls != 0 {
		t.Fatalf("系統發起者不應觸發申請者重驗，實得呼叫 %d 次", verifier.calls)
	}
	if packager.calls != 1 {
		t.Fatalf("報告打包者應被呼叫一次，實得 %d", packager.calls)
	}

	// 反向：由人發起的報告仍然重驗，失權即取消
	human := mustCreateReportJob(t, svc, 7, "auditor", `{"scope_kind":"all","period":"2"}`)
	w.RunCycle()
	humanGot := reloadJob(t, db, human.ID)
	if verifier.calls != 1 {
		t.Fatalf("由人發起的報告應重驗一次，實得 %d", verifier.calls)
	}
	if humanGot.Status != model.ExportJobFailed ||
		humanGot.ErrorSummary != model.ExportJobErrRequesterRevoked {
		t.Fatalf("失權的人為發起應取消，實得狀態 %q 摘要 %q",
			humanGot.Status, humanGot.ErrorSummary)
	}
	_ = db
}

func TestExportJobDedupByKindForReports(t *testing.T) {
	svc := NewAuditExportJobService(newJobServiceDB(t))
	const filter = `{"scope_kind":"all","period_start":"2026-09-01T00:00:00Z"}`

	first := mustCreateReportJob(t, svc, 3, "auditor-a", filter)
	// 另一個申請者、同一份報告：命中去重，拿到同一張工作單
	same, created, err := svc.CreateReportJob(model.ExportJobKindRotationReport, filter, "",
		"auditor-b", 4, nil, nil)
	if err != nil {
		t.Fatalf("第二次發起: %v", err)
	}
	if created || same.ID != first.ID {
		t.Fatalf("報告去重不含申請者：應回同一張工作單 %d，實得 %d（created=%v）",
			first.ID, same.ID, created)
	}

	// 發起者名稱不同但去重鍵相同時仍去重（去重鍵由呼叫端給）
	other, created, err := svc.CreateReportJob(model.ExportJobKindRotationReport,
		`{"scope_kind":"all","generated_by":"someone"}`, filter, "auditor-c", 5, nil, nil)
	if err != nil {
		t.Fatalf("第三次發起: %v", err)
	}
	if created || other.ID != first.ID {
		t.Fatalf("去重鍵相同時應回同一張工作單，實得 %d（created=%v）", other.ID, created)
	}

	// 不同區間＝不同報告，照常受理
	if _, created, err := svc.CreateReportJob(model.ExportJobKindRotationReport,
		`{"scope_kind":"all","period_start":"2026-10-01T00:00:00Z"}`, "", "auditor-a", 3,
		nil, nil); err != nil || !created {
		t.Fatalf("不同參數的報告應受理，created=%v err=%v", created, err)
	}

	// guard 是排程節流的落點：回錯即拒絕受理
	sentinel := errors.New("同一排程已有進行中工作單")
	_, _, err = svc.CreateReportJob(model.ExportJobKindRotationReport,
		`{"scope_kind":"all","period_start":"2026-11-01T00:00:00Z"}`, "", "system", 0, nil,
		func([]model.AuditExportJob) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("guard 的錯誤應原樣上拋，實得 %v", err)
	}
}

func TestExportJobListDefaultsToEvidenceBundle(t *testing.T) {
	svc := NewAuditExportJobService(newJobServiceDB(t))

	mine := mustCreatePendingJob(t, svc, 1, 200)
	report := mustCreateReportJob(t, svc, 0, "system", `{"scope_kind":"all","schedule_id":9}`)

	// 缺省＝證據包，且只列本人：報告不得混進「我的匯出」
	jobs, total, err := svc.List(1, "", 1, 20)
	if err != nil {
		t.Fatalf("清單查詢: %v", err)
	}
	if total != 1 || len(jobs) != 1 || jobs[0].ID != mine.ID {
		t.Fatalf("缺省種類應只列本人的證據包 %d，實得 total=%d jobs=%v", mine.ID, total, jobs)
	}

	// 報告分頁：不綁申請者，任一具權限者都看得到同一張
	reports, total, err := svc.List(999, model.ExportJobKindRotationReport, 1, 20)
	if err != nil {
		t.Fatalf("報告清單查詢: %v", err)
	}
	if total != 1 || len(reports) != 1 || reports[0].ID != report.ID {
		t.Fatalf("報告分頁應列出系統產出的工作單 %d，實得 total=%d", report.ID, total)
	}

	// 反向：證據包分頁對非申請者仍為空
	if _, total, err := svc.List(999, model.ExportJobKindEvidenceBundle, 1, 20); err != nil || total != 0 {
		t.Fatalf("他人的證據包不得出現在其清單中，實得 total=%d err=%v", total, err)
	}
}

func TestExportJobUnknownKindFailsPackaging(t *testing.T) {
	verifier := &countingVerifier{allowed: true}
	w, svc, db, _ := newWorkerEnv(t, &stubJobExporter{mode: "ok", payload: "x"}, verifier)
	// 刻意不註冊打包者：組裝缺漏必須走失敗路徑，而不是產出一個空包
	job := mustCreateReportJob(t, svc, 0, "system", `{"scope_kind":"all"}`)
	for i := 0; i < exportJobMaxAttempts; i++ {
		w.RunCycle()
	}
	got := reloadJob(t, db, job.ID)
	if got.Status != model.ExportJobFailed {
		t.Fatalf("無對應打包者的工作單應以失敗告終，實得 %q", got.Status)
	}
}
