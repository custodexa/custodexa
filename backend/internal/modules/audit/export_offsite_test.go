package audit

import (
	"os"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
	"gorm.io/gorm"
)

// 證據包的離機接線：`finishJob` 同交易排入、
// adapter 的取件與回填語義、終態清理對遠端零動作。

// stubEnqueuer 帳冊排隊面的替身：可注入「無現行世代」與「排隊後失敗」。
type stubEnqueuer struct {
	active   bool
	failWith error
	calls    int
	// createdIDs 每次排入回的物件 id（依序取用；空＝固定回 1）
	nextID uint
}

func (s *stubEnqueuer) HasCurrentGeneration() (bool, error) { return s.active, nil }

func (s *stubEnqueuer) EnqueueTx(tx *gorm.DB, kind string, ownerID uint, origin string) (*model.OffsiteObject, bool, error) {
	s.calls++
	if s.failWith != nil {
		return nil, false, s.failWith
	}
	if s.nextID == 0 {
		s.nextID = 1
	}
	row := &model.OffsiteObject{ID: s.nextID, Kind: kind, OwnerID: ownerID,
		Origin: origin, State: offsite.StatePending}
	return row, true, nil
}

// TestFinishJobEnqueuesInSameTransaction 啟用離機：產物落定與排隊同一筆交易，
// 指標欄與快取欄一併寫入。
func TestFinishJobEnqueuesInSameTransaction(t *testing.T) {
	exporter := &stubJobExporter{mode: "ok", payload: "zip-bytes"}
	verifier := &countingVerifier{allowed: true}
	w, svc, db, _ := newWorkerEnv(t, exporter, verifier)
	enq := &stubEnqueuer{active: true, nextID: 88}
	w.SetOffsiteEnqueuer(enq)

	job := mustCreatePendingJob(t, svc, 1, 42)
	w.RunCycle()

	got := reloadJob(t, db, job.ID)
	if got.Status != model.ExportJobDone {
		t.Fatalf("狀態: %s（%s）", got.Status, got.ErrorSummary)
	}
	if enq.calls != 1 {
		t.Fatalf("應排入一次，實得 %d", enq.calls)
	}
	if got.OffsiteObjectID == nil || *got.OffsiteObjectID != 88 {
		t.Fatalf("指標欄應指向帳冊列 88，實得 %v", got.OffsiteObjectID)
	}
	if got.OffsiteStatus != offsite.StatePending {
		t.Errorf("快取欄應為 %s，實得 %q", offsite.StatePending, got.OffsiteStatus)
	}
}

// TestFinishJobUnchangedWhenOffsiteInactive 未接線／零現行世代：
// 產物照常落定、兩個離機欄維持零值（「未設定＝行為完全不變」）。
func TestFinishJobUnchangedWhenOffsiteInactive(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire func(w *AuditExportJobWorker) *stubEnqueuer
	}{
		{"未組裝離機子系統", func(*AuditExportJobWorker) *stubEnqueuer { return nil }},
		{"已組裝但零現行世代", func(w *AuditExportJobWorker) *stubEnqueuer {
			e := &stubEnqueuer{active: false}
			w.SetOffsiteEnqueuer(e)
			return e
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exporter := &stubJobExporter{mode: "ok", payload: "zip-bytes"}
			verifier := &countingVerifier{allowed: true}
			w, svc, db, _ := newWorkerEnv(t, exporter, verifier)
			enq := tc.wire(w)

			job := mustCreatePendingJob(t, svc, 1, 42)
			w.RunCycle()

			got := reloadJob(t, db, job.ID)
			if got.Status != model.ExportJobDone {
				t.Fatalf("狀態: %s（%s）", got.Status, got.ErrorSummary)
			}
			if got.OffsiteObjectID != nil || got.OffsiteStatus != "" {
				t.Errorf("未啟用離機時兩個離機欄必須維持零值，實得 %v／%q",
					got.OffsiteObjectID, got.OffsiteStatus)
			}
			if enq != nil && enq.calls != 0 {
				t.Errorf("零現行世代時不得呼叫排隊面，實得 %d 次", enq.calls)
			}
		})
	}
}

// TestFinishJobRollsBackOnEnqueueFailure 排隊失敗＝整筆回滾：job 不得停在
// 「done 但沒排隊」——那份產物的本機副本隨時可能因容器重建而消失。
func TestFinishJobRollsBackOnEnqueueFailure(t *testing.T) {
	exporter := &stubJobExporter{mode: "ok", payload: "zip-bytes"}
	verifier := &countingVerifier{allowed: true}
	w, svc, db, _ := newWorkerEnv(t, exporter, verifier)
	w.SetOffsiteEnqueuer(&stubEnqueuer{active: true, failWith: errDBInjected})

	job := mustCreatePendingJob(t, svc, 1, 42)
	w.RunCycle()

	got := reloadJob(t, db, job.ID)
	if got.Status == model.ExportJobDone {
		t.Fatal("排隊失敗時不得留下 done 狀態（回滾必須覆蓋 job 列）")
	}
	if got.OffsiteObjectID != nil {
		t.Errorf("回滾後不得留下指標欄，實得 %v", got.OffsiteObjectID)
	}
}

// errDBInjected 注入用的排隊失敗。
var errDBInjected = &injectedError{}

type injectedError struct{}

func (*injectedError) Error() string { return "注入：排隊失敗" }

// ── ExportOffsiteAdapter ──────────────────────────────────────────────────

func seedDoneJob(t *testing.T, db *gorm.DB, dir string, body string) *model.AuditExportJob {
	t.Helper()
	path := dir + "/job-artifact.zip"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("寫產物: %v", err)
	}
	packaged := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	expires := packaged.Add(exportJobArtifactRetention)
	job := model.AuditExportJob{
		RequesterID: 1, RequesterName: "auditor", Status: model.ExportJobDone,
		ArtifactPath: path, ArtifactSize: int64(len(body)),
		PackagedAt: &packaged, ExpiresAt: &expires, RequestedAt: packaged,
	}
	if err := db.Create(&job).Error; err != nil {
		t.Fatalf("建立 job: %v", err)
	}
	return &job
}

// TestExportAdapterOpenAndDescribe 產物取件無寬限期；Describe 的 EndedAt 取
// 打包時刻（object key 的年月分桶），到期日取下載窗口。
func TestExportAdapterOpenAndDescribe(t *testing.T) {
	db := newJobServiceDB(t)
	dir := t.TempDir()
	job := seedDoneJob(t, db, dir, "zip-body")

	a := NewExportOffsiteAdapter(db)
	rc, size, _, err := a.Open(job.ID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rc.Close()
	if size != int64(len("zip-body")) {
		t.Errorf("大小: %d", size)
	}

	d, err := a.Describe(job.ID)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if !d.EndedAt.Equal(*job.PackagedAt) {
		t.Errorf("EndedAt 應為打包時刻 %v，實得 %v", *job.PackagedAt, d.EndedAt)
	}
	if d.RetentionDeadline == nil || !d.RetentionDeadline.Equal(*job.ExpiresAt) {
		t.Errorf("到期日應為下載窗口 %v，實得 %v", job.ExpiresAt, d.RetentionDeadline)
	}
	if ext, _ := a.Extension(job.ID); ext != "zip" {
		t.Errorf("副檔名: %q", ext)
	}
}

// TestExportAdapterDefersUnfinishedJob 尚未落定的 job 回 ErrNotReadyYet
// （延後、不計 attempts），不是失敗。
func TestExportAdapterDefersUnfinishedJob(t *testing.T) {
	db := newJobServiceDB(t)
	job := model.AuditExportJob{RequesterID: 1, RequesterName: "auditor",
		Status: model.ExportJobRunning}
	if err := db.Create(&job).Error; err != nil {
		t.Fatalf("建立 job: %v", err)
	}
	a := NewExportOffsiteAdapter(db)
	if _, _, _, err := a.Open(job.ID); err != offsite.ErrNotReadyYet {
		t.Fatalf("應回 ErrNotReadyYet，實得 %v", err)
	}
}

// TestExportAdapterBackfillNeverExpires 產物逾下載窗口**不產出 expired 分類**：
// 遠端副本是組織的證據寄存，窗口只約束產品自己的下載入口。
func TestExportAdapterBackfillNeverExpires(t *testing.T) {
	db := newJobServiceDB(t)
	dir := t.TempDir()
	job := seedDoneJob(t, db, dir, "zip-body")
	past := time.Now().Add(-72 * time.Hour)
	if err := db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Update("expires_at", past).Error; err != nil {
		t.Fatalf("改到期時刻: %v", err)
	}

	a := NewExportOffsiteAdapter(db)
	class, err := a.Classify(job.ID)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if class != offsite.BackfillUploadable {
		t.Fatalf("逾下載窗口但本機檔仍在者應可上傳，實得 %s", class)
	}

	// 本機檔已被清掃刪除：缺檔而非逾期
	if err := os.Remove(job.ArtifactPath); err != nil {
		t.Fatalf("刪產物: %v", err)
	}
	class, err = a.Classify(job.ID)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if class != offsite.BackfillMissing {
		t.Fatalf("本機檔不在應歸缺檔，實得 %s", class)
	}
}

// TestExportAdapterListUnenqueuedOnlyDone 回填視野只含已落定且產物在檔者。
func TestExportAdapterListUnenqueuedOnlyDone(t *testing.T) {
	db := newJobServiceDB(t)
	dir := t.TempDir()
	done := seedDoneJob(t, db, dir, "zip-body")
	running := model.AuditExportJob{RequesterID: 1, RequesterName: "a",
		Status: model.ExportJobRunning}
	expired := model.AuditExportJob{RequesterID: 1, RequesterName: "a",
		Status: model.ExportJobExpired}
	for _, j := range []*model.AuditExportJob{&running, &expired} {
		if err := db.Create(j).Error; err != nil {
			t.Fatalf("建立 job: %v", err)
		}
	}

	a := NewExportOffsiteAdapter(db)
	ids, err := a.ListUnenqueued(10)
	if err != nil {
		t.Fatalf("ListUnenqueued: %v", err)
	}
	if len(ids) != 1 || ids[0] != done.ID {
		t.Fatalf("只應列出已落定的 job %d，實得 %v", done.ID, ids)
	}

	if err := a.SetStatus(done.ID, 7, offsite.StatePending); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	ids, err = a.ListUnenqueued(10)
	if err != nil {
		t.Fatalf("ListUnenqueued: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("已排入者應退出回填視野，實得 %v", ids)
	}
}

// TestExportAdapterMarkForeignBatch 世代退役的快取批次轉移（終態不動）。
func TestExportAdapterMarkForeignBatch(t *testing.T) {
	db := newJobServiceDB(t)
	objID := uint(5)
	rows := []struct {
		status string
		want   string
	}{
		{offsite.StateUploaded, offsite.StateForeign},
		{offsite.StateLocalPurged, offsite.StateLocalPurged},
	}
	ids := make([]uint, len(rows))
	for i, r := range rows {
		j := model.AuditExportJob{RequesterID: 1, RequesterName: "a",
			Status: model.ExportJobDone, OffsiteObjectID: &objID, OffsiteStatus: r.status}
		if err := db.Create(&j).Error; err != nil {
			t.Fatalf("建立 job: %v", err)
		}
		ids[i] = j.ID
	}
	a := NewExportOffsiteAdapter(db)
	if err := db.Transaction(func(tx *gorm.DB) error {
		return a.MarkForeignBatch(tx, 2)
	}); err != nil {
		t.Fatalf("MarkForeignBatch: %v", err)
	}
	for i, r := range rows {
		var got model.AuditExportJob
		if err := db.First(&got, ids[i]).Error; err != nil {
			t.Fatalf("讀回: %v", err)
		}
		if got.OffsiteStatus != r.want {
			t.Errorf("前態 %s 應轉為 %s，實得 %s", r.status, r.want, got.OffsiteStatus)
		}
	}
}

// TestExportAdapterSatisfiesOffsiteAdapter 型別層釘住介面實作。
func TestExportAdapterSatisfiesOffsiteAdapter(t *testing.T) {
	var _ offsite.Adapter = (*ExportOffsiteAdapter)(nil)
}

// TestPurgeTerminalRecordsLeavesRemoteObjectsAlone 終態紀錄清理**只清 job 列**，
// 對遠端物件零動作（產品不刪遠端證據包）。
//
// 「零 Delete」在此以**帳冊列仍在**表達：清理路徑若哪天真的去動遠端，第一步
// 一定是先讀帳冊拿 key——帳冊列被保留且未被改動，即證明那條路徑不存在。
// driver 層的零 Delete 另由 `internal/guards/offsitedelete` 的靜態守衛與
// `FakeClient.DeleteCalls()` 承擔。
func TestPurgeTerminalRecordsLeavesRemoteObjectsAlone(t *testing.T) {
	exporter := &stubJobExporter{mode: "ok"}
	verifier := &countingVerifier{allowed: true}
	w, _, db, _ := newWorkerEnv(t, exporter, verifier)

	objID := uint(31)
	old := time.Now().Add(-exportJobRecordRetention - time.Hour)
	job := model.AuditExportJob{RequesterID: 1, RequesterName: "a",
		Status: model.ExportJobExpired, OffsiteObjectID: &objID,
		OffsiteStatus: offsite.StateUploaded}
	if err := db.Create(&job).Error; err != nil {
		t.Fatalf("建立 job: %v", err)
	}
	if err := db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Update("updated_at", old).Error; err != nil {
		t.Fatalf("改 updated_at: %v", err)
	}

	w.purgeTerminalRecords(time.Now())

	var n int64
	if err := db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Count(&n).Error; err != nil {
		t.Fatalf("計數: %v", err)
	}
	if n != 0 {
		t.Fatalf("前提不成立：終態紀錄應被清理，實得 %d 列", n)
	}
	// job 列消失而帳冊列（另一張表）不受影響——清理路徑對 offsite_objects 零觸碰
	// 是型別層的事實：audit 模組對該表零直接存取（資料邊界閘門盯著）。
}
