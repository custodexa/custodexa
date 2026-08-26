package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 打包 worker。
//
// 本檔釘六件事：
//  1. 成功流轉：pending→running→done，產物落檔（0600）、SHA-256/大小/雙時刻/過期時刻齊。
//  2. panic 不殺行程（sidecar 紅線）：替身 exporter 以呼叫計數證明注入點走到，
//     測試行程存活即證明 recover 生效；重試上限後轉 failed。
//  3. 重啟恢復：running 懸置列於 Start 時回 pending。
//  4. 過期清除：逾期 done 轉 expired、檔案刪除、下載路徑清空。
//  5. 失權取消：驗證器回 false（呼叫計數證明注入點走到）→ failed＋
//     requester_revoked＋產物清除＋審計列可查得。
//  6. 每次重試重驗申請者：失敗回 pending 後再領件，驗證器計數遞增。

// stubJobExporter 打包替身：可設定成功寫入、回錯或 panic；記錄呼叫次數與
// 收到的 requestedAt（雙時戳的來源驗證）
type stubJobExporter struct {
	calls       int
	mode        string // "ok" | "err" | "panic"
	payload     string
	requestedAt []time.Time
}

func (s *stubJobExporter) ExportForJob(w io.Writer, _ *ExportFilter, _ uint, _ string,
	requestedAt time.Time) (*ExportManifest, error) {
	s.calls++
	s.requestedAt = append(s.requestedAt, requestedAt)
	switch s.mode {
	case "panic":
		panic("stub exporter panic（注入）")
	case "err":
		return nil, errors.New("stub 打包失敗（注入）")
	}
	if _, err := io.WriteString(w, s.payload); err != nil {
		return nil, err
	}
	return &ExportManifest{Mode: ExportModeEvidenceBundle}, nil
}

// countingVerifier 申請者重驗替身：記錄呼叫數
type countingVerifier struct {
	calls   int
	allowed bool
	err     error
}

func (v *countingVerifier) fn(uint) (bool, error) {
	v.calls++
	return v.allowed, v.err
}

func newWorkerEnv(t *testing.T, exporter *stubJobExporter, verifier *countingVerifier) (*AuditExportJobWorker, *AuditExportJobService, *gorm.DB, string) {
	t.Helper()
	db := newJobServiceDB(t)
	dir := t.TempDir()
	w := NewAuditExportJobWorker(db, exporter, verifier.fn, nil, dir)
	return w, NewAuditExportJobService(db), db, dir
}

func mustCreatePendingJob(t *testing.T, svc *AuditExportJobService, requester uint, sessionID uint) *model.AuditExportJob {
	t.Helper()
	job, created, err := svc.CreateJob(requester, "auditor", jobFilterForSession(sessionID))
	if err != nil || !created {
		t.Fatalf("建立 pending job: created=%v err=%v", created, err)
	}
	return job
}

func reloadJob(t *testing.T, db *gorm.DB, id uint) *model.AuditExportJob {
	t.Helper()
	var job model.AuditExportJob
	if err := db.First(&job, id).Error; err != nil {
		t.Fatalf("讀回 job %d: %v", id, err)
	}
	return &job
}

func TestWorkerSuccessFlow(t *testing.T) {
	exporter := &stubJobExporter{mode: "ok", payload: "zip-bytes-placeholder"}
	verifier := &countingVerifier{allowed: true}
	w, svc, db, dir := newWorkerEnv(t, exporter, verifier)
	if err := w.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	w.Stop()

	job := mustCreatePendingJob(t, svc, 1, 42)
	before := time.Now()
	w.RunCycle()

	got := reloadJob(t, db, job.ID)
	if got.Status != model.ExportJobDone {
		t.Fatalf("狀態: %s（error_summary=%s）", got.Status, got.ErrorSummary)
	}
	if exporter.calls != 1 || verifier.calls != 1 {
		t.Fatalf("exporter=%d verifier=%d，領件未走到打包與重驗", exporter.calls, verifier.calls)
	}
	// 雙時刻：exporter 收到發起時刻，job 記打包時刻與過期時刻
	if len(exporter.requestedAt) != 1 || !exporter.requestedAt[0].Equal(job.RequestedAt) {
		t.Fatalf("requestedAt 未傳遞: %v vs %v", exporter.requestedAt, job.RequestedAt)
	}
	if got.PackagedAt == nil || got.PackagedAt.Before(before) {
		t.Fatalf("packaged_at 缺失或早於打包: %v", got.PackagedAt)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(got.PackagedAt.Add(exportJobArtifactRetention)) {
		t.Fatalf("expires_at 不等於打包時刻＋保留期: %v", got.ExpiresAt)
	}
	// 產物：路徑、內容、大小、SHA-256、檔案權限 0600
	if got.ArtifactPath == "" || !strings.HasPrefix(got.ArtifactPath, dir) {
		t.Fatalf("artifact_path: %q", got.ArtifactPath)
	}
	body, err := os.ReadFile(got.ArtifactPath)
	if err != nil || string(body) != exporter.payload {
		t.Fatalf("產物內容: %v %q", err, body)
	}
	if got.ArtifactSize != int64(len(exporter.payload)) {
		t.Fatalf("大小: %d", got.ArtifactSize)
	}
	if got.ArtifactSHA256 == "" {
		t.Fatal("SHA-256 缺失")
	}
	info, err := os.Stat(got.ArtifactPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("產物檔權限 %o，要求 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("產物目錄權限 %o，要求 0700", dirInfo.Mode().Perm())
	}
}

func TestWorkerPanicDoesNotKillProcessAndHitsRetryCap(t *testing.T) {
	exporter := &stubJobExporter{mode: "panic"}
	verifier := &countingVerifier{allowed: true}
	w, svc, db, _ := newWorkerEnv(t, exporter, verifier)
	job := mustCreatePendingJob(t, svc, 1, 42)

	for i := 0; i < exportJobMaxAttempts; i++ {
		w.RunCycle() // panic 在 runJob 的 recover 內化；本測試跑到下一行即證明行程存活
	}
	if exporter.calls != exportJobMaxAttempts {
		t.Fatalf("panic 注入點走到 %d 次，want %d（-run 寫窄／前置早退防線）", exporter.calls, exportJobMaxAttempts)
	}
	got := reloadJob(t, db, job.ID)
	if got.Status != model.ExportJobFailed || got.ErrorSummary != model.ExportJobErrPackFailed {
		t.Fatalf("重試上限後應 failed/pack_failed: %s/%s", got.Status, got.ErrorSummary)
	}
	if got.Attempts != exportJobMaxAttempts {
		t.Fatalf("attempts=%d", got.Attempts)
	}
	// failed 不阻擋重新發起（與去重測試同一斷言在受理層，這裡驗端到端）
	if _, created, err := svc.CreateJob(1, "auditor", jobFilterForSession(42)); err != nil || !created {
		t.Fatalf("failed 後重新發起被擋: created=%v err=%v", created, err)
	}
}

func TestWorkerRetryReverifiesRequesterEachAttempt(t *testing.T) {
	exporter := &stubJobExporter{mode: "err"}
	verifier := &countingVerifier{allowed: true}
	w, svc, db, _ := newWorkerEnv(t, exporter, verifier)
	job := mustCreatePendingJob(t, svc, 1, 42)

	w.RunCycle() // 第一次：驗過、打包失敗、回 pending
	if got := reloadJob(t, db, job.ID); got.Status != model.ExportJobPending {
		t.Fatalf("首敗未回 pending: %s", got.Status)
	}
	w.RunCycle() // 重試：必須再驗一次
	if verifier.calls != 2 {
		t.Fatalf("重試未重驗申請者: verifier calls=%d", verifier.calls)
	}
}

func TestWorkerRestartRecoversRunning(t *testing.T) {
	exporter := &stubJobExporter{mode: "ok", payload: "x"}
	verifier := &countingVerifier{allowed: true}
	w, svc, db, _ := newWorkerEnv(t, exporter, verifier)
	job := mustCreatePendingJob(t, svc, 1, 42)
	if err := db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Update("status", model.ExportJobRunning).Error; err != nil {
		t.Fatalf("懸置 running: %v", err)
	}

	if err := w.Start(); err != nil { // 重啟＝Start：running→pending
		t.Fatalf("Start: %v", err)
	}
	w.Stop()
	if got := reloadJob(t, db, job.ID); got.Status != model.ExportJobPending {
		t.Fatalf("懸置 job 未恢復: %s", got.Status)
	}
}

func TestWorkerExpiresArtifacts(t *testing.T) {
	exporter := &stubJobExporter{mode: "ok", payload: "zip"}
	verifier := &countingVerifier{allowed: true}
	w, svc, db, _ := newWorkerEnv(t, exporter, verifier)
	if err := w.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	w.Stop()
	job := mustCreatePendingJob(t, svc, 1, 42)
	w.RunCycle()
	got := reloadJob(t, db, job.ID)
	if got.Status != model.ExportJobDone {
		t.Fatalf("前置 done 失敗: %s", got.Status)
	}
	artifact := got.ArtifactPath

	// 倒填過期時刻（不等真實 24h）
	past := time.Now().Add(-time.Minute)
	if err := db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Update("expires_at", past).Error; err != nil {
		t.Fatalf("倒填過期: %v", err)
	}
	w.RunCycle()

	got = reloadJob(t, db, job.ID)
	if got.Status != model.ExportJobExpired {
		t.Fatalf("逾期未轉 expired: %s", got.Status)
	}
	if got.ArtifactPath != "" {
		t.Fatalf("過期後 artifact_path 未清空: %q", got.ArtifactPath)
	}
	if got.ArtifactSHA256 == "" {
		t.Fatal("SHA-256 應保留供紀錄比對")
	}
	if _, err := os.Stat(artifact); !os.IsNotExist(err) {
		t.Fatalf("逾期產物檔仍在: %v", err)
	}
}

func TestWorkerCancelsRevokedRequesterAndAudits(t *testing.T) {
	// 真 AuditLogService 接 sqlite 審計庫（同步模式），讀回斷言「取消可於審計查得」
	auditDB := newJobServiceDB(t)
	if err := auditDB.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	oldDB := database.DB
	database.DB = auditDB
	t.Cleanup(func() { database.DB = oldDB })
	auditSvc := NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})

	exporter := &stubJobExporter{mode: "ok", payload: "never"}
	verifier := &countingVerifier{allowed: false} // 失權
	db := newJobServiceDB(t)
	dir := t.TempDir()
	w := NewAuditExportJobWorker(db, exporter, verifier.fn, auditSvc, dir)
	svc := NewAuditExportJobService(db)
	job := mustCreatePendingJob(t, svc, 7, 42)

	// 預置殘留產物（先前嘗試留下的暫存檔），取消必須連它一起清
	stale := w.jobArtifactTempPath(job.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatalf("預置殘檔: %v", err)
	}

	w.RunCycle()

	if verifier.calls != 1 {
		t.Fatalf("重驗注入點未走到: calls=%d", verifier.calls)
	}
	if exporter.calls != 0 {
		t.Fatalf("失權後仍進入打包: exporter calls=%d", exporter.calls)
	}
	got := reloadJob(t, db, job.ID)
	if got.Status != model.ExportJobFailed || got.ErrorSummary != model.ExportJobErrRequesterRevoked {
		t.Fatalf("失權取消狀態: %s/%s", got.Status, got.ErrorSummary)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("殘留產物未清: %v", err)
	}
	// 審計列：resource=audit_export、denied、details 含 job 與申請者識別
	var rows []model.AuditLog
	if err := auditDB.Where("resource = ?", string(model.ResourceAuditExport)).Find(&rows).Error; err != nil {
		t.Fatalf("查審計: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("取消審計列數=%d want 1", len(rows))
	}
	row := rows[0]
	if row.Status != model.StatusDenied ||
		!strings.Contains(row.Details, model.ExportJobErrRequesterRevoked) ||
		!strings.Contains(row.Details, fmt.Sprintf(`"job_id":"%d"`, job.ID)) ||
		!strings.Contains(row.Details, `"requester_id":"7"`) {
		t.Fatalf("取消審計欄位不齊: status=%s details=%s", row.Status, row.Details)
	}
}

// 驗證基礎設施失敗（err 非 nil）不取消——查不到不等於失權，走重試路徑
func TestWorkerVerifierErrorRetriesNotCancels(t *testing.T) {
	exporter := &stubJobExporter{mode: "ok", payload: "x"}
	verifier := &countingVerifier{allowed: false, err: errors.New("db down（注入）")}
	w, svc, db, _ := newWorkerEnv(t, exporter, verifier)
	job := mustCreatePendingJob(t, svc, 1, 42)

	w.RunCycle()
	got := reloadJob(t, db, job.ID)
	if got.Status != model.ExportJobPending {
		t.Fatalf("基礎設施失敗被誤判失權: %s/%s", got.Status, got.ErrorSummary)
	}
	if got.ErrorSummary == model.ExportJobErrRequesterRevoked {
		t.Fatal("誤標 requester_revoked")
	}
}

func TestWorkerPurgesTerminalRecords(t *testing.T) {
	exporter := &stubJobExporter{mode: "ok", payload: "x"}
	verifier := &countingVerifier{allowed: true}
	w, svc, db, _ := newWorkerEnv(t, exporter, verifier)
	job := mustCreatePendingJob(t, svc, 1, 42)
	stale := time.Now().Add(-exportJobRecordRetention - time.Hour)
	if err := db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		UpdateColumns(map[string]any{"status": model.ExportJobExpired, "updated_at": stale}).Error; err != nil {
		t.Fatalf("倒填終態: %v", err)
	}
	// 未逾保存期的終態列不得被清
	fresh := mustCreatePendingJob(t, svc, 1, 43)
	if err := db.Model(&model.AuditExportJob{}).Where("id = ?", fresh.ID).
		Update("status", model.ExportJobFailed).Error; err != nil {
		t.Fatalf("fresh failed: %v", err)
	}

	w.RunCycle()

	var count int64
	if err := db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("逾保存期終態列未清: count=%d err=%v", count, err)
	}
	if err := db.Model(&model.AuditExportJob{}).Where("id = ?", fresh.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("未逾期終態列被誤清: count=%d err=%v", count, err)
	}
}

func TestResolveExportArtifactDir(t *testing.T) {
	if got := ResolveExportArtifactDir("/tmp/x/"); got != "/tmp/x" {
		t.Fatalf("顯式值未正規化: %q", got)
	}
	t.Setenv("EXPORT_ARTIFACT_PATH", "/data/exports/")
	if got := ResolveExportArtifactDir(""); got != "/data/exports" {
		t.Fatalf("env 解析: %q", got)
	}
	t.Setenv("EXPORT_ARTIFACT_PATH", "")
	if got := ResolveExportArtifactDir(""); got != DefaultExportArtifactDir {
		t.Fatalf("出廠預設: %q", got)
	}
}
