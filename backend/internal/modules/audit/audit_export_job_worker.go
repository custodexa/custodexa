package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 證據包打包 worker。
//
// 單一背景 goroutine、Ticker 輪詢領件（沿改密 runner 的背景慣例）；每輪：
// 過期清掃 → 終態紀錄清理 → 領一件 pending 打包。**panic 不得殺行程**
// （sidecar 紅線：goroutine panic 直接終止行程，旁路功能不該有這個權力）——
// 週期本體與單件處理各有 recover，panic 走與失敗相同的重試／終態路徑。
//
// 領件與每次重試（重試＝回 pending 再被領）都重驗申請者主體狀態與稽核檢視
// 權限；失效即取消並清產物，取消入審計。

const (
	// exportJobPollInterval 領件輪詢間隔。3 秒——匯出是人工發起後等著下載的
	// 流程，間隔直接墊高申請者的等待底線；領件查詢是帶索引的單列掃描，成本可忽略
	exportJobPollInterval = 3 * time.Second
	// exportJobMaxAttempts 打包重試上限（含首次）。3 次——打包失敗多半是
	// 確定性錯誤（範圍解析、磁碟、解密），無限重試只會空轉（成本紅線：長迴圈須設上限）
	exportJobMaxAttempts = 3
)

// jobBundleExporter 打包能力的窄介面（AuditExportService 實作；測試注入替身）
type jobBundleExporter interface {
	ExportForJob(w io.Writer, filter *ExportFilter, exporterID uint,
		exporterName string, requestedAt time.Time) (*ExportManifest, error)
}

// ExportRequesterVerifier 申請者主體重驗：allowed=false＝已停用、刪除或失去
// 稽核檢視權限（job 取消）；err＝驗證基礎設施失敗（不取消，走重試路徑——
// 查不到不等於失權，誤取消會把暫時性故障放大成申請者的損失）。
// 判定本體由組裝根以 identity 服務組出（audit 模組不直讀 users 表）。
type ExportRequesterVerifier func(userID uint) (allowed bool, err error)

// AuditExportJobWorker 打包 worker
type AuditExportJobWorker struct {
	db        *gorm.DB
	exporter  jobBundleExporter
	verify    ExportRequesterVerifier
	auditLogs *AuditLogService // 取消入審計；nil（測試）時僅 log

	dir      string        // 產物暫存根（已 Resolve）
	interval time.Duration // 測試可縮短

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewAuditExportJobWorker 建立 worker（dir 經 ResolveExportArtifactDir 正規化）
func NewAuditExportJobWorker(db *gorm.DB, exporter jobBundleExporter,
	verify ExportRequesterVerifier, auditLogs *AuditLogService, dir string) *AuditExportJobWorker {
	return &AuditExportJobWorker{
		db: db, exporter: exporter, verify: verify, auditLogs: auditLogs,
		dir:      ResolveExportArtifactDir(dir),
		interval: exportJobPollInterval,
	}
}

// jobArtifactPath／jobArtifactTempPath 產物落檔路徑（最終檔與打包中暫存檔）
func (w *AuditExportJobWorker) jobArtifactPath(jobID uint) string {
	return filepath.Join(w.dir, fmt.Sprintf("job-%d.zip", jobID))
}

func (w *AuditExportJobWorker) jobArtifactTempPath(jobID uint) string {
	return w.jobArtifactPath(jobID) + ".tmp"
}

// Start 建產物目錄（0700）、恢復懸置 job（running→pending）、啟動輪詢 goroutine。
func (w *AuditExportJobWorker) Start() error {
	// MkdirAll 受 umask 影響，Chmod 顯式釘 0700：產物是解密後的證據明文，
	// 目錄權限最小化（backlog #1 的低成本部分）
	if err := os.MkdirAll(w.dir, 0o700); err != nil {
		return fmt.Errorf("建立匯出產物目錄失敗: %w", err)
	}
	if err := os.Chmod(w.dir, 0o700); err != nil {
		return fmt.Errorf("設定匯出產物目錄權限失敗: %w", err)
	}

	// 行程重啟時 running 是懸置態（打包早已中斷），重置回 pending 重跑——
	// 打包冪等：重跑只是重寫暫存檔。attempts 保留（重啟不清失敗記憶）
	if err := w.db.Model(&model.AuditExportJob{}).
		Where("status = ?", model.ExportJobRunning).
		Update("status", model.ExportJobPending).Error; err != nil {
		return fmt.Errorf("恢復懸置匯出 job 失敗: %w", err)
	}

	w.stopCh = make(chan struct{})
	w.doneCh = make(chan struct{})
	go w.loop()
	log.Println("[AuditExportJob] 證據包打包 worker 已啟動")
	return nil
}

// Stop 停止輪詢並等待當前週期結束
func (w *AuditExportJobWorker) Stop() {
	if w.stopCh == nil {
		return
	}
	close(w.stopCh)
	<-w.doneCh
	w.stopCh = nil
}

func (w *AuditExportJobWorker) loop() {
	defer close(w.doneCh)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.RunCycle()
		}
	}
}

// RunCycle 一輪：過期清掃 → 終態紀錄清理 → 領件打包。匯出供測試直呼
// （不經 Ticker 的時序不確定）；panic 在此兜底 recover——sidecar 紅線。
func (w *AuditExportJobWorker) RunCycle() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[AuditExportJob] 週期 panic 已攔截（行程續存）: %v", r)
		}
	}()
	now := time.Now()
	w.sweepExpired(now)
	w.purgeTerminalRecords(now)
	w.processNext(now)
}

// sweepExpired 逾期產物清除：刪檔＋轉 expired＋清產物路徑（SHA-256 與大小
// 保留供紀錄比對）。先刪檔後改態——反序在刪檔失敗時會留下「已 expired 但
// 檔案還在」的孤兒明文
func (w *AuditExportJobWorker) sweepExpired(now time.Time) {
	var due []model.AuditExportJob
	if err := w.db.Where("status = ? AND expires_at IS NOT NULL AND expires_at <= ?",
		model.ExportJobDone, now).Find(&due).Error; err != nil {
		log.Printf("[AuditExportJob] 過期掃描失敗: %v", err)
		return
	}
	for i := range due {
		job := due[i]
		if err := w.removeArtifacts(job.ID); err != nil {
			log.Printf("[AuditExportJob] job=%d 過期清檔失敗（下輪重試）: %v", job.ID, err)
			continue
		}
		if err := w.db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
			Updates(map[string]any{"status": model.ExportJobExpired, "artifact_path": ""}).Error; err != nil {
			log.Printf("[AuditExportJob] job=%d 轉過期態失敗: %v", job.ID, err)
		}
	}
}

// purgeTerminalRecords 終態紀錄保存期清理（防 job 表無界增長）。
// done 不在此列——它必先經過期清掃轉 expired 才進入終態清理
func (w *AuditExportJobWorker) purgeTerminalRecords(now time.Time) {
	cutoff := now.Add(-exportJobRecordRetention)
	if err := w.db.Where("status IN ? AND updated_at < ?",
		[]string{model.ExportJobFailed, model.ExportJobExpired}, cutoff).
		Delete(&model.AuditExportJob{}).Error; err != nil {
		log.Printf("[AuditExportJob] 終態紀錄清理失敗: %v", err)
	}
}

// processNext 領最舊的 pending 打包（CAS 領件；單 worker 下 CAS 是防未來多副本
// 誤入的低成本保險，多副本租約屬 HA 前置、記 backlog）。
//
// 取件用 Limit(1).Find 而非 First：本查詢每 3 秒一輪且**絕大多數輪次無件**，
// First 的 ErrRecordNotFound 會以 gorm Error 級寫 log——release 模式
// （logger.Error）下等於常態性刷出假錯誤
func (w *AuditExportJobWorker) processNext(now time.Time) {
	var due []model.AuditExportJob
	if err := w.db.Where("status = ?", model.ExportJobPending).
		Order("id ASC").Limit(1).Find(&due).Error; err != nil {
		log.Printf("[AuditExportJob] 領件查詢失敗: %v", err)
		return
	}
	if len(due) == 0 {
		return
	}
	job := due[0]
	claim := w.db.Model(&model.AuditExportJob{}).
		Where("id = ? AND status = ?", job.ID, model.ExportJobPending).
		Updates(map[string]any{"status": model.ExportJobRunning, "attempts": gorm.Expr("attempts + 1")})
	if claim.Error != nil {
		log.Printf("[AuditExportJob] job=%d 領件失敗: %v", job.ID, claim.Error)
		return
	}
	if claim.RowsAffected == 0 {
		return // 已被他人領走
	}
	job.Attempts++

	w.runJob(&job, now)
}

// runJob 單件打包；panic 走與錯誤相同的重試／終態路徑（sidecar 紅線＋重試上限）
func (w *AuditExportJobWorker) runJob(job *model.AuditExportJob, now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[AuditExportJob] job=%d 打包 panic 已攔截（行程續存）: %v", job.ID, r)
			w.failOrRetry(job, fmt.Errorf("panic: %v", r))
		}
	}()

	// 領件重驗申請者：主體已失效即取消並清產物（每次重試回到這裡再驗一次）
	allowed, err := w.verify(job.RequesterID)
	if err != nil {
		w.failOrRetry(job, fmt.Errorf("申請者重驗失敗: %w", err))
		return
	}
	if !allowed {
		w.cancelRevoked(job)
		return
	}

	filter, err := ParseExportFilterSnapshot(job.FilterJSON)
	if err != nil {
		w.failOrRetry(job, err)
		return
	}

	if err := w.removeArtifacts(job.ID); err != nil { // 重跑前清殘檔（冪等）
		w.failOrRetry(job, err)
		return
	}
	tempPath := w.jobArtifactTempPath(job.ID)
	f, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		w.failOrRetry(job, fmt.Errorf("開啟產物暫存檔失敗: %w", err))
		return
	}

	hasher := sha256.New()
	_, exportErr := w.exporter.ExportForJob(io.MultiWriter(f, hasher), filter,
		job.RequesterID, job.RequesterName, job.RequestedAt)
	closeErr := f.Close()
	if exportErr == nil {
		exportErr = closeErr
	}
	if exportErr != nil {
		_ = os.Remove(tempPath)
		w.failOrRetry(job, exportErr)
		return
	}

	w.finishJob(job, tempPath, hasher, time.Now())
}

// finishJob 產物落定：rename 暫存檔→最終檔，job 轉 done（雙時刻、SHA-256、
// 大小、過期時刻）
func (w *AuditExportJobWorker) finishJob(job *model.AuditExportJob, tempPath string, hasher hash.Hash, packagedAt time.Time) {
	finalPath := w.jobArtifactPath(job.ID)
	info, err := os.Stat(tempPath)
	if err != nil {
		w.failOrRetry(job, fmt.Errorf("讀取產物大小失敗: %w", err))
		return
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		_ = os.Remove(tempPath)
		w.failOrRetry(job, fmt.Errorf("產物落定失敗: %w", err))
		return
	}
	expires := packagedAt.Add(exportJobArtifactRetention)
	if err := w.db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Updates(map[string]any{
			"status":          model.ExportJobDone,
			"artifact_path":   finalPath,
			"artifact_sha256": fmt.Sprintf("%x", hasher.Sum(nil)),
			"artifact_size":   info.Size(),
			"error_summary":   "",
			"packaged_at":     packagedAt,
			"expires_at":      expires,
		}).Error; err != nil {
		// DB 更新失敗：檔案已落地但狀態未定，清檔回重試路徑——
		// 「檔案在而狀態不是 done」的中間態不可下載，留著只是孤兒明文
		_ = os.Remove(finalPath)
		w.failOrRetry(job, fmt.Errorf("job 完成態寫入失敗: %w", err))
		return
	}
	log.Printf("[AuditExportJob] job=%d 打包完成 size=%d expires=%s",
		job.ID, info.Size(), expires.Format(time.RFC3339))
}

// failOrRetry 失敗處置：未達重試上限回 pending（下輪重領、重驗、重打包），
// 達上限轉 failed＋機器碼摘要。原因原文只進 log（可能挾帶路徑等內部細節）
func (w *AuditExportJobWorker) failOrRetry(job *model.AuditExportJob, cause error) {
	log.Printf("[AuditExportJob] job=%d 第 %d 次打包失敗: %v", job.ID, job.Attempts, cause)
	status := model.ExportJobPending
	summary := ""
	if job.Attempts >= exportJobMaxAttempts {
		status = model.ExportJobFailed
		summary = model.ExportJobErrPackFailed
	}
	if err := w.db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Updates(map[string]any{"status": status, "error_summary": summary}).Error; err != nil {
		log.Printf("[AuditExportJob] job=%d 失敗態寫入失敗: %v", job.ID, err)
	}
}

// cancelRevoked 失權取消：清產物、轉 failed（機器碼 requester_revoked）、入審計
func (w *AuditExportJobWorker) cancelRevoked(job *model.AuditExportJob) {
	if err := w.removeArtifacts(job.ID); err != nil {
		log.Printf("[AuditExportJob] job=%d 失權清檔失敗: %v", job.ID, err)
	}
	if err := w.db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Updates(map[string]any{
			"status":        model.ExportJobFailed,
			"error_summary": model.ExportJobErrRequesterRevoked,
			"artifact_path": "",
		}).Error; err != nil {
		log.Printf("[AuditExportJob] job=%d 失權取消寫入失敗: %v", job.ID, err)
	}
	w.auditRevokedCancel(job)
	log.Printf("[AuditExportJob] job=%d 已因申請者失權取消", job.ID)
}

// auditRevokedCancel 取消入審計（spec：取消可於審計查得）。
// 行為者是系統（worker），非申請者本人——user_id=0/username=system 沿匿名列慣例；
// 申請者與 job 識別入 details
func (w *AuditExportJobWorker) auditRevokedCancel(job *model.AuditExportJob) {
	if w.auditLogs == nil {
		return
	}
	details, err := json.Marshal(map[string]string{
		"reason":       model.ExportJobErrRequesterRevoked,
		"job_id":       strconv.FormatUint(uint64(job.ID), 10),
		"requester_id": strconv.FormatUint(uint64(job.RequesterID), 10),
		"requester":    job.RequesterName,
	})
	if err != nil {
		log.Printf("[AuditExportJob] job=%d 取消審計欄位組裝失敗: %v", job.ID, err)
		return
	}
	jobRef := job.ID
	w.auditLogs.Log(&AuditLogEntry{
		UserID:     0,
		Username:   "system",
		Action:     model.ActionUpdate,
		Resource:   model.ResourceAuditExport,
		ResourceID: &jobRef,
		Status:     model.StatusDenied,
		Details:    string(details),
	})
}

// removeArtifacts 清除 job 的暫存與最終產物（不存在視為已清）
func (w *AuditExportJobWorker) removeArtifacts(jobID uint) error {
	for _, p := range []string{w.jobArtifactTempPath(jobID), w.jobArtifactPath(jobID)} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("清除產物 %s 失敗: %w", filepath.Base(p), err)
		}
	}
	return nil
}
