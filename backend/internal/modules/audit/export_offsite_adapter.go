package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
	"gorm.io/gorm"
)

// ExportOffsiteAdapter 證據包產物的離機上傳適配。
//
// 與錄影 adapter 的兩個實質差異：
//
//   - **無寬限期**：zip 由本後端寫完、rename 後才轉 done，大小精確、沒有尾段，
//     `finishJob` 排入的當下即可取件。
//   - **到期語義不同**：產物的 `expires_at` 是**下載窗口**（24 小時），
//     不是保留期。窗口過了本機檔即被清掃刪除，但遠端副本仍在——那正是
//     「組織的證據寄存」角色，故回填分類**不因逾期而跳過**已上傳者。
type ExportOffsiteAdapter struct {
	db  *gorm.DB
	now func() time.Time
}

// NewExportOffsiteAdapter 建立證據包 adapter。
func NewExportOffsiteAdapter(db *gorm.DB) *ExportOffsiteAdapter {
	return &ExportOffsiteAdapter{db: db, now: time.Now}
}

// SetClockForTest 覆寫時間源（僅測試）。
func (a *ExportOffsiteAdapter) SetClockForTest(now func() time.Time) { a.now = now }

// Kind 本 adapter 服務的上傳目標種類。
func (a *ExportOffsiteAdapter) Kind() string { return offsite.KindExport }

func (a *ExportOffsiteAdapter) loadJob(ownerID uint) (*model.AuditExportJob, error) {
	var job model.AuditExportJob
	if err := a.db.First(&job, ownerID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrExportJobNotFound
		}
		return nil, fmt.Errorf("查詢匯出工作失敗: %w", err)
	}
	return &job, nil
}

// Open 開啟產物 zip 供上傳。
//
// 產物尚未落定（非 done、或 artifact_path 為空）時回 `ErrNotReadyYet`：
// **延後而不計 attempts**——那不是失敗，是還沒到。
func (a *ExportOffsiteAdapter) Open(ownerID uint) (io.ReadSeekCloser, int64, time.Time, error) {
	job, err := a.loadJob(ownerID)
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	if job.Status != model.ExportJobDone || job.ArtifactPath == "" {
		return nil, 0, time.Time{}, offsite.ErrNotReadyYet
	}
	info, err := os.Stat(job.ArtifactPath)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("讀取證據包產物資訊失敗: %w", err)
	}
	f, err := os.Open(job.ArtifactPath)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("開啟證據包產物失敗: %w", err)
	}
	return f, info.Size(), info.ModTime(), nil
}

// Stat 只取大小與 mtime（上傳後複驗）。
func (a *ExportOffsiteAdapter) Stat(ownerID uint) (int64, time.Time, error) {
	job, err := a.loadJob(ownerID)
	if err != nil {
		return 0, time.Time{}, err
	}
	if job.ArtifactPath == "" {
		return 0, time.Time{}, offsite.ErrNotReadyYet
	}
	info, err := os.Stat(job.ArtifactPath)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("讀取證據包產物資訊失敗: %w", err)
	}
	return info.Size(), info.ModTime(), nil
}

// SetStatus 寫回擁有表的顯示快取（objectID=0 時不動指標欄，語義同錄影 adapter）。
func (a *ExportOffsiteAdapter) SetStatus(ownerID, objectID uint, status string) error {
	updates := map[string]any{"offsite_status": status}
	if objectID != 0 {
		updates["offsite_object_id"] = objectID
	}
	if err := a.db.Model(&model.AuditExportJob{}).Where("id = ?", ownerID).
		Updates(updates).Error; err != nil {
		return fmt.Errorf("寫回匯出工作離機快取失敗: %w", err)
	}
	return nil
}

// Describe 擁有者的顯示事實。
//
// RetentionDeadline 取 `expires_at`（**下載窗口**而非保留期）：失敗清單上
// 「距到期天數」對證據包的意義是「還剩多久這份產物在本機消失」，逾期後本機無檔，
// 屆時只剩遠端副本。
func (a *ExportOffsiteAdapter) Describe(ownerID uint) (offsite.OwnerDescription, error) {
	job, err := a.loadJob(ownerID)
	if err != nil {
		return offsite.OwnerDescription{}, err
	}
	out := offsite.OwnerDescription{
		Label:             fmt.Sprintf("job-%d", job.ID),
		EndedAt:           job.CreatedAt,
		RetentionDeadline: job.ExpiresAt,
	}
	if job.PackagedAt != nil {
		// **打包完成時刻決定 object key 的年月分桶**：用「現在」會讓重傳落到別的桶
		out.EndedAt = *job.PackagedAt
	}
	return out, nil
}

// ListUnenqueued 尚未排入的已完成工作（最新優先）。
//
// 只列 `done` 且產物路徑非空者：`expired` 的本機檔已被清掃刪除，回填它只會
// 每輪掃描各記一次「缺檔」。
func (a *ExportOffsiteAdapter) ListUnenqueued(limit int) ([]uint, error) {
	if limit <= 0 {
		return nil, nil
	}
	var ids []uint
	if err := a.db.Model(&model.AuditExportJob{}).
		Where("offsite_object_id IS NULL AND status = ? AND artifact_path <> ''", model.ExportJobDone).
		Order("id DESC").Limit(limit).
		Pluck("id", &ids).Error; err != nil {
		return nil, fmt.Errorf("查詢未排入離機的匯出工作失敗: %w", err)
	}
	return ids, nil
}

// Classify 回填掃描的分類。
//
// **不產出 `expired`**：產物的下載窗口過期不代表它不該離機——遠端副本是組織的
// 證據寄存，窗口只約束產品自己的下載入口。逾期者的本機檔已被
// `sweepExpired` 刪除，故落在 `missing`。
func (a *ExportOffsiteAdapter) Classify(ownerID uint) (offsite.BackfillClass, error) {
	job, err := a.loadJob(ownerID)
	if err != nil {
		return "", err
	}
	if job.ArtifactPath == "" {
		return offsite.BackfillMissing, nil
	}
	if _, err := os.Stat(job.ArtifactPath); err != nil {
		return offsite.BackfillMissing, nil
	}
	return offsite.BackfillUploadable, nil
}

// Extension 產物副檔名（不含點）。
func (a *ExportOffsiteAdapter) Extension(uint) (string, error) { return "zip", nil }

// MarkForeignBatch 世代退役時批次把擁有表快取寫成 foreign（設定服務的鎖內交易）。
//
// 判準與錄影 adapter 相同、理由亦相同：audit 不得碰 `offsite_objects`，
// 而帳冊不變式使「非終態的快取」與「該世代的帳冊列」逐列對應。
func (a *ExportOffsiteAdapter) MarkForeignBatch(tx *gorm.DB, generationID uint) error {
	if err := tx.Model(&model.AuditExportJob{}).
		Where("offsite_object_id IS NOT NULL AND offsite_status IN ?", []string{
			offsite.StatePending, offsite.StateUploading, offsite.StateUploaded,
			offsite.StateFailed, offsite.StateIntegrityMismatch,
		}).
		Update("offsite_status", offsite.StateForeign).Error; err != nil {
		return fmt.Errorf("批次寫回匯出工作離機快取（世代 %d 退役）失敗: %w", generationID, err)
	}
	return nil
}
