package session

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

// RecordingOffsiteAdapter 會話錄影的離機上傳適配。
//
// **分工反轉後的形狀**：`offsite.Uploader` 擁有並讀寫 `offsite_objects`，
// 本 adapter 只做四件事——開啟本機錄影檔（含圖形寬限期）、寫回擁有表快取、
// 描述擁有者、回填掃描的列舉與分類。`session` 模組對 `offsite_objects`
// **零直接存取**（資料邊界閘門與 offsite 包內守衛雙向盯著）。
//
// 建構於組裝根：`*gorm.DB` 與保留天數取得函式由外部注入，本型別不讀全域也不讀政策表
// ——保留天數住在 `policy` 模組，讓 session 為了一個顯示欄位去 import 它並不划算，
// 而組裝根本來就同時看得到兩者。
type RecordingOffsiteAdapter struct {
	db *gorm.DB
	// retentionDays 錄影保留天數（0＝永久不刪）。函式而非值：政策是營運中會改的，
	// 快取一個啟動當下的數字會讓「調短保留期」對回填分類與失敗清單的到期欄失效
	retentionDays func() int
	now           func() time.Time
}

// NewRecordingOffsiteAdapter 建立錄影 adapter。retentionDays 為 nil 時視為永久（0）。
func NewRecordingOffsiteAdapter(db *gorm.DB, retentionDays func() int) *RecordingOffsiteAdapter {
	if retentionDays == nil {
		retentionDays = func() int { return 0 }
	}
	return &RecordingOffsiteAdapter{db: db, retentionDays: retentionDays, now: time.Now}
}

// SetClockForTest 覆寫時間源（僅測試）。
func (a *RecordingOffsiteAdapter) SetClockForTest(now func() time.Time) { a.now = now }

// Kind 本 adapter 服務的上傳目標種類。
func (a *RecordingOffsiteAdapter) Kind() string { return offsite.KindRecording }

// isGraphicsProtocol 圖形協議判準（錄影由 guacd 直寫，尾段晚於 rename）。
//
// 與 `audit_export_service.go:recordingExt` 同一組值域；兩處各自為政是既有形態，
// 本函式不代改對方（那屬另一個收口任務）。
func isGraphicsProtocol(p model.ProtocolType) bool {
	return p == model.ProtocolRDP || p == model.ProtocolVNC
}

// loadSession 取會話（不含關聯）。查無回 ErrSessionNotFound。
func (a *RecordingOffsiteAdapter) loadSession(ownerID uint) (*model.Session, error) {
	var s model.Session
	if err := a.db.First(&s, ownerID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("查詢會話失敗: %w", err)
	}
	return &s, nil
}

// Open 開啟錄影檔供上傳；回傳大小與 mtime。
//
// **圖形錄影的寬限期**：guacd 直寫且無收尾訊號，尾段寫入晚於 rename。
// 取件條件＝`now − mtime ≥ offsite.GraphicsUploadGraceSeconds` 且該會話已非
// `active`；未滿足回 `offsite.ErrNotReadyYet`（**延後，不計 attempts**——寬限期不是失敗）。
// 文字錄影的 fd 於 `UpdateRecording` 之前即由後端關閉、大小精確，故即可取件。
func (a *RecordingOffsiteAdapter) Open(ownerID uint) (io.ReadSeekCloser, int64, time.Time, error) {
	sess, err := a.loadSession(ownerID)
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	if sess.RecordingPath == "" {
		return nil, 0, time.Time{}, ErrSessionHasNoRecording
	}
	info, err := os.Stat(sess.RecordingPath)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("讀取錄影檔資訊失敗: %w", err)
	}
	if isGraphicsProtocol(sess.Protocol) {
		if sess.Status == model.SessionStatusActive {
			return nil, 0, time.Time{}, offsite.ErrNotReadyYet
		}
		if a.now().Sub(info.ModTime()) < time.Duration(offsite.GraphicsUploadGraceSeconds)*time.Second {
			return nil, 0, time.Time{}, offsite.ErrNotReadyYet
		}
	}
	f, err := os.Open(sess.RecordingPath)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("開啟錄影檔失敗: %w", err)
	}
	return f, info.Size(), info.ModTime(), nil
}

// Stat 只取大小與 mtime（上傳後複驗；不必再開檔）。
func (a *RecordingOffsiteAdapter) Stat(ownerID uint) (int64, time.Time, error) {
	sess, err := a.loadSession(ownerID)
	if err != nil {
		return 0, time.Time{}, err
	}
	if sess.RecordingPath == "" {
		return 0, time.Time{}, ErrSessionHasNoRecording
	}
	info, err := os.Stat(sess.RecordingPath)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("讀取錄影檔資訊失敗: %w", err)
	}
	return info.Size(), info.ModTime(), nil
}

// SetStatus 寫回擁有表的顯示快取。
//
// **objectID 為 0 時不動指標欄**：回填掃描的 `skipped_missing`／`skipped_expired`
// 兩類**不建帳冊列**，指標必須維持 NULL——`idx_sessions_offsite_backfill` 的
// partial WHERE 正是 `offsite_object_id IS NULL`，寫進去會讓它們自回填視野中消失。
func (a *RecordingOffsiteAdapter) SetStatus(ownerID, objectID uint, status string) error {
	updates := map[string]any{"offsite_status": status}
	if objectID != 0 {
		updates["offsite_object_id"] = objectID
	}
	if err := a.db.Model(&model.Session{}).Where("id = ?", ownerID).
		Updates(updates).Error; err != nil {
		return fmt.Errorf("寫回會話離機快取失敗: %w", err)
	}
	return nil
}

// Describe 擁有者的顯示事實（失敗清單與 object key 的年月分桶）。
//
// **EndedAt 必須是真實的結束時刻**：它決定 object key 的年月分桶
// （`offsite.RecordingObjectKey`），取「現在」會讓同一場會話在不同時點重傳落到
// 不同的 key。`end_time` 為 NULL 的存量列退回 `start_time`（同一場會話的分桶仍穩定）。
func (a *RecordingOffsiteAdapter) Describe(ownerID uint) (offsite.OwnerDescription, error) {
	var sess model.Session
	if err := a.db.Preload("User").Preload("Asset").First(&sess, ownerID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return offsite.OwnerDescription{}, ErrSessionNotFound
		}
		return offsite.OwnerDescription{}, fmt.Errorf("查詢會話失敗: %w", err)
	}
	out := offsite.OwnerDescription{
		Label:   sess.SessionID,
		EndedAt: sess.StartTime,
	}
	if sess.EndTime != nil {
		out.EndedAt = *sess.EndTime
	}
	if sess.User != nil && sess.Asset != nil {
		out.Label = sess.User.Username + "@" + sess.Asset.Name
	}
	if days := a.retentionDays(); days > 0 {
		deadline := out.EndedAt.AddDate(0, 0, days)
		out.RetentionDeadline = &deadline
	}
	return out, nil
}

// ListUnenqueued 尚未排入的會話 id（最新優先）。
//
// 查詢面對齊 `idx_sessions_offsite_backfill`（`(id) WHERE offsite_object_id IS NULL
// AND has_recording`）。回填的兩個跳過分類刻意仍留在本視野內：檔案還原回來
// （`skipped_missing`）或保留期改長（`skipped_expired`）之後，下一輪掃描要能再看一次。
func (a *RecordingOffsiteAdapter) ListUnenqueued(limit int) ([]uint, error) {
	if limit <= 0 {
		return nil, nil
	}
	var ids []uint
	if err := a.db.Model(&model.Session{}).
		Where("offsite_object_id IS NULL AND has_recording").
		Order("id DESC").Limit(limit).
		Pluck("id", &ids).Error; err != nil {
		return nil, fmt.Errorf("查詢未排入離機的會話失敗: %w", err)
	}
	return ids, nil
}

// Classify 回填掃描的三分類。
func (a *RecordingOffsiteAdapter) Classify(ownerID uint) (offsite.BackfillClass, error) {
	sess, err := a.loadSession(ownerID)
	if err != nil {
		return "", err
	}
	if sess.RecordingPath == "" {
		// has_recording 為真而路徑為空＝資料不一致；歸「缺檔」而非建列上傳
		return offsite.BackfillMissing, nil
	}
	info, err := os.Stat(sess.RecordingPath)
	if err != nil {
		return offsite.BackfillMissing, nil
	}
	if days := a.retentionDays(); days > 0 {
		// 判準與 CleanupOldRecordings 同源（檔案 mtime 對 cutoff），
		// 否則會出現「掃描說沒過期、清理正要刪」的競跑
		if info.ModTime().Before(a.now().AddDate(0, 0, -days)) {
			return offsite.BackfillExpired, nil
		}
	}
	return offsite.BackfillUploadable, nil
}

// Extension 物件 key 的副檔名（不含點）。
func (a *RecordingOffsiteAdapter) Extension(ownerID uint) (string, error) {
	sess, err := a.loadSession(ownerID)
	if err != nil {
		return "", err
	}
	if isGraphicsProtocol(sess.Protocol) {
		return "guac", nil
	}
	return "cast", nil
}

// MarkForeignBatch 世代退役時批次把擁有表快取寫成 foreign（在設定服務的鎖內交易中）。
//
// **判準是「快取態」而非世代欄，因為 session 不得碰 `offsite_objects`**：
// 帳冊的不變式使兩者等價——`Ledger.MarkForeign` 轉移的正是
// `state ∉ {local_purged, foreign}` 的列，而任一時刻**非終態的帳冊列必然屬於現行世代**
// （舊世代的列在它退役的那一筆交易裡就已轉 foreign）。故以相同的狀態集合圈選快取，
// 與帳冊側逐列對應。generationID 只用於錯誤訊息——它是呼叫端的脈絡，不是本查詢的條件。
func (a *RecordingOffsiteAdapter) MarkForeignBatch(tx *gorm.DB, generationID uint) error {
	if err := tx.Model(&model.Session{}).
		Where("offsite_object_id IS NOT NULL AND offsite_status IN ?", []string{
			offsite.StatePending, offsite.StateUploading, offsite.StateUploaded,
			offsite.StateFailed, offsite.StateIntegrityMismatch,
		}).
		Update("offsite_status", offsite.StateForeign).Error; err != nil {
		return fmt.Errorf("批次寫回會話離機快取（世代 %d 退役）失敗: %w", generationID, err)
	}
	return nil
}
