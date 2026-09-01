package session

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
)

// 離機啟用後的錄影保留。
//
// # 兩段，語義刻意不同
//
//	快取清除段：帳冊 uploaded ∧ uploaded_at 早於快取期 → 刪本機檔，
//	            **`recording_path`／`recording_size`／`has_recording` 三欄不動、
//	            水位不動**。錄影仍可播（來源判定改走離機）。
//	政策到期段：錄影保留期到 → 本機檔照既有流程刪除，**帳冊標 local_purged**、
//	            擁有表清三欄、保管鏈事件；**對遠端零呼叫**（產品不代刪）。
//
// 把兩者混為一談會得到兩種相反的錯誤：快取段若清了三欄，離機的意義就沒了
// （證據還在遠端卻宣稱這場沒有錄影）；政策段若不清三欄，過期的錄影會以離機來源
// 繼續被播出來——保留政策形同虛設。

// OffsiteRetentionLedger 保留清理需要的帳冊面（消費者側窄介面）。
//
// 由 `offsite.Ledger` 滿足。**`session` 不得直接碰 `offsite_objects`**
// （表所有權歸 `internal/offsite`，資料邊界閘門盯著），故到期處置一律經本介面。
type OffsiteRetentionLedger interface {
	// ListLocalCacheExpired 本機快取期已到的物件（只讀）
	ListLocalCacheExpired(kind string, cutoff time.Time, limit int) ([]model.OffsiteObject, error)
	// MarkLocalPurged 到期處置（逐狀態轉移表）；**不發任何遠端呼叫**
	MarkLocalPurged(objectID uint) (offsite.RetentionOutcome, error)
}

// SetOffsiteRetentionLedger 接上保留清理用的帳冊面（組裝根）。
func (s *RecordingService) SetOffsiteRetentionLedger(l OffsiteRetentionLedger) { s.ledger = l }

// offsiteRetentionScanBatch 單輪快取清除的檢視上限（每筆一次 stat＋一次刪檔）。
const offsiteRetentionScanBatch = 2000

// PurgeOffsiteLocalCache 快取清除段：刪除已離機且超過快取期的本機錄影檔。
//
// cacheDays <= 0＝不提前清（政策出廠值），直接返回。
// 回傳實際刪除的檔數。
//
// **三欄與水位皆不動**：那兩者的語義是「這場的錄影沒了」，而這裡的事實是
// 「本機這一份沒了、遠端那一份還在」。錄影儲存量統計會因此下降，那是正確的
// ——它量的是本機目錄。
func (s *RecordingService) PurgeOffsiteLocalCache(cacheDays int) (int, error) {
	if cacheDays <= 0 || s.ledger == nil {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -cacheDays)
	rows, err := s.ledger.ListLocalCacheExpired(offsite.KindRecording, cutoff, offsiteRetentionScanBatch)
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	deleted := 0
	for i := range rows {
		sessionID := rows[i].OwnerID
		var sess model.Session
		if err := database.DB.Select("id", "recording_path").
			First(&sess, sessionID).Error; err != nil {
			log.Printf("[RecordingRetention] 快取清除查無會話（session=%d）: %v", sessionID, err)
			continue
		}
		if sess.RecordingPath == "" {
			continue
		}
		if err := os.Remove(sess.RecordingPath); err != nil {
			if !os.IsNotExist(err) {
				log.Printf("[RecordingRetention] 快取清除刪檔失敗（session=%d）: %v", sessionID, err)
			}
			continue
		}
		deleted++
	}
	if deleted > 0 {
		log.Printf("[RecordingRetention] 離機本機快取清除 %d 檔（快取期 %d 天；錄影仍可自離機副本播放）",
			deleted, cacheDays)
	}
	return deleted, nil
}

// PurgeExpiredOffsiteRecords 政策到期段的 DB 分支：本機**已無檔**但仍有帳冊列的
// 過期會話。
//
// Walk 段只看得到磁碟上還在的檔案；已被快取清除段刪掉的那些，其帳冊列與擁有表
// 三欄會永遠停在原狀——worker 仍可能領取（pending／failed）、離機狀態欄仍宣稱
// uploaded。本分支補上這一格：`offsite_object_id IS NOT NULL ∧ end_time < cutoff`
// → `MarkLocalPurged` ＋ 清三欄。
//
// maxPerRun <= 0＝不限（沿 retention_max_per_run 的「0＝無上限」語義）。
func (s *RecordingService) PurgeExpiredOffsiteRecords(retentionDays, maxPerRun int) (int, error) {
	if retentionDays <= 0 || s.ledger == nil {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	limit := maxPerRun
	if limit <= 0 || limit > offsiteRetentionScanBatch {
		limit = offsiteRetentionScanBatch
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// **`has_recording` 是掃描的終止條件**：到期處置會把它翻成 false，
	// 少了這個條件，已處置的列每輪都會被重新選出來（`offsite_object_id` 與
	// `end_time` 都不變），單輪上限於是永遠被同一批舊列吃光，新到期的列排不進來
	var sessions []model.Session
	if err := database.DB.
		Where("offsite_object_id IS NOT NULL AND has_recording AND end_time IS NOT NULL AND end_time < ?",
			cutoff).
		Order("id ASC").Limit(limit).Find(&sessions).Error; err != nil {
		return 0, fmt.Errorf("查詢已離機的過期會話失敗: %w", err)
	}

	purged := 0
	for i := range sessions {
		sess := sessions[i]
		if sess.RecordingPath != "" {
			// 本機檔還在＝Walk 段的責任（mtime 判準）；此處不代刪，
			// 避免兩條路徑對同一個檔案競跑
			if _, err := os.Stat(sess.RecordingPath); err == nil {
				continue
			}
		}
		if s.markOffsitePurged(&sess) {
			purged++
		}
	}
	return purged, nil
}

// markOffsitePurged 對單一會話執行到期處置：帳冊轉移＋擁有表清欄。
//
// 回傳 true＝本輪確實處置了一列（`uploading` 於租約期內會被延後，回 false）。
// **呼叫端須持有 s.mu**。
func (s *RecordingService) markOffsitePurged(sess *model.Session) bool {
	if sess.OffsiteObjectID == nil {
		return false
	}
	outcome, err := s.ledger.MarkLocalPurged(*sess.OffsiteObjectID)
	if err != nil {
		if errors.Is(err, offsite.ErrObjectNotInLedger) {
			// 帳冊列已不在（人為清理、部分還原）：擁有表的指標是懸空的，清掉它
			s.clearOffsiteColumns(sess.ID, "")
			return false
		}
		log.Printf("[RecordingRetention] 帳冊到期處置失敗（session=%d object=%d）: %v",
			sess.ID, *sess.OffsiteObjectID, err)
		return false
	}
	if outcome.Deferred {
		// 在途上傳：租約到期回收回 pending 後，下一輪按 pending 處置
		return false
	}
	if outcome.ClearOwnerColumns {
		s.clearOffsiteColumns(sess.ID, outcome.NewState)
	}
	// 冪等命中（帳冊已是 local_purged）不計入本輪處置數：那一列**這一輪沒發生
	// 任何事**，計進去會讓單輪上限被已完成的工作吃掉
	return !outcome.Idempotent
}

// clearOffsiteColumns 清錄影三欄並把離機快取欄寫成處置後的狀態。
//
// 三欄的清除語義沿 `clearRecordingInDB`；離機快取欄**不清空而是寫新狀態**
// （`local_purged`／維持 `foreign`）——清空會讓管理介面把「已到期清除」讀成
// 「從未離機」，那正是帳冊要記住的區別。
func (s *RecordingService) clearOffsiteColumns(sessionID uint, newState string) {
	updates := map[string]any{
		"recording_path": "",
		"recording_size": 0,
		"has_recording":  false,
		"offsite_status": newState,
	}
	if err := database.DB.Model(&model.Session{}).Where("id = ?", sessionID).
		Updates(updates).Error; err != nil {
		log.Printf("[RecordingRetention] 清除會話錄影欄位失敗（session=%d）: %v", sessionID, err)
	}
}
