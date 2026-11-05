package session

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/keystroke"
	"github.com/custodexa/backend/internal/keystroke/reader"
	"github.com/custodexa/backend/internal/model"
)

// 鍵盤紀錄的保留期清除。與錄影清理互不呼叫：錄影清理走錄影根目錄，
// 本清理只處理鍵盤紀錄根目錄與 keystroke_records 列。
//
// 判定以紀錄列為準：狀態為 complete／incomplete／failed，且
// COALESCE(ended_at, last_write_at, started_at) 早於截止時間者到期；
// status=recording 一律跳過（會話仍在進行或尚待對帳）。到期者刪檔、
// file_key_enc 設為空字串（不是 NULL，信封遷移的 `<> ''` 謂詞會跳過它）、標 purged。
// 檔案已不存在照樣標 purged。
//
// 這只抹除在線資料庫中的封存金鑰；清除之前取得的備份仍含當時的資料庫與檔案，
// 可解出清除前的紀錄。

// KeystrokePurgeResult 一次清除的統計。
type KeystrokePurgeResult struct {
	Purged  int // 到期紀錄列（含檔案）
	Orphans int // 無對應紀錄列的孤兒檔
	Errors  int // 無法處理的項目（路徑被拒、刪檔失敗）
}

var keystrokePurgeStatuses = []string{
	model.KeystrokeStatusComplete, model.KeystrokeStatusIncomplete, model.KeystrokeStatusFailed,
}

// PurgeKeystrokes 供保留排程呼叫的窄介面形式：回傳到期紀錄數、孤兒檔數，
// 有無法處理的項目時回傳錯誤（已處理者不回復）。
func (s *KeystrokeService) PurgeKeystrokes(days, limit int) (purged, orphans int, err error) {
	res, err := s.PurgeExpiredKeystrokes(days, limit)
	if err == nil && res.Errors > 0 {
		err = errors.New("部分鍵盤紀錄項目無法處理")
	}
	return res.Purged, res.Orphans, err
}

// PurgeExpiredKeystrokes 清除保留 days 天之外的鍵盤紀錄。limit 為紀錄列與孤兒檔
// 共用的單次上限（<=0 表示不限）。days<=0 不做事。
func (s *KeystrokeService) PurgeExpiredKeystrokes(days, limit int) (KeystrokePurgeResult, error) {
	var res KeystrokePurgeResult
	if days <= 0 {
		return res, nil
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	remaining := limit
	if remaining <= 0 {
		remaining = int(^uint(0) >> 1)
	}

	var rows []model.KeystrokeRecord
	if err := s.db.Where("status IN ? AND COALESCE(ended_at, last_write_at, started_at) < ?",
		keystrokePurgeStatuses, cutoff).Order("id").Limit(remaining).Find(&rows).Error; err != nil {
		return res, err
	}
	for i := range rows {
		row := &rows[i]
		if row.FilePath != "" {
			full, err := reader.ResolveInRoot(s.root, row.FilePath)
			if err != nil {
				log.Printf("[Keystroke] 清除略過路徑越界的紀錄: record=%d", row.ID)
				res.Errors++
				continue
			}
			if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
				log.Printf("[Keystroke] 刪除紀錄檔失敗: record=%d", row.ID)
				res.Errors++
				continue
			}
		}
		now := time.Now()
		if err := s.db.Model(&model.KeystrokeRecord{}).Where("id = ?", row.ID).Updates(map[string]interface{}{
			"status": model.KeystrokeStatusPurged, "purged_at": now, "file_key_enc": "",
		}).Error; err != nil {
			res.Errors++
			continue
		}
		res.Purged++
		remaining--
	}

	if remaining > 0 {
		n, errs := s.purgeOrphans(cutoff, remaining)
		res.Orphans += n
		res.Errors += errs
	}
	return res, nil
}

// purgeOrphans 依日期子目錄由舊到新掃描，只處理日期早於截止日的子目錄。
// 每個子目錄以一次查詢載入該日期前綴的全部 file_path 做集合比對，
// 無對應列且 mtime 早於截止時間的 .cxkr 一般檔刪除；空的日期子目錄移除。
func (s *KeystrokeService) purgeOrphans(cutoff time.Time, limit int) (removed, errCount int) {
	ents, err := os.ReadDir(s.root)
	if err != nil {
		return 0, 0
	}
	cutDay := cutoff.UTC().Format("2006-01-02")
	var dirs []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if _, perr := time.Parse("2006-01-02", e.Name()); perr != nil {
			continue
		}
		if e.Name() < cutDay {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		if removed >= limit {
			return
		}
		var known []string
		if err := s.db.Model(&model.KeystrokeRecord{}).Where("file_path LIKE ?", d+"/%").
			Pluck("file_path", &known).Error; err != nil {
			errCount++
			continue
		}
		set := make(map[string]bool, len(known))
		for _, k := range known {
			set[filepath.ToSlash(k)] = true
		}
		dirPath := filepath.Join(s.root, d)
		files, err := os.ReadDir(dirPath)
		if err != nil {
			errCount++
			continue
		}
		left := 0
		for _, f := range files {
			if removed >= limit {
				left++
				continue
			}
			info, ierr := f.Info()
			if ierr != nil || !info.Mode().IsRegular() || !strings.HasSuffix(f.Name(), keystroke.FileExt) {
				left++
				continue
			}
			if set[d+"/"+f.Name()] || !info.ModTime().Before(cutoff) {
				left++
				continue
			}
			if rerr := os.Remove(filepath.Join(dirPath, f.Name())); rerr != nil {
				errCount++
				left++
				continue
			}
			removed++
		}
		if left == 0 {
			_ = os.Remove(dirPath) // 空目錄才移除；非空時失敗是預期
		}
	}
	return
}
