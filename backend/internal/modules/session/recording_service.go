package session

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/recorder"
	"gorm.io/gorm"
)

var (
	// ErrRecordingNotFound 錄製檔案不存在
	ErrRecordingNotFound = errors.New("錄製檔案不存在")
	// ErrSessionHasNoRecording Session 沒有錄製檔案
	ErrSessionHasNoRecording = errors.New("Session 沒有錄製檔案")
)

// RecordingService 錄製檔案管理服務
type RecordingService struct {
	basePath string       // 錄製檔案基礎路徑
	mu       sync.RWMutex // 保護並發存取
}

// NewRecordingService 創建錄製服務
// NewRecordingService 創建錄製服務。
//
// basePath 一律經 recorder.ResolveBasePath 正規化（空字串→RECORDING_PATH→出廠預設，
// 結果 filepath.Clean）：本服務的 filepath.Walk 以它為根，而 Walk 對子檔案回傳
// filepath.Join(root, ...)＝clean 路徑；寫入端（proxy 更名、asciicast 開檔）用的是同一個
// 收口點，兩邊因此逐字相同，clearRecordingInDB 的精確比對才可能命中。
func NewRecordingService(basePath string) *RecordingService {
	return &RecordingService{
		basePath: recorder.ResolveBasePath(basePath),
	}
}

// GetRecordingBySessionID 根據 SessionID 獲取錄製檔案路徑
func (s *RecordingService) GetRecordingBySessionID(sessionID uint) (filePath string, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 查詢 Session
	var session model.Session
	result := database.DB.First(&session, sessionID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", ErrSessionNotFound
		}
		return "", fmt.Errorf("查詢 Session 失敗: %w", result.Error)
	}

	// 檢查是否有錄製檔案
	if session.RecordingPath == "" {
		return "", ErrSessionHasNoRecording
	}

	// 檢查檔案是否存在
	if _, err := os.Stat(session.RecordingPath); os.IsNotExist(err) {
		return "", ErrRecordingNotFound
	}

	return session.RecordingPath, nil
}

// GetRecordingStream 獲取錄製檔案的 Reader（用於串流播放）
func (s *RecordingService) GetRecordingStream(sessionID uint) (io.ReadCloser, error) {
	filePath, err := s.GetRecordingBySessionID(sessionID)
	if err != nil {
		return nil, err
	}

	// 開啟檔案
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("開啟錄製檔案失敗: %w", err)
	}

	return file, nil
}

// RecordingStats 錄製統計資訊
type RecordingStats struct {
	TotalSize  int64  `json:"total_size"`  // 總大小（bytes）
	Count      int    `json:"count"`       // 錄製檔案數量
	OldestDate string `json:"oldest_date"` // 最早的錄製日期
	NewestDate string `json:"newest_date"` // 最新的錄製日期
}

// recordingDateOf 推導單一錄影檔所屬日期（YYYY-MM-DD）。
//
// 兩條錄影路徑的落檔結構不同，不能只認一種：文字終端由本後端寫入
// `basePath/YYYY-MM-DD/session-N.cast`（internal/recorder/asciicast.go），目錄名
// 即會話開始日，語義最準，優先採用；圖形協議（RDP/VNC）的錄影由 guacd 直接寫在
// basePath **根層**、沒有日期子目錄（實測 /var/lib/custodexa/recordings/session-33.guac，
// 更名邏輯見 internal/proxy/handler.go），沿用目錄名會在 time.Parse 失敗處被整個
// 跳過——結果是 Oldest/NewestDate 這兩個欄位靜默地只描述文字錄影。故退回檔案
// mtime（圖形錄影的最後寫入時刻＝會話結束），寧可日期粒度略偏也不要漏掉整類錄影。
func recordingDateOf(path string, info os.FileInfo) string {
	date := filepath.Base(filepath.Dir(path))
	if _, err := time.Parse("2006-01-02", date); err == nil {
		return date
	}
	return info.ModTime().Format("2006-01-02")
}

// countsTowardStorage 判定某個檔案是否計入錄影儲存量。
//
// **判準刻意採「排除非錄影檔」而非「白名單副檔名」**。本函式的消費端是
// custodexa_recording_storage_bytes 指標與 `GET /recordings/stats`（主控頁的錄影
// 佔用卡），它們問的是「錄影目錄吃掉多少磁碟」，權威是 du 而不是格式清單，
// 於是兩種判準的失敗模式完全不對稱：
//   - 白名單漏一種格式＝靜默低報。這正是本次修的缺陷——圖形協議的 .guac 自始
//     未被計入，而單檔比文字錄影大兩個數量級（實測 188KB vs 1KB 級），指標與
//     介面上的佔用量因此長期說謊，且沒有任何訊號會提醒你漏了。新協議上線
//     忘記加副檔名就會重演一次。
//   - 更關鍵：圖形錄影在會話**進行中根本沒有副檔名**（guacd 寫的是
//     basePath/rdp-<nanos>，會話結束才更名為 session-N.guac），任何副檔名白名單
//     都會漏掉最大那批檔案的整個存活期——而那正是空間失控時最需要看見的時刻。
//   - 排除清單漏擋一個雜項檔＝多算幾 byte。方向保守（寧可略為高報而非低報），
//     數字與 du 對得上，出錯時是可見的。
//
// 排除的是隱藏檔：recorder.ProbeWritable 會在錄影目錄建 `.probe-*` 探測檔（正常
// 即刻刪除，行程被砍時可能殘留），它不是錄影；同一條也擋掉 OS 產生的 .DS_Store。
// 非常規檔（symlink 等）亦不計——它們不代表本目錄的實際佔用，計入會重複計算。
func countsTowardStorage(info os.FileInfo) bool {
	if info.IsDir() || !info.Mode().IsRegular() {
		return false
	}
	return !strings.HasPrefix(info.Name(), ".")
}

// GetRecordingStats 獲取錄製統計資訊（涵蓋文字與圖形兩類錄影，判準見 countsTowardStorage）
func (s *RecordingService) GetRecordingStats() (*RecordingStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &RecordingStats{}

	// 遍歷錄製目錄
	err := filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// 如果目錄不存在，返回空統計
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}

		if !countsTowardStorage(info) {
			return nil
		}

		stats.TotalSize += info.Size()
		stats.Count++

		date := recordingDateOf(path, info)
		if stats.OldestDate == "" || date < stats.OldestDate {
			stats.OldestDate = date
		}
		if stats.NewestDate == "" || date > stats.NewestDate {
			stats.NewestDate = date
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("統計錄製檔案失敗: %w", err)
	}

	return stats, nil
}

// DeleteRecording 刪除錄製檔案
func (s *RecordingService) DeleteRecording(sessionID uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 查詢 Session
	var session model.Session
	result := database.DB.First(&session, sessionID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("查詢 Session 失敗: %w", result.Error)
	}

	// 檢查是否有錄製檔案
	if session.RecordingPath == "" {
		return ErrSessionHasNoRecording
	}

	filePath := session.RecordingPath

	// 刪除檔案
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("刪除錄製檔案失敗: %w", err)
	}

	// 更新資料庫（清空錄製資訊）
	updates := map[string]interface{}{
		"recording_path": "",
		"recording_size": 0,
		"has_recording":  false,
	}

	if err := database.DB.Model(&model.Session{}).Where("id = ?", sessionID).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新 Session 失敗: %w", err)
	}

	return nil
}

// CleanupOldRecordings 依保留期清理錄影目錄（涵蓋文字 .cast、圖形 .guac 與
// 中斷留下的無副檔名孤兒檔；判準與理由見迴圈內註解）。retentionDays<=0 由呼叫端
// （audit/retention_service.go）解讀為「永久不刪」而根本不會呼叫進來，此處視為錯誤。
func (s *RecordingService) CleanupOldRecordings(retentionDays int) (deletedCount int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if retentionDays <= 0 {
		return 0, fmt.Errorf("保留天數必須大於 0")
	}

	// 計算截止日期
	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)
	deletedCount = 0

	// 遍歷錄製目錄
	err = filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}

		// **刪除端刻意與統計端同判準（排除隱藏檔與非常規檔，其餘皆為候選），
		// 而非直覺上更保守的副檔名白名單**——理由是白名單在這裡不保守，是漏洞：
		//
		//   - 舊實作只認 .cast，圖形協議的 .guac 從未被清理過。保留期預設 90 天
		//     （對應 PCI 10.5.1，policy/security_policy_service.go），而圖形錄影是
		//     佔空間的大宗（實測單檔 188KB vs 文字錄影 1KB 級）：磁碟只增不減，
		//     稽核看到的「已設 90 天保留」對圖形錄影形同沒設。
		//   - 更關鍵的是**孤兒檔**：guacd 把進行中的圖形錄影寫成 basePath/rdp-<nanos>
		//     （無副檔名），由後端在會話結束時更名為 session-N.guac
		//     （internal/proxy/handler.go）。後端在會話中崩潰、容器被砍或更名失敗，
		//     該檔就永遠停在無副檔名狀態：DB 的 recording_path 記的是更名後的路徑，
		//     產品端再也讀不到它——它不是進行中的錄影，也不是可用的錄影，純粹佔磁碟，
		//     且每次異常中斷就多一個。任何副檔名白名單都會讓這批檔案永不被清理，
		//     那正是本次要修的空間洩漏本身。
		//
		// **「進行中的錄影不會被刪」由下面的 mtime 判準承擔，且它足夠**：檔案每次
		// 寫入都會刷新 mtime，進行中者的 mtime 恆約等於現在，不可能早於截止日；
		// 孤兒檔的 mtime 停在中斷時刻，過了保留期即為真正的過期資料。同一個時間
		// 判準把兩者乾淨分開，不需要第二套格式判準（多加一套只會把孤兒檔漏掉）。
		//
		// 註：兩端「同判準」但保守方向仍不同——統計端多算幾 byte 只是佔用量略為高報，
		// 刪除端多刪一檔則不可逆。此處敢對齊，是因為排除掉的隱藏檔（recorder 的
		// `.probe-*`、.DS_Store）與非常規檔本就不是錄影，而**留下**的每一類都確實
		// 是錄影目錄該由保留期管的資料。
		if !countsTowardStorage(info) {
			return nil
		}

		// 檢查檔案修改時間
		if info.ModTime().Before(cutoffDate) {
			// 刪除檔案
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("刪除檔案失敗 %s: %w", path, err)
			}

			// 更新資料庫（清空錄製資訊）
			if err := s.clearRecordingInDB(path); err != nil {
				// 記錄錯誤但繼續清理
				fmt.Printf("清空資料庫記錄失敗 %s: %v\n", path, err)
			}

			deletedCount++
		}

		return nil
	})

	if err != nil {
		return deletedCount, fmt.Errorf("清理錄製檔案失敗: %w", err)
	}

	// 清理空目錄
	s.cleanupEmptyDirs()

	return deletedCount, nil
}

// clearRecordingInDB 清空資料庫中的錄製資訊
func (s *RecordingService) clearRecordingInDB(filePath string) error {
	updates := map[string]interface{}{
		"recording_path": "",
		"recording_size": 0,
		"has_recording":  false,
	}

	// 根據檔案路徑查找並更新 Session
	return database.DB.Model(&model.Session{}).
		Where("recording_path = ?", filePath).
		Updates(updates).Error
}

// cleanupEmptyDirs 清理空的日期目錄
func (s *RecordingService) cleanupEmptyDirs() {
	filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() || path == s.basePath {
			return nil
		}

		// 檢查目錄是否為空
		entries, err := os.ReadDir(path)
		if err == nil && len(entries) == 0 {
			os.Remove(path)
		}

		return nil
	})
}

// GetRecordingMetadata 獲取錄製元數據
type RecordingMetadata struct {
	SessionID uint      `json:"session_id"`
	FilePath  string    `json:"file_path"`
	FileSize  int64     `json:"file_size"`
	Duration  int       `json:"duration"` // 秒數
	CreatedAt time.Time `json:"created_at"`
	Protocol  string    `json:"protocol"`
	Username  string    `json:"username"`
	AssetName string    `json:"asset_name,omitempty"`
}

// GetRecordingMetadata 獲取錄製元數據（含檔案資訊）
func (s *RecordingService) GetRecordingMetadata(sessionID uint) (*RecordingMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 查詢 Session（含關聯資料）
	var session model.Session
	result := database.DB.
		Preload("User").
		Preload("Asset").
		First(&session, sessionID)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("查詢 Session 失敗: %w", result.Error)
	}

	// 檢查是否有錄製檔案
	if session.RecordingPath == "" {
		return nil, ErrSessionHasNoRecording
	}

	// 檢查檔案是否存在並獲取檔案資訊
	fileInfo, err := os.Stat(session.RecordingPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrRecordingNotFound
		}
		return nil, fmt.Errorf("獲取檔案資訊失敗: %w", err)
	}

	// 組裝元數據
	metadata := &RecordingMetadata{
		SessionID: session.ID,
		FilePath:  session.RecordingPath,
		FileSize:  fileInfo.Size(),
		Duration:  session.Duration,
		CreatedAt: session.StartTime,
		Protocol:  string(session.Protocol),
	}

	// 添加用戶資訊
	if session.User != nil {
		metadata.Username = session.User.Username
	}

	// 添加資產資訊
	if session.Asset != nil {
		metadata.AssetName = session.Asset.Name
	}

	return metadata, nil
}

// RecordingProtocol 取該會話錄影的協定別（modular-architecture W4 4.8）。
//
// **薄包裝，語義逐字等同 GetRecordingMetadata 的 Protocol 欄**：匯出端（audit 模組）
// 對 metadata 的唯一用途是決定 zip 內副檔名，若讓它照抄 GetRecordingMetadata 的簽名，
// audit 就得 import 住在本包的 RecordingMetadata 型別——C↔E 環根本沒斷。收窄到只回
// 那一個字串，型別相依隨之消失（介面宣告見 internal/modules/audit/recording_port.go）。
// 錯誤一律原樣上拋，呼叫端的「取不到就跳過該筆」處置與收口前逐字相同。
func (s *RecordingService) RecordingProtocol(sessionID uint) (string, error) {
	meta, err := s.GetRecordingMetadata(sessionID)
	if err != nil {
		return "", err
	}
	return meta.Protocol, nil
}
