package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/custodexa/backend/internal/recorder"
	"gorm.io/gorm"
)

var (
	// ErrRecordingNotFound 錄製檔案不存在
	ErrRecordingNotFound = errors.New("錄製檔案不存在")
	// ErrSessionHasNoRecording Session 沒有錄製檔案
	ErrSessionHasNoRecording = errors.New("Session 沒有錄製檔案")
)

// OffsiteRetriever 離機取回面（消費者側窄介面）。
//
// 由 `offsite.Fetcher` 滿足；nil＝本部署未組裝離機子系統，來源判定退回
// 「本機有就播、沒有就是既有錯誤」的原行為（零改動）。
type OffsiteRetriever interface {
	// Object 帳冊列（size／sha256／state 是來源判定的權威事實）
	Object(objectID uint) (*model.OffsiteObject, error)
	// Fetch 取回並驗證離機副本；驗證不符回 offsite.ErrIntegrityMismatch（零位元組交付）
	Fetch(ctx context.Context, objectID uint) (*offsite.FetchedObject, error)
}

// RecordingSourceLocal／Offsite 錄影本體的來源（`RecordingMetadata.source`
// 與審計 Details 的 `source`）。
const (
	RecordingSourceLocal   = "local"
	RecordingSourceOffsite = "offsite"
)

// 退路原因（進審計 Details，不對外分類）。
const (
	// FallbackLocalMissing 本機 stat 失敗（檔案不在）
	FallbackLocalMissing = "local_missing"
	// FallbackLocalUnreadable 本機檔在但開不了（權限、I/O 錯）
	FallbackLocalUnreadable = "local_unreadable"
	// FallbackLocalTruncated 本機檔比帳冊記載的短＝截斷
	FallbackLocalTruncated = "local_truncated"
	// FallbackLocalDivergent 大小相同而整檔雜湊不符＝本機被改動
	FallbackLocalDivergent = "local_divergent"
)

// ResolvedRecording 來源判定的結果。
type ResolvedRecording struct {
	// Path 可供交付的檔案路徑：本機錄影檔，或**已驗證**的離機暫存檔
	Path string
	// Source local／offsite
	Source string
	// Fallback 走離機的原因（空＝本機來源）
	Fallback string
	// Size 交付內容的大小（離機時取帳冊 size）
	Size int64
	// Name 對外的檔名（恆取自會話的 recording_path）。**不得用 Path 的 basename**：
	// 離機來源時那是暫存檔名（物件 id），下載下來的檔案會失去可辨識性
	Name string
	// ModTime 供 ServeContent 的 Last-Modified
	ModTime time.Time
}

// RecordingService 錄製檔案管理服務
type RecordingService struct {
	basePath string       // 錄製檔案基礎路徑
	mu       sync.RWMutex // 保護並發存取
	// offsite 離機取回面；nil＝未組裝
	offsite OffsiteRetriever
	// ledger 保留清理用的帳冊面；nil＝未組裝
	ledger OffsiteRetentionLedger
}

// SetOffsiteRetriever 接上離機取回面（組裝根）。
func (s *RecordingService) SetOffsiteRetriever(r OffsiteRetriever) { s.offsite = r }

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

// GetRecordingBySessionID 根據 SessionID 獲取可交付的錄製檔案路徑
// （離機來源時為已驗證的暫存檔；來源與退路原因見 ResolveRecording）。
func (s *RecordingService) GetRecordingBySessionID(sessionID uint) (filePath string, err error) {
	res, err := s.ResolveRecording(sessionID, false)
	if err != nil {
		return "", err
	}
	return res.Path, nil
}

// ResolveRecording 來源判定。
//
// # 判準
//
//	本機 stat＋open 成功 ∧ 大小 ≥ 帳冊 size            → 本機
//	  （圖形錄影的尾段使本機**合法地**比上傳版長，不是異常）
//	本機大小 < 帳冊 size                                 → 離機，退路 local_truncated
//	本機 stat 失敗／open 失敗                            → 離機，退路 local_missing／local_unreadable
//	整檔路徑（verifyHash）大小相等而雜湊不符             → 離機，退路 local_divergent
//	未離機且本機缺檔                                     → 既有錯誤（零改動）
//
// verifyHash 只在**整檔路徑**（證據包裝入、下載）為真：那些路徑本就逐位元組讀完
// 整個檔案，順手算雜湊幾乎免費；串流播放不算——為了播一個 Range 去讀完整檔
// 是把首位元組延遲換成一個不對稱的保證。
func (s *RecordingService) ResolveRecording(sessionID uint, verifyHash bool) (ResolvedRecording, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sess model.Session
	result := database.DB.First(&sess, sessionID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ResolvedRecording{}, ErrSessionNotFound
		}
		return ResolvedRecording{}, fmt.Errorf("查詢 Session 失敗: %w", result.Error)
	}
	return s.resolveFor(&sess, verifyHash)
}

// resolveFor 對**已讀出的**會話列做來源判定。
//
// **不自己取鎖也不自己查庫**：GetRecordingMetadata 需要帶關聯的同一列，
// 讓它把那一列傳進來即可——否則同一次呼叫要打兩趟一模一樣的查詢，
// 而 RWMutex 的遞迴 RLock 在有寫者排隊時還會死鎖。呼叫端持鎖。
func (s *RecordingService) resolveFor(sess *model.Session, verifyHash bool) (ResolvedRecording, error) {
	if sess.RecordingPath == "" {
		return ResolvedRecording{}, ErrSessionHasNoRecording
	}

	info, statErr := os.Stat(sess.RecordingPath)

	// 未組裝離機子系統或本會話從未排入：逐字維持既有行為
	// （錯誤映射沿 GetRecordingMetadata 的既有形態：不存在→ErrRecordingNotFound，
	// 其餘 stat 錯誤→包裝上拋）
	if s.offsite == nil || sess.OffsiteObjectID == nil {
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return ResolvedRecording{}, ErrRecordingNotFound
			}
			return ResolvedRecording{}, fmt.Errorf("獲取檔案資訊失敗: %w", statErr)
		}
		return ResolvedRecording{Path: sess.RecordingPath, Source: RecordingSourceLocal,
			Size: info.Size(), ModTime: info.ModTime(),
			Name: filepath.Base(sess.RecordingPath)}, nil
	}

	fallback := ""
	switch {
	case statErr != nil:
		fallback = FallbackLocalMissing
		if !os.IsNotExist(statErr) {
			fallback = FallbackLocalUnreadable
		}
	default:
		if f, openErr := os.Open(sess.RecordingPath); openErr != nil {
			fallback = FallbackLocalUnreadable
		} else {
			fallback = s.localAnomaly(f, info, *sess.OffsiteObjectID, verifyHash)
			f.Close()
		}
	}
	if fallback == "" {
		return ResolvedRecording{Path: sess.RecordingPath, Source: RecordingSourceLocal,
			Size: info.Size(), ModTime: info.ModTime(),
			Name: filepath.Base(sess.RecordingPath)}, nil
	}

	fetched, err := s.offsite.Fetch(context.Background(), *sess.OffsiteObjectID)
	if err != nil {
		// 帳冊沒有可取回的副本時，對外仍收斂為既有的「錄影檔不存在」——
		// 離機側的失敗細分只進審計與帳冊
		if errors.Is(err, offsite.ErrNoOffsiteCopy) {
			return ResolvedRecording{}, ErrRecordingNotFound
		}
		return ResolvedRecording{}, err
	}
	return ResolvedRecording{Path: fetched.Path, Source: RecordingSourceOffsite,
		Fallback: fallback, Size: fetched.Size, ModTime: fetched.UploadedAt,
		Name: filepath.Base(sess.RecordingPath)}, nil
}

// localAnomaly 本機檔異常的判定（回空字串＝本機可用）。
func (s *RecordingService) localAnomaly(f *os.File, info os.FileInfo, objectID uint, verifyHash bool) string {
	row, err := s.offsite.Object(objectID)
	if err != nil {
		// 帳冊讀不到：本機檔在且開得了就用本機——沒有理由因為旁路子系統的
		// 讀取失敗而拒絕交付一個存在的錄影
		log.Printf("[RecordingService] 讀取離機帳冊列失敗（object=%d，改用本機來源）: %v", objectID, err)
		return ""
	}
	if row.SHA256 == "" || row.Size == 0 {
		return "" // 尚未上傳成功：離機側沒有可比對的事實
	}
	if info.Size() < row.Size {
		return FallbackLocalTruncated
	}
	if verifyHash && info.Size() == row.Size {
		sum := sha256.New()
		if _, err := io.Copy(sum, f); err != nil {
			return FallbackLocalUnreadable
		}
		if hex.EncodeToString(sum.Sum(nil)) != row.SHA256 {
			return FallbackLocalDivergent
		}
	}
	return ""
}

// GetRecordingStream 獲取錄製檔案的 Reader（用於串流播放與證據包裝入）。
//
// **整檔路徑**：呼叫端逐位元組讀完，故來源判定順帶比對整檔雜湊
// （大小相同而內容被改的本機檔會退到離機）。
func (s *RecordingService) GetRecordingStream(sessionID uint) (io.ReadCloser, error) {
	res, err := s.ResolveRecording(sessionID, true)
	if err != nil {
		return nil, err
	}

	// 開啟檔案
	file, err := os.Open(res.Path)
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

// clearRecordingInDB 清空資料庫中的錄製資訊。
//
// **已離機者另走帳冊到期處置**：本機檔剛被保留政策刪除，帳冊必須
// 一併標記 `local_purged`（或 foreign 維持 foreign）並發保管鏈事件，否則會留下
// 「本機檔已刪卻仍被 worker 領取」的孤兒列，且離機狀態欄永遠停在 uploaded。
// **對遠端零呼叫**——遠端到期清理由部署方的 bucket lifecycle 承擔。
func (s *RecordingService) clearRecordingInDB(filePath string) error {
	if s.ledger != nil {
		var sessions []model.Session
		if err := database.DB.Where("recording_path = ? AND offsite_object_id IS NOT NULL",
			filePath).Find(&sessions).Error; err != nil {
			log.Printf("[RecordingRetention] 查詢已離機的過期會話失敗（%s）: %v", filePath, err)
		}
		for i := range sessions {
			// markOffsitePurged 內含擁有表清欄（含離機狀態），成立即不必再走下面那句
			if s.markOffsitePurged(&sessions[i]) {
				continue
			}
		}
	}

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
	// Source 本體來源 local／offsite。離機時 FileSize 取帳冊記載的
	// 大小——本機檔可能已因保留政策清除或截斷，回報磁碟上那個數字會說謊
	Source string `json:"source"`
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

	// 來源判定共用同一列（不另打一趟查詢）
	res, err := s.resolveFor(&session, false)
	if err != nil {
		return nil, err
	}

	// 組裝元數據。**FilePath／FileSize 取來源判定的結果**：離機來源時磁碟上
	// 那個檔案可能已被保留政策清除或截斷，回報它會說謊
	metadata := &RecordingMetadata{
		SessionID: session.ID,
		FilePath:  res.Path,
		FileSize:  res.Size,
		Duration:  session.Duration,
		CreatedAt: session.StartTime,
		Protocol:  string(session.Protocol),
		Source:    res.Source,
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

// RecordingProtocol 取該會話錄影的協定別。
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
